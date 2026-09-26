//go:build li && linux

package delivery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

func OpenJournalRewriteSource(cfg JournalConfig, format string) (*JournalRewriteSource, error) {
	return OpenJournalRewriteSourceOwned(cfg, format, nil, nil)
}

// Owned borrows the directory and .lock ownership acquired by the coordinator in
// stable descriptor order. Close releases only child/usage owners it acquired.
func OpenJournalRewriteSourceOwned(cfg JournalConfig, format string, dir *securestore.Dir, owner *securestore.Lock) (*JournalRewriteSource, error) {
	return OpenJournalRewriteSourceCatalogOwned(cfg, format, dir, owner, ".segments")
}
func OpenJournalRewriteSourceCatalogOwned(cfg JournalConfig, format string, dir *securestore.Dir, owner *securestore.Lock, catalogName string) (_ *JournalRewriteSource, result error) {
	if catalogName == "" || len(catalogName) > 255 || strings.ContainsAny(catalogName, "/\\") || catalogName == "." || catalogName == ".." {
		return nil, errJournalSchema
	}
	cfg.rewriteCatalog = catalogName

	if format != "lcx2" && format != "per-record" && format != "segments" || cfg.Interface != PDUTypeX2 && cfg.Interface != PDUTypeX3 {
		return nil, errJournalSchema
	}
	cfg.offline = true
	cfg.rewriteDir = dir
	cfg.rewriteLock = owner
	cfg.MaxPending = 4096
	cfg.MaxRecords = 2_000_000
	if cfg.Interface == PDUTypeX2 {
		cfg.MaxRecords = 1_000_000
	}
	var j *Journal
	var err error
	if format == "segments" {
		j, err = openSegmentJournal(cfg, false)
	} else {
		if cfg.Interface != PDUTypeX2 {
			return nil, errJournalSchema
		}
		cfg.MaxRecords = 1_000_000
		j, err = openLegacyJournal(cfg, false)
	}
	if err != nil {
		return nil, err
	}
	source := &JournalRewriteSource{j: j}
	failed := true
	defer func() {
		if failed {
			result = errors.Join(result, source.Close())
		}
	}()
	if format == "segments" && j.segments == nil || format != "segments" && j.segments != nil || format == "lcx2" && j.usage != nil || format == "per-record" && j.usage == nil {
		return nil, errJournalSchema
	}
	m := JournalRewriteMetadata{Format: format, JournalUUID: j.UUID(), StateIncarnation: j.cfg.StateIncarnation, Interface: cfg.Interface, MaxAge: j.cfg.MaxAge, RecordHighwater: j.next, AdmissionHighwater: j.next}
	h := sha256.New()
	var ids []uint64
	if s, ok := j.segments.(*journalSegments); ok {
		m.AdmissionHighwater = s.catalog.AdmissionLease
		raw, err := j.store.Read(catalogName, 4<<20)
		if err != nil {
			return nil, err
		}
		h.Write(raw)
		for _, ref := range s.catalog.Selected {
			e := s.extents[ref.ID]
			h.Write(e.ref.ID[:])
			var n [16]byte
			binary.BigEndian.PutUint64(n[:8], e.generation)
			binary.BigEndian.PutUint64(n[8:], uint64(e.cursor))
			h.Write(n[:])
			h.Write(e.chain[:])
			m.AllocatedBytes += e.file.AllocatedBytes()
		}
		for id := range s.locations {
			ids = append(ids, id)
		}
	} else {
		raw, err := j.store.Read(".state", 4096)
		if err != nil {
			return nil, err
		}
		h.Write(raw)
		for id := range j.entries {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	for _, id := range ids {
		r, err := j.readRecord(id)
		if err != nil {
			return nil, err
		}
		if _, err := journalPDUCheckpoint(r.Data, cfg.Interface, r.XID, false); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(r.Data)
		h.Write(sum[:])
		clear(r.Data)
		if j.entries[id] != nil {
			m.Records++
			m.PlaintextBytes += j.entries[id].payloadBytes
		}
	}
	if err := source.VisitControls(func(b []byte) error { h.Write(b); return nil }); err != nil {
		return nil, err
	}
	m.AllocatedBytes = 0
	if err := j.store.WalkEntries(func(name string) error {
		var size int64
		var err error
		switch {
		case strings.HasPrefix(name, ".usage-"), strings.HasPrefix(name, ".securestore-lock-"):
			size, err = j.store.MetadataAllocatedSize(name)
		case strings.HasPrefix(name, ".securestore-stage-"), strings.HasPrefix(name, ".securestore-tmp-"):
			size, err = j.store.RotationTemporaryAllocatedSize(name)
		default:
			size, err = j.store.AllocatedSize(name)
		}
		if err != nil {
			return err
		}
		if size > cfg.MaxBytes-m.AllocatedBytes {
			return ErrJournalFull
		}
		m.AllocatedBytes += size
		return nil
	}); err != nil {
		return nil, err
	}
	copy(m.Digest[:], h.Sum(nil))
	source.metadata = m
	failed = false
	return source, nil
}
func (s *JournalRewriteSource) VisitRecords(visit func(JournalRecord, uint64) error) error {
	ids := make([]uint64, 0, len(s.j.entries))
	for id := range s.j.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	for _, id := range ids {
		r, err := s.j.readRecord(id)
		if err != nil {
			return err
		}
		admission := id
		if segments, ok := s.j.segments.(*journalSegments); ok {
			admission = segments.locations[id].admission
		} else {
			r.Interface = PDUTypeX2
			r.JournalUUID = s.metadata.JournalUUID
			r.Provenance = li.DeliveryProvenance{Kind: "legacy_x2", CallID: r.CallID, CallGeneration: r.CallGeneration}
		}
		err = visit(r, admission)
		clear(r.Data)
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *JournalRewriteSource) VisitControls(visit func([]byte) error) error {
	var items []journalControl
	if segments, ok := s.j.segments.(*journalSegments); ok {
		for _, c := range segments.controls {
			items = append(items, c)
		}
		for _, cp := range segments.checkpoints {
			v := cp
			items = append(items, journalControl{Kind: "sequence", Sequence: &v})
		}
		for id, reason := range segments.terminals {
			if reason != "revoked" {
				items = append(items, journalControl{Kind: reason, ID: id})
			}
		}
	} else {
		if err := s.j.VisitSequences(func(cp x2x3.SequenceCheckpoint) error {
			v := cp
			items = append(items, journalControl{Kind: "sequence", Sequence: &v})
			return nil
		}); err != nil {
			return err
		}
	}
	sort.Slice(items, func(a, b int) bool {
		x, _ := json.Marshal(items[a])
		y, _ := json.Marshal(items[b])
		return string(x) < string(y)
	})
	for _, item := range items {
		b, err := json.Marshal(item)
		if err != nil {
			return err
		}
		if err := visit(b); err != nil {
			return err
		}
	}
	return nil
}

// Plan bounds packing loss by one maximum frame per extent. It validates full
// payloads again while computing exact metadata/fragment charges; no output is
// created. The seal/block upper bounds also include all head/index bootstraps.
func (s *JournalRewriteSource) Plan(ring *securestore.Keyring) (JournalRewritePlan, error) {
	if ring == nil {
		return JournalRewritePlan{}, errJournalSchema
	}
	var plan JournalRewritePlan
	var dataBytes, controlBytes int64
	var controlCount uint64
	var frameCost int64
	var fragments uint64
	flush := func() {
		if frameCost > 0 {
			dataBytes += (frameCost + 4095) / 4096 * 4096
			plan.Seals += 2
			frameCost = 0
		}
	}
	err := s.VisitRecords(func(r JournalRecord, _ uint64) error {
		if r.JournalUUID == uuid.Nil {
			r.JournalUUID = uuid.UUID{1}
		}
		meta, err := encodeRecordMetadata(r)
		if err != nil {
			return err
		}
		for pos := 0; pos < len(r.Data); pos += journalFragmentPlain {
			n := min(journalFragmentPlain, len(r.Data)-pos)
			cost := int64(n + len(ring.ActiveID()) + 256 + 2*len(meta) + 512)
			if frameCost+cost > journalBatchBytes {
				flush()
			}
			frameCost += cost
			fragments++
			plan.Seals++
		}
		return nil
	})
	if err != nil {
		return plan, err
	}
	flush()
	err = s.VisitControls(func(b []byte) error {
		controlBytes += int64(len(b) + 1)
		controlCount++
		return nil
	})
	if err != nil {
		return plan, err
	}
	usable := int64(securestore.FixedSegmentBytes - securestore.FixedSegmentDataStart - securestore.FixedSegmentMaxAppend)
	plan.DataSegments = max(1, int((dataBytes+usable-1)/usable))
	plan.ControlSegments = max(1, int((controlBytes+usable-1)/usable))
	if plan.DataSegments+plan.ControlSegments > journalSegmentMax {
		return plan, ErrJournalFull
	}
	plan.Seals += uint64(plan.DataSegments+plan.ControlSegments)*3 + (uint64(controlBytes/(journalBatchBytes-8192)+1)+controlCount/4096)*2 + 8
	// Every invocation costs at most its plaintext/ciphertext blocks plus bounded
	// framing. This deliberately overcharges segment-capacity rather than data.
	plan.AllocatedBytes = int64(plan.DataSegments+plan.ControlSegments) * securestore.FixedSegmentBytes
	plan.Blocks = uint64(plan.AllocatedBytes/8) + plan.Seals*1024 + fragments*1024
	return plan, nil
}

type journalRewriteTarget struct {
	controls           []journalControl
	controlBytes       int
	s                  *journalSegments
	slots              []JournalRewriteSegment
	used               map[uuid.UUID]bool
	batch              []journalOperation
	batchBytes         int
	finished, closed   bool
	lastID             uint64
	expected, imported uint64
}

func OpenJournalRewriteTarget(opts JournalRewriteTargetOptions) (*JournalRewriteTarget, error) {
	cfg := opts.Config
	m := opts.Metadata
	if opts.Directory == nil || opts.Owner == nil || opts.Usage == nil || cfg.Keys == nil || m.JournalUUID == uuid.Nil || cfg.Interface != m.Interface || opts.Usage.StoreID() != [16]byte(m.JournalUUID) || len(opts.Segments) < 2 || len(opts.Segments) > journalSegmentMax {
		return nil, errJournalSchema
	}
	cfg.offline = true
	cfg.rewriteDir = opts.Directory
	cfg.rewriteLock = opts.Owner
	cfg.StateIncarnation = m.StateIncarnation
	cfg.MaxAge = m.MaxAge
	cfg.MaxRecords = 2_000_000
	cfg.MaxPending = 4096
	j := &Journal{cfg: cfg, store: opts.Directory, lock: opts.Owner, usage: opts.Usage, borrowedUsage: true, keys: cfg.Keys, storeID: [16]byte(m.JournalUUID), entries: map[uint64]*journalEntry{}, heldByDID: map[uuid.UUID]int{}, next: m.RecordHighwater}
	var err error
	j.writer, err = securestore.NewWriter(opts.Usage)
	if err != nil {
		return nil, err
	}
	s := &journalSegments{j: j, deferCatalog: true, extents: map[uuid.UUID]*journalSegmentState{}, locations: map[uint64]journalRecordLocation{}, checkpoints: map[string]x2x3.SequenceCheckpoint{}, controls: map[string]journalControl{}, terminals: map[uint64]string{}, catalog: journalSegmentCatalog{Version: 1, JournalUUID: m.JournalUUID, StateIncarnation: m.StateIncarnation, Interface: m.Interface, MaxAgeNanos: int64(m.MaxAge), RecordLease: m.RecordHighwater, AdmissionLease: m.AdmissionHighwater}}
	j.segments = s
	s.dataLimit = cfg.MaxBytes
	s.controlLimit = cfg.MaxBytes
	target := &journalRewriteTarget{s: s, slots: opts.Segments, used: map[uuid.UUID]bool{}, expected: m.Records}
	names := map[uuid.UUID]bool{}
	for _, slot := range opts.Segments {
		if slot.ID == uuid.Nil || names[slot.ID] || slot.Kind != "data" && slot.Kind != "control" || slot.Owner == nil || slot.Initialize == nil {
			return nil, errJournalSchema
		}
		names[slot.ID] = true
	}
	s.preparedExtent = target.prepare
	return &JournalRewriteTarget{backend: target}, nil
}
func (t *journalRewriteTarget) prepare(kind string) (*journalSegmentState, error) {
	for _, slot := range t.slots {
		if slot.Kind != kind || t.used[slot.ID] {
			continue
		}
		t.used[slot.ID] = true
		e := &journalSegmentState{ref: journalSegmentRef{slot.ID, kind}, lock: slot.Owner, cursor: securestore.FixedSegmentDataStart, priorCursor: securestore.FixedSegmentDataStart}
		t.s.extents[slot.ID] = e
		bootstrap, err := t.s.bootstrap(e)
		if err != nil {
			return nil, err
		}
		out, err := slot.Initialize(bootstrap)
		if out != securestore.Committed || err != nil {
			return nil, journalStorageError(out, err)
		}
		e.file, err = t.s.j.store.OpenFixedSegment(segmentName(slot.ID))
		if err != nil {
			return nil, err
		}
		if err := e.file.Activate(e.cursor, 0); err != nil {
			return nil, err
		}
		t.s.catalog.Pending = append(t.s.catalog.Pending, e.ref)
		return e, nil
	}
	return nil, ErrJournalFull
}
func (t *journalRewriteTarget) importRecord(r JournalRecord, admission uint64) error {
	if t.closed || t.finished || r.ID <= t.lastID || r.ID > t.s.catalog.RecordLease || admission == 0 || admission > t.s.catalog.AdmissionLease || r.JournalUUID != t.s.j.UUID() || r.Interface != t.s.j.cfg.Interface || r.StateIncarnation != t.s.j.cfg.StateIncarnation {
		return errJournalSchema
	}
	if _, err := journalPDUCheckpoint(r.Data, r.Interface, r.XID, false); err != nil {
		return err
	}
	meta, err := encodeRecordMetadata(r)
	if err != nil {
		return err
	}
	size := len(r.Data) + 2*len(meta)
	if t.batchBytes+size > journalBatchBytes {
		if err := t.flush(); err != nil {
			return err
		}
	}
	r.Data = append([]byte(nil), r.Data...)
	t.batch = append(t.batch, journalOperation{record: r, admission: admission, metadata: meta})
	t.batchBytes += size
	t.lastID = r.ID
	t.imported++
	if t.batchBytes >= journalBatchBytes {
		return t.flush()
	}
	return nil
}
func (t *journalRewriteTarget) flush() error {
	if len(t.batch) == 0 {
		return nil
	}
	err := t.s.persistBatch(t.batch)
	for _, op := range t.batch {
		clear(op.record.Data)
	}
	t.batch = nil
	t.batchBytes = 0
	return err
}
func (t *journalRewriteTarget) importControl(b []byte) error {
	if t.closed || t.finished || len(b) > journalBatchBytes {
		return errJournalSchema
	}
	var c journalControl
	if err := strictSegmentJSON(b, &c); err != nil {
		return err
	}
	if err := t.s.validateControl(c); err != nil {
		return err
	}
	if t.controlBytes+len(b)+1 > journalBatchBytes-8192 || len(t.controls) == 4096 {
		if err := t.flushControls(); err != nil {
			return err
		}
	}
	t.controls = append(t.controls, c)
	t.controlBytes += len(b) + 1
	return nil

}
func (t *journalRewriteTarget) finish() ([]byte, error) {
	if t.closed || t.finished || t.imported != t.expected {
		return nil, errJournalSchema
	}
	if err := t.flush(); err != nil {
		return nil, err
	}
	if err := t.flushControls(); err != nil {
		return nil, err
	}
	if t.s.activeControl == nil {
		if _, err := t.s.createExtent("control"); err != nil {
			return nil, err
		}
	}
	if t.s.activeData == nil {
		if _, err := t.s.createExtent("data"); err != nil {
			return nil, err
		}
	}
	t.s.catalog.Pending = nil
	p, err := json.Marshal(t.s.catalog)
	if err != nil {
		return nil, err
	}
	defer clear(p)
	b, err := t.s.j.writer.Seal(securestore.JournalState, securestore.Binding{Store: t.s.j.storeID, Object: "segment-catalog"}, p)
	if err != nil {
		return nil, err
	}
	t.finished = true
	return b, nil
}
func (t *journalRewriteTarget) close() error {
	if t.closed {
		return nil
	}
	t.closed = true
	for _, op := range t.batch {
		clear(op.record.Data)
	}
	var err error
	for _, e := range t.s.extents {
		if e.file != nil {
			err = errors.Join(err, e.file.Close())
		}
	}
	return err
}

// PublicationNames are opaque metadata: coordinators bind these names to their
// authenticated transaction before preparation, never infer authority from them.
func JournalRewriteSegmentName(id uuid.UUID) string      { return segmentName(id) }
func JournalRewriteSegmentStageName(id uuid.UUID) string { return segmentStageName(id) }

func (t *journalRewriteTarget) flushControls() error {
	if len(t.controls) == 0 {
		return nil
	}
	_, err := t.s.writeControls(t.controls)
	t.controls = nil
	t.controlBytes = 0
	return err
}

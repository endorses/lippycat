//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const segmentFrameHeader = 32
const segmentChunkMax = 768 << 10

type productionSegmentHead struct {
	Version          int
	Journal, Segment uuid.UUID
	Interface        PDUType
	Kind             string
	Generation       uint64
	End              int64
	Chain            [32]byte
}
type segmentFragment struct {
	ID, Admission  uint64
	Part, Parts    uint32
	Total          uint32
	Offset, Length uint32
	Hash           [32]byte
	Metadata       []byte
}
type segmentIndex struct {
	Version          int
	Journal, Segment uuid.UUID
	Interface        PDUType
	Kind             string
	Generation       uint64
	Start, End       int64
	Previous         [32]byte
	Fragments        []segmentFragment
	Controls         []journalControl
}
type journalFragmentLocation struct {
	segment uuid.UUID
	offset  int64
	length  int
	hash    [32]byte
}
type journalFragmentAssembly struct {
	metadata     []byte
	admission    uint64
	parts, total uint32
	chunks       []journalFragmentLocation
	bytes        uint64
}

func (s *journalSegments) segmentBinding(e *journalSegmentState, suffix string) securestore.Binding {
	return securestore.Binding{Store: s.j.storeID, Object: "segment/" + e.ref.ID.String() + "/" + suffix}
}
func blockEnvelope(b []byte) ([]byte, error) {
	if len(b) > securestore.FixedSegmentBlock-4 {
		return nil, errJournalSchema
	}
	out := make([]byte, securestore.FixedSegmentBlock)
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out, nil
}
func (s *journalSegments) head(e *journalSegmentState, slot uint8, generation uint64, end int64, chain [32]byte) ([]byte, error) {
	p, _ := json.Marshal(productionSegmentHead{1, s.j.UUID(), e.ref.ID, s.j.cfg.Interface, e.ref.Kind, generation, end, chain})
	defer clear(p)
	seal := s.j.writer.Seal
	if e.ref.Kind == "control" && !s.ordinaryControl && !s.deferCatalog {
		seal = s.j.writer.SealControl
	}
	b, err := seal(securestore.JournalState, s.segmentBinding(e, fmt.Sprintf("head/%d", slot)), p)
	if err != nil {
		return nil, err
	}
	return blockEnvelope(b)
}
func (s *journalSegments) bootstrap(e *journalSegmentState) ([]byte, error) {
	p, _ := json.Marshal(productionSegmentHead{Version: 1, Journal: s.j.UUID(), Segment: e.ref.ID, Interface: s.j.cfg.Interface, Kind: e.ref.Kind, End: securestore.FixedSegmentDataStart})
	defer clear(p)
	b, err := s.j.writer.SealControl(securestore.JournalState, s.segmentBinding(e, "bootstrap"), p)
	if err != nil {
		return nil, err
	}
	out, err := blockEnvelope(b)
	if err != nil {
		return nil, err
	}
	for slot := uint8(0); slot < 2; slot++ {
		b, err := s.head(e, slot, 0, securestore.FixedSegmentDataStart, [32]byte{})
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}
func (s *journalSegments) readHead(e *journalSegmentState, block int, suffix string) (productionSegmentHead, error) {
	var h productionSegmentHead
	b := make([]byte, securestore.FixedSegmentBlock)
	if err := e.file.ReadAt(b, int64(block*securestore.FixedSegmentBlock)); err != nil {
		return h, err
	}
	n := int(binary.BigEndian.Uint32(b))
	if n <= 0 || n > len(b)-4 {
		return h, errJournalSchema
	}
	for _, v := range b[4+n:] {
		if v != 0 {
			return h, errJournalSchema
		}
	}
	p, err := s.j.keys.Open(securestore.JournalState, s.segmentBinding(e, suffix), b[4:4+n], securestore.FixedSegmentBlock)
	if err != nil {
		return h, err
	}
	defer clear(p)
	if err := strictSegmentJSON(p, &h); err != nil {
		return h, err
	}
	if h.Version != 1 || h.Journal != s.j.UUID() || h.Segment != e.ref.ID || h.Interface != s.j.cfg.Interface || h.Kind != e.ref.Kind || h.End < securestore.FixedSegmentDataStart || h.End > securestore.FixedSegmentBytes || h.End%securestore.FixedSegmentBlock != 0 {
		return h, errJournalSchema
	}
	return h, nil
}
func (s *journalSegments) openExtent(ref journalSegmentRef) error {
	if ref.ID == uuid.Nil || ref.Kind != "data" && ref.Kind != "control" || s.extents[ref.ID] != nil {
		return errJournalSchema
	}
	lock, err := s.j.store.Lock(segmentName(ref.ID))
	if err != nil {
		return err
	}
	e := &journalSegmentState{ref: ref, lock: lock}
	s.extents[ref.ID] = e
	e.file, err = s.j.store.OpenFixedSegment(segmentName(ref.ID))
	if err != nil {
		return err
	}
	boot, err := s.readHead(e, 0, "bootstrap")
	if err != nil {
		return err
	}
	if boot.Generation != 0 || boot.End != securestore.FixedSegmentDataStart || boot.Chain != [32]byte{} {
		return errJournalSchema
	}
	a, err := s.readHead(e, 1, "head/0")
	if err != nil {
		return err
	}
	b, err := s.readHead(e, 2, "head/1")
	if err != nil {
		return err
	}
	selected := a
	e.active = 0
	if b.Generation > a.Generation {
		selected = b
		e.active = 1
	}
	if a.Generation == b.Generation {
		if a.Generation != 0 || a.End != b.End || a.Chain != b.Chain {
			return errJournalSchema
		}
	} else if a.Generation+1 != b.Generation && b.Generation+1 != a.Generation {
		return errJournalSchema
	}
	prior := b
	if e.active == 1 {
		prior = a
	}
	e.priorGeneration = prior.Generation
	e.priorCursor = prior.End
	e.priorChain = prior.Chain
	e.cursor = selected.End
	e.generation = selected.Generation
	e.chain = selected.Chain
	if ref.Kind == "data" {
		s.dataAllocated += e.file.AllocatedBytes()
		s.activeData = e
	} else {
		s.controlAllocated += e.file.AllocatedBytes()
		s.activeControl = e
	}
	if s.dataAllocated > s.dataLimit || s.controlAllocated > s.controlLimit {
		return ErrJournalFull
	}
	return nil
}
func (s *journalSegments) appendFrame(e *journalSegmentState, body []byte, fragments []segmentFragment, controls []journalControl) (securestore.Outcome, error) {
	if len(body) > journalBatchBytes || len(fragments) > 4096 || len(controls) > 4096 {
		return securestore.NotCommitted, errJournalSchema
	}
	index := segmentIndex{1, s.j.UUID(), e.ref.ID, s.j.cfg.Interface, e.ref.Kind, e.generation + 1, e.cursor, 0, e.chain, fragments, controls}
	// End is independent of ciphertext bytes; reserve the largest decimal End width
	// using the actual canonical encoding until its padded length stabilizes.
	index.End = e.cursor + securestore.FixedSegmentMaxAppend
	var p, b []byte
	var err error
	var padded int
	for attempt := 0; attempt < 3; attempt++ {
		p, err = json.Marshal(index)
		if err != nil || len(p) > journalBatchBytes {
			return securestore.NotCommitted, errJournalSchema
		}
		// Envelope framing is fixed for a given binding and key ID. Seal once after
		// deriving its exact size with the public sizing helper.
		envelopeBytes, err := s.j.writer.SealedSize(securestore.JournalBatchIndex, s.segmentBinding(e, fmt.Sprintf("batch/%d", index.Generation)), len(p))
		if err != nil {
			return securestore.NotCommitted, err
		}
		padded = (segmentFrameHeader + len(body) + envelopeBytes + securestore.FixedSegmentBlock - 1) / securestore.FixedSegmentBlock * securestore.FixedSegmentBlock
		end := e.cursor + int64(padded)
		if end == index.End {
			break
		}
		index.End = end
	}
	if padded > securestore.FixedSegmentMaxAppend || index.End > securestore.FixedSegmentBytes {
		return securestore.NotCommitted, ErrJournalFull
	}
	seal := s.j.writer.Seal
	if e.ref.Kind == "control" && !s.ordinaryControl && !s.deferCatalog {
		seal = s.j.writer.SealControl
	}
	b, err = seal(securestore.JournalBatchIndex, s.segmentBinding(e, fmt.Sprintf("batch/%d", index.Generation)), p)
	clear(p)
	if err != nil {
		return securestore.NotCommitted, err
	}
	frame := make([]byte, padded)
	defer clear(frame)
	copy(frame, "LJS2")
	binary.BigEndian.PutUint32(frame[4:], uint32(padded))
	binary.BigEndian.PutUint32(frame[8:], uint32(segmentFrameHeader+len(body)))
	binary.BigEndian.PutUint32(frame[12:], uint32(len(b)))
	binary.BigEndian.PutUint64(frame[16:], index.Generation)
	copy(frame[segmentFrameHeader:], body)
	copy(frame[segmentFrameHeader+len(body):], b)
	chain := sha256.Sum256(frame)
	head, err := s.head(e, e.active^1, index.Generation, index.End, chain)
	if err != nil {
		return securestore.NotCommitted, err
	}
	var out securestore.Outcome
	if s.commitFrame != nil {
		out, err = s.commitFrame(e.file, frame, head)
	} else {
		out, err = e.file.Commit(frame, head)
	}
	if out == securestore.Committed {
		e.fragments += len(fragments)
		e.priorGeneration = e.generation
		e.priorCursor = e.cursor
		e.priorChain = e.chain
		e.generation = index.Generation
		e.cursor = index.End
		e.chain = chain
		e.active ^= 1
	}
	return out, journalStorageError(out, err)
}
func (s *journalSegments) scanExtent(e *journalSegmentState, visit func(segmentIndex) error) error {
	return s.scanExtentMode(e, visit, true)
}
func (s *journalSegments) scanExtentMode(e *journalSegmentState, visit func(segmentIndex) error, activate bool) error {
	cursor := int64(securestore.FixedSegmentDataStart)
	var previous [32]byte
	var generation uint64
	if e.priorGeneration == 0 && (e.priorCursor != cursor || e.priorChain != previous) {
		return errJournalSchema
	}
	for cursor < e.cursor {
		header := make([]byte, segmentFrameHeader)
		if err := e.file.ReadAt(header, cursor); err != nil {
			return err
		}
		n, off, size := int(binary.BigEndian.Uint32(header[4:])), int(binary.BigEndian.Uint32(header[8:])), int(binary.BigEndian.Uint32(header[12:]))
		if string(header[:4]) != "LJS2" || n <= 0 || n > securestore.FixedSegmentMaxAppend || n%securestore.FixedSegmentBlock != 0 || cursor+int64(n) > e.cursor || off < segmentFrameHeader || off > n || size <= 0 || size > n-off || binary.BigEndian.Uint64(header[16:]) != generation+1 || !bytes.Equal(header[24:], make([]byte, 8)) {
			return errJournalSchema
		}
		frame := make([]byte, n)
		if err := e.file.ReadAt(frame, cursor); err != nil {
			return err
		}
		for _, v := range frame[off+size:] {
			if v != 0 {
				return errJournalSchema
			}
		}
		p, err := s.j.keys.Open(securestore.JournalBatchIndex, s.segmentBinding(e, fmt.Sprintf("batch/%d", generation+1)), frame[off:off+size], journalBatchBytes)
		if err != nil {
			return err
		}
		var index segmentIndex
		err = strictSegmentJSON(p, &index)
		clear(p)
		if err != nil {
			return err
		}
		if index.Version != 1 || index.Journal != s.j.UUID() || index.Segment != e.ref.ID || index.Interface != s.j.cfg.Interface || index.Kind != e.ref.Kind || index.Generation != generation+1 || index.Start != cursor || index.End != cursor+int64(n) || index.Previous != previous || len(index.Fragments) > 4096 || len(index.Controls) > 4096 {
			return errJournalSchema
		}
		if e.ref.Kind == "data" && len(index.Controls) > 0 || e.ref.Kind == "control" && (len(index.Fragments) > 0 || off != segmentFrameHeader) {
			return errJournalSchema
		}
		pos := uint32(segmentFrameHeader)
		for _, f := range index.Fragments {
			if f.Offset != pos || f.Length == 0 || f.Length > segmentChunkMax || uint64(f.Offset)+uint64(f.Length) > uint64(off) || f.Hash != sha256.Sum256(frame[f.Offset:f.Offset+f.Length]) {
				return errJournalSchema
			}
			pos += f.Length
		}
		if int(pos) != off {
			return errJournalSchema
		}
		if err := visit(index); err != nil {
			return err
		}
		previous = sha256.Sum256(frame)
		clear(frame)
		generation++
		cursor += int64(n)
		if generation == e.priorGeneration && (cursor != e.priorCursor || previous != e.priorChain) {
			return errJournalSchema
		}
	}
	if cursor != e.cursor || generation != e.generation || previous != e.chain {
		return errJournalSchema
	}
	if activate && !s.j.cfg.offline {
		return s.activateExtent(e)
	}
	return nil
}

// activateExtent is called only after both heads and their selected prefixes
// have authenticated under the same retained owners.
func (s *journalSegments) activateExtent(e *journalSegmentState) error {
	err := e.file.Activate(e.cursor, e.active)
	if errors.Is(err, securestore.ErrFixedDirtyTail) {
		if closeErr := e.file.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		e.file, err = s.j.store.OpenFixedSegment(segmentName(e.ref.ID))
		if err != nil {
			return err
		}
		if _, err = e.file.DiscardUnselectedTail(e.cursor); err != nil {
			return err
		}
		return e.file.Activate(e.cursor, e.active)
	}
	return err
}

func (s *journalSegments) recoverControlsAndProducts() error {
	assemblies := map[uint64]*journalFragmentAssembly{}
	for _, ref := range s.catalog.Selected {
		e := s.extents[ref.ID]
		if err := s.scanExtent(e, func(index segmentIndex) error {
			for _, c := range index.Controls {
				if err := s.applyControl(c, true); err != nil {
					return err
				}
			}
			e.fragments += len(index.Fragments)
			for _, f := range index.Fragments {
				if f.ID == 0 || f.ID > s.catalog.RecordLease || f.Admission == 0 || f.Admission > s.catalog.AdmissionLease || f.Parts == 0 || f.Parts > 128 || f.Part >= f.Parts || f.Total == 0 || int64(f.Total) > journalMaxRecord+journalMetadataMax+4096 {
					return errJournalSchema
				}
				rec, n, err := decodeRecordMetadata(f.Metadata)
				if err != nil || rec.ID != f.ID || rec.JournalUUID != s.j.UUID() || rec.Interface != s.j.cfg.Interface || rec.StateIncarnation != s.j.cfg.StateIncarnation || n > uint64(journalMaxRecord) || uint64(f.Total) != n || uint64(f.Parts) != (n+journalFragmentPlain-1)/journalFragmentPlain {
					return errJournalSchema
				}
				a := assemblies[f.ID]
				if a == nil {
					if f.Part != 0 || s.locations[f.ID].metadata != nil || len(assemblies)+len(s.locations) >= s.j.cfg.MaxRecords {
						return errJournalSchema
					}
					charge := journalLocationCharge(len(f.Metadata), int(n))
					if charge > journalIndexMemory-s.indexBytes {
						return ErrJournalFull
					}
					s.indexBytes += charge
					a = &journalFragmentAssembly{metadata: f.Metadata, admission: f.Admission, parts: f.Parts, total: f.Total}
					assemblies[f.ID] = a
				}
				if uint32(len(a.chunks)) != f.Part || a.parts != f.Parts || a.total != f.Total || a.admission != f.Admission || !bytes.Equal(a.metadata, f.Metadata) {
					return errJournalSchema
				}
				a.chunks = append(a.chunks, journalFragmentLocation{ref.ID, index.Start + int64(f.Offset), int(f.Length), f.Hash})
				a.bytes += uint64(f.Length)
				if f.Part+1 == f.Parts {
					if a.bytes == 0 {
						return errJournalSchema
					}
					s.locations[f.ID] = journalRecordLocation{metadata: a.metadata, admission: a.admission, chunks: a.chunks, charge: journalLocationCharge(len(a.metadata), int(n))}
					delete(assemblies, f.ID)
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	for _, a := range assemblies {
		_, size, _ := decodeRecordMetadata(a.metadata)
		s.indexBytes -= journalLocationCharge(len(a.metadata), int(size))
	}
	// A prefix without its final authenticated fragment is an interrupted admission,
	// never a delivery record. Its leased identities remain consumed.
	for id, loc := range s.locations {
		rec, n, err := decodeRecordMetadata(loc.metadata)
		if err != nil {
			return err
		}
		if rec.Provenance.Kind == "call" {
			c := s.controls[journalCallKey(callForRecord(rec))]
			if c.Call == nil || c.Call.identity() != callForRecord(rec).identity() || c.Call.CoveredRecordHighwater < rec.ID || c.Call.CoveredAdmissionHighwater < loc.admission {
				return errJournalSchema
			}
		}
		if s.terminalReason(rec, loc.admission) != "" {
			continue
		}
		if !s.terminalCreditAvailable() || s.controlMemory+int64(len(s.j.entries)+1)*32 > journalControlMemory {
			return ErrJournalFull
		}
		s.j.entries[id] = &journalEntry{did: rec.DID, payloadBytes: int64(n), persisted: true, held: true, size: loc.charge}
		s.j.heldByDID[rec.DID]++
		s.observeDeadline(rec)
		s.controlLiability += journalTerminalCredit
		for _, chunk := range loc.chunks {
			s.extents[chunk.segment].live++
		}
	}
	return nil
}
func (s *journalSegments) readRecord(id uint64) (JournalRecord, error) {
	s.ioMu.Lock()
	defer s.ioMu.Unlock()
	return s.readRecordLocked(id)
}
func (s *journalSegments) readRecordLocked(id uint64) (JournalRecord, error) {
	loc, ok := s.locations[id]
	if !ok {
		return JournalRecord{}, errors.New("journal product unavailable")
	}
	rec, total, err := decodeRecordMetadata(loc.metadata)
	if err != nil || total > uint64(journalMaxRecord) {
		return JournalRecord{}, errJournalSchema
	}
	rec.Data = make([]byte, int(total))
	pos := 0
	purpose := securestore.X2Product
	if s.j.cfg.Interface == PDUTypeX3 {
		purpose = securestore.X3Product
	}
	for part, c := range loc.chunks {
		e := s.extents[c.segment]
		if e == nil {
			clear(rec.Data)
			return JournalRecord{}, errJournalSchema
		}
		cipher := make([]byte, c.length)
		if err := e.file.ReadAt(cipher, c.offset); err != nil {
			clear(rec.Data)
			return JournalRecord{}, err
		}
		if sha256.Sum256(cipher) != c.hash {
			clear(rec.Data)
			return JournalRecord{}, errJournalSchema
		}
		plain, err := s.j.keys.Open(purpose, s.productBinding(id, part), cipher, segmentChunkMax)
		clear(cipher)
		if err != nil {
			clear(rec.Data)
			return JournalRecord{}, err
		}
		if len(plain) != min(journalFragmentPlain, len(rec.Data)-pos) {
			clear(plain)
			clear(rec.Data)
			return JournalRecord{}, errJournalSchema
		}
		copy(rec.Data[pos:], plain)
		pos += len(plain)
		clear(plain)
	}
	prefix, err := recordPrefix(rec, uint64(len(rec.Data)))
	if err != nil || pos != len(rec.Data) || recordContentHash(prefix, rec.Data) != rec.ContentSHA256 {
		clear(rec.Data)
		return JournalRecord{}, errJournalSchema
	}
	if _, err := journalPDUCheckpoint(rec.Data, s.j.cfg.Interface, rec.XID, s.j.cfg.PreserveSequences); err != nil {
		clear(rec.Data)
		return JournalRecord{}, err
	}
	return rec, nil
}
func (s *journalSegments) productBinding(id uint64, part int) securestore.Binding {
	return securestore.Binding{Store: s.j.storeID, Object: fmt.Sprintf("%d/fragment/%d", id, part)}
}

func journalLocationCharge(metadata, data int) int64 {
	return int64(512 + metadata + (data/journalFragmentPlain+1)*64)
}

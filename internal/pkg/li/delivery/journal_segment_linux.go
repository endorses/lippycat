//go:build li && linux

package delivery

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const journalBatchBytes = 1 << 20
const journalBatchDelay = 10 * time.Millisecond
const journalSegmentMax = 4096
const journalIDLease = 4096
const journalSegmentScratch = int64(6 * securestore.FixedSegmentBytes)
const journalSegmentMinimum = int64(10 * securestore.FixedSegmentBytes)

type journalSegmentRef struct {
	ID   uuid.UUID
	Kind string
}
type journalSegmentCatalog struct {
	Version                       int
	JournalUUID, StateIncarnation uuid.UUID
	Interface                     PDUType
	RecordLease, AdmissionLease   uint64
	MaxAgeNanos                   int64
	Selected                      []journalSegmentRef
	Pending                       []journalSegmentRef
}
type journalRecordLocation struct {
	segment    uuid.UUID
	offset     int64
	length     int
	cipherHash [32]byte
	chunks     []journalFragmentLocation
	metadata   []byte
	admission  uint64
	charge     int64
}
type journalSegmentState struct {
	fragments       int
	priorGeneration uint64
	priorCursor     int64
	priorChain      [32]byte
	ref             journalSegmentRef
	file            *securestore.FixedSegment
	lock            *securestore.Lock
	generation      uint64
	cursor          int64
	active          uint8
	chain           [32]byte
	live            int
}
type journalControl struct {
	Kind       string
	ID         uint64
	Record     *JournalRecord
	Call       *journalCallControl
	Revocation *li.StateRevocation
	Sequence   *x2x3.SequenceCheckpoint
	Highwater  uint64
}
type journalControlRequest struct {
	controls []journalControl
	done     chan journalControlResult
}
type journalControlResult struct {
	out securestore.Outcome
	err error
}
type journalCallback struct {
	id  uint64
	fn  func(uint64, error)
	err error
}

type journalSegments struct {
	controlMemory                   int64
	commitFrame                     func(*securestore.FixedSegment, []byte, []byte) (securestore.Outcome, error)
	retainedAllocation              int64
	ordinaryControl                 bool
	deadlineByID                    map[uint64]*journalDeadline
	deadlines                       journalDeadlines
	deferCatalog                    bool
	compacting                      bool
	catalogName                     string
	catalogWrite                    func(string, []byte) error
	preparedExtent                  func(string) (*journalSegmentState, error)
	j                               *Journal
	ioMu                            sync.Mutex
	controlSend                     sync.RWMutex
	controlsClosed                  bool
	pendingBytes, indexBytes        int64
	dataFree                        int64
	recordLease, admissionLease     uint64
	catalog                         journalSegmentCatalog
	extents                         map[uuid.UUID]*journalSegmentState
	activeData, activeControl       *journalSegmentState
	locations                       map[uint64]journalRecordLocation
	checkpoints                     map[string]x2x3.SequenceCheckpoint
	controls                        map[string]journalControl
	terminals                       map[uint64]string
	controlsCh                      chan journalControlRequest
	controlsDone                    chan struct{}
	callbacks                       chan journalCallback
	callbacksDone                   chan struct{}
	admission                       uint64
	reservations                    int
	reservedBytes, controlLiability int64
	dataAllocated, controlAllocated int64
	dataLimit, controlLimit         int64
	faulted                         bool
}

func openSegmentJournal(cfg JournalConfig, upgrade bool) (_ *Journal, result error) {
	if cfg.Interface != PDUTypeX2 && cfg.Interface != PDUTypeX3 {
		return nil, errJournalSchema
	}
	if (!cfg.offline || cfg.preflight) && cfg.Interface == PDUTypeX3 && (cfg.StateIncarnation == uuid.Nil || cfg.MaxAge <= 0) {
		return nil, errors.New("X3 journal requires administrative incarnation and positive maximum age")
	}
	if cfg.MaxPending <= 0 || cfg.MaxRecords <= 0 || cfg.MaxRecords > 2_000_000 || cfg.Interface == PDUTypeX2 && cfg.MaxRecords > 1_000_000 || cfg.MaxBytes < journalSegmentMinimum {
		return nil, errors.New("segmented journal requires bounded entries and at least 320 MiB allocated workspace")
	}
	ring := cfg.Keys
	var err error
	if ring == nil {
		keyID, legacy := cfg.KeyID, cfg.LegacyKeyID
		if keyID == "" {
			keyID = journalDefaultKeyID
			if legacy == "" {
				legacy = keyID
			}
		}
		ring, err = securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: keyID, File: cfg.KeyFile}, Prior: cfg.ReadKeys, LegacyID: legacy})
		if err != nil {
			return nil, err
		}
	}
	if cfg.ValidateKeys != nil {
		if err := cfg.ValidateKeys(ring); err != nil {
			return nil, err
		}
	}
	dir, err := journalOpenDirectory(cfg)
	if err != nil {
		return nil, err
	}
	j := &Journal{cfg: cfg, store: dir, keys: ring, entries: map[uint64]*journalEntry{}, sequences: map[string]journalSequenceEntry{}, heldByDID: map[uuid.UUID]int{}, ops: make(chan journalOperation, min(cfg.MaxPending, 4096)), done: make(chan struct{}), wake: make(chan struct{}, 1)}
	j.cfg.MaxPending = cap(j.ops)
	j.telemetry.Initialize("encrypted", ring)

	defer func() {
		if result != nil {
			result = errors.Join(result, j.closeStorage())
		}
	}()
	j.lock = cfg.rewriteLock
	if j.lock == nil {
		j.lock, err = dir.Lock(".lock")
	}
	if err != nil {
		return nil, err
	}
	if !cfg.offline {
		if _, e := dir.Read(".journal-retired", 4<<20); e == nil {
			return nil, errors.New("journal source has been retired by offline rewrite")
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	}
	existed := true
	if _, err = dir.Read(".lock", 0); errors.Is(err, os.ErrNotExist) {
		existed = false
		out, e := dir.Create(".lock", nil)
		if e != nil {
			return nil, journalStorageError(out, e)
		}
	} else if err != nil {
		return nil, err
	}
	_, catalogPresentErr := dir.FileIdentity(".segments")
	if catalogPresentErr != nil && !errors.Is(catalogPresentErr, os.ErrNotExist) {
		return nil, catalogPresentErr
	}
	if errors.Is(catalogPresentErr, os.ErrNotExist) && cfg.rewriteCatalog == "" {
		if _, err := dir.Read(".state", 4096); err == nil {
			if cfg.Interface != PDUTypeX2 {
				return nil, errors.New("legacy X2 directory cannot be opened as X3")
			}
			if err := j.closeStorage(); err != nil {
				return nil, err
			}
			j.store = nil
			j.lock = nil
			cfg.Keys = ring
			cfg.ValidateKeys = nil
			return openLegacyJournal(cfg, upgrade)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	j.allocationUnit, err = dir.AllocationUnit()
	if err != nil {
		return nil, err
	}
	j.faultReserve = max(4<<20, cfg.MaxBytes/10)
	j.stats.MaxBytes = cfg.MaxBytes
	j.writeFile = j.writePath
	s := &journalSegments{j: j, extents: map[uuid.UUID]*journalSegmentState{}, locations: map[uint64]journalRecordLocation{}, checkpoints: map[string]x2x3.SequenceCheckpoint{}, controls: map[string]journalControl{}, terminals: map[uint64]string{}, controlsCh: make(chan journalControlRequest, min(cfg.MaxPending, 4096)), controlsDone: make(chan struct{}), callbacks: make(chan journalCallback, min(cfg.MaxPending, 4096)), callbacksDone: make(chan struct{})}
	s.controlLimit = max(2*securestore.FixedSegmentBytes, cfg.MaxBytes/10)
	s.dataLimit = cfg.MaxBytes - s.controlLimit - max(journalSegmentScratch, cfg.MaxBytes/10) - (4 << 20)
	if s.dataLimit < securestore.FixedSegmentBytes {
		return nil, ErrJournalFull
	}
	j.segments = s
	catalogName := cfg.rewriteCatalog
	if catalogName == "" {
		catalogName = ".segments"
	}
	raw, err := dir.Read(catalogName, 4<<20)
	if errors.Is(err, os.ErrNotExist) {
		if cfg.offline {
			return nil, os.ErrNotExist
		}
		if existed {
			return nil, errors.New("required segment catalog is missing from used storage")
		}
		names := 0
		if err := dir.WalkEntries(func(name string) error {
			if name != ".lock" && !strings.HasPrefix(name, ".securestore-lock-") {
				names++
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if names != 0 {
			return nil, errors.New("new segment store is not empty")
		}
		if err := j.initializeUsage(); err != nil {
			return nil, err
		}
		s.catalog = journalSegmentCatalog{Version: 1, JournalUUID: j.UUID(), StateIncarnation: cfg.StateIncarnation, Interface: cfg.Interface, MaxAgeNanos: int64(cfg.MaxAge)}
		if err := s.persistCatalog(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		if cfg.offline && cfg.rewriteUsage != nil {
			j.usage = cfg.rewriteUsage
			j.borrowedUsage = true
		} else {
			j.usage, err = securestore.OpenUsage(dir, ring, [16]byte{})
			if err != nil {
				return nil, err
			}
		}
		if err = j.installWriter(); err != nil {
			return nil, err
		}
		plain, err := ring.Open(securestore.JournalState, securestore.Binding{Store: j.storeID, Object: "segment-catalog"}, raw, 4<<20)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		if err := strictSegmentJSON(plain, &s.catalog); err != nil {
			return nil, err
		}
		if cfg.offline && !cfg.preflight {
			cfg.StateIncarnation = s.catalog.StateIncarnation
			cfg.MaxAge = time.Duration(s.catalog.MaxAgeNanos)
			j.cfg.StateIncarnation = cfg.StateIncarnation
			j.cfg.MaxAge = cfg.MaxAge
		}
		if s.catalog.Version != 1 || s.catalog.JournalUUID != j.UUID() || s.catalog.Interface != cfg.Interface || s.catalog.StateIncarnation != cfg.StateIncarnation || len(s.catalog.Selected) > journalSegmentMax || len(s.catalog.Pending) > journalSegmentMax {
			return nil, errJournalSchema
		}
		j.next = s.catalog.RecordLease
		s.admission = s.catalog.AdmissionLease
		for _, ref := range s.catalog.Selected {
			if err := s.openExtent(ref); err != nil {
				return nil, err
			}
		}
		if err := s.recoverControlsAndProducts(); err != nil {
			return nil, err
		}
		// Exact catalog-owned pending extents were never publication authorities.
		// Authenticate all selected history before cleaning those bounded stages.
		if !cfg.offline {
			if err := s.recoverPending(); err != nil {
				return nil, err
			}
		}
	}
	if cfg.offline {
		s.recordLease = s.catalog.RecordLease
		s.admissionLease = s.catalog.AdmissionLease
		j.readOnly = true
		j.stats.Persisted = len(j.entries)
		j.stats.Held = len(j.entries)
		return j, nil
	}
	if err := startSegmentOwner(s); err != nil {
		return nil, err
	}
	launchSegmentOwner(s)
	return j, nil
}

func startSegmentOwner(s *journalSegments) error {
	j := s.j
	if err := s.inventoryAllocation(); err != nil {
		return err
	}
	if err := s.closeRecoveredCalls(); err != nil {
		return err
	}
	if err := s.renewLeases(); err != nil {
		return err
	}
	if s.activeControl == nil {
		if _, err := s.createExtent("control"); err != nil {
			return err
		}
	}
	if s.activeData == nil {
		if _, err := s.createExtent("data"); err != nil {
			return err
		}
	}
	s.publishBytes()
	j.stats.Bytes = s.dataAllocated + s.controlAllocated + s.retainedAllocation
	j.stats.Persisted = len(j.entries)
	j.stats.Retained = len(j.entries)
	j.stats.Held = len(j.entries)
	j.telemetry.Ready()
	return nil
}
func launchSegmentOwner(s *journalSegments) {
	go s.callbackLoop()
	go s.controlLoop()
	go s.j.run()
}
func strictSegmentJSON(b []byte, v any) error {
	if len(b) > 4<<20 {
		return errJournalSchema
	}
	if err := preflightSegmentJSON(b); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return errJournalSchema
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errJournalSchema
	}
	canonical, err := json.Marshal(v)
	if err != nil || !bytes.Equal(canonical, b) {
		return errJournalSchema
	}
	return nil
}
func (s *journalSegments) persistCatalog() error {
	if s.deferCatalog {
		return nil
	}
	plain, err := json.Marshal(s.catalog)
	if err != nil || len(plain) > 4<<20 {
		return errJournalSchema
	}
	defer clear(plain)
	b, err := s.j.writer.SealControl(securestore.JournalState, securestore.Binding{Store: s.j.storeID, Object: "segment-catalog"}, plain)
	if err != nil {
		return err
	}
	name := s.catalogName
	if name == "" {
		name = ".segments"
	}
	if s.catalogWrite != nil {
		return s.catalogWrite(name, b)
	}
	out, err := s.j.store.Replace(name, b)
	return journalStorageError(out, err)
}
func (s *journalSegments) renewLeases() error {
	if s.catalog.RecordLease > ^uint64(0)-journalIDLease || s.catalog.AdmissionLease > ^uint64(0)-journalIDLease {
		return errors.New("journal identity lease exhausted")
	}
	s.catalog.RecordLease += journalIDLease
	s.catalog.AdmissionLease += journalIDLease
	err := s.persistCatalog()
	if err == nil {
		s.j.mu.Lock()
		s.recordLease = s.catalog.RecordLease
		s.admissionLease = s.catalog.AdmissionLease
		s.j.mu.Unlock()
	}
	return err
}
func segmentName(id uuid.UUID) string      { return ".segment-" + id.String() + ".bin" }
func segmentStageName(id uuid.UUID) string { return ".segment-stage-" + id.String() + ".bin" }
func (s *journalSegments) createExtent(kind string) (*journalSegmentState, error) {
	allocated, limit := s.dataAllocated, s.dataLimit
	if kind == "control" {
		allocated, limit = s.controlAllocated, s.controlLimit
	}
	if allocated+securestore.FixedSegmentBytes > limit {
		return nil, ErrJournalFull
	}
	if len(s.catalog.Selected) >= journalSegmentMax {
		return nil, ErrJournalFull
	}
	extent, err := s.prepareExtent(kind)
	if err != nil {
		return nil, err
	}
	ref := extent.ref
	if allocated+extent.file.AllocatedBytes() > limit {
		return nil, ErrJournalFull
	}
	s.catalog.Pending = s.catalog.Pending[:len(s.catalog.Pending)-1]
	s.catalog.Selected = append(s.catalog.Selected, ref)
	if err := s.persistCatalog(); err != nil {
		return nil, err
	}
	if kind == "control" {
		s.activeControl = extent
		s.controlAllocated += extent.file.AllocatedBytes()
	} else {
		s.activeData = extent
		s.dataAllocated += extent.file.AllocatedBytes()
	}
	s.publishBytes()
	return extent, nil
}
func (s *journalSegments) prepareExtent(kind string) (*journalSegmentState, error) {
	if s.preparedExtent != nil {
		return s.preparedExtent(kind)
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	ref := journalSegmentRef{id, kind}
	s.catalog.Pending = append(s.catalog.Pending, ref)
	if err := s.persistCatalog(); err != nil {
		return nil, err
	}
	lock, err := s.j.store.Lock(segmentName(id))
	if err != nil {
		return nil, err
	}
	extent := &journalSegmentState{ref: ref, lock: lock, cursor: securestore.FixedSegmentDataStart, priorCursor: securestore.FixedSegmentDataStart}
	s.extents[id] = extent
	bootstrap, err := s.bootstrap(extent)
	if err != nil {
		return nil, err
	}
	out, err := s.j.store.InitializeFixedSegment(segmentStageName(id), segmentName(id), bootstrap)
	if err != nil {
		return nil, journalStorageError(out, err)
	}
	extent.file, err = s.j.store.OpenFixedSegment(segmentName(id))
	if err != nil {
		return nil, err
	}
	if err := extent.file.Activate(extent.cursor, 0); err != nil {
		return nil, err
	}
	return extent, nil
}
func (s *journalSegments) recoverPending() error {
	for _, ref := range s.catalog.Pending {
		if ref.ID == uuid.Nil || ref.Kind != "data" && ref.Kind != "control" {
			return errJournalSchema
		}
		for _, name := range []string{segmentName(ref.ID), segmentStageName(ref.ID)} {
			_, err := s.j.store.FileIdentity(name)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			out, err := s.j.store.Remove(name)
			if err != nil {
				return journalStorageError(out, err)
			}
		}
	}
	if len(s.catalog.Pending) > 0 {
		s.catalog.Pending = nil
		return s.persistCatalog()
	}
	return nil
}
func (s *journalSegments) highwaters() (uint64, uint64) {
	s.j.mu.Lock()
	defer s.j.mu.Unlock()
	return s.j.next, s.admission
}
func (s *journalSegments) visitSequences(visit func(x2x3.SequenceCheckpoint) error) error {
	s.ioMu.Lock()
	items := make([]x2x3.SequenceCheckpoint, 0, len(s.checkpoints))
	for _, cp := range s.checkpoints {
		items = append(items, cp)
	}
	s.ioMu.Unlock()
	sort.Slice(items, func(a, b int) bool {
		ka, _ := productionSequenceKey(items[a].Context)
		kb, _ := productionSequenceKey(items[b].Context)
		return ka < kb
	})
	for _, cp := range items {
		if err := visit(cp); err != nil {
			return err
		}
	}
	return nil
}
func (s *journalSegments) close() (result error) {
	for _, e := range s.extents {
		if e.file != nil {
			result = errors.Join(result, e.file.Close())
		}
		if e.lock != nil {
			result = errors.Join(result, e.lock.Close())
		}
	}
	return result
}

func preflightSegmentJSON(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	depth, nodes := 0, 0
	var arrays []int
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errJournalSchema
		}
		nodes++
		if nodes > 131072 {
			return errJournalSchema
		}
		if text, ok := token.(string); ok && len(text) > 128<<10 {
			return errJournalSchema
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				if depth > 16 {
					return errJournalSchema
				}
				if delim == '[' {
					arrays = append(arrays, 0)
				} else {
					arrays = append(arrays, -1)
				}
			case '}', ']':
				depth--
				if depth < 0 || len(arrays) == 0 {
					return errJournalSchema
				}
				arrays = arrays[:len(arrays)-1]
			default:
				return errJournalSchema
			}
		}
		if len(arrays) > 0 && arrays[len(arrays)-1] >= 0 {
			if delim, ok := token.(json.Delim); !ok || delim == ']' || delim == '}' {
				arrays[len(arrays)-1]++
				if arrays[len(arrays)-1] > 4096 {
					return errJournalSchema
				}
			}
		}
	}
	if depth != 0 {
		return errJournalSchema
	}
	return nil
}

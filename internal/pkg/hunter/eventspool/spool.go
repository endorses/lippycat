// Package eventspool provides a crash-recoverable, bounded spool for event batches.
package eventspool

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"google.golang.org/protobuf/proto"
)

const (
	recordExtension        = ".eventbatch"
	policyFileName         = "session-policy.json"
	manifestFileName       = "manifest.json"
	journalFileName        = "journal.log"
	lockFileName           = ".owner.lock"
	recordVersion          = uint16(1)
	manifestVersion        = uint32(1)
	headerSize             = 30
	defaultCheckpointEvery = uint64(128)
	defaultRetrievalLimit  = 128
	maxJournalFramePayload = 16 << 20
	journalFrameHeaderSize = 36
	MaxRecordPayloadBytes  = uint64(protoadapter.MaxEncodedBatchBytes)
	maxCollectionEntries   = 4096
)

var (
	recordMagic            = [8]byte{'L', 'C', 'E', 'V', 'S', 'P', 'L', '1'}
	journalMagic           = [8]byte{'L', 'C', 'E', 'V', 'J', 'N', 'L', '1'}
	ErrRecordTooLarge      = errors.New("event spool record exceeds maximum payload")
	ErrDurabilityUncertain = errors.New("event spool durability is uncertain; recovery required")
	ErrCheckpointRequired  = errors.New("event spool checkpoint maintenance is required before further mutation")
	ErrClosed              = errors.New("event spool is closed")
)

type SessionPolicy struct {
	Version            uint32 `json:"version"`
	SourceNodeID       string `json:"source_node_id"`
	ProducerSessionID  string `json:"producer_session_id"`
	DeliveryProfile    string `json:"delivery_profile"`
	IncludeHTTPHeaders bool   `json:"include_http_headers"`
	SemanticRevision   uint32 `json:"semantic_revision"`
}

type ExhaustionPolicy string

const (
	DropOldest ExhaustionPolicy = "drop_oldest"
	DropNew    ExhaustionPolicy = "drop_new"
)

type RejectionReason string

const (
	RejectionNone           RejectionReason = ""
	RejectionRecordTooLarge RejectionReason = "record_too_large"
	RejectionExhausted      RejectionReason = "exhausted"
	// RejectionPendingLossFlush asks the forwarding sink to publish bounded
	// loss-only records and retry the still-unhandled incoming batch.
	RejectionPendingLossFlush RejectionReason = "pending_loss_flush"
)

type Config struct {
	Directory      string
	MaxBytes       uint64
	MaxRecordBytes uint64
	MaxAge         time.Duration
	Policy         ExhaustionPolicy
	Clock          func() time.Time
	// CheckpointEvery is the minimum journal-frame trigger. The active-set
	// checkpoint base raises it so full checkpoint rewrites remain amortized linear.
	CheckpointEvery   uint64
	fs                *fsOps
	journalFrameLimit int
}

type record struct {
	name, path        string
	created           time.Time
	size, payloadSize uint64
	batch             *eventsv1.ProtocolEventBatch
}
type manifestRecord struct {
	Name              string `json:"name"`
	CreatedUnixNano   int64  `json:"created_unix_nano"`
	Size              uint64 `json:"size"`
	SourceNodeID      string `json:"source_node_id"`
	ProducerSessionID string `json:"producer_session_id"`
	BatchSequence     uint64 `json:"batch_sequence"`
}
type manifest struct {
	Version                                                    uint32 `json:"version"`
	Generation, AppliedTransactions, LogicalBytes              uint64
	Records                                                    []manifestRecord      `json:"records"`
	PendingLosses                                              []*eventsv1.EventLoss `json:"pending_losses,omitempty"`
	SourceNodeID, ProducerSessionID                            string
	LastEventSequence, LastBatchSequence, RetiredBatchSequence uint64
	SessionPolicy                                              *SessionPolicy `json:"session_policy,omitempty"`
}
type transaction struct {
	Version                                                    uint32 `json:"version"`
	Generation, Sequence                                       uint64
	Add                                                        []manifestRecord      `json:"add,omitempty"`
	Remove                                                     []string              `json:"remove,omitempty"`
	PendingLosses                                              []*eventsv1.EventLoss `json:"pending_losses,omitempty"`
	SourceNodeID, ProducerSessionID                            string
	LastEventSequence, LastBatchSequence, RetiredBatchSequence uint64
	SessionPolicy                                              *SessionPolicy `json:"session_policy,omitempty"`
	ResetSession                                               bool           `json:"reset_session,omitempty"`
}

type EnqueueResult struct {
	Stored    bool
	Losses    []*eventsv1.EventLoss
	Rejection RejectionReason
}
type RetentionResult struct{ Committed bool }
type Status struct {
	LogicalBytes, PhysicalBytes                     uint64
	PendingRecords, PendingLosses                   int
	DurabilityUncertain, CheckpointRequired, Closed bool
	CleanupError                                    string
}
type Metrics struct{ TransactionRecordVisits, ReplayRecordVisits, RetrievalCalls, RetrievalClones, RetrievalVisits, ACKRemovalVisits, MetadataBytes, Syncs, Checkpoints, Rotations, JournalFrames, MaxJournalFrames uint64 }
type CleanupError struct {
	Operation, Path string
	Err             error
}

func (e *CleanupError) Error() string {
	return fmt.Sprintf("event spool cleanup after committed mutation: %s %q: %v", e.Operation, e.Path, e.Err)
}
func (e *CleanupError) Unwrap() error { return e.Err }

type fsOps struct {
	createTemp func(string, string) (spoolFile, error)
	openFile   func(string, int, os.FileMode) (spoolFile, error)
	rename     func(string, string) error
	remove     func(string) error
	syncDir    func(string) error
}
type spoolFile interface {
	Name() string
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

func defaultFS() *fsOps {
	return &fsOps{
		func(d, p string) (spoolFile, error) { return os.CreateTemp(d, p) },
		func(p string, f int, _ os.FileMode) (spoolFile, error) { return openRegularNoFollow(p, f) },
		os.Rename,
		os.Remove,
		syncDirectory,
	}
}

type Spool struct {
	mu                                                                        sync.Mutex
	config                                                                    Config
	fs                                                                        *fsOps
	records                                                                   []record
	index                                                                     map[string]string
	activeNames                                                               map[string]bool
	bytes, physicalBytes, generation, txSequence, transactionsSinceCheckpoint uint64
	pendingLosses                                                             []*eventsv1.EventLoss
	uncertain, checkpointRequired, closed                                     bool
	checkpointErr                                                             error
	cleanupErr                                                                error
	orphanFailures                                                            map[string]error
	unaccountedPhysical                                                       map[string]bool
	lock                                                                      *os.File
	metrics                                                                   Metrics
	identitySet, homogeneous                                                  bool
	singleSource, singleProducer                                              string
	lastEventSequence, lastBatchSequence, retiredBatchSequence                uint64
	checkpointRecordBase                                                      int
	commitCount                                                               uint64
	sessionPolicy                                                             *SessionPolicy
}

// Open exclusively owns the directory until Close. The manifest and committed
// journal are authoritative; record-only legacy directories are migrated.
func Open(config Config) (_ *Spool, retErr error) {
	if config.Directory == "" {
		return nil, errors.New("open event spool: directory is required")
	}
	if config.Policy == "" {
		config.Policy = DropOldest
	}
	if config.Policy != DropOldest && config.Policy != DropNew {
		return nil, fmt.Errorf("open event spool: invalid exhaustion policy %q", config.Policy)
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaxRecordBytes == 0 {
		config.MaxRecordBytes = MaxRecordPayloadBytes
	}
	if config.MaxRecordBytes > MaxRecordPayloadBytes {
		return nil, fmt.Errorf("open event spool: maximum record payload %d exceeds transport-compatible limit %d", config.MaxRecordBytes, MaxRecordPayloadBytes)
	}
	if config.CheckpointEvery == 0 {
		config.CheckpointEvery = defaultCheckpointEvery
	}
	if config.journalFrameLimit == 0 {
		config.journalFrameLimit = maxJournalFramePayload
	}
	fs := config.fs
	if fs == nil {
		fs = defaultFS()
	}
	if err := os.MkdirAll(config.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("open event spool: create directory: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(config.Directory, lockFileName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open event spool: ownership lock: %w", err)
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("open event spool: directory is already owned: %w", err)
	}
	s := &Spool{config: config, fs: fs, lock: lock, index: map[string]string{}}
	defer func() {
		if retErr != nil {
			_ = s.releaseLock()
		}
	}()
	if err = s.load(); err != nil {
		return nil, err
	}
	s.checkpointRecordBase = len(s.records)
	return s, nil
}

func (s *Spool) load() error {
	m, err := readManifest(filepath.Join(s.config.Directory, manifestFileName))
	if errors.Is(err, os.ErrNotExist) {
		return s.migrateLegacy()
	}
	if err != nil {
		return err
	}
	resolved, replayed, err := s.resolveJournal(m)
	if err != nil {
		return err
	}
	if err = s.loadManifest(resolved); err != nil {
		return err
	}
	if err = s.syncRecoveredState(); err != nil {
		return err
	}
	s.transactionsSinceCheckpoint = replayed
	s.checkpointRecordBase = len(m.Records)
	if s.shouldCheckpoint() {
		generation := s.generation
		if err = s.rotateCheckpoint(); err != nil {
			if s.generation == generation || errors.Is(err, ErrDurabilityUncertain) {
				return fmt.Errorf("open event spool: compact recovered journal: %w", err)
			}
			s.cleanupErr = err
		}
	}
	if err = s.cleanupOrphans(); err != nil {
		s.cleanupErr = err
	}
	return s.refreshPhysical()
}
func readManifest(path string) (manifest, error) {
	f, err := openRegularNoFollow(path, os.O_RDONLY)
	if err != nil {
		return manifest{}, err
	}
	defer f.Close()
	payload, err := io.ReadAll(f)
	if err != nil {
		return manifest{}, fmt.Errorf("read event spool manifest %q: %w", path, err)
	}
	var m manifest
	if err = json.Unmarshal(payload, &m); err != nil {
		return manifest{}, fmt.Errorf("read event spool manifest %q: %w", path, err)
	}
	if m.Version != manifestVersion || m.Generation == 0 {
		return manifest{}, fmt.Errorf("read event spool manifest %q: unsupported version or generation", path)
	}
	return m, nil
}
func (s *Spool) loadManifest(m manifest) error {
	seen := map[string]bool{}
	var total uint64
	for _, mr := range m.Records {
		if !safeBasename(mr.Name) || seen[mr.Name] {
			return fmt.Errorf("read event spool manifest: unsafe or duplicate record %q", mr.Name)
		}
		seen[mr.Name] = true
		r, err := readRecord(filepath.Join(s.config.Directory, mr.Name), s.config.MaxRecordBytes)
		if err != nil {
			return err
		}
		if r.size != mr.Size || r.created.UnixNano() != mr.CreatedUnixNano || r.batch.GetSourceNodeId() != mr.SourceNodeID || r.batch.GetProducerSessionId() != mr.ProducerSessionID || r.batch.GetBatchSequence() != mr.BatchSequence {
			return fmt.Errorf("read event spool manifest: metadata mismatch for %q", mr.Name)
		}
		if total > ^uint64(0)-r.size {
			return errors.New("read event spool manifest: logical bytes overflow")
		}
		total += r.size
		s.records = append(s.records, r)
	}
	if total != m.LogicalBytes {
		return fmt.Errorf("read event spool manifest: logical bytes %d differ from records %d", m.LogicalBytes, total)
	}
	if (m.SourceNodeID == "") != (m.ProducerSessionID == "") {
		return errors.New("read event spool manifest: incomplete fixed identity")
	}
	if m.SessionPolicy != nil && (m.SessionPolicy.SourceNodeID != m.SourceNodeID || m.SessionPolicy.ProducerSessionID != m.ProducerSessionID) {
		return errors.New("read event spool manifest: session policy identity does not match fixed identity")
	}
	if m.SessionPolicy != nil {
		if err := validateSessionPolicy(*m.SessionPolicy); err != nil {
			return fmt.Errorf("read event spool manifest: invalid session policy: %w", err)
		}
	}
	if len(m.PendingLosses) > 0 {
		if err := validateRetainedLosses(m.PendingLosses, m.SourceNodeID, m.ProducerSessionID); err != nil {
			return fmt.Errorf("read event spool manifest: %w", err)
		}
	}
	var observedEvent, observedBatch uint64
	for _, r := range s.records {
		b := r.batch
		if m.SourceNodeID == "" || b.GetSourceNodeId() != m.SourceNodeID || b.GetProducerSessionId() != m.ProducerSessionID {
			return errors.New("read event spool manifest: record identity does not match fixed identity")
		}
		observedBatch = max(observedBatch, b.GetBatchSequence())
		observedEvent = max(observedEvent, b.GetLastEventSequence())
		for _, loss := range b.GetStats().GetLosses() {
			for _, eventRange := range loss.GetEventSequenceRanges() {
				observedEvent = max(observedEvent, eventRange.GetLast())
			}
		}
	}
	for _, loss := range m.PendingLosses {
		if m.SourceNodeID == "" || loss.GetSourceNodeId() != m.SourceNodeID || loss.GetProducerSessionId() != m.ProducerSessionID {
			return errors.New("read event spool manifest: pending loss identity does not match fixed identity")
		}
		for _, eventRange := range loss.GetEventSequenceRanges() {
			observedEvent = max(observedEvent, eventRange.GetLast())
		}
	}
	if m.LastEventSequence < observedEvent || m.LastBatchSequence < observedBatch {
		return errors.New("read event spool manifest: high-water marks underreport active state")
	}
	if m.RetiredBatchSequence > m.LastBatchSequence {
		return errors.New("read event spool manifest: retired batch sequence exceeds high-water mark")
	}
	s.bytes = total
	s.pendingLosses = normalizeLosses(m.PendingLosses)
	s.generation = m.Generation
	s.txSequence = m.AppliedTransactions
	sortRecords(s.records)
	s.rebuildIndex()
	s.singleSource, s.singleProducer = m.SourceNodeID, m.ProducerSessionID
	s.lastEventSequence, s.lastBatchSequence = m.LastEventSequence, m.LastBatchSequence
	s.retiredBatchSequence = m.RetiredBatchSequence
	if m.SessionPolicy != nil {
		copyPolicy := *m.SessionPolicy
		s.sessionPolicy = &copyPolicy
	}
	if s.singleSource != "" {
		s.identitySet = true
		s.homogeneous = true
	}
	return validateUniqueRecords(s.records)
}
func (s *Spool) migrateLegacy() error {
	entries, err := os.ReadDir(s.config.Directory)
	if err != nil {
		return fmt.Errorf("open event spool: read directory: %w", err)
	}
	reuseJournal, err := inspectLegacyJournal(entries, s.config.Directory)
	if err != nil {
		return fmt.Errorf("migrate event spool: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), recordExtension) {
			continue
		}
		r, err := readRecord(filepath.Join(s.config.Directory, e.Name()), s.config.MaxRecordBytes)
		if err != nil {
			return err
		}
		s.records = append(s.records, r)
		if s.bytes > ^uint64(0)-r.size {
			return errors.New("migrate event spool: byte overflow")
		}
		s.bytes += r.size
	}
	sortRecords(s.records)
	if err = validateUniqueRecords(s.records); err != nil {
		return fmt.Errorf("migrate event spool: %w", err)
	}
	if len(s.records) > 1 {
		source, session := s.records[0].batch.GetSourceNodeId(), s.records[0].batch.GetProducerSessionId()
		for _, r := range s.records[1:] {
			if r.batch.GetSourceNodeId() != source || r.batch.GetProducerSessionId() != session {
				return errors.New("migrate event spool: legacy records contain multiple producer sessions")
			}
		}
	}
	s.generation = 1
	s.rebuildIndex()
	s.updateHighWater()
	if legacyPolicy, policyErr := readSessionPolicy(filepath.Join(s.config.Directory, policyFileName)); policyErr == nil {
		if s.identitySet && (legacyPolicy.SourceNodeID != s.singleSource || legacyPolicy.ProducerSessionID != s.singleProducer) {
			return errors.New("migrate event spool policy: identity does not match legacy records")
		}
		if !s.identitySet {
			s.singleSource, s.singleProducer = legacyPolicy.SourceNodeID, legacyPolicy.ProducerSessionID
			s.identitySet = true
		}
		s.sessionPolicy = &legacyPolicy
	} else if !errors.Is(policyErr, os.ErrNotExist) {
		return fmt.Errorf("migrate event spool policy: %w", policyErr)
	}
	if !reuseJournal {
		if err = s.createJournal(s.generation); err != nil {
			return fmt.Errorf("migrate event spool: %w", err)
		}
	}
	if err = s.publishCheckpoint(); err != nil {
		return fmt.Errorf("migrate event spool: %w", err)
	}
	// Once the initial checkpoint is durable, migration has the same
	// authoritative active set as normal recovery. Retry any temporary files
	// left by an interrupted pre-manifest write before reporting physical usage.
	if err = s.cleanupOrphans(); err != nil {
		s.cleanupErr = err
	}
	return s.refreshPhysical()
}

// inspectLegacyJournal distinguishes a genuinely legacy record-only directory
// from a damaged current-format spool. The sole safe retry case is the empty
// generation-one journal durably published immediately before the initial
// migration checkpoint. Any transaction frame (or any other journal artifact)
// makes a missing manifest ambiguous and must be left for operator recovery.
func inspectLegacyJournal(entries []os.DirEntry, directory string) (bool, error) {
	var journals []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == journalFileName || (strings.HasPrefix(name, "journal-") && strings.HasSuffix(name, ".log")) {
			journals = append(journals, name)
		}
	}
	if len(journals) == 0 {
		return false, nil
	}
	if len(journals) != 1 || journals[0] != journalFileName {
		return false, fmt.Errorf("manifest is missing while journal artifacts exist: %v", journals)
	}
	path := filepath.Join(directory, journalFileName)
	file, err := openRegularNoFollow(path, os.O_RDONLY)
	if err != nil {
		return false, fmt.Errorf("inspect migration journal: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("inspect migration journal: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != 20 {
		return false, errors.New("manifest is missing while a non-empty or invalid journal exists")
	}
	payload := make([]byte, 20)
	if _, err = io.ReadFull(file, payload); err != nil {
		return false, fmt.Errorf("inspect migration journal: %w", err)
	}
	if !bytes.Equal(payload[:8], journalMagic[:]) || binary.BigEndian.Uint32(payload[8:12]) != manifestVersion || binary.BigEndian.Uint64(payload[12:20]) != 1 {
		return false, errors.New("manifest is missing while a non-empty or invalid journal exists")
	}
	return true, nil
}

func journalPath(directory string, generation uint64) string {
	if generation == 1 {
		return filepath.Join(directory, journalFileName)
	}
	return filepath.Join(directory, fmt.Sprintf("journal-%020d.log", generation))
}

func (s *Spool) Enqueue(batch *eventsv1.ProtocolEventBatch) (EnqueueResult, error) {
	if batch == nil {
		return EnqueueResult{}, errors.New("enqueue event batch: nil batch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mutable(); err != nil {
		return EnqueueResult{}, err
	}
	s.retryKnownCleanup()
	if s.identitySet && (batch.GetSourceNodeId() != s.singleSource || batch.GetProducerSessionId() != s.singleProducer) {
		return EnqueueResult{}, errors.New("enqueue event batch: producer identity does not match fixed spool session")
	}
	if err := validateLossShape(batch); err != nil {
		return EnqueueResult{}, fmt.Errorf("enqueue event batch: %w", err)
	}
	if err := validateBatchLossIdentity(batch); err != nil {
		return EnqueueResult{}, fmt.Errorf("enqueue event batch: %w", err)
	}
	key := identityKey(batch.GetSourceNodeId(), batch.GetProducerSessionId(), batch.GetBatchSequence())
	if _, exists := s.index[key]; exists {
		return EnqueueResult{}, fmt.Errorf("enqueue event batch: duplicate batch identity %s", key)
	}
	if s.identitySet && batch.GetBatchSequence() <= s.retiredBatchSequence {
		return EnqueueResult{}, fmt.Errorf("enqueue event batch: batch sequence %d does not advance durable retirement mark %d", batch.GetBatchSequence(), s.retiredBatchSequence)
	}
	now := s.config.Clock()
	incoming := proto.Clone(batch).(*eventsv1.ProtocolEventBatch)
	var newLosses []*eventsv1.EventLoss
	incoming.Stats = appendLosses(incoming.GetStats(), s.pendingLosses)
	if err := validateLossAccounting(incoming.Stats.GetLosses()); err != nil {
		return EnqueueResult{}, fmt.Errorf("enqueue event batch: %w", err)
	}
	incoming.Stats.Losses = normalizeLosses(incoming.Stats.GetLosses())
	payload, err := marshalAndValidate(incoming, s.config.MaxRecordBytes)
	if err != nil && len(s.pendingLosses) > 0 {
		withoutPending := proto.Clone(batch).(*eventsv1.ProtocolEventBatch)
		withoutPending.Stats = appendLosses(withoutPending.GetStats(), nil)
		withoutPending.Stats.Losses = normalizeLosses(withoutPending.Stats.GetLosses())
		if _, incomingErr := marshalAndValidate(withoutPending, s.config.MaxRecordBytes); incomingErr == nil {
			return EnqueueResult{Rejection: RejectionPendingLossFlush}, nil
		}
	}
	if errors.Is(err, ErrRecordTooLarge) {
		own := ownRangeLoss(batch)
		retained, retainErr := mergeLossesChecked(s.pendingLosses, lossesForBatch(batch))
		if retainErr != nil {
			return EnqueueResult{}, fmt.Errorf("enqueue oversized event batch: retain exact loss coverage: %w", retainErr)
		}
		if committed, e := s.commitPendingLosses(retained); e != nil {
			if committed {
				return EnqueueResult{Losses: own, Rejection: RejectionRecordTooLarge}, e
			}
			return EnqueueResult{}, e
		}
		return EnqueueResult{Losses: own, Rejection: RejectionRecordTooLarge}, ErrRecordTooLarge
	}
	if err != nil {
		own := ownRangeLoss(batch)
		retained, retainErr := mergeLossesChecked(s.pendingLosses, lossesForBatch(batch))
		if retainErr != nil {
			return EnqueueResult{}, fmt.Errorf("reject event batch: retain exact loss coverage: %w", retainErr)
		}
		committed, commitErr := s.commitPendingLosses(retained)
		if commitErr != nil {
			if committed {
				return EnqueueResult{Losses: own, Rejection: RejectionExhausted}, commitErr
			}
			return EnqueueResult{}, commitErr
		}
		return EnqueueResult{Losses: own, Rejection: RejectionExhausted}, nil
	}
	recordBytes := uint64(headerSize) + uint64(len(payload))
	if s.config.Policy == DropNew && (s.wouldExceedByteLimit(s.bytes, recordBytes) || s.hasExpired(now)) {
		own := ownRangeLoss(batch)
		retained, retainErr := mergeLossesChecked(s.pendingLosses, lossesForBatch(batch))
		if retainErr != nil {
			return EnqueueResult{}, fmt.Errorf("drop new event batch: retain exact loss coverage: %w", retainErr)
		}
		if committed, e := s.commitPendingLosses(retained); e != nil {
			if committed {
				return EnqueueResult{Losses: own, Rejection: RejectionExhausted}, e
			}
			return EnqueueResult{}, e
		}
		return EnqueueResult{Losses: own, Rejection: RejectionExhausted}, nil
	}
	var victims []record
	remaining := s.bytes
	if s.config.Policy == DropOldest {
		for len(victims) < len(s.records) && (s.recordExpired(s.records[len(victims)], now) || s.wouldExceedByteLimit(remaining, recordBytes)) {
			v := s.records[len(victims)]
			victims = append(victims, v)
			remaining -= v.size
			wireLosses := lossesForBatch(v.batch)
			if _, lossErr := normalizeLossesChecked(wireLosses); lossErr != nil {
				return EnqueueResult{}, fmt.Errorf("drop oldest event batch: preserve victim loss coverage: %w", lossErr)
			}
			// Only the victim's delivered events are newly lost locally. Losses
			// inherited by that record remain wire coverage but were counted when
			// they were first incurred.
			newLosses = normalizeLosses(append(newLosses, ownRangeLoss(v.batch)...))
			incoming.Stats = appendLosses(incoming.GetStats(), wireLosses)
			incoming.Stats.Losses, err = normalizeLossesChecked(incoming.Stats.GetLosses())
			if err != nil {
				return EnqueueResult{}, fmt.Errorf("drop oldest event batch: merge exact loss coverage: %w", err)
			}
			payload, err = marshalAndValidate(incoming, s.config.MaxRecordBytes)
			if err != nil {
				break
			}
			recordBytes = uint64(headerSize) + uint64(len(payload))
		}
		if err != nil || s.overByteLimit(recordBytes) {
			own := ownRangeLoss(batch)
			retained, retainErr := mergeLossesChecked(s.pendingLosses, lossesForBatch(batch))
			if retainErr != nil {
				return EnqueueResult{}, fmt.Errorf("reject replacement event batch: retain exact loss coverage: %w", retainErr)
			}
			if committed, e := s.commitPendingLosses(retained); e != nil {
				if committed {
					return EnqueueResult{Losses: own, Rejection: RejectionExhausted}, e
				}
				return EnqueueResult{}, e
			}
			if errors.Is(err, ErrRecordTooLarge) {
				return EnqueueResult{Losses: own, Rejection: RejectionRecordTooLarge}, ErrRecordTooLarge
			}
			return EnqueueResult{Losses: own, Rejection: RejectionExhausted}, nil
		}
	}
	r, err := s.writeRecord(now, incoming, payload)
	if err != nil {
		return EnqueueResult{}, err
	}
	tx := transaction{Version: manifestVersion, Generation: s.generation, Sequence: s.txSequence + 1, Add: []manifestRecord{toManifestRecord(r)}}
	for _, v := range victims {
		tx.Remove = append(tx.Remove, v.name)
		tx.RetiredBatchSequence = max(tx.RetiredBatchSequence, v.batch.GetBatchSequence())
	}
	beforeCommit := s.commitCount
	if err = s.commit(tx); err != nil {
		if s.commitCount > beforeCommit {
			// The active-set transaction is already authoritative. A subsequent
			// checkpoint-maintenance failure must not invite the caller to reuse
			// this batch sequence or retry it as a fresh admission.
			return EnqueueResult{Stored: true, Losses: newLosses}, err
		}
		if errors.Is(err, ErrDurabilityUncertain) {
			return EnqueueResult{}, err
		}
		cleanupErr := s.retryCleanup([]string{r.name})
		return EnqueueResult{}, errors.Join(err, cleanupErr)
	}
	if cleanupErr := s.retryCleanup(tx.Remove); cleanupErr != nil {
		return EnqueueResult{Stored: true, Losses: newLosses}, cleanupErr
	}
	return EnqueueResult{Stored: true, Losses: newLosses}, nil
}
func (s *Spool) commitPendingLosses(losses []*eventsv1.EventLoss) (bool, error) {
	if len(losses) > 0 {
		source, session := s.singleSource, s.singleProducer
		if !s.identitySet {
			source, session = losses[0].GetSourceNodeId(), losses[0].GetProducerSessionId()
		}
		if err := validateRetainedLosses(losses, source, session); err != nil {
			return false, fmt.Errorf("commit event spool pending losses: %w", err)
		}
	}
	if proto.Equal(&eventsv1.EventBatchStats{Losses: s.pendingLosses}, &eventsv1.EventBatchStats{Losses: losses}) {
		return true, nil
	}
	tx := transaction{Version: manifestVersion, Generation: s.generation, Sequence: s.txSequence + 1, PendingLosses: losses}
	before := s.commitCount
	err := s.commit(tx)
	return s.commitCount > before, err
}

func (s *Spool) RetainLosses(losses []*eventsv1.EventLoss) (RetentionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mutable(); err != nil {
		return RetentionResult{}, err
	}
	s.retryKnownCleanup()
	expectedSource, expectedSession := s.singleSource, s.singleProducer
	if !s.identitySet && len(losses) > 0 && losses[0] != nil {
		expectedSource, expectedSession = losses[0].GetSourceNodeId(), losses[0].GetProducerSessionId()
	}
	if err := validateRetainedLosses(losses, expectedSource, expectedSession); err != nil {
		return RetentionResult{}, fmt.Errorf("retain event losses: %w", err)
	}
	combined := append(cloneLosses(s.pendingLosses), losses...)
	normalized, err := normalizeLossesChecked(combined)
	if err != nil {
		return RetentionResult{}, fmt.Errorf("retain event losses: %w", err)
	}
	committed, err := s.commitPendingLosses(normalized)
	return RetentionResult{Committed: committed}, err
}

func (s *Spool) Ack(source, session string, sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mutable(); err != nil {
		return err
	}
	s.retryKnownCleanup()
	var remove []string
	retired := s.retiredBatchSequence
	if s.singleSession(source, session) {
		end := 0
		for end < len(s.records) {
			s.metrics.ACKRemovalVisits++
			if s.records[end].batch.GetBatchSequence() > sequence {
				break
			}
			end++
		}
		for _, r := range s.records[:end] {
			remove = append(remove, r.name)
			retired = max(retired, r.batch.GetBatchSequence())
		}
	} else {
		for _, r := range s.records {
			s.metrics.ACKRemovalVisits++
			b := r.batch
			if b.GetSourceNodeId() == source && b.GetProducerSessionId() == session && b.GetBatchSequence() <= sequence {
				remove = append(remove, r.name)
				retired = max(retired, b.GetBatchSequence())
			}
		}
	}
	if len(remove) == 0 {
		return nil
	}
	if err := s.commit(transaction{Version: manifestVersion, Generation: s.generation, Sequence: s.txSequence + 1, Remove: remove, PendingLosses: cloneLosses(s.pendingLosses), RetiredBatchSequence: retired}); err != nil {
		return err
	}
	return s.retryCleanup(remove)
}

func (s *Spool) BatchesAfter(source, session string, after uint64, limit int) ([]*eventsv1.ProtocolEventBatch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if s.uncertain {
		return nil, ErrDurabilityUncertain
	}
	if s.checkpointRequired {
		return nil, fmt.Errorf("%w: %v", ErrCheckpointRequired, s.checkpointErr)
	}
	if limit <= 0 {
		limit = defaultRetrievalLimit
	}
	s.metrics.RetrievalCalls++
	out := make([]*eventsv1.ProtocolEventBatch, 0, min(limit, len(s.records)))
	start := 0
	if s.singleSession(source, session) {
		start = sort.Search(len(s.records), func(i int) bool {
			s.metrics.RetrievalVisits++
			return s.records[i].batch.GetBatchSequence() > after
		})
	}
	for _, r := range s.records[start:] {
		s.metrics.RetrievalVisits++
		b := r.batch
		if b.GetSourceNodeId() == source && b.GetProducerSessionId() == session && b.GetBatchSequence() > after {
			out = append(out, proto.Clone(b).(*eventsv1.ProtocolEventBatch))
			s.metrics.RetrievalClones++
			if len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

func (s *Spool) singleSession(source, session string) bool {
	return !s.identitySet || (s.homogeneous && s.singleSource == source && s.singleProducer == session)
}
func (s *Spool) Contains(source, session string, seq uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.index[identityKey(source, session, seq)]
	return ok && !s.closed && !s.uncertain && !s.checkpointRequired
}
func (s *Spool) IsActive(source, session string, seq uint64) bool {
	return s.Contains(source, session, seq)
}
func (s *Spool) Batches() []*eventsv1.ProtocolEventBatch {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*eventsv1.ProtocolEventBatch, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, proto.Clone(r.batch).(*eventsv1.ProtocolEventBatch))
	}
	return out
}
func (s *Spool) Bytes() uint64         { s.mu.Lock(); defer s.mu.Unlock(); return s.bytes }
func (s *Spool) PhysicalBytes() uint64 { s.mu.Lock(); defer s.mu.Unlock(); return s.physicalBytes }
func (s *Spool) HasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uncertain || s.checkpointRequired || s.bytes != 0 || len(s.pendingLosses) != 0
}

func (s *Spool) HasPendingLosses() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pendingLosses) != 0
}

// PendingLossesRequireFlush reports whether the complete durable loss set can
// no longer fit in one receiver-valid loss-only batch. Callers flush bounded
// prefixes at this boundary so repeated rejection remains linear and durable.
func (s *Spool) PendingLossesRequireFlush(source, session string, batchSequence uint64, semanticRevision uint32) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	if s.uncertain {
		return false, ErrDurabilityUncertain
	}
	if s.checkpointRequired {
		return false, fmt.Errorf("%w: %v", ErrCheckpointRequired, s.checkpointErr)
	}
	if len(s.pendingLosses) == 0 {
		return false, nil
	}
	if source != s.singleSource || session != s.singleProducer || batchSequence == 0 {
		return false, errors.New("inspect event spool pending losses: producer identity does not match fixed spool session")
	}
	batch := &eventsv1.ProtocolEventBatch{
		SourceNodeId: source, ProducerSessionId: session, BatchSequence: batchSequence,
		SemanticProfileRevision: semanticRevision,
		Stats:                   &eventsv1.EventBatchStats{Losses: cloneLosses(s.pendingLosses)},
	}
	_, err := marshalAndValidate(batch, s.config.MaxRecordBytes)
	return err != nil, nil
}

// FlushPendingLosses publishes one bounded loss-only batch. The new record and
// removal of the represented durable pending coverage are one journal
// transaction, so callers may advance batchSequence exactly when Stored is true.
func (s *Spool) FlushPendingLosses(source, session string, batchSequence uint64, semanticRevision uint32) (EnqueueResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mutable(); err != nil {
		return EnqueueResult{}, err
	}
	s.retryKnownCleanup()
	if len(s.pendingLosses) == 0 {
		return EnqueueResult{}, nil
	}
	if source == "" || session == "" || batchSequence == 0 {
		return EnqueueResult{}, errors.New("flush event spool pending losses: incomplete batch identity")
	}
	if s.identitySet && (source != s.singleSource || session != s.singleProducer) {
		return EnqueueResult{}, errors.New("flush event spool pending losses: producer identity does not match fixed spool session")
	}
	key := identityKey(source, session, batchSequence)
	if _, exists := s.index[key]; exists {
		return EnqueueResult{}, fmt.Errorf("flush event spool pending losses: duplicate batch identity %s", key)
	}
	if s.identitySet && batchSequence <= s.retiredBatchSequence {
		return EnqueueResult{}, fmt.Errorf("flush event spool pending losses: batch sequence %d does not advance durable retirement mark %d", batchSequence, s.retiredBatchSequence)
	}
	coverage := cloneLosses(s.pendingLosses)
	batch := &eventsv1.ProtocolEventBatch{SourceNodeId: source, ProducerSessionId: session, BatchSequence: batchSequence, SemanticProfileRevision: semanticRevision, Stats: &eventsv1.EventBatchStats{}}
	var remaining []*eventsv1.EventLoss
	buildCarrier := func() ([]byte, error) {
		prefix, rest := splitPendingLosses(coverage, maxCollectionEntries)
		batch.Stats.Losses = prefix
		payload, err := marshalAndValidate(batch, s.config.MaxRecordBytes)
		for errors.Is(err, ErrRecordTooLarge) && lossSplitUnits(prefix) > 1 {
			prefix, rest = splitPendingLosses(coverage, lossSplitUnits(prefix)/2)
			batch.Stats.Losses = prefix
			payload, err = marshalAndValidate(batch, s.config.MaxRecordBytes)
		}
		remaining = rest
		return payload, err
	}
	payload, err := buildCarrier()
	if err != nil {
		return EnqueueResult{}, fmt.Errorf("flush event spool pending losses: %w", err)
	}
	recordBytes := uint64(headerSize) + uint64(len(payload))
	now := s.config.Clock()
	if s.overByteLimit(recordBytes) {
		return EnqueueResult{Rejection: RejectionExhausted}, nil
	}
	if s.config.Policy == DropNew && (s.wouldExceedByteLimit(s.bytes, recordBytes) || s.hasExpired(now)) {
		return EnqueueResult{Rejection: RejectionExhausted}, nil
	}
	var victims []record
	var newLosses []*eventsv1.EventLoss
	remainingBytes := s.bytes
	if s.config.Policy == DropOldest {
		for len(victims) < len(s.records) && (s.recordExpired(s.records[len(victims)], now) || s.wouldExceedByteLimit(remainingBytes, recordBytes)) {
			victim := s.records[len(victims)]
			victims = append(victims, victim)
			remainingBytes -= victim.size
			coverage, err = mergeLossesChecked(coverage, lossesForBatch(victim.batch))
			if err != nil {
				return EnqueueResult{}, fmt.Errorf("flush event spool pending losses: preserve victim loss coverage: %w", err)
			}
			newLosses = normalizeLosses(append(newLosses, ownRangeLoss(victim.batch)...))
			// An evicted record can precede every pending range. Repartition
			// the complete coverage so this carrier explains that new gap,
			// rather than deferring it behind the receiver's high-water mark.
			payload, err = buildCarrier()
			if err != nil {
				return EnqueueResult{}, fmt.Errorf("flush event spool pending losses: replacement carrier: %w", err)
			}
			recordBytes = uint64(headerSize) + uint64(len(payload))
			if s.overByteLimit(recordBytes) {
				return EnqueueResult{Rejection: RejectionExhausted}, nil
			}
		}
		// Replacement is allowed only when it strictly reduces the bounded
		// pending-loss work. Without this monotonic measure, a one-record spool
		// can alternate two loss-only carriers forever.
		if len(victims) > 0 && lossSplitUnits(remaining) >= lossSplitUnits(s.pendingLosses) {
			return EnqueueResult{Rejection: RejectionExhausted}, nil
		}
	}
	r, err := s.writeRecord(s.config.Clock(), batch, payload)
	if err != nil {
		return EnqueueResult{}, err
	}
	tx := transaction{Version: manifestVersion, Generation: s.generation, Sequence: s.txSequence + 1, Add: []manifestRecord{toManifestRecord(r)}, PendingLosses: remaining}
	for _, victim := range victims {
		tx.Remove = append(tx.Remove, victim.name)
		tx.RetiredBatchSequence = max(tx.RetiredBatchSequence, victim.batch.GetBatchSequence())
	}
	beforeCommit := s.commitCount
	if err = s.commit(tx); err != nil {
		if s.commitCount > beforeCommit {
			return EnqueueResult{Stored: true, Losses: newLosses}, err
		}
		if errors.Is(err, ErrDurabilityUncertain) {
			return EnqueueResult{}, err
		}
		cleanupErr := s.retryCleanup([]string{r.name})
		return EnqueueResult{}, errors.Join(err, cleanupErr)
	}
	if cleanupErr := s.retryCleanup(tx.Remove); cleanupErr != nil {
		return EnqueueResult{Stored: true, Losses: newLosses}, cleanupErr
	}
	return EnqueueResult{Stored: true, Losses: newLosses}, nil
}
func (s *Spool) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{LogicalBytes: s.bytes, PhysicalBytes: s.physicalBytes, PendingRecords: len(s.records), PendingLosses: len(s.pendingLosses), DurabilityUncertain: s.uncertain, CheckpointRequired: s.checkpointRequired, Closed: s.closed}
	if s.cleanupErr != nil {
		st.CleanupError = s.cleanupErr.Error()
	}
	return st
}
func (s *Spool) SnapshotMetrics() Metrics { s.mu.Lock(); defer s.mu.Unlock(); return s.metrics }

func (s *Spool) Recover() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.records = nil
	s.index = map[string]string{}
	s.activeNames = map[string]bool{}
	s.bytes, s.physicalBytes = 0, 0
	s.pendingLosses = nil
	s.generation, s.txSequence, s.transactionsSinceCheckpoint = 0, 0, 0
	s.identitySet, s.homogeneous = false, true
	s.singleSource, s.singleProducer = "", ""
	s.lastEventSequence, s.lastBatchSequence = 0, 0
	s.retiredBatchSequence = 0
	s.sessionPolicy = nil
	s.cleanupErr = nil
	s.orphanFailures = nil
	s.unaccountedPhysical = nil
	s.checkpointRequired = false
	s.checkpointErr = nil
	s.uncertain = false
	if err := s.load(); err != nil {
		s.uncertain = true
		return fmt.Errorf("recover event spool: %w", err)
	}
	s.checkpointRecordBase = len(s.records)
	return nil
}
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.releaseLock()
}
func (s *Spool) releaseLock() error {
	if s.lock == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	closeErr := s.lock.Close()
	s.lock = nil
	if unlockErr != nil {
		return fmt.Errorf("close event spool lock: %w", unlockErr)
	}
	return closeErr
}

func (s *Spool) RecoveryState() (source, session string, lastEvent, lastBatch uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uncertain {
		return "", "", 0, 0, ErrDurabilityUncertain
	}
	if s.checkpointRequired {
		return "", "", 0, 0, fmt.Errorf("%w: %v", ErrCheckpointRequired, s.checkpointErr)
	}
	if s.closed {
		return "", "", 0, 0, ErrClosed
	}
	return s.singleSource, s.singleProducer, s.lastEventSequence, s.lastBatchSequence, nil
}

func (s *Spool) updateHighWater() {
	for _, r := range s.records {
		b := r.batch
		if s.singleSource == "" {
			s.singleSource, s.singleProducer = b.GetSourceNodeId(), b.GetProducerSessionId()
			s.identitySet = true
		}
		s.lastEventSequence = max(s.lastEventSequence, b.GetLastEventSequence())
		s.lastBatchSequence = max(s.lastBatchSequence, b.GetBatchSequence())
		for _, loss := range b.GetStats().GetLosses() {
			for _, eventRange := range loss.GetEventSequenceRanges() {
				s.lastEventSequence = max(s.lastEventSequence, eventRange.GetLast())
			}
		}
	}
	for _, loss := range s.pendingLosses {
		if s.singleSource == "" {
			s.singleSource, s.singleProducer = loss.GetSourceNodeId(), loss.GetProducerSessionId()
			s.identitySet = true
		}
		for _, eventRange := range loss.GetEventSequenceRanges() {
			s.lastEventSequence = max(s.lastEventSequence, eventRange.GetLast())
		}
	}
}

func (s *Spool) BindSessionPolicy(policy SessionPolicy) error {
	if policy.Version == 0 {
		policy.Version = 1
	}
	if err := validateSessionPolicy(policy); err != nil {
		return fmt.Errorf("bind event spool session policy: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mutable(); err != nil {
		return err
	}
	s.retryKnownCleanup()
	if s.sessionPolicy != nil && *s.sessionPolicy == policy {
		return nil
	}
	if len(s.records) > 0 || len(s.pendingLosses) > 0 {
		if s.sessionPolicy == nil {
			return errors.New("bind event spool session policy: pending legacy records have no recoverable session policy; drain them with the previous version or move the spool aside")
		}
		return fmt.Errorf("bind event spool session policy: pending records use policy %+v, configured policy is %+v", *s.sessionPolicy, policy)
	}
	return s.resetSessionLocked(policy)
}

// ResetSession durably establishes a new fixed producer identity, zeroes the
// drained session's high-water marks, and binds its policy in one transaction.
func (s *Spool) ResetSession(policy SessionPolicy) error {
	if policy.Version == 0 {
		policy.Version = 1
	}
	if err := validateSessionPolicy(policy); err != nil {
		return fmt.Errorf("reset event spool session: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.mutable(); err != nil {
		return err
	}
	if len(s.records) > 0 || len(s.pendingLosses) > 0 {
		return errors.New("reset event spool session: spool is not drained")
	}
	return s.resetSessionLocked(policy)
}
func (s *Spool) resetSessionLocked(policy SessionPolicy) error {
	copyPolicy := policy
	tx := transaction{Version: manifestVersion, Generation: s.generation, Sequence: s.txSequence + 1, SourceNodeID: policy.SourceNodeID, ProducerSessionID: policy.ProducerSessionID, SessionPolicy: &copyPolicy, ResetSession: true}
	return s.commit(tx)
}
func readSessionPolicy(path string) (SessionPolicy, error) {
	f, err := openRegularNoFollow(path, os.O_RDONLY)
	if err != nil {
		return SessionPolicy{}, err
	}
	payload, readErr := io.ReadAll(f)
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return SessionPolicy{}, fmt.Errorf("read event spool session policy: %w", errors.Join(readErr, closeErr))
	}
	var p SessionPolicy
	if err = json.Unmarshal(payload, &p); err != nil {
		return SessionPolicy{}, fmt.Errorf("read event spool session policy: %w", err)
	}
	if err = validateSessionPolicy(p); err != nil {
		return SessionPolicy{}, fmt.Errorf("read event spool session policy: %w", err)
	}
	return p, nil
}

func validateSessionPolicy(policy SessionPolicy) error {
	if policy.Version != 1 {
		return fmt.Errorf("unsupported version %d", policy.Version)
	}
	if policy.SourceNodeID == "" || policy.ProducerSessionID == "" || policy.DeliveryProfile == "" || policy.SemanticRevision == 0 {
		return errors.New("incomplete policy")
	}
	return nil
}

func (s *Spool) mutable() error {
	if s.closed {
		return ErrClosed
	}
	if s.uncertain {
		return ErrDurabilityUncertain
	}
	if s.checkpointRequired {
		return fmt.Errorf("%w: %v", ErrCheckpointRequired, s.checkpointErr)
	}
	return nil
}
func (s *Spool) overByteLimit(n uint64) bool { return s.config.MaxBytes > 0 && n > s.config.MaxBytes }
func (s *Spool) wouldExceedByteLimit(current, added uint64) bool {
	return added > ^uint64(0)-current || s.overByteLimit(current+added)
}
func (s *Spool) recordExpired(r record, now time.Time) bool {
	return s.config.MaxAge > 0 && now.Sub(r.created) > s.config.MaxAge
}
func (s *Spool) hasExpired(now time.Time) bool {
	return len(s.records) > 0 && s.recordExpired(s.records[0], now)
}
func (s *Spool) rebuildIndex() {
	s.index = map[string]string{}
	s.activeNames = map[string]bool{}
	s.identitySet = false
	s.homogeneous = true
	s.singleSource = ""
	s.singleProducer = ""
	for _, r := range s.records {
		s.activeNames[r.name] = true
		s.index[identityKey(r.batch.GetSourceNodeId(), r.batch.GetProducerSessionId(), r.batch.GetBatchSequence())] = r.name
		if !s.identitySet {
			s.identitySet = true
			s.singleSource = r.batch.GetSourceNodeId()
			s.singleProducer = r.batch.GetProducerSessionId()
		} else if r.batch.GetSourceNodeId() != s.singleSource || r.batch.GetProducerSessionId() != s.singleProducer {
			s.homogeneous = false
		}
	}
}
func identityKey(source, session string, seq uint64) string {
	return fmt.Sprintf("%s\x00%s\x00%020d", source, session, seq)
}
func safeBasename(name string) bool {
	return name != "" && filepath.Base(name) == name && name != "." && name != ".." && strings.HasSuffix(name, recordExtension)
}
func sortRecords(records []record) {
	oneSession := true
	if len(records) > 1 {
		first := records[0].batch
		for _, r := range records[1:] {
			if r.batch.GetSourceNodeId() != first.GetSourceNodeId() || r.batch.GetProducerSessionId() != first.GetProducerSessionId() {
				oneSession = false
				break
			}
		}
	}
	sort.Slice(records, func(i, j int) bool {
		a, b := records[i].batch, records[j].batch
		if oneSession && a.GetBatchSequence() != b.GetBatchSequence() {
			return a.GetBatchSequence() < b.GetBatchSequence()
		}
		if !records[i].created.Equal(records[j].created) {
			return records[i].created.Before(records[j].created)
		}
		return records[i].name < records[j].name
	})
}
func validateUniqueRecords(records []record) error {
	seen := map[string]bool{}
	for _, r := range records {
		k := identityKey(r.batch.GetSourceNodeId(), r.batch.GetProducerSessionId(), r.batch.GetBatchSequence())
		if seen[k] {
			return fmt.Errorf("duplicate record identity %s", k)
		}
		seen[k] = true
	}
	return nil
}
func toManifestRecord(r record) manifestRecord {
	return manifestRecord{Name: r.name, CreatedUnixNano: r.created.UnixNano(), Size: r.size, SourceNodeID: r.batch.GetSourceNodeId(), ProducerSessionID: r.batch.GetProducerSessionId(), BatchSequence: r.batch.GetBatchSequence()}
}

func appendLosses(stats *eventsv1.EventBatchStats, losses []*eventsv1.EventLoss) *eventsv1.EventBatchStats {
	if stats == nil {
		stats = &eventsv1.EventBatchStats{}
	} else {
		stats = proto.Clone(stats).(*eventsv1.EventBatchStats)
	}
	stats.Losses = append(stats.Losses, cloneLosses(losses)...)
	return stats
}
func cloneLosses(in []*eventsv1.EventLoss) []*eventsv1.EventLoss {
	out := make([]*eventsv1.EventLoss, 0, len(in))
	for _, loss := range in {
		if loss != nil {
			out = append(out, proto.Clone(loss).(*eventsv1.EventLoss))
		}
	}
	return out
}
func ownRangeLoss(batch *eventsv1.ProtocolEventBatch) []*eventsv1.EventLoss {
	if len(batch.GetEvents()) == 0 {
		return nil
	}
	ranges := make([]*eventsv1.SequenceRange, 0, len(batch.GetEvents()))
	var count uint64
	for _, event := range batch.GetEvents() {
		if event == nil || event.GetEventSequence() == 0 {
			continue
		}
		sequence := event.GetEventSequence()
		count++
		if len(ranges) > 0 && ranges[len(ranges)-1].Last != ^uint64(0) && sequence == ranges[len(ranges)-1].Last+1 {
			ranges[len(ranges)-1].Last = sequence
			continue
		}
		ranges = append(ranges, &eventsv1.SequenceRange{First: sequence, Last: sequence})
	}
	if count == 0 {
		return nil
	}
	return []*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: count, SourceNodeId: batch.GetSourceNodeId(), ProducerSessionId: batch.GetProducerSessionId(), EventSequenceRanges: ranges}}
}
func lossesForBatch(batch *eventsv1.ProtocolEventBatch) []*eventsv1.EventLoss {
	return append(cloneLosses(batch.GetStats().GetLosses()), ownRangeLoss(batch)...)
}

func mergeLossesChecked(left, right []*eventsv1.EventLoss) ([]*eventsv1.EventLoss, error) {
	return normalizeLossesChecked(append(cloneLosses(left), right...))
}

func normalizeLossesChecked(input []*eventsv1.EventLoss) ([]*eventsv1.EventLoss, error) {
	if err := validateLossAccounting(input); err != nil {
		return nil, err
	}
	if err := validateDisjointLossRanges(input); err != nil {
		return nil, err
	}
	return normalizeLosses(input), nil
}

type lossKey struct {
	source, session string
	kind            eventsv1.LossKind
}

func normalizeLosses(input []*eventsv1.EventLoss) []*eventsv1.EventLoss {
	groups := map[lossKey][]*eventsv1.SequenceRange{}
	unranged := map[lossKey]uint64{}
	for _, loss := range input {
		if loss == nil {
			continue
		}
		k := lossKey{loss.GetSourceNodeId(), loss.GetProducerSessionId(), loss.GetKind()}
		if len(loss.GetEventSequenceRanges()) == 0 {
			unranged[k] += loss.GetCount()
			continue
		}
		var covered uint64
		for _, r := range loss.GetEventSequenceRanges() {
			if r != nil && r.GetFirst() > 0 && r.GetLast() >= r.GetFirst() {
				groups[k] = append(groups[k], &eventsv1.SequenceRange{First: r.GetFirst(), Last: r.GetLast()})
				covered += r.GetLast() - r.GetFirst() + 1
			}
		}
		if loss.GetCount() > covered {
			unranged[k] += loss.GetCount() - covered
		}
	}
	keys := make([]lossKey, 0, len(groups)+len(unranged))
	seen := map[lossKey]bool{}
	for k := range groups {
		keys = append(keys, k)
		seen[k] = true
	}
	for k := range unranged {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		if keys[i].session != keys[j].session {
			return keys[i].session < keys[j].session
		}
		return keys[i].kind < keys[j].kind
	})
	out := make([]*eventsv1.EventLoss, 0, len(keys))
	for _, k := range keys {
		ranges := groups[k]
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].First < ranges[j].First })
		merged := make([]*eventsv1.SequenceRange, 0, len(ranges))
		for _, r := range ranges {
			if len(merged) == 0 || (merged[len(merged)-1].Last != ^uint64(0) && r.First > merged[len(merged)-1].Last+1) {
				merged = append(merged, r)
				continue
			}
			if r.Last > merged[len(merged)-1].Last {
				merged[len(merged)-1].Last = r.Last
			}
		}
		count := unranged[k]
		for _, r := range merged {
			count += r.Last - r.First + 1
		}
		if count > 0 {
			out = append(out, &eventsv1.EventLoss{Kind: k.kind, Count: count, SourceNodeId: k.source, ProducerSessionId: k.session, EventSequenceRanges: merged})
		}
	}
	return out
}

func lossSplitUnits(losses []*eventsv1.EventLoss) int {
	total := 0
	for _, loss := range losses {
		if len(loss.GetEventSequenceRanges()) == 0 {
			total++
		} else {
			total += len(loss.GetEventSequenceRanges())
		}
	}
	return total
}

func validateRetainedLosses(losses []*eventsv1.EventLoss, source, session string) error {
	if source == "" || session == "" {
		return errors.New("loss producer identity is incomplete")
	}
	for _, loss := range losses {
		if loss == nil {
			return errors.New("nil loss")
		}
		if loss.GetSourceNodeId() != source || loss.GetProducerSessionId() != session {
			return errors.New("producer identity does not match fixed spool session")
		}
		shapeProbe := &eventsv1.ProtocolEventBatch{Stats: &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{loss}}}
		if err := validateLossShape(shapeProbe); err != nil {
			return fmt.Errorf("invalid loss: %w", err)
		}
		ranges := loss.GetEventSequenceRanges()
		for start := 0; start < max(1, len(ranges)); start += maxCollectionEntries {
			part := proto.Clone(loss).(*eventsv1.EventLoss)
			if len(ranges) > 0 {
				end := min(start+maxCollectionEntries, len(ranges))
				part.EventSequenceRanges = cloneRanges(ranges[start:end])
				part.Count = rangedCount(part.EventSequenceRanges)
				if start == 0 {
					part.Count += loss.GetCount() - rangedCount(ranges)
				}
			}
			probe := &eventsv1.ProtocolEventBatch{
				SourceNodeId: source, ProducerSessionId: session, BatchSequence: 1,
				Stats: &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{part}},
			}
			if err := protoadapter.ValidateBatch(probe); err != nil {
				return fmt.Errorf("invalid loss: %w", err)
			}
			if len(ranges) == 0 {
				break
			}
		}
	}
	if err := validateLossAccounting(losses); err != nil {
		return err
	}
	return validateDisjointLossRanges(losses)
}

func validateLossAccounting(losses []*eventsv1.EventLoss) error {
	type accounting struct {
		extra  uint64
		ranges []*eventsv1.SequenceRange
	}
	groups := make(map[lossKey]*accounting)
	for _, loss := range losses {
		if loss == nil {
			continue
		}
		key := lossKey{loss.GetSourceNodeId(), loss.GetProducerSessionId(), loss.GetKind()}
		group := groups[key]
		if group == nil {
			group = &accounting{}
			groups[key] = group
		}
		covered := rangedCount(loss.GetEventSequenceRanges())
		if loss.GetCount() < covered || loss.GetCount()-covered > ^uint64(0)-group.extra {
			return errors.New("event loss count overflows exact accounting")
		}
		group.extra += loss.GetCount() - covered
		group.ranges = append(group.ranges, loss.GetEventSequenceRanges()...)
	}
	for _, group := range groups {
		sort.Slice(group.ranges, func(i, j int) bool { return group.ranges[i].GetFirst() < group.ranges[j].GetFirst() })
		total := group.extra
		var first, last uint64
		for _, eventRange := range group.ranges {
			if eventRange == nil {
				continue
			}
			if first == 0 {
				first, last = eventRange.GetFirst(), eventRange.GetLast()
				continue
			}
			if last == ^uint64(0) || eventRange.GetFirst() <= last+1 {
				if eventRange.GetLast() > last {
					last = eventRange.GetLast()
				}
				continue
			}
			if first == 1 && last == ^uint64(0) {
				return errors.New("event loss count overflows exact accounting")
			}
			count := last - first + 1
			if count > ^uint64(0)-total {
				return errors.New("event loss count overflows exact accounting")
			}
			total += count
			first, last = eventRange.GetFirst(), eventRange.GetLast()
		}
		if first != 0 {
			if first == 1 && last == ^uint64(0) {
				return errors.New("event loss count overflows exact accounting")
			}
			count := last - first + 1
			if count > ^uint64(0)-total {
				return errors.New("event loss count overflows exact accounting")
			}
		}
	}
	return nil
}

func validateDisjointLossRanges(losses []*eventsv1.EventLoss) error {
	type keyedRange struct {
		key         lossKey
		first, last uint64
	}
	var ranges []keyedRange
	for _, loss := range losses {
		if loss != nil {
			key := lossKey{source: loss.GetSourceNodeId(), session: loss.GetProducerSessionId(), kind: loss.GetKind()}
			for _, eventRange := range loss.GetEventSequenceRanges() {
				if eventRange != nil {
					ranges = append(ranges, keyedRange{key: key, first: eventRange.GetFirst(), last: eventRange.GetLast()})
				}
			}
		}
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].first == ranges[j].first {
			return ranges[i].last > ranges[j].last
		}
		return ranges[i].first < ranges[j].first
	})
	if len(ranges) == 0 {
		return nil
	}
	activeKey, activeLast := ranges[0].key, ranges[0].last
	for _, eventRange := range ranges[1:] {
		if eventRange.first <= activeLast && eventRange.key != activeKey {
			return errors.New("event loss ranges overlap across loss kinds")
		}
		if eventRange.last > activeLast {
			activeKey, activeLast = eventRange.key, eventRange.last
		}
	}
	return nil
}

func splitPendingLosses(losses []*eventsv1.EventLoss, maxRanges int) (prefix, remaining []*eventsv1.EventLoss) {
	if maxRanges < 1 {
		maxRanges = 1
	}
	// Normalization groups ranges by kind, but carrier publication must follow
	// event order across all kinds. Otherwise an earlier kind can advance the
	// receiver's high-water beyond ranges left for a subsequent carrier.
	var units []*eventsv1.EventLoss
	for _, loss := range losses {
		if loss == nil {
			continue
		}
		ranges := loss.GetEventSequenceRanges()
		if len(ranges) == 0 {
			units = append(units, proto.Clone(loss).(*eventsv1.EventLoss))
			continue
		}
		extra := loss.GetCount() - rangedCount(ranges)
		for index, eventRange := range ranges {
			part := &eventsv1.EventLoss{
				Kind: loss.Kind, SourceNodeId: loss.SourceNodeId, ProducerSessionId: loss.ProducerSessionId,
				Count:               eventRange.Last - eventRange.First + 1,
				EventSequenceRanges: []*eventsv1.SequenceRange{{First: eventRange.First, Last: eventRange.Last}},
			}
			if index == 0 {
				part.Count += extra
			}
			units = append(units, part)
		}
	}
	sort.SliceStable(units, func(i, j int) bool {
		left, right := units[i].GetEventSequenceRanges(), units[j].GetEventSequenceRanges()
		if len(left) == 0 {
			return false
		}
		if len(right) == 0 {
			return true
		}
		return left[0].First < right[0].First
	})
	boundary := min(maxRanges, len(units))
	return normalizeLosses(units[:boundary]), normalizeLosses(units[boundary:])
}

func cloneRanges(input []*eventsv1.SequenceRange) []*eventsv1.SequenceRange {
	out := make([]*eventsv1.SequenceRange, 0, len(input))
	for _, eventRange := range input {
		if eventRange != nil {
			out = append(out, proto.Clone(eventRange).(*eventsv1.SequenceRange))
		}
	}
	return out
}

func rangedCount(ranges []*eventsv1.SequenceRange) uint64 {
	var total uint64
	for _, eventRange := range ranges {
		total += eventRange.GetLast() - eventRange.GetFirst() + 1
	}
	return total
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("sync event spool directory: %w", err)
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return fmt.Errorf("sync event spool directory: %w", err)
	}
	return nil
}

// readRecord validates the open file's exact size and configured payload bound
// before allocating. The 4 MiB default matches processor ingress; gRPC's 10 MiB
// ceiling therefore always has room for the enclosing ingress message.
func readRecord(path string, maxPayload uint64) (record, error) {
	entryInfo, err := os.Lstat(path)
	if err != nil {
		return record{}, fmt.Errorf("inspect event spool record %q: %w", path, err)
	}
	if !entryInfo.Mode().IsRegular() {
		return record{}, fmt.Errorf("inspect event spool record %q: record is not a regular file", path)
	}
	// O_NOFOLLOW closes the Lstat/open replacement window: even a symlink to the
	// same inode must never become an authoritative record outside this spool.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return record{}, fmt.Errorf("open event spool record %q: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return record{}, fmt.Errorf("stat event spool record %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(entryInfo, info) {
		return record{}, fmt.Errorf("stat event spool record %q: record changed while opening", path)
	}
	if info.Size() < headerSize {
		return record{}, fmt.Errorf("read event spool record %q: file is smaller than header", path)
	}
	header := make([]byte, headerSize)
	if _, err = io.ReadFull(f, header); err != nil {
		return record{}, fmt.Errorf("read event spool record %q header: %w", path, err)
	}
	if !bytes.Equal(header[:8], recordMagic[:]) || binary.BigEndian.Uint16(header[8:10]) != recordVersion {
		return record{}, fmt.Errorf("read event spool record %q: invalid format", path)
	}
	length := binary.BigEndian.Uint64(header[18:26])
	if length > maxPayload {
		return record{}, fmt.Errorf("read event spool record %q: payload length %d exceeds limit %d", path, length, maxPayload)
	}
	remaining := uint64(info.Size() - headerSize)
	if length != remaining {
		return record{}, fmt.Errorf("read event spool record %q: declared payload length %d does not match file remainder %d", path, length, remaining)
	}
	payload := make([]byte, int(length))
	if _, err = io.ReadFull(f, payload); err != nil {
		return record{}, fmt.Errorf("read event spool record %q payload: %w", path, err)
	}
	if crc32.ChecksumIEEE(payload) != binary.BigEndian.Uint32(header[26:30]) {
		return record{}, fmt.Errorf("read event spool record %q: checksum mismatch", path)
	}
	b := new(eventsv1.ProtocolEventBatch)
	if err = proto.Unmarshal(payload, b); err != nil {
		return record{}, fmt.Errorf("read event spool record %q protobuf: %w", path, err)
	}
	if err = protoadapter.ValidateBatch(b); err != nil {
		return record{}, fmt.Errorf("read event spool record %q transport validation: %w", path, err)
	}
	if err = validateBatchLossIdentity(b); err != nil {
		return record{}, fmt.Errorf("read event spool record %q durable loss identity: %w", path, err)
	}
	return record{name: filepath.Base(path), path: path, created: time.Unix(0, int64(binary.BigEndian.Uint64(header[10:18]))), size: uint64(info.Size()), payloadSize: length, batch: b}, nil
}
func marshalAndValidate(batch *eventsv1.ProtocolEventBatch, maxPayload uint64) ([]byte, error) {
	if err := protoadapter.ValidateBatch(batch); err != nil {
		return nil, fmt.Errorf("enqueue event batch: transport validation: %w", err)
	}
	if err := validateBatchLossIdentity(batch); err != nil {
		return nil, fmt.Errorf("enqueue event batch: durable loss identity: %w", err)
	}
	if len(batch.GetEvents()) > maxCollectionEntries || len(batch.GetStats().GetLosses()) > maxCollectionEntries {
		return nil, errors.New("enqueue event batch: transport collection limit exceeded")
	}
	ranges := 0
	for _, loss := range batch.GetStats().GetLosses() {
		ranges += len(loss.GetEventSequenceRanges())
		if ranges > maxCollectionEntries {
			return nil, errors.New("enqueue event batch: transport loss range limit exceeded")
		}
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("enqueue event batch: marshal: %w", err)
	}
	if uint64(len(payload)) > maxPayload {
		return nil, fmt.Errorf("%w: %d > %d", ErrRecordTooLarge, len(payload), maxPayload)
	}
	return payload, nil
}

func validateBatchLossIdentity(batch *eventsv1.ProtocolEventBatch) error {
	for _, loss := range batch.GetStats().GetLosses() {
		if loss == nil {
			continue
		}
		if loss.GetSourceNodeId() != batch.GetSourceNodeId() || loss.GetProducerSessionId() != batch.GetProducerSessionId() {
			return errors.New("event loss producer identity does not match batch identity")
		}
	}
	return nil
}

func validateLossShape(batch *eventsv1.ProtocolEventBatch) error {
	if batch.GetFirstEventSequence() == 1 && batch.GetLastEventSequence() == ^uint64(0) {
		return errors.New("event sequence range count overflows")
	}
	for _, loss := range batch.GetStats().GetLosses() {
		if loss == nil {
			return errors.New("nil event loss")
		}
		var covered, previous uint64
		for i, eventRange := range loss.GetEventSequenceRanges() {
			if eventRange == nil || eventRange.GetFirst() == 0 || eventRange.GetLast() < eventRange.GetFirst() {
				return errors.New("invalid event loss range")
			}
			if i > 0 && eventRange.GetFirst() <= previous {
				return errors.New("event loss ranges overlap or are out of order")
			}
			if eventRange.GetFirst() == 1 && eventRange.GetLast() == ^uint64(0) {
				return errors.New("event loss range count overflows")
			}
			count := eventRange.GetLast() - eventRange.GetFirst() + 1
			if covered > ^uint64(0)-count {
				return errors.New("event loss range count overflows")
			}
			covered += count
			previous = eventRange.GetLast()
		}
		if loss.GetCount() < covered {
			return errors.New("event loss count is smaller than its ranges")
		}
	}
	return nil
}

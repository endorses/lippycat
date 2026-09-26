//go:build li

package delivery

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

var ErrJournalFull = errors.New("X2 journal capacity exhausted")
var ErrJournalClosed = errors.New("X2 journal closed or faulted")
var ErrPersistenceUncertain = errors.New("X2 persistence outcome uncertain")
var ErrJournalMigrationRequired = errors.New("legacy X2 journal requires offline upgrade with a fresh active key before mutation")

const journalOverhead = int64(4096) // Conservative JSON/framing reservation; payload expands by 4/3.
const journalFaultReserve = int64(16384)
const journalMaxRecord = int64(64 << 20)

type JournalConfig struct {
	rewriteExclusions map[string]bool
	offline           bool
	preflight         bool
	rewriteCatalog    string
	rewriteDir        *securestore.Dir
	rewriteLock       *securestore.Lock
	rewriteUsage      *securestore.Usage
	Keys              *securestore.Keyring

	// Interface explicitly selects the production segmented writer. Zero retains
	// the original X2 API compatibility mode for existing deployments.
	Interface        PDUType
	StateIncarnation uuid.UUID
	MaxAge           time.Duration

	PreserveSequences  bool
	Dir, KeyFile       string
	KeyID, LegacyKeyID string
	ReadKeys           []securestore.KeyRef
	// ValidateKeys runs once with the actual owner ring before filesystem changes.
	ValidateKeys           func(*securestore.Keyring) error
	MaxBytes               int64
	MaxPending, MaxRecords int
}

// JournalRecord stores the original encoded X2 product. Replay never re-encodes it.
type JournalRecord struct {
	Interface                                      PDUType               `json:"-"`
	JournalUUID, StateIncarnation, CallIncarnation uuid.UUID             `json:"-"`
	Deadline                                       time.Time             `json:"-"`
	ContentSHA256                                  [32]byte              `json:"-"`
	Provenance                                     li.DeliveryProvenance `json:"-"`

	ID                                                    uint64
	DID, XID                                              uuid.UUID
	TaskGeneration, DestinationGeneration, CallGeneration uint64
	CallID                                                string
	AdmittedAt, CapturedAt                                time.Time
	Data                                                  []byte
}
type JournalStats struct {
	Approved, Retained int
	Expired, Revoked   uint64

	ReplayPending            int
	Uncertain                int
	Bytes, MaxBytes          int64
	Pending, Persisted, Held int
	Rejected                 uint64
	LastError                string
}
type journalEntry struct {
	did                         uuid.UUID
	payloadBytes                int64
	authorized                  bool
	size                        int64
	held, persisted, completing bool
}
type journalOperation struct {
	admission uint64
	reserved  int64
	metadata  []byte
	record    JournalRecord
	complete  uint64
	callback  func(uint64, error)
	barrier   chan struct{}
}

// Journal has one filesystem worker and a bounded admission channel. Admission is
// not a durability acknowledgement: only the callback after fsync confirms it.
// Recovered records are always held; authorization belongs to the ADMF owner.
type Journal struct {
	borrowedUsage       bool
	preparedTemporaries []string
	segments            journalSegmentBackend

	heldByDID      map[uuid.UUID]int
	replayRevision uint64
	replayStarted  bool
	allocationUnit int64
	faultReserve   int64
	// writeFile is the atomic storage boundary, injected by fault tests before admission.
	writeFile   func(string, []byte) error
	sequences   map[string]journalSequenceEntry
	sendMu      sync.RWMutex
	purgeMu     sync.RWMutex
	controlMu   sync.Mutex
	wake        chan struct{}
	checkpoints []uint64
	mu          sync.Mutex
	cfg         JournalConfig
	store       *securestore.Dir
	keys        *securestore.Keyring
	usage       *securestore.Usage
	writer      *securestore.Writer
	storeID     [16]byte
	readOnly    bool
	// Used only during offline construction to classify partial bootstrap.
	bootstrapTouched bool
	// A resumable legacy bootstrap with no state cannot accept new-format objects.
	legacyBootstrapOnly bool
	entries             map[uint64]*journalEntry
	next                uint64
	stats               JournalStats
	telemetry           securestore.Telemetry
	lastErr             error
	ops                 chan journalOperation
	done                chan struct{}
	closed              bool
	lock                *securestore.Lock
}

func OpenJournal(cfg JournalConfig) (*Journal, error) { return openJournal(cfg, false) }
func openJournal(cfg JournalConfig, upgrade bool) (*Journal, error) {
	if cfg.Interface != 0 {
		return openSegmentJournal(cfg, upgrade)
	}
	return openLegacyJournal(cfg, upgrade)
}
func (j *Journal) UUID() uuid.UUID { return uuid.UUID(j.storeID) }
func (j *Journal) Highwaters() (uint64, uint64) {
	if j.segments != nil {
		return j.segments.highwaters()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.next, j.next
}

// ReadOnly reports a legacy recovery/export owner that cannot seal or mutate.
func (j *Journal) ReadOnly() bool { return j.readOnly }

// A crash may leave a durable product without its sequence checkpoint or ID
// watermark. Repair both before callers can purge or deliver that last evidence.
// Otherwise another restart could reuse an already observed sequence or record ID.
func (j *Journal) repairRecoveredCheckpoints() error {
	ids := make([]uint64, 0, len(j.entries))
	for id := range j.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	if j.cfg.PreserveSequences {
		for _, id := range ids {
			rec, err := j.readRecord(id)
			if err != nil {
				return err
			}
			seq, err := j.prepareSequence(rec.Data)
			if err != nil {
				return err
			}
			if seq == nil {
				continue
			}
			size := j.diskSize(int64(len(seq.data)))
			if size-seq.oldSize > j.cfg.MaxBytes-j.faultReserve-j.stats.Bytes {
				return ErrJournalFull
			}
			if err := j.writeFile(filepath.Join(j.cfg.Dir, seq.key+".seq"), seq.data); err != nil {
				return err
			}
			j.sequences[seq.key] = journalSequenceEntry{size: size, next: seq.checkpoint.Next}
			j.stats.Bytes += size - seq.oldSize
		}
	}
	if len(ids) == 0 {
		return nil
	}
	state, err := j.encodeObject(securestore.JournalState, "journal-state", JournalRecord{ID: j.next})
	if err != nil {
		return err
	}
	return j.writeFile(filepath.Join(j.cfg.Dir, ".state"), state)
}
func (j *Journal) path(id uint64) string {
	return filepath.Join(j.cfg.Dir, fmt.Sprintf("%020d.x2", id))
}
func (j *Journal) Admit(rec JournalRecord, cb func(uint64, error)) (uint64, error) {
	return j.admit(rec, cb, true)
}
func (j *Journal) admit(rec JournalRecord, cb func(uint64, error), clone bool) (uint64, error) {
	if j.segments != nil {
		return j.segments.admit(rec, cb, clone)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.readOnly {
		return 0, ErrJournalMigrationRequired
	}
	if j.closed || j.stats.LastError != "" {
		return 0, ErrJournalClosed
	}
	if len(rec.Data) > int(journalMaxRecord) || len(rec.CallID) > 64<<10 || !utf8.ValidString(rec.CallID) {
		j.stats.Rejected++
		return 0, ErrJournalFull
	}
	size := max(journalSequenceReserve, j.allocationUnit) + j.diskSize(journalOverhead+int64(len(rec.Data))*2+int64(len(rec.CallID))*6)
	if size > journalMaxRecord || size > j.cfg.MaxBytes-j.faultReserve-j.stats.Bytes || len(j.entries) >= j.cfg.MaxRecords || len(j.ops) == cap(j.ops) {
		j.stats.Rejected++
		return 0, ErrJournalFull
	}
	if j.next == ^uint64(0) {
		return 0, fmt.Errorf("journal record IDs exhausted")
	}
	j.next++
	rec.ID = j.next
	if clone {
		rec.Data = append([]byte(nil), rec.Data...)
	}
	j.entries[rec.ID] = &journalEntry{did: rec.DID, payloadBytes: int64(len(rec.Data)), size: size}
	j.stats.Bytes += size
	j.stats.Pending++
	// Flush can occupy the last channel slot without holding mu. Never wait
	// here: the worker needs mu to finish its current operation and free space.
	select {
	case j.ops <- journalOperation{record: rec, callback: cb}:
		return rec.ID, nil
	default:
		delete(j.entries, rec.ID)
		j.stats.Bytes -= size
		j.stats.Pending--
		j.stats.Rejected++
		return 0, ErrJournalFull
	}
}

// Complete checkpoints local write completion. A crash before the checkpoint may
// replay the record: local write completion never establishes MDF receipt.
func (j *Journal) Complete(id uint64) error {
	if j.segments != nil {
		return j.segments.terminal(id, "complete")
	}
	if j.readOnly {
		return ErrJournalMigrationRequired
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.stats.LastError != "" {
		return ErrJournalClosed
	}
	e := j.entries[id]
	if e == nil || e.completing {
		return nil
	}
	if !e.persisted {
		return fmt.Errorf("journal record persistence is pending")
	}
	e.completing = true
	j.checkpoints = append(j.checkpoints, id)
	select {
	case j.wake <- struct{}{}:
	default:
	}
	return nil
}
func (j *Journal) Stats() JournalStats {
	j.mu.Lock()
	defer j.mu.Unlock()
	v := j.stats
	v.Approved = v.ReplayPending
	v.Retained = v.Persisted
	return v
}

// Release marks an explicitly reconciled record eligible for the delivery owner.
// It does not delete product or make a delivery decision on its own.
func (j *Journal) Release(id uint64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.releaseLocked(id)
}

func (j *Journal) releaseLocked(id uint64) {
	if e := j.entries[id]; e != nil && e.held {
		e.held = false
		if e.authorized {
			e.authorized = false
			j.stats.ReplayPending--
		}
		j.stats.Held--
		j.decrementHeldLocked(e.did)
	}
}
func (j *Journal) Close() error {
	if j.cfg.offline {
		j.mu.Lock()
		defer j.mu.Unlock()
		if j.closed {
			return j.lastErr
		}
		j.closed = true
		j.lastErr = j.closeStorage()
		return j.lastErr
	}
	j.sendMu.Lock()
	j.mu.Lock()
	if !j.closed {
		j.closed = true
		j.telemetry.Closing()
		close(j.ops)
	}
	j.mu.Unlock()
	j.sendMu.Unlock()
	<-j.done
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.lastErr
}
func (j *Journal) run() {
	if j.segments != nil {
		j.segments.run()
		return
	}
	defer close(j.done)
	defer func() {
		j.purgeMu.Lock()
		defer j.purgeMu.Unlock()
		if err := j.closeStorage(); err != nil {
			j.fault(err)
		}
	}()
	for {
		select {
		case <-j.wake:
			j.checkpoint()
		case op, ok := <-j.ops:
			if !ok {
				j.checkpoint()
				return
			}
			if op.barrier != nil {
				j.checkpoint()
				close(op.barrier)
				continue
			}
			var seq *sequenceWrite
			var err error
			j.mu.Lock()
			faulted := j.stats.LastError != ""
			j.mu.Unlock()
			if faulted {
				err = ErrJournalClosed
			} else {
				seq, err = j.prepareSequence(op.record.Data)
			}
			var b []byte
			if err == nil {
				b, err = j.encodeObject(securestore.X2Product, journalObjectID(op.record.ID), op.record)
			}
			productWritten := false
			if err == nil {
				err = j.write(op.record.ID, b)
				productWritten = err == nil
			}
			if err == nil && seq != nil {
				err = j.writeFile(filepath.Join(j.cfg.Dir, seq.key+".seq"), seq.data)
			}
			if err == nil {
				var state []byte
				state, err = j.encodeObject(securestore.JournalState, "journal-state", JournalRecord{ID: op.record.ID})
				if err == nil {
					err = j.writeFile(filepath.Join(j.cfg.Dir, ".state"), state)
				}
			}
			if err != nil && (productWritten || errors.Is(err, ErrPersistenceUncertain)) {
				err = &securestore.CommitError{Outcome: securestore.Uncertain, Op: "persist journal product and checkpoints", Err: errors.Join(ErrPersistenceUncertain, err)}
			}
			j.mu.Lock()
			e := j.entries[op.record.ID]
			j.stats.Pending--
			if err == nil {
				if seq != nil {
					j.sequences[seq.key] = journalSequenceEntry{size: j.diskSize(int64(len(seq.data))), next: seq.checkpoint.Next}
					j.stats.Bytes += j.diskSize(int64(len(seq.data))) - seq.oldSize
				}
				j.stats.Bytes += j.diskSize(int64(len(b))) - e.size
				e.size = j.diskSize(int64(len(b)))
				e.persisted = true
				j.stats.Persisted++
			} else {
				if j.lastErr == nil {
					j.lastErr = err
					j.stats.LastError = err.Error()
				}
				if errors.Is(err, ErrPersistenceUncertain) {
					j.stats.Uncertain++
				}
			}
			j.mu.Unlock()
			j.telemetry.Record(securestore.OutcomeOf(err), err)
			if err != nil {
				j.telemetry.Fault(err)
			}
			if op.callback != nil {
				op.callback(op.record.ID, err)
			}
		}
	}
}
func (j *Journal) checkpoint() {
	j.mu.Lock()
	if j.stats.LastError != "" {
		j.mu.Unlock()
		return
	}
	ids := j.checkpoints
	j.checkpoints = nil
	j.mu.Unlock()
	for _, id := range ids {
		err := j.removeRecord(id)
		j.telemetry.Record(securestore.OutcomeOf(err), err)
		if err != nil {
			j.fault(fmt.Errorf("checkpoint journal: %w", err))
			return
		}
		j.mu.Lock()
		if e := j.entries[id]; e != nil {
			j.stats.Bytes -= e.size
			j.stats.Persisted--
			if e.held {
				if e.authorized {
					j.stats.ReplayPending--
				}
				j.stats.Held--
				j.decrementHeldLocked(e.did)
			}
			delete(j.entries, id)
		}
		j.mu.Unlock()
	}
}

// Flush waits for all earlier admissions and checkpoints. Filesystem sync is not
// cancellable by Go; operators must use a responsive local filesystem.
func (j *Journal) Flush() error {
	barrier := make(chan struct{})
	j.sendMu.RLock()
	j.mu.Lock()
	if j.closed {
		j.mu.Unlock()
		j.sendMu.RUnlock()
		return ErrJournalClosed
	}
	// Admission uses nonblocking reservation, so release the lock while waiting
	// for room. Close is serialized with Flush by the client shutdown owner.
	j.mu.Unlock()
	j.ops <- journalOperation{barrier: barrier}
	j.sendMu.RUnlock()
	<-barrier
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.lastErr
}
func (j *Journal) fault(err error) {
	j.telemetry.Fault(err)
	j.mu.Lock()
	if j.lastErr == nil {
		j.lastErr = err
		j.stats.LastError = err.Error()
	}
	j.mu.Unlock()
	logger.Error("X2 journal fault", "fault_code", securestore.PublicFaultCode(err))
}
func (j *Journal) write(id uint64, b []byte) error {
	return j.writeFile(j.path(id), b)
}
func (j *Journal) writePath(path string, b []byte) error {
	out, err := j.store.Replace(filepath.Base(path), b)
	if out != securestore.NotCommitted {
		j.bootstrapTouched = true
	}
	return journalStorageError(out, err)
}
func (j *Journal) syncDir() error { return j.store.Sync() }

// VisitHeld bounds recovery payload memory to a single record.
func (j *Journal) VisitHeld(visit func(JournalRecord) error) error {
	j.mu.Lock()
	ids := make([]uint64, 0, j.stats.Held)
	for id, e := range j.entries {
		if e.held && !e.completing {
			ids = append(ids, id)
		}
	}
	j.mu.Unlock()
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	for _, id := range ids {
		record, err := j.readRecord(id)
		if err != nil {
			return err
		}
		if err := visit(record); err != nil {
			return err
		}
	}
	return nil
}

// Purge is a synchronous explicit administrative checkpoint for held product.
func (j *Journal) Purge(id uint64) error {
	if j.segments != nil {
		return j.segments.terminal(id, "purge")
	}
	if j.readOnly {
		return ErrJournalMigrationRequired
	}
	// Keep the exclusive spool ownership alive through deletion and directory
	// sync. Close must not release the process lock while a purge is in flight.
	j.purgeMu.RLock()
	defer j.purgeMu.RUnlock()
	j.mu.Lock()
	if j.closed || j.stats.LastError != "" {
		j.mu.Unlock()
		return ErrJournalClosed
	}
	e := j.entries[id]
	if e == nil {
		j.mu.Unlock()
		return nil
	}
	if !e.held || e.completing {
		j.mu.Unlock()
		return fmt.Errorf("record is not held")
	}
	e.completing = true
	j.mu.Unlock()
	err := j.removeRecord(id)
	j.telemetry.Record(securestore.OutcomeOf(err), err)
	if err != nil {
		j.fault(err)
		return err
	}
	j.mu.Lock()
	j.stats.Bytes -= e.size
	j.stats.Persisted--
	j.stats.Held--
	j.decrementHeldLocked(e.did)
	if e.authorized {
		j.stats.ReplayPending--
	}
	delete(j.entries, id)
	j.mu.Unlock()
	return nil
}

func (j *Journal) diskSize(n int64) int64 {
	return ((n + j.allocationUnit - 1) / j.allocationUnit) * j.allocationUnit
}

func (j *Journal) HoldsDestination(did uuid.UUID) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.heldByDID[did] > 0
}

// revokeDestinationReplay invalidates approvals for backlog that has not yet
// acquired a queue owner. The caller holds controlMu so an overlapping approval
// cannot publish a decision made before destination removal.
func (j *Journal) revokeDestinationReplay(did uuid.UUID) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range j.entries {
		if e.did == did && e.held && e.authorized {
			e.authorized = false
			j.stats.ReplayPending--
		}
	}
	j.replayRevision++
}

func (j *Journal) decrementHeldLocked(did uuid.UUID) {
	if j.heldByDID[did] <= 1 {
		delete(j.heldByDID, did)
	} else {
		j.heldByDID[did]--
	}
}

// Hold detaches durable product from a removed queue without losing its replay
// identity. Reauthorization is required even when the same UUID is reused.
func (j *Journal) Hold(id uint64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if e := j.entries[id]; e != nil && e.persisted && !e.held && !e.completing {
		e.held = true
		e.authorized = false
		j.stats.Held++
		j.heldByDID[e.did]++
		j.replayRevision++
	}
}

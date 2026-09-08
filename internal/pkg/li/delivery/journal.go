//go:build li

package delivery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
)

var ErrJournalFull = errors.New("X2 journal capacity exhausted")
var ErrJournalClosed = errors.New("X2 journal closed or faulted")
var ErrPersistenceUncertain = errors.New("X2 persistence outcome uncertain")

const journalOverhead = int64(4096) // Conservative JSON/framing reservation; payload expands by 4/3.
const journalFaultReserve = int64(16384)
const journalMaxRecord = int64(64 << 20)

type JournalConfig struct {
	PreserveSequences      bool
	Dir, KeyFile           string
	MaxBytes               int64
	MaxPending, MaxRecords int
}

// JournalRecord stores the original encoded X2 product. Replay never re-encodes it.
type JournalRecord struct {
	ID                                                    uint64
	DID, XID                                              uuid.UUID
	TaskGeneration, DestinationGeneration, CallGeneration uint64
	CallID                                                string
	AdmittedAt, CapturedAt                                time.Time
	Data                                                  []byte
}
type JournalStats struct {
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
	record   JournalRecord
	complete uint64
	callback func(uint64, error)
	barrier  chan struct{}
}

// Journal has one filesystem worker and a bounded admission channel. Admission is
// not a durability acknowledgement: only the callback after fsync confirms it.
// Recovered records are always held; authorization belongs to the ADMF owner.
type Journal struct {
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
	aead        cipher.AEAD
	entries     map[uint64]*journalEntry
	next        uint64
	stats       JournalStats
	ops         chan journalOperation
	done        chan struct{}
	closed      bool
	lock        *os.File
}

func OpenJournal(cfg JournalConfig) (*Journal, error) {
	if cfg.MaxBytes <= journalFaultReserve || cfg.MaxPending <= 0 || cfg.MaxRecords <= 0 {
		return nil, fmt.Errorf("invalid X2 journal capacity")
	}
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, fmt.Errorf("create X2 journal: %w", err)
	}
	if err := checkJournalMode(cfg.Dir, true); err != nil {
		return nil, err
	}
	if err := checkJournalMode(cfg.KeyFile, false); err != nil {
		return nil, err
	}
	key, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read journal key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("journal key must contain exactly 32 raw bytes")
	}
	block, err := aes.NewCipher(key)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(cfg.Dir, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open journal lock: %w", err)
	}
	fail := func(e error) (*Journal, error) {
		if ce := lock.Close(); ce != nil {
			logger.Error("Close journal lock", "error", ce)
		}
		return nil, e
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("lock journal: %w", err))
	}
	j := &Journal{cfg: cfg, aead: aead, entries: make(map[uint64]*journalEntry), ops: make(chan journalOperation, cfg.MaxPending), done: make(chan struct{}), lock: lock}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(cfg.Dir, &fs); err != nil {
		return fail(fmt.Errorf("inspect journal filesystem: %w", err))
	}
	j.allocationUnit = max(4096, int64(fs.Bsize))
	j.faultReserve = max(journalFaultReserve, 2*j.allocationUnit)
	j.writeFile = j.writePath
	j.sequences = make(map[string]journalSequenceEntry)
	j.heldByDID = make(map[uuid.UUID]int)
	j.wake = make(chan struct{}, 1)
	j.stats.MaxBytes = cfg.MaxBytes
	dir, err := os.Open(cfg.Dir)
	if err != nil {
		return fail(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			logger.Error("Close journal recovery directory", "error", err)
		}
	}()
	// Read bounded batches: a reduced limit or an unexpectedly large spool must
	// not allocate the complete directory or index before capacity is checked.
	for {
		files, readErr := dir.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fail(readErr)
		}
		for _, f := range files {
			name := f.Name()
			if name == ".state" {
				path := filepath.Join(cfg.Dir, name)
				if err := checkJournalMode(path, false); err != nil {
					return fail(err)
				}
				info, err := f.Info()
				if err != nil {
					return fail(err)
				}
				if info.Size() > 4096 {
					return fail(fmt.Errorf("oversized journal state"))
				}
				b, err := os.ReadFile(path)
				if err != nil {
					return fail(err)
				}
				r, err := j.decode(b)
				if err != nil {
					return fail(err)
				}
				if r.ID > j.next {
					j.next = r.ID
				}
				continue
			}
			if name == ".lock" {
				continue
			}
			if strings.HasSuffix(name, ".tmp") {
				if _, err := strconv.ParseUint(strings.TrimSuffix(name, ".x2.tmp"), 10, 64); (err != nil || !strings.HasSuffix(name, ".x2.tmp")) && !validSequenceTemp(name) && name != ".state.tmp" {
					return fail(fmt.Errorf("unexpected temporary journal file %q", name))
				}
				if err := os.Remove(filepath.Join(cfg.Dir, name)); err != nil {
					return fail(fmt.Errorf("remove incomplete journal record: %w", err))
				}
				continue
			}
			if strings.HasSuffix(name, ".seq") {
				if len(j.sequences) >= cfg.MaxRecords {
					return fail(fmt.Errorf("recovered journal exceeds configured capacity"))
				}
				if err := j.recoverSequence(name); err != nil {
					return fail(err)
				}
				if j.stats.Bytes > cfg.MaxBytes-j.faultReserve {
					return fail(fmt.Errorf("recovered journal exceeds configured capacity"))
				}
				continue
			}
			if !strings.HasSuffix(name, ".x2") {
				return fail(fmt.Errorf("unexpected journal file %q", name))
			}
			if len(j.entries) >= cfg.MaxRecords {
				return fail(fmt.Errorf("recovered journal exceeds configured capacity"))
			}
			id, err := strconv.ParseUint(strings.TrimSuffix(name, ".x2"), 10, 64)
			if err != nil || id == 0 {
				return fail(fmt.Errorf("invalid journal record name %q", name))
			}
			path := filepath.Join(cfg.Dir, name)
			if err := checkJournalMode(path, false); err != nil {
				return fail(err)
			}
			info, err := f.Info()
			if err != nil {
				return fail(err)
			}
			if info.Size() > journalMaxRecord || info.Size() <= 0 {
				return fail(fmt.Errorf("invalid journal record size"))
			}
			if j.diskSize(info.Size()) > cfg.MaxBytes-j.faultReserve-j.stats.Bytes {
				return fail(fmt.Errorf("recovered journal exceeds configured capacity"))
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fail(err)
			}
			rec, err := j.decode(data)
			if err != nil {
				return fail(fmt.Errorf("recover journal %s: %w", name, err))
			}
			if rec.ID != id {
				return fail(fmt.Errorf("journal identity mismatch"))
			}
			j.entries[id] = &journalEntry{did: rec.DID, payloadBytes: int64(len(rec.Data)), size: j.diskSize(int64(len(data))), held: true, persisted: true}
			j.stats.Bytes += j.diskSize(int64(len(data)))
			j.stats.Persisted++
			j.stats.Held++
			j.heldByDID[rec.DID]++
			if id > j.next {
				j.next = id
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if j.stats.Bytes > cfg.MaxBytes-j.faultReserve || len(j.entries) > cfg.MaxRecords || len(j.sequences) > cfg.MaxRecords {
		return fail(fmt.Errorf("recovered journal exceeds configured capacity"))
	}
	if err := j.repairRecoveredCheckpoints(); err != nil {
		return fail(fmt.Errorf("repair recovered journal checkpoints: %w", err))
	}
	go j.run()
	return j, nil
}

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
			data, err := os.ReadFile(j.path(id))
			if err != nil {
				return err
			}
			rec, err := j.decode(data)
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
	state, err := j.encode(JournalRecord{ID: j.next})
	if err != nil {
		return err
	}
	return j.writeFile(filepath.Join(j.cfg.Dir, ".state"), state)
}
func checkJournalMode(path string, dir bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat journal path: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || st.IsDir() != dir || (!dir && !st.Mode().IsRegular()) || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("journal path %q must be a private regular file (0600) or directory (0700)", path)
	}
	return nil
}
func (j *Journal) path(id uint64) string {
	return filepath.Join(j.cfg.Dir, fmt.Sprintf("%020d.x2", id))
}
func (j *Journal) Admit(rec JournalRecord, cb func(uint64, error)) (uint64, error) {
	return j.admit(rec, cb, true)
}
func (j *Journal) admit(rec JournalRecord, cb func(uint64, error), clone bool) (uint64, error) {
	size := max(journalSequenceReserve, j.allocationUnit) + j.diskSize(journalOverhead+int64(len(rec.Data))*2+int64(len(rec.CallID))*6)
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.stats.LastError != "" {
		return 0, ErrJournalClosed
	}
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
func (j *Journal) Stats() JournalStats { j.mu.Lock(); defer j.mu.Unlock(); return j.stats }

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
	j.sendMu.Lock()
	j.mu.Lock()
	if !j.closed {
		j.closed = true
		close(j.ops)
	}
	j.mu.Unlock()
	j.sendMu.Unlock()
	<-j.done
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.stats.LastError != "" {
		return errors.New(j.stats.LastError)
	}
	return nil
}
func (j *Journal) run() {
	defer close(j.done)
	defer func() {
		j.purgeMu.Lock()
		defer j.purgeMu.Unlock()
		if err := j.lock.Close(); err != nil {
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
			seq, err := j.prepareSequence(op.record.Data)
			var b []byte
			if err == nil {
				b, err = j.encode(op.record)
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
				state, err = j.encode(JournalRecord{ID: op.record.ID})
				if err == nil {
					err = j.writeFile(filepath.Join(j.cfg.Dir, ".state"), state)
				}
			}
			if err != nil && productWritten && !errors.Is(err, ErrPersistenceUncertain) {
				err = fmt.Errorf("%w: %w", ErrPersistenceUncertain, err)
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
				j.stats.LastError = err.Error()
				if errors.Is(err, ErrPersistenceUncertain) {
					j.stats.Uncertain++
				}
			}
			j.mu.Unlock()
			if op.callback != nil {
				op.callback(op.record.ID, err)
			}
		}
	}
}
func (j *Journal) checkpoint() {
	j.mu.Lock()
	ids := j.checkpoints
	j.checkpoints = nil
	j.mu.Unlock()
	for _, id := range ids {
		err := os.Remove(j.path(id))
		if err == nil {
			err = j.syncDir()
		}
		if err != nil {
			j.fault(fmt.Errorf("checkpoint journal: %w", err))
			continue
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
	stats := j.Stats()
	if stats.LastError != "" {
		return errors.New(stats.LastError)
	}
	return nil
}
func (j *Journal) fault(err error) {
	j.mu.Lock()
	j.stats.LastError = err.Error()
	j.mu.Unlock()
	logger.Error("X2 journal fault", "error", err)
}
func (j *Journal) encode(rec JournalRecord) ([]byte, error) {
	plain, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, j.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte("LCX2\x01"), nonce...)
	out = j.aead.Seal(out, nonce, plain, []byte("LCX2\x01"))
	out = binary.BigEndian.AppendUint32(out, crc32.ChecksumIEEE(out))
	return out, nil
}
func (j *Journal) decode(b []byte) (JournalRecord, error) {
	var rec JournalRecord
	n := j.aead.NonceSize()
	if len(b) < 5+n+j.aead.Overhead()+4 || string(b[:5]) != "LCX2\x01" {
		return rec, fmt.Errorf("invalid journal version or truncated record")
	}
	if crc32.ChecksumIEEE(b[:len(b)-4]) != binary.BigEndian.Uint32(b[len(b)-4:]) {
		return rec, fmt.Errorf("journal checksum mismatch")
	}
	plain, err := j.aead.Open(nil, b[5:5+n], b[5+n:len(b)-4], b[:5])
	if err != nil {
		return rec, fmt.Errorf("journal authentication: %w", err)
	}
	if err := json.Unmarshal(plain, &rec); err != nil {
		return rec, err
	}
	return rec, nil
}
func (j *Journal) write(id uint64, b []byte) error {
	return j.writeFile(j.path(id), b)
}
func (j *Journal) writePath(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create journal record: %w", err)
	}
	_, writeErr := f.Write(b)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("persist journal record: %w", writeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if err := j.syncDir(); err != nil {
		return fmt.Errorf("%w: %w", ErrPersistenceUncertain, err)
	}
	return nil
}
func (j *Journal) syncDir() error {
	f, err := os.Open(j.cfg.Dir)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

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
		data, err := os.ReadFile(j.path(id))
		if err != nil {
			return err
		}
		record, err := j.decode(data)
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
	err := os.Remove(j.path(id))
	if err == nil {
		err = j.syncDir()
	}
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

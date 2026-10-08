//go:build li

package li

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const (
	callCorrelationStoreObject    = "li-call-correlation/v1"
	maxCallCorrelationStoreBytes  = 32 << 20
	maxCallCorrelationRecordBytes = 128 << 10
	maxCallCorrelationStoredTasks = 1024
)

// StoredCallCorrelation is a retained decision, never an authorization grant.
// CommonTasks must be revalidated against live generations before extending a group.
type StoredCallCorrelation struct {
	CallID        string
	GroupID       uint64
	LastActivity  time.Time
	TerminalUntil time.Time
	CommonTasks   []CallCorrelationTask
}

// CallCorrelationStore exclusively owns a preinitialized authenticated snapshot.
// Its keyring must use dedicated fresh key material, independent of other stores.
// Uncertain writes fault the owner: close/reopen and reconcile before retrying.
type CallCorrelationStore struct {
	mu         sync.Mutex
	telemetry  securestore.Telemetry
	dir        *securestore.Dir
	lock       *securestore.Lock
	ring       *securestore.Keyring
	usage      *securestore.Usage
	writer     *securestore.Writer
	name       string
	path       string
	keys       securestore.KeyConfig
	id         uuid.UUID
	maxRecords int
	fault      error
	closed     bool
	write      func(string, []byte) (securestore.Outcome, error)
}

func validateCorrelationRecord(r StoredCallCorrelation) error {
	if r.CallID == "" || len(r.CallID) > 4096 || !utf8.ValidString(r.CallID) || strings.ContainsRune(r.CallID, 0) || r.LastActivity.IsZero() || len(r.CommonTasks) > maxCallCorrelationStoredTasks {
		return errors.New("invalid retained call correlation record")
	}
	seen := make(map[CallCorrelationTask]struct{}, len(r.CommonTasks))
	for _, task := range r.CommonTasks {
		if task.XID == uuid.Nil || task.Generation == 0 {
			return errors.New("invalid retained call correlation task")
		}
		if _, ok := seen[task]; ok {
			return errors.New("duplicate retained call correlation task")
		}
		seen[task] = struct{}{}
	}
	return nil
}

func correlationRecordLimit(maxRecords int) error {
	if maxRecords < 1 || maxRecords > 1_000_000 {
		return errors.New("invalid call correlation record limit")
	}
	return nil
}

// marshalCorrelationSnapshot uses a versioned header followed by bounded JSON
// records. Framing lets recovery reject record/count overflow before allocation.
func marshalCorrelationSnapshot(id uuid.UUID, records []StoredCallCorrelation, maxRecords int) ([]byte, error) {
	if id == uuid.Nil || len(records) > maxRecords {
		return nil, errors.New("invalid call correlation snapshot bounds")
	}
	var b bytes.Buffer
	b.WriteString(callCorrelationStoreObject + " " + id.String() + "\n")
	seen := make(map[string]struct{}, len(records))
	for _, r := range records {
		if err := validateCorrelationRecord(r); err != nil {
			return nil, err
		}
		if _, ok := seen[r.CallID]; ok {
			return nil, errors.New("duplicate call correlation decision")
		}
		seen[r.CallID] = struct{}{}
		raw, err := json.Marshal(r)
		if err != nil {
			return nil, fmt.Errorf("encode call correlation record: %w", err)
		}
		if len(raw) > maxCallCorrelationRecordBytes || b.Len()+len(raw)+1 > maxCallCorrelationStoreBytes {
			return nil, errors.New("call correlation snapshot byte limit exceeded")
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

func decodeCorrelationSnapshot(raw []byte, id uuid.UUID, maxRecords int, budget int64) ([]StoredCallCorrelation, error) {
	if len(raw) > maxCallCorrelationStoreBytes {
		return nil, errors.New("call correlation snapshot byte limit exceeded")
	}
	header, body, found := bytes.Cut(raw, []byte{'\n'})
	if !found || string(header) != callCorrelationStoreObject+" "+id.String() {
		return nil, securestore.ErrBinding
	}
	count := bytes.Count(body, []byte{'\n'})
	// Charge decoded strings, slices, map overhead and temporary record objects.
	if count > maxRecords || int64(len(raw))*12+int64(count)*256 > budget {
		return nil, errors.New("call correlation snapshot decode limit exceeded")
	}
	records := make([]StoredCallCorrelation, 0, count)
	seen := make(map[string]struct{}, count)
	for len(body) > 0 {
		line, rest, ok := bytes.Cut(body, []byte{'\n'})
		if !ok || len(line) == 0 || len(line) > maxCallCorrelationRecordBytes {
			return nil, errors.New("invalid call correlation record framing")
		}
		body = rest
		var r StoredCallCorrelation
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&r); err != nil {
			return nil, fmt.Errorf("decode call correlation record: %w", err)
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			return nil, errors.New("trailing call correlation record data")
		}
		if err := validateCorrelationRecord(r); err != nil {
			return nil, err
		}
		if _, ok := seen[r.CallID]; ok {
			return nil, errors.New("duplicate call correlation decision")
		}
		seen[r.CallID] = struct{}{}
		records = append(records, r)
	}
	return records, nil
}

func OpenCallCorrelationStore(path string, keys securestore.KeyConfig, maxRecords int) (store *CallCorrelationStore, result error) {
	if err := correlationRecordLimit(maxRecords); err != nil {
		return nil, err
	}
	parent, name, err := stateStorePath(path)
	if err != nil {
		return nil, err
	}
	ring, err := securestore.LoadKeyring(keys)
	if err != nil {
		return nil, err
	}
	dir, err := securestore.OpenDir(parent)
	if err != nil {
		return nil, err
	}
	keys.Prior = append([]securestore.KeyRef(nil), keys.Prior...)
	s := &CallCorrelationStore{dir: dir, ring: ring, name: name, path: path, keys: keys, maxRecords: maxRecords, write: dir.Replace}
	s.telemetry.Initialize("encrypted", ring)
	defer func() {
		if result != nil {
			result = errors.Join(result, s.Close())
		}
	}()
	s.lock, err = dir.Lock(name)
	if err != nil {
		return nil, err
	}
	identity, err := dir.FileIdentity(name)
	if err != nil {
		return nil, err
	}
	if ring.UsesFile(identity) || name == ring.UsageFileName() {
		return nil, errors.New("call correlation snapshot conflicts with key or usage storage")
	}
	s.usage, err = securestore.OpenUsage(dir, ring, [16]byte{})
	if err != nil {
		return nil, err
	}
	s.id = uuid.UUID(s.usage.StoreID())
	s.telemetry.BindUsage(s.usage)
	s.writer, err = securestore.NewWriter(s.usage)
	if err != nil {
		return nil, err
	}
	if _, err = s.load(); err != nil {
		return nil, err
	}
	s.telemetry.Ready()
	return s, nil
}

func (s *CallCorrelationStore) available() error {
	if s.closed {
		return os.ErrClosed
	}
	if s.fault != nil {
		return errors.Join(ErrStateStoreFault, s.fault)
	}
	return nil
}
func (s *CallCorrelationStore) load() ([]StoredCallCorrelation, error) {
	if err := s.available(); err != nil {
		return nil, err
	}
	raw, err := s.dir.Read(s.name, maxCallCorrelationStoreBytes+securestore.MaxHeaderBytes+18+int64(len(callCorrelationStoreObject))+16)
	if err != nil {
		return nil, err
	}
	plain, err := s.ring.Open(securestore.CallCorrelationState, securestore.Binding{Store: [16]byte(s.id), Object: callCorrelationStoreObject}, raw, maxCallCorrelationStoreBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return decodeCorrelationSnapshot(plain, s.id, s.maxRecords, 256<<20)
}
func (s *CallCorrelationStore) Load() ([]StoredCallCorrelation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.load()
	if err != nil && !s.closed {
		s.fault = err
		s.telemetry.Fault(err)
	}
	return records, err
}
func (s *CallCorrelationStore) Save(records []StoredCallCorrelation) (out securestore.Outcome, result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out = securestore.NotCommitted
	defer func() {
		s.telemetry.Record(out, result)
		if s.fault != nil {
			s.telemetry.Fault(s.fault)
		}
		if result != nil {
			result = &securestore.CommitError{Outcome: out, Op: "write call correlation snapshot", Err: result}
		}
	}()
	if err := s.available(); err != nil {
		return out, err
	}
	plain, err := marshalCorrelationSnapshot(s.id, records, s.maxRecords)
	if err != nil {
		return out, err
	}
	defer clear(plain)
	data, err := s.writer.Seal(securestore.CallCorrelationState, securestore.Binding{Store: [16]byte(s.id), Object: callCorrelationStoreObject}, plain)
	if err != nil {
		if errors.Is(err, securestore.ErrUsageFault) {
			s.fault = err
		}
		return out, err
	}
	out, err = s.write(s.name, data)
	if err == nil && out != securestore.Committed {
		err = errors.New("call correlation snapshot did not commit")
	}
	if out == securestore.Uncertain || securestore.OutcomeOf(err) == securestore.Uncertain {
		s.fault = err
	}
	return out, err
}
func (s *CallCorrelationStore) Close() (result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.telemetry.Closing()
	defer func() { s.telemetry.Closed(result) }()
	if s.usage != nil {
		result = errors.Join(result, s.usage.Close())
		s.usage = nil
		s.writer = nil
	}
	if s.lock != nil {
		result = errors.Join(result, s.lock.Close())
		s.lock = nil
	}
	if s.dir != nil {
		result = errors.Join(result, s.dir.Close())
		s.dir = nil
	}
	return result
}

// Reconcile reopens the existing authenticated snapshot and usage ledger after
// an uncertain write. It never initializes missing files or replaces corrupt
// state. The caller retains its desired decisions and may retry Save only after
// this succeeds; the recovered snapshot is not authoritative for published IDs.
func (s *CallCorrelationStore) Reconcile() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return os.ErrClosed
	}
	if s.fault == nil {
		return nil
	}
	var cleanup error
	if s.usage != nil {
		cleanup = errors.Join(cleanup, s.usage.Close())
		s.usage = nil
		s.writer = nil
	}
	if s.lock != nil {
		cleanup = errors.Join(cleanup, s.lock.Close())
		s.lock = nil
	}
	if s.dir != nil {
		cleanup = errors.Join(cleanup, s.dir.Close())
		s.dir = nil
	}
	if cleanup != nil {
		s.fault = errors.Join(s.fault, cleanup)
		s.telemetry.Fault(s.fault)
		return fmt.Errorf("close call correlation owner before reconciliation: %w", cleanup)
	}
	// Reopen only the retained configured path; provisioning remains explicit.
	reopened, err := OpenCallCorrelationStore(s.path, s.keys, s.maxRecords)
	if err != nil {
		s.fault = err
		s.telemetry.Fault(err)
		return fmt.Errorf("reopen authenticated call correlation storage: %w", err)
	}
	if reopened.id != s.id {
		err = errors.Join(securestore.ErrBinding, reopened.Close())
		s.fault = err
		s.telemetry.Fault(err)
		return err
	}
	s.dir, s.lock, s.ring, s.usage, s.writer = reopened.dir, reopened.lock, reopened.ring, reopened.usage, reopened.writer
	s.write = s.dir.Replace
	s.fault = nil
	s.telemetry.BindUsage(s.usage)
	s.telemetry.Ready()
	return nil
}

// Keyring returns the immutable loaded keyring for startup path/key independence
// validation. Callers must not format its key material in diagnostics.
func (s *CallCorrelationStore) Keyring() *securestore.Keyring {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ring
}

func (s *CallCorrelationStore) StoreID() uuid.UUID { s.mu.Lock(); defer s.mu.Unlock(); return s.id }
func (s *CallCorrelationStore) Fault() error       { s.mu.Lock(); defer s.mu.Unlock(); return s.fault }
func (s *CallCorrelationStore) StorageStatus() securestore.StorageStatus {
	return s.telemetry.Snapshot()
}

// InitializeCallCorrelationStore explicitly provisions an empty store. Never
// remove a ledger after partial failure or reuse its key with a fresh ledger.
func InitializeCallCorrelationStore(path string, keys securestore.KeyConfig, maxRecords int) (out securestore.Outcome, result error) {
	out = securestore.NotCommitted
	touched := false
	defer func() {
		if result != nil {
			if touched && out != securestore.Committed {
				out = securestore.Uncertain
			}
			result = &securestore.CommitError{Outcome: out, Op: "initialize call correlation snapshot", Err: result}
		}
	}()
	if err := correlationRecordLimit(maxRecords); err != nil {
		return out, err
	}
	parent, name, err := stateStorePath(path)
	if err != nil {
		return out, err
	}
	ring, err := securestore.LoadKeyring(keys)
	if err != nil {
		return out, err
	}
	dir, err := securestore.OpenDir(parent)
	if err != nil {
		return out, err
	}
	defer func() { result = errors.Join(result, dir.Close()) }()
	if name == ring.UsageFileName() {
		return out, errors.New("call correlation snapshot conflicts with usage storage")
	}
	lock, err := dir.Lock(name)
	if err != nil {
		return out, err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	if _, err := dir.FileIdentity(name); err == nil {
		return out, os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	id := uuid.New()
	usageOut, err := securestore.InitializeUsage(dir, ring, [16]byte(id))
	touched = usageOut != securestore.NotCommitted
	if err != nil {
		return out, err
	}
	usage, err := securestore.OpenUsage(dir, ring, [16]byte(id))
	if err != nil {
		return out, err
	}
	defer func() { result = errors.Join(result, usage.Close()) }()
	writer, err := securestore.NewWriter(usage)
	if err != nil {
		return out, err
	}
	plain, err := marshalCorrelationSnapshot(id, nil, maxRecords)
	if err != nil {
		return out, err
	}
	defer clear(plain)
	raw, err := writer.Seal(securestore.CallCorrelationState, securestore.Binding{Store: [16]byte(id), Object: callCorrelationStoreObject}, plain)
	if err != nil {
		return out, err
	}
	out, err = dir.Create(name, raw)
	if err == nil && out != securestore.Committed {
		err = errors.New("call correlation initialization did not commit")
	}
	return out, err
}

func RotateCallCorrelationStore(source, destination string, sourceKeys, newKeys securestore.KeyConfig, maxRecords int, options StateRotationOptions) (securestore.SnapshotRotationResult, error) {
	failed := securestore.SnapshotRotationResult{Outcome: securestore.NotCommitted, ExternalBackupsExcluded: true}
	if err := correlationRecordLimit(maxRecords); err != nil {
		return failed, err
	}
	oldRing, err := securestore.LoadKeyring(sourceKeys)
	if err != nil {
		return failed, err
	}
	newRing, err := securestore.LoadKeyring(newKeys)
	if err != nil {
		return failed, err
	}
	return securestore.RotateSnapshot(securestore.SnapshotRotationOptions{Source: source, Destination: destination, SourceKeys: oldRing, NewKeys: newRing, InPlace: options.InPlace, Resume: options.Resume, MaxWorkingBytes: options.MaxWorkingBytes}, securestore.SnapshotRotationOwner{Purpose: securestore.CallCorrelationState, Object: callCorrelationStoreObject, MaxPayloadBytes: maxCallCorrelationStoreBytes, Validate: func(raw []byte, store [16]byte, budget int64) (securestore.SnapshotValidation, error) {
		_, err := decodeCorrelationSnapshot(raw, uuid.UUID(store), maxRecords, budget)
		return securestore.SnapshotValidation{}, err
	}})
}

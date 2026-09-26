//go:build li

package li

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

const stateSnapshotObject = "administrative-state"
const maxStateEnvelopeBytes = MaxStateSnapshotBytes + securestore.MaxHeaderBytes + 18 + len(stateSnapshotObject) + 16

var ErrStateStoreFault = errors.New("LI state store is faulted; close and reconcile before reopening")

// EncryptedStateStore owns a preinitialized snapshot and its key-use ledger.
// It does not select candidates, reconcile filters, or grant admission.
type EncryptedStateStore struct {
	mu     sync.Mutex
	dir    *securestore.Dir
	lock   *securestore.Lock
	ring   *securestore.Keyring
	usage  *securestore.Usage
	writer *securestore.Writer
	name   string
	id     uuid.UUID
	fault  error
	closed bool
	write  func(string, []byte) (securestore.Outcome, error)
}

func stateStorePath(path string) (string, string, error) {
	if path == "" {
		return "", "", errors.New("LI state snapshot path is required")
	}
	parent, name := ".", path
	if slash := strings.LastIndexByte(path, '/'); slash >= 0 {
		parent, name = path[:slash], path[slash+1:]
		if parent == "" {
			parent = "/"
		}
	}
	if name == "" || name == "." || name == ".." {
		return "", "", errors.New("invalid LI state snapshot basename")
	}
	return parent, name, nil
}

// OpenStateStore validates the complete authenticated snapshot before returning.
// Missing state or usage never silently initializes an empty administrative state.
func OpenStateStore(path string, keys securestore.KeyConfig) (store *EncryptedStateStore, result error) {
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
	s := &EncryptedStateStore{dir: dir, ring: ring, name: name, write: dir.Replace}
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
		return nil, errors.New("LI state snapshot conflicts with key or usage storage")
	}
	s.usage, err = securestore.OpenUsage(dir, ring, [16]byte{})
	if err != nil {
		return nil, err
	}
	s.id = uuid.UUID(s.usage.StoreID())
	s.writer, err = securestore.NewWriter(s.usage)
	if err != nil {
		return nil, err
	}
	if _, err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *EncryptedStateStore) available() error {
	if s.closed {
		return os.ErrClosed
	}
	if s.fault != nil {
		return errors.Join(ErrStateStoreFault, s.fault)
	}
	return nil
}

func (s *EncryptedStateStore) load() (*StateSnapshot, error) {
	if err := s.available(); err != nil {
		return nil, err
	}
	data, err := s.dir.Read(s.name, int64(maxStateEnvelopeBytes))
	if err != nil {
		return nil, err
	}
	plain, err := s.ring.Open(securestore.AdministrativeState, securestore.Binding{Store: [16]byte(s.id), Object: stateSnapshotObject}, data, MaxStateSnapshotBytes)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	snapshot, err := UnmarshalStateSnapshot(plain)
	if err != nil {
		return nil, err
	}
	if snapshot.Incarnation != s.id {
		return nil, securestore.ErrBinding
	}
	return snapshot, nil
}

func (s *EncryptedStateStore) Load() (*StateSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, err := s.load()
	if err != nil && !s.closed {
		s.fault = err
	}
	return snapshot, err
}

func (s *EncryptedStateStore) Save(snapshot *StateSnapshot) (securestore.Outcome, error) {
	return s.save(snapshot, false)
}

// SaveControl explicitly selects reserved key capacity. Only the lifecycle owner
// can classify withdrawal or completion of already accepted operations as control.
func (s *EncryptedStateStore) SaveControl(snapshot *StateSnapshot) (securestore.Outcome, error) {
	return s.save(snapshot, true)
}

func (s *EncryptedStateStore) save(snapshot *StateSnapshot, control bool) (out securestore.Outcome, result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out = securestore.NotCommitted
	defer func() {
		if result != nil {
			result = &securestore.CommitError{Outcome: out, Op: "write LI state snapshot", Err: result}
		}
	}()
	if err := s.available(); err != nil {
		return out, err
	}
	if snapshot == nil || snapshot.Incarnation != s.id {
		return out, securestore.ErrBinding
	}
	plain, err := MarshalStateSnapshot(snapshot)
	if err != nil {
		return out, err
	}
	defer clear(plain)
	binding := securestore.Binding{Store: [16]byte(s.id), Object: stateSnapshotObject}
	var data []byte
	if control {
		data, err = s.writer.SealControl(securestore.AdministrativeState, binding, plain)
	} else {
		data, err = s.writer.Seal(securestore.AdministrativeState, binding, plain)
	}
	if err != nil {
		if errors.Is(err, securestore.ErrUsageFault) {
			s.fault = err
		}
		return out, err
	}
	out, err = s.write(s.name, data)
	if err == nil && out != securestore.Committed {
		err = errors.New("LI state snapshot did not commit")
	}
	if out == securestore.Uncertain || securestore.OutcomeOf(err) == securestore.Uncertain {
		s.fault = err
	}
	return out, err
}

func (s *EncryptedStateStore) StoreID() uuid.UUID { s.mu.Lock(); defer s.mu.Unlock(); return s.id }
func (s *EncryptedStateStore) Fault() error       { s.mu.Lock(); defer s.mu.Unlock(); return s.fault }

func (s *EncryptedStateStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var result error
	if s.usage != nil {
		result = s.usage.Close()
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

// InitStateStore is explicit fresh-store provisioning, not a resumable migration
// command. The caller supplies the new nonzero incarnation and complete snapshot.
// It refuses existing snapshots/ledgers. A partial initialization retains all
// artifacts and returns Uncertain for explicit offline reconciliation.
func InitStateStore(path string, keys securestore.KeyConfig, snapshot *StateSnapshot) (out securestore.Outcome, result error) {
	return initStateStore(path, keys, snapshot, func(dir *securestore.Dir, name string, data []byte) (securestore.Outcome, error) {
		return dir.Create(name, data)
	})
}

func initStateStore(path string, keys securestore.KeyConfig, snapshot *StateSnapshot, create func(*securestore.Dir, string, []byte) (securestore.Outcome, error)) (out securestore.Outcome, result error) {
	out = securestore.NotCommitted
	touched := false
	defer func() {
		if result != nil {
			if touched && out != securestore.Committed {
				out = securestore.Uncertain
			}
			result = &securestore.CommitError{Outcome: out, Op: "initialize LI state snapshot", Err: result}
		}
	}()
	plain, err := MarshalStateSnapshot(snapshot)
	if err != nil {
		return out, err
	}
	defer clear(plain)
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
		return out, errors.New("LI state snapshot conflicts with usage storage")
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
	usageOut, err := securestore.InitializeUsage(dir, ring, [16]byte(snapshot.Incarnation))
	touched = usageOut != securestore.NotCommitted
	if err != nil {
		return out, err
	}
	usage, err := securestore.OpenUsage(dir, ring, [16]byte(snapshot.Incarnation))
	if err != nil {
		return out, err
	}
	defer func() { result = errors.Join(result, usage.Close()) }()
	writer, err := securestore.NewWriter(usage)
	if err != nil {
		return out, err
	}
	data, err := writer.Seal(securestore.AdministrativeState, securestore.Binding{Store: [16]byte(snapshot.Incarnation), Object: stateSnapshotObject}, plain)
	if err != nil {
		return out, err
	}
	out, err = create(dir, name, data)
	if err == nil && out != securestore.Committed {
		err = fmt.Errorf("LI state initialization did not commit")
	}
	return out, err
}

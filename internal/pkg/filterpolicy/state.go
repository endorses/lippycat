package filterpolicy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

var ErrNotReady = errors.New("shared policy has not been reconciled")

// State owns one protected signed snapshot. The snapshot is also the persistent
// rollback watermark. It remains authoritative when local installation fails;
// recovery must reconcile it before any older policy can become ready.
type State struct {
	mu          sync.Mutex
	verifier    *Verifier
	dir         *securestore.Dir
	lock        *securestore.Lock
	name        string
	latest      *management.SignedPolicySnapshot
	ready       bool
	fault       error
	closed      bool
	encryption  *encryptedPolicyState
	subscribers map[chan *management.SignedPolicySnapshot]struct{}
}

func Open(c Config) (*State, error) {
	verifier, err := NewVerifier(c)
	if err != nil {
		return nil, err
	}
	c = verifier.config
	parent, name := ".", c.StateFile
	if slash := strings.LastIndexByte(c.StateFile, '/'); slash >= 0 {
		parent, name = c.StateFile[:slash], c.StateFile[slash+1:]
		if parent == "" {
			parent = "/"
		}
	}
	if name == "" || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid shared policy state path")
	}
	if c.StorageProtection == "private" {
		if err := securestore.EnsureDir(parent); err != nil {
			return nil, err
		}
	}
	dir, err := securestore.OpenDir(parent)
	if err != nil {
		return nil, err
	}
	lock, err := dir.Lock(name)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	state := &State{verifier: verifier, dir: dir, lock: lock, name: name, subscribers: make(map[chan *management.SignedPolicySnapshot]struct{})}
	encoded, err := state.readSnapshot(c)
	if c.StorageProtection == "private" && errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return nil, errors.Join(err, state.Close())
	}
	defer clear(encoded)
	if c.StorageProtection == "encrypted" && len(encoded) == 0 {
		return state, nil
	}
	snapshot := &management.SignedPolicySnapshot{}
	if err := proto.Unmarshal(encoded, snapshot); err != nil {
		return nil, errors.Join(ErrInvalid, state.Close())
	}
	if err := verifier.Verify(snapshot); err != nil {
		return nil, errors.Join(err, state.Close())
	}
	state.latest = snapshot
	return state, nil
}

func (s *State) Verifier() *Verifier { return s.verifier }
func cloneSnapshot(snapshot *management.SignedPolicySnapshot) *management.SignedPolicySnapshot {
	if snapshot == nil {
		return nil
	}
	return proto.Clone(snapshot).(*management.SignedPolicySnapshot)
}

// Latest is durable desired state, which may still require installation after
// restart. Network handlers must use Snapshot, which requires readiness.
func (s *State) Latest() *management.SignedPolicySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneSnapshot(s.latest)
}
func (s *State) HasSnapshot() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.latest != nil }

func (s *State) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ready && s.fault == nil && !s.closed
}
func (s *State) Snapshot() (*management.SignedPolicySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	if s.fault != nil {
		return nil, s.fault
	}
	if !s.ready {
		return nil, ErrNotReady
	}
	return cloneSnapshot(s.latest), nil
}

func (s *State) check(snapshot *management.SignedPolicySnapshot) error {
	if s.closed {
		return os.ErrClosed
	}
	if s.fault != nil {
		return s.fault
	}
	if err := s.verifier.Verify(snapshot); err != nil {
		return err
	}
	if s.latest != nil {
		if snapshot.Snapshot.Revision < s.latest.Snapshot.Revision {
			return ErrRollback
		}
		if snapshot.Snapshot.Revision == s.latest.Snapshot.Revision && !proto.Equal(snapshot.Snapshot, s.latest.Snapshot) {
			return ErrRollback
		}
	}
	return nil
}
func (s *State) Check(snapshot *management.SignedPolicySnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.check(snapshot)
}

// Accept persists the complete authenticated replacement before publication.
// apply runs under State ordering and must not call back into State. Failure
// leaves readiness false; retrying the same durable revision can reconcile it.
func (s *State) Accept(snapshot *management.SignedPolicySnapshot, apply func(*management.PolicySnapshot) error) error {
	if snapshot == nil || proto.Size(snapshot) > MaxSnapshotBytes {
		return ErrInvalid
	}
	snapshot = cloneSnapshot(snapshot)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.check(snapshot); err != nil {
		return err
	}
	same := s.latest != nil && snapshot.Snapshot.Revision == s.latest.Snapshot.Revision
	if same && s.ready {
		return nil
	}
	var saveErr error
	if !same {
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(snapshot)
		if err != nil {
			return err
		}
		outcome, err := s.writeSnapshot(encoded, snapshot)
		clear(encoded)
		if outcome == securestore.Uncertain {
			s.fault = errors.Join(ErrNotReady, err)
			s.ready = false
			return &securestore.CommitError{Outcome: outcome, Op: "save shared policy", Err: s.fault}
		}
		if outcome != securestore.Committed {
			return err
		}
		saveErr = err
		s.latest = snapshot
	}
	s.ready = false
	if apply != nil {
		if err := apply(proto.Clone(snapshot.Snapshot).(*management.PolicySnapshot)); err != nil {
			return &securestore.CommitError{Outcome: securestore.Committed, Op: "install shared policy", Err: errors.Join(ErrNotReady, saveErr, err)}
		}
	}
	s.ready = true
	for channel := range s.subscribers {
		// Full replacements allow safe coalescing. A slow subscriber always sees
		// the latest complete state rather than an incomplete delta sequence.
		select {
		case <-channel:
		default:
		}
		channel <- cloneSnapshot(s.latest)
	}
	if saveErr != nil {
		return &securestore.CommitError{Outcome: securestore.Committed, Op: "save shared policy", Err: saveErr}
	}
	return nil
}

func (s *State) Subscribe() (chan *management.SignedPolicySnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, os.ErrClosed
	}
	if s.fault != nil {
		return nil, s.fault
	}
	channel := make(chan *management.SignedPolicySnapshot, 1)
	if s.ready {
		channel <- cloneSnapshot(s.latest)
	}
	s.subscribers[channel] = struct{}{}
	return channel, nil
}
func (s *State) Unsubscribe(channel chan *management.SignedPolicySnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.subscribers[channel]; ok {
		delete(s.subscribers, channel)
		close(channel)
	}
}
func (s *State) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for channel := range s.subscribers {
		close(channel)
		delete(s.subscribers, channel)
	}
	var cryptoErr error
	if s.encryption != nil && s.encryption.usage != nil {
		cryptoErr = s.encryption.usage.Close()
	}
	return errors.Join(cryptoErr, s.lock.Close(), s.dir.Close())
}

// Keyring exposes immutable loaded storage references for independent-key checks.
// It has no raw-key export or mutator and must never be logged.
func (s *State) Keyring() *securestore.Keyring {
	if s.encryption == nil {
		return nil
	}
	return s.encryption.keys
}

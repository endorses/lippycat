//go:build li

package li

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radius"
)

// RADIUSCorrelationConfig configures one authoritative allocator. Encoders with
// the same NFID/IPID must use the same shared, flock-capable state path. Deleting
// this state requires provisioning a new NFID/IPID identity.
type RADIUSCorrelationConfig struct {
	Path, NFID, IPID     string
	RequestLifetime      time.Duration
	MaxEntries, MaxBytes int
	Now                  func() time.Time
}

type radiusCorrelationKey struct {
	Scope       radius.CaptureScope
	ID          radius.Identity
	Observation bool
}
type radiusCorrelationEntry struct {
	value    uint64
	deadline time.Time
	cost     int
}
type radiusCorrelationState struct {
	NFID, IPID string
	Reserved   uint64
}

var radiusAllocatorIdentities = struct {
	sync.Mutex
	active map[[2]string]bool
}{active: make(map[[2]string]bool)}

// RADIUSCorrelationAllocator reserves durable counter ranges before issuing IDs.
// Its bounded map retains allocations across task XIDs, never across restarts.
// A capacity failure preserves existing entries instead of evicting live IDs.
type RADIUSCorrelationAllocator struct {
	mu             sync.Mutex
	config         RADIUSCorrelationConfig
	lock           *os.File
	next, reserved uint64
	entries        map[radiusCorrelationKey]radiusCorrelationEntry
	bytes          int
	failed         error
	closed         bool
	nextCleanup    time.Time
}

func NewRADIUSCorrelationAllocator(c RADIUSCorrelationConfig) (*RADIUSCorrelationAllocator, error) {
	if c.Path == "" || c.NFID == "" || c.IPID == "" {
		return nil, fmt.Errorf("RADIUS correlation requires persistent state path and explicit NFID/IPID")
	}
	if c.RequestLifetime == 0 {
		c.RequestLifetime = 30 * time.Second
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = 65536
	}
	if c.MaxBytes == 0 {
		c.MaxBytes = 16 << 20
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.RequestLifetime < time.Second || c.RequestLifetime > 300*time.Second || c.MaxEntries < 1 || c.MaxEntries > 1048576 || c.MaxBytes < 1<<20 || c.MaxBytes > 256<<20 {
		return nil, fmt.Errorf("invalid RADIUS correlation bounds")
	}
	identity := [2]string{c.NFID, c.IPID}
	radiusAllocatorIdentities.Lock()
	defer radiusAllocatorIdentities.Unlock()
	if radiusAllocatorIdentities.active[identity] {
		return nil, fmt.Errorf("RADIUS NFID/IPID already has an active allocator")
	}
	lock, err := os.OpenFile(c.Path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open RADIUS correlation lock: %w", err)
	}
	fail := func(err error) (*RADIUSCorrelationAllocator, error) { return nil, errors.Join(err, lock.Close()) }
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("lock RADIUS correlation state: %w", err))
	}
	a := &RADIUSCorrelationAllocator{config: c, lock: lock, entries: make(map[radiusCorrelationKey]radiusCorrelationEntry)}
	raw, err := os.ReadFile(c.Path)
	if err == nil {
		var state radiusCorrelationState
		if err := json.Unmarshal(raw, &state); err != nil {
			return fail(fmt.Errorf("decode RADIUS correlation state: %w", err))
		}
		if state.NFID != c.NFID || state.IPID != c.IPID || state.Reserved == 0 {
			return fail(fmt.Errorf("RADIUS correlation state identity or reservation invalid"))
		}
		a.reserved = state.Reserved
	} else if !os.IsNotExist(err) {
		return fail(fmt.Errorf("read RADIUS correlation state: %w", err))
	}
	a.next = a.reserved
	if err := a.reserve(); err != nil {
		return fail(err)
	}
	radiusAllocatorIdentities.active[identity] = true
	return a, nil
}

// reserve atomically replaces and syncs state, including its directory, before
// any reserved value becomes visible. An uncertain write poisons this allocator.
func (a *RADIUSCorrelationAllocator) reserve() error {
	if a.reserved == math.MaxUint64 {
		return fmt.Errorf("RADIUS correlation counter exhausted")
	}
	end := a.reserved + 1<<20
	if end < a.reserved {
		end = math.MaxUint64
	}
	raw, err := json.Marshal(radiusCorrelationState{NFID: a.config.NFID, IPID: a.config.IPID, Reserved: end})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(a.config.Path), ".radius-correlation-*")
	if err != nil {
		return fmt.Errorf("create RADIUS correlation reservation: %w", err)
	}
	name := f.Name()
	_, writeErr := f.Write(raw)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	err = errors.Join(writeErr, f.Close())
	if err == nil {
		err = os.Rename(name, a.config.Path)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("persist RADIUS correlation reservation: %w", err), os.Remove(name))
	}
	dir, err := os.Open(filepath.Dir(a.config.Path))
	if err != nil {
		return fmt.Errorf("open correlation state directory: %w", err)
	}
	if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
		return fmt.Errorf("sync correlation state directory: %w", err)
	}
	a.reserved = end
	return nil
}

// Allocate receives an already admitted observation. Exchange deadlines use
// request first-seen time, not arrival at this encoder. Orphans have independent
// observation keys so matching multiple tasks still shares one correlation ID.
func (a *RADIUSCorrelationAllocator) Allocate(o *radius.Observation) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return 0, fmt.Errorf("RADIUS correlation allocator closed")
	}
	if a.failed != nil {
		return 0, a.failed
	}
	if o == nil || o.Message == nil || o.Scope.Epoch == [16]byte{} || o.Capture.ID.Epoch != o.Scope.Epoch || o.Capture.ID.Sequence == 0 {
		return 0, fmt.Errorf("invalid RADIUS correlation observation")
	}
	now := a.config.Now()
	key := radiusCorrelationKey{Scope: o.Scope, ID: o.Capture.ID, Observation: true}
	first := o.Capture.Timestamp
	if o.Association.Status == radius.AssociationRequest || o.Association.Status == radius.AssociationUnique {
		key.ID = o.Association.RequestInstanceID
		key.Observation = false
		first = o.Association.RequestFirstSeen
		if key.ID.Epoch != o.Scope.Epoch || key.ID.Sequence == 0 {
			return 0, fmt.Errorf("invalid RADIUS request instance")
		}
	}
	deadline := first.Add(a.config.RequestLifetime)
	if first.IsZero() || !now.Before(deadline) {
		return 0, fmt.Errorf("RADIUS correlation observation expired")
	}
	// Cleanup is bounded to one sweep per second, independent of packet rate.
	// Expired observations are already rejected above, even between sweeps.
	if !now.Before(a.nextCleanup) {
		for k, v := range a.entries {
			if !now.Before(v.deadline) {
				delete(a.entries, k)
				a.bytes -= v.cost
			}
		}
		a.nextCleanup = now.Add(time.Second)
	}
	if v, ok := a.entries[key]; ok {
		if !v.deadline.Equal(deadline) {
			return 0, fmt.Errorf("inconsistent RADIUS request lifetime")
		}
		return v.value, nil
	}
	// Charge fixed map/key/value overhead and all retained string backing bytes.
	cost := 256 + len(key.Scope.OriginNodeID) + len(key.Scope.SourceID) + len(key.Scope.OperatorScope) + len(key.Scope.ProfileRevision)
	if len(a.entries) >= a.config.MaxEntries || cost > a.config.MaxBytes-a.bytes {
		return 0, fmt.Errorf("RADIUS correlation map capacity reached")
	}
	if a.next == a.reserved {
		if err := a.reserve(); err != nil {
			a.failed = err
			return 0, err
		}
	}
	a.next++
	key.Scope.OriginNodeID = strings.Clone(key.Scope.OriginNodeID)
	key.Scope.SourceID = strings.Clone(key.Scope.SourceID)
	key.Scope.OperatorScope = strings.Clone(key.Scope.OperatorScope)
	key.Scope.ProfileRevision = strings.Clone(key.Scope.ProfileRevision)
	a.entries[key] = radiusCorrelationEntry{value: a.next, deadline: deadline, cost: cost}
	a.bytes += cost
	return a.next, nil
}

func (a *RADIUSCorrelationAllocator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	err := a.lock.Close()
	radiusAllocatorIdentities.Lock()
	delete(radiusAllocatorIdentities.active, [2]string{a.config.NFID, a.config.IPID})
	radiusAllocatorIdentities.Unlock()
	clear(a.entries)
	a.bytes = 0
	return err
}

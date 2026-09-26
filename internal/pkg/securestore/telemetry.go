package securestore

import (
	"errors"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
)

// PublicFaultCode returns only fixed categories, never wrapped error text,
// paths, keys, object identities or caller-controlled data.
func PublicFaultCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrKeyExhausted):
		return "key_exhausted"
	case errors.Is(err, ErrUsageFault):
		return "usage_ledger_fault"
	case errors.Is(err, ErrAuthentication):
		return "authentication_failed"
	case errors.Is(err, ErrBinding):
		return "identity_mismatch"
	case errors.Is(err, ErrEnvelope):
		return "invalid_envelope"
	case errors.Is(err, ErrLocked):
		return "ownership_conflict"
	case errors.Is(err, os.ErrClosed):
		return "closed"
	case errors.Is(err, os.ErrNotExist):
		return "required_file_missing"
	case errors.Is(err, os.ErrPermission):
		return "permission_denied"
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return "capacity_exhausted"
	default:
		return "storage_error"
	}
}

func OutcomeName(out Outcome) string {
	switch out {
	case Committed:
		return "committed"
	case Uncertain:
		return "uncertain"
	default:
		return "not_committed"
	}
}

// KeyIDs is detached public metadata from the actual immutable loaded ring.
// IDs are bounded operator labels; no paths, file identities or key fingerprints
// are included. Prior excludes active, including when it is also the legacy key.
func (r *Keyring) KeyIDs() (active string, prior []string) {
	if r == nil {
		return "", nil
	}
	for id := range r.keys {
		if id != r.active.id {
			prior = append(prior, id)
		}
	}
	sort.Strings(prior)
	return r.active.id, prior
}

// StorageStatus describes the owner, not an API request. Mutation counters are
// Save calls for snapshots and product+checkpoint transactions for X2. Counters
// reset with the owner. Mode/state/outcomes/faults are fixed public vocabulary.
type StorageStatus struct {
	Mode, State, FaultCode, LastErrorCode, LastOutcome    string
	PolicyFaultCode                                       string
	AdmissionBlocked                                      bool
	Commits, DefiniteFailures, Uncertain, CleanupWarnings uint64
	ActiveKeyID                                           string
	PriorKeyIDs                                           []string
	Usage                                                 *UsageStats
}

// Telemetry publishes small immutable views. Its private writer mutex is never
// held over owner I/O; Snapshot never acquires a mutex or calls the filesystem.
// An owner must not copy Telemetry after first use.
type Telemetry struct {
	mu    sync.Mutex
	view  atomic.Pointer[StorageStatus]
	usage atomic.Pointer[Usage]
}

func (t *Telemetry) update(fn func(*StorageStatus)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := StorageStatus{State: "unopened"}
	if old := t.view.Load(); old != nil {
		v = *old
	}
	fn(&v)
	t.view.Store(&v)
}

func (t *Telemetry) Initialize(mode string, ring *Keyring) {
	active, prior := ring.KeyIDs()
	t.update(func(v *StorageStatus) { v.Mode, v.ActiveKeyID, v.PriorKeyIDs = mode, active, prior })
}

func (t *Telemetry) BindUsage(u *Usage) { t.usage.Store(u) }
func (t *Telemetry) Ready() {
	t.update(func(v *StorageStatus) {
		if v.State != "closing" && v.State != "closed" {
			v.State, v.FaultCode = "ready", ""
		}
	})
}
func (t *Telemetry) Closing() {
	t.update(func(v *StorageStatus) {
		if v.State != "closed" {
			v.State = "closing"
		}
	})
}
func (t *Telemetry) Closed(err error) {
	t.update(func(v *StorageStatus) {
		v.State = "closed"
		if err != nil {
			v.FaultCode = PublicFaultCode(err)
		}
	})
}
func (t *Telemetry) Fault(err error) {
	if err == nil {
		return
	}
	t.update(func(v *StorageStatus) {
		if v.State != "closed" && v.State != "closing" {
			v.State = "faulted"
		}
		if v.FaultCode == "" {
			v.FaultCode = PublicFaultCode(err)
		}
	})
}

func (t *Telemetry) Record(out Outcome, err error) {
	t.update(func(v *StorageStatus) {
		v.LastOutcome, v.LastErrorCode = OutcomeName(out), PublicFaultCode(err)
		switch out {
		case Committed:
			v.Commits++
			if err != nil {
				v.CleanupWarnings++
			}
		case Uncertain:
			v.Uncertain++
		default:
			v.DefiniteFailures++
		}
	})
}

func (t *Telemetry) Snapshot() StorageStatus {
	v := StorageStatus{Mode: "disabled", State: "unopened"}
	if p := t.view.Load(); p != nil {
		v = *p
	}
	v.PriorKeyIDs = append([]string(nil), v.PriorKeyIDs...)
	if u := t.usage.Load(); u != nil {
		stats := u.Stats()
		v.Usage = &stats
	}
	return v
}

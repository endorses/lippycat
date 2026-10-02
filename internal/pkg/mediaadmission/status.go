package mediaadmission

import (
	"sync"
	"time"
)

// StatusProvider exposes snapshots without capture/transport dependencies.
type StatusProvider interface{ Status() Snapshot }
type Snapshot struct {
	Enabled          bool
	ConfiguredMode   Mode
	FailurePolicy    FailurePolicy
	EndpointCapacity int
	Scopes           []ScopeTelemetry
	Metadata         MetadataStats
	Evidence         EvidenceStats
	Media            MediaDiagnostics
}
type ScopeTelemetry struct {
	ScopeStatus
	Counters          [16]uint64
	CounterReadFailed bool
}
type EvidenceStats struct {
	Received, Overwritten, Malformed, ReadErrors uint64
	Retained, Capacity                           int
	Incomplete                                   bool
}
type MediaDiagnostics struct {
	Tracked, SelectedAnsweredWithoutMedia int
	AttributedPackets, TrackingRejected   uint64
}

// ShadowSample is opt-in diagnostic evidence; ordinary Snapshot omits endpoints,
// fingerprints and per-call identifiers. Hash collisions and lost samples prevent
// interpreting this as exact packet identity.
type ShadowSample struct {
	Domain                                            DomainID
	Generation, EventMonotonicNS, ObservedMonotonicNS uint64
	ObservedAt                                        time.Time
	Reason, Length, Fingerprint                       uint32
	Source, Destination                               EndpointKey
}
type diagnosticCall struct {
	domain                       DomainID
	answered, active, attributed bool
	selectedAt                   time.Time
}
type Diagnostics struct {
	mu                   sync.Mutex
	capacity             int
	interval             time.Duration
	calls                map[OwnerID]diagnosticCall
	attributed, rejected uint64
}

func NewDiagnostics(capacity int, interval time.Duration) *Diagnostics {
	return &Diagnostics{capacity: capacity, interval: interval, calls: make(map[OwnerID]diagnosticCall)}
}
func (d *Diagnostics) Selection(owner OwnerID, domain DomainID, answered, active bool, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, exists := d.calls[owner]
	if !exists {
		if len(d.calls) >= d.capacity {
			d.rejected++
			return
		}
		v.selectedAt = at
	}
	if answered && active && (!v.answered || !v.active) {
		v.selectedAt = at
	}
	v.domain = domain
	v.answered = answered
	v.active = active
	d.calls[owner] = v
}
func (d *Diagnostics) Attributed(owner OwnerID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.attributed++
	if v, ok := d.calls[owner]; ok {
		v.attributed = true
		d.calls[owner] = v
	}
}
func (d *Diagnostics) Finalized(owner OwnerID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.calls, owner)
}
func (d *Diagnostics) Snapshot(now time.Time) MediaDiagnostics {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := MediaDiagnostics{Tracked: len(d.calls), AttributedPackets: d.attributed, TrackingRejected: d.rejected}
	for _, v := range d.calls {
		if v.answered && v.active && !v.attributed && now.Sub(v.selectedAt) >= d.interval {
			s.SelectedAnsweredWithoutMedia++
		}
	}
	return s
}

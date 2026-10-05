package mediaadmission

import (
	"sync"
	"sync/atomic"
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
	Shadow           ShadowStats
	Media            MediaDiagnostics
}
type ScopeTelemetry struct {
	ScopeStatus
	Counters          [16]uint64
	CounterReadFailed bool
}
type EvidenceStats struct {
	Received, Overwritten, Malformed, ReadErrors uint64
	KernelLost                                   uint64
	ClockReadErrors                              uint64
	SampleEvery                                  uint32
	Retained, Capacity                           int
	Incomplete                                   bool
}
type MediaDiagnostics struct {
	Tracked, SelectedAnsweredWithoutMedia int
	UnknownExpectation, InactiveSelected  int
	AttributedPackets, TrackingRejected   uint64
	Alerts                                uint64
	AttributionDropped                    uint64
	ObservationUncertain                  int
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
	IdentityLength                                    uint32
	Identity                                          [256]byte
	SampleEvery                                       uint32
}
type diagnosticCall struct {
	domain                       DomainID
	answered, active, attributed bool
	selectedAt                   time.Time
	known                        bool
	revision, reference          uint64
	lastAlert                    time.Time
	observationEpoch             uint64
}
type Diagnostics struct {
	mu                    sync.Mutex
	capacity              int
	interval              time.Duration
	calls                 map[OwnerID]diagnosticCall
	attributed, rejected  uint64
	nextReference, alerts uint64
	attributionDropped    atomic.Uint64
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
		d.nextReference++
		v.reference = d.nextReference
		v.known = true
		v.observationEpoch = d.attributionDropped.Load()
	}
	if answered && active && (!v.answered || !v.active) {
		v.selectedAt = at
	}
	v.domain = domain
	v.answered = answered
	v.active = active
	d.calls[owner] = v
}

// Expectation resets missing-media evidence when accepted endpoints or their
// completeness changes. Unknown derivation is distinct from inactive media.
func (d *Diagnostics) Expectation(owner OwnerID, domain DomainID, known, active bool, revision uint64, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, exists := d.calls[owner]
	if !exists {
		return
	}
	if v.revision != revision || v.known != known || v.active != active {
		v.attributed = false
		v.selectedAt = at
		v.lastAlert = time.Time{}
		v.observationEpoch = d.attributionDropped.Load()
	}
	v.domain, v.known, v.active, v.revision = domain, known, active, revision
	d.calls[owner] = v
}

type MissingMediaAlert struct {
	Reference uint64
	Domain    DomainID
}

// MissingAlerts emits at most eight notices per poll and one per owner per
// configured interval. References are transient counters, never signaling IDs.
func (d *Diagnostics) MissingAlerts(now time.Time) []MissingMediaAlert {
	d.mu.Lock()
	defer d.mu.Unlock()
	var alerts []MissingMediaAlert
	for owner, v := range d.calls {
		if len(alerts) == 8 {
			break
		}
		if v.observationEpoch == d.attributionDropped.Load() && v.known && v.answered && v.active && !v.attributed && now.Sub(v.selectedAt) >= d.interval && (v.lastAlert.IsZero() || now.Sub(v.lastAlert) >= d.interval) {
			alerts = append(alerts, MissingMediaAlert{Reference: v.reference, Domain: v.domain})
			v.lastAlert = now
			d.calls[owner] = v
			d.alerts++
		}
	}
	return alerts
}
func (d *Diagnostics) Attributed(owner OwnerID) {
	if !d.mu.TryLock() {
		d.attributionDropped.Add(1)
		return
	}
	defer d.mu.Unlock()
	d.attributed++
	if v, ok := d.calls[owner]; ok {
		v.attributed = true
		v.observationEpoch = d.attributionDropped.Load()
		d.calls[owner] = v
	}
}
func (d *Diagnostics) Finalized(owner OwnerID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.calls, owner)
}

// AttributionUnavailable records evidence lost before an owner could be
// verified, without waiting for diagnostic maintenance.
func (d *Diagnostics) AttributionUnavailable() { d.attributionDropped.Add(1) }
func (d *Diagnostics) Snapshot(now time.Time) MediaDiagnostics {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := MediaDiagnostics{Tracked: len(d.calls), AttributedPackets: d.attributed, TrackingRejected: d.rejected, Alerts: d.alerts, AttributionDropped: d.attributionDropped.Load()}
	for _, v := range d.calls {
		if !v.known {
			s.UnknownExpectation++
		} else if !v.active {
			s.InactiveSelected++
		}
		if v.observationEpoch != d.attributionDropped.Load() {
			s.ObservationUncertain++
		}
		if v.observationEpoch == d.attributionDropped.Load() && v.known && v.answered && v.active && !v.attributed && now.Sub(v.selectedAt) >= d.interval {
			s.SelectedAnsweredWithoutMedia++
		}
	}
	return s
}

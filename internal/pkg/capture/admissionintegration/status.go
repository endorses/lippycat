package admissionintegration

import (
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"sync"
	"time"
)

type sessionTelemetry struct {
	mu                  sync.Mutex
	counters            func(mediaadmission.DomainID) ([16]uint64, error)
	stop                func() error
	done                chan struct{}
	samples             []mediaadmission.ShadowSample
	next                int
	evidence            mediaadmission.EvidenceStats
	diagnostics         *mediaadmission.Diagnostics
	correlator          *mediaadmission.ShadowCorrelator
	kernelLost          uint64
	clockErrorsBaseline uint64
	last                map[mediaadmission.DomainID]mediaadmission.State
}

func (s *Session) Status() mediaadmission.Snapshot {
	if s == nil {
		return mediaadmission.Snapshot{}
	}
	result := mediaadmission.Snapshot{Enabled: s.Config.Enabled, ConfiguredMode: s.Config.Mode, FailurePolicy: s.Config.FailurePolicy, EndpointCapacity: s.Config.EndpointCapacity}
	if s.Controller != nil {
		for _, scope := range s.Controller.Status() {
			if scope.Reason != "" {
				scope.Reason = "admission synchronization failed"
			}
			t := mediaadmission.ScopeTelemetry{ScopeStatus: scope}
			if s.telemetry != nil && s.telemetry.counters != nil {
				var err error
				t.Counters, err = s.telemetry.counters(scope.Domain)
				t.CounterReadFailed = err != nil
			}
			result.Scopes = append(result.Scopes, t)
		}
	} else {
		result.Scopes = []mediaadmission.ScopeTelemetry{{ScopeStatus: mediaadmission.ScopeStatus{State: mediaadmission.StateDisabled}}}
	}
	if s.Metadata != nil {
		result.Metadata = s.Metadata.Stats()
	}
	if s.telemetry != nil {
		s.telemetry.mu.Lock()
		result.Evidence = s.telemetry.evidence
		s.telemetry.mu.Unlock()
		result.Media = s.telemetry.diagnostics.Snapshot(time.Now())
		result.Evidence.ClockReadErrors = monotonicReadErrors() - s.telemetry.clockErrorsBaseline
		if result.Evidence.ClockReadErrors != 0 {
			result.Evidence.Incomplete = true
		}
		if s.telemetry.correlator != nil {
			result.Shadow = s.telemetry.correlator.Snapshot()
			if result.Shadow.Incomplete != 0 {
				result.Evidence.Incomplete = true
			}
		}
	}
	for _, scope := range result.Scopes {
		if scope.CounterReadFailed {
			result.Evidence.Incomplete = true
		}
		if scope.Counters[11] > 0 {
			result.Evidence.Incomplete = true
		}
		result.Evidence.KernelLost += scope.Counters[11]
	}
	return result
}
func (s *Session) ShadowEvidence() []mediaadmission.ShadowSample {
	if s.telemetry == nil {
		return nil
	}
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()
	n := len(s.telemetry.samples)
	out := make([]mediaadmission.ShadowSample, 0, n)
	if n < s.Config.ShadowEvidenceCapacity {
		return append(out, s.telemetry.samples...)
	}
	out = append(out, s.telemetry.samples[s.telemetry.next:]...)
	return append(out, s.telemetry.samples[:s.telemetry.next]...)
}
func (s *Session) RecordSelection(owner mediaadmission.OwnerID, domain mediaadmission.DomainID, answered, active bool, at time.Time) {
	if s.telemetry != nil {
		s.telemetry.diagnostics.Selection(owner, domain, answered, active, at)
		if s.telemetry.correlator != nil {
			s.telemetry.correlator.Selection(owner, domain, monotonicTime(at))
		}
	}
}

func (s *Session) RecordSelectionLifetime(owner mediaadmission.OwnerID, domain mediaadmission.DomainID, createdAt, selectedAt time.Time) {
	if s.telemetry != nil && s.telemetry.correlator != nil {
		// The lifetime hook can precede the compatibility selection hook.
		// Selection retains its first monotonic conversion without renewal.
		s.telemetry.correlator.Selection(owner, domain, monotonicTime(selectedAt))
		s.telemetry.correlator.RecordLifetimeStart(owner, domain, monotonicTime(createdAt))
	}
}

// RecordMediaExpectation is called after the owner's endpoint update. A
// confirmed scope snapshot supplies only a conservative publication upper
// bound; it never invents historical packet identity from current maps.
func (s *Session) RecordMediaExpectation(owner mediaadmission.OwnerID, domain mediaadmission.DomainID, known, active bool, revision uint64, at time.Time) {
	if s.telemetry == nil {
		return
	}
	s.telemetry.diagnostics.Expectation(owner, domain, known, active, revision, at)
	if s.telemetry.correlator == nil {
		return
	}
	var published, generation uint64
	if known && active && s.Controller != nil {
		for _, scope := range s.Controller.Status() {
			if scope.Domain == domain && scope.State == mediaadmission.StateShadow && !scope.ControlUncertain && scope.PendingUpdates == 0 && scope.InstalledGeneration == scope.DesiredGeneration {
				published, generation = monotonicNow(), scope.LastConfirmed.Generation
			}
		}
	}
	s.telemetry.correlator.Expectation(owner, domain, known, active, revision, published, generation)
}

// RecordObservedPacket runs once after managed capture activation and before
// decoding. Full bounded bytes remain transient; status exposes counts only.
func (s *Session) RecordObservedPacket(domain mediaadmission.DomainID, frame []byte) {
	if s.telemetry != nil && s.telemetry.correlator != nil {
		s.telemetry.correlator.Observed(domain, frame, monotonicNow())
	}
}

// RecordAttributedPacket requires the adapter to verify current exact endpoint
// attribution to this selected owner lifetime before calling it.
func (s *Session) RecordAttributedPacket(owner mediaadmission.OwnerID, domain mediaadmission.DomainID, frame []byte) {
	if s.telemetry != nil && s.telemetry.correlator != nil {
		s.telemetry.correlator.Attributed(owner, domain, frame, monotonicNow())
	}
}

// RecordAttributionUnavailable is a nonblocking diagnostic fallback when the
// adapter cannot verify an owner without waiting for lifecycle reconciliation.
func (s *Session) RecordAttributionUnavailable() {
	if s.telemetry == nil {
		return
	}
	s.telemetry.diagnostics.AttributionUnavailable()
	if s.telemetry.correlator != nil {
		s.telemetry.correlator.EvidenceLost(monotonicNow())
	}
}
func (s *Session) RecordAttributedMedia(owner mediaadmission.OwnerID) {
	if s.telemetry != nil {
		s.telemetry.diagnostics.Attributed(owner)
	}
}
func (s *Session) RecordFinalized(owner mediaadmission.OwnerID) {
	if s.telemetry != nil {
		s.telemetry.diagnostics.Finalized(owner)
		if s.telemetry.correlator != nil {
			s.telemetry.correlator.Finalized(owner, monotonicNow())
		}
	}
}

func (s *Session) maintainTelemetry() {
	if s.telemetry == nil {
		return
	}
	if s.telemetry.correlator != nil {
		var lost uint64
		if s.telemetry.counters != nil {
			for _, domain := range s.Config.Domains() {
				counts, err := s.telemetry.counters(domain)
				if err != nil {
					s.telemetry.correlator.EvidenceLost(monotonicNow())
					continue
				}
				lost += counts[11]
			}
			if lost != s.telemetry.kernelLost {
				s.telemetry.correlator.EvidenceLost(monotonicNow())
				s.telemetry.kernelLost = lost
			}
		}
		s.telemetry.correlator.Advance(monotonicNow())
	}
	for _, alert := range s.telemetry.diagnostics.MissingAlerts(time.Now()) {
		logger.Warn("Selected media has not been observed", "owner_reference", alert.Reference, "domain", alert.Domain, "state", "known-active-media-missing")
	}
}
func (s *Session) closeTelemetry() error {
	if s.telemetry == nil || s.telemetry.stop == nil {
		return nil
	}
	err := s.telemetry.stop()
	<-s.telemetry.done
	return err
}
func (s *Session) logTransitions() {
	if s.telemetry == nil || s.Controller == nil {
		return
	}
	s.telemetry.mu.Lock()
	defer s.telemetry.mu.Unlock()
	for _, scope := range s.Controller.Status() {
		previous := s.telemetry.last[scope.Domain]
		if previous == scope.State {
			continue
		}
		s.telemetry.last[scope.Domain] = scope.State
		logger.Info("RTP admission state changed", "domain", scope.Domain, "previous", previous, "state", scope.State, "control_uncertain", scope.ControlUncertain, "pending_updates", scope.PendingUpdates, "desired_generation", scope.DesiredGeneration, "installed_generation", scope.InstalledGeneration)
	}
}

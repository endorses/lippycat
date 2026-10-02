package admissionintegration

import (
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"sync"
	"time"
)

type sessionTelemetry struct {
	mu          sync.Mutex
	counters    func(mediaadmission.DomainID) ([16]uint64, error)
	stop        func() error
	done        chan struct{}
	samples     []mediaadmission.ShadowSample
	next        int
	evidence    mediaadmission.EvidenceStats
	diagnostics *mediaadmission.Diagnostics
	last        map[mediaadmission.DomainID]mediaadmission.State
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
	}
	for _, scope := range result.Scopes {
		if scope.Counters[11] > 0 {
			result.Evidence.Incomplete = true
		}
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

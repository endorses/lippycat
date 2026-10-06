// Package admissiontelemetry adapts neutral snapshots to management transport.
package admissiontelemetry

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

func ToProtoPointer(snapshot *mediaadmission.Snapshot) *management.MediaAdmissionStatus {
	if snapshot == nil {
		return nil
	}
	return ToProto(*snapshot)
}
func ToProto(s mediaadmission.Snapshot) *management.MediaAdmissionStatus {
	p := &management.MediaAdmissionStatus{Enabled: s.Enabled, ConfiguredMode: string(s.ConfiguredMode), FailurePolicy: string(s.FailurePolicy), EndpointCapacity: uint64(s.EndpointCapacity), PendingDialogs: uint64(s.Metadata.Dialogs), PendingEndpoints: uint64(s.Metadata.Endpoints), PendingBytes: uint64(s.Metadata.Bytes), MetadataEvicted: s.Metadata.Evicted, MetadataExpired: s.Metadata.Expired, MetadataRejected: s.Metadata.Rejected, PromotionMisses: s.Metadata.PromotionMisses, MetadataPromotions: s.Metadata.Promotions, EvidenceReceived: s.Evidence.Received, EvidenceOverwritten: s.Evidence.Overwritten, EvidenceMalformed: s.Evidence.Malformed, EvidenceReadErrors: s.Evidence.ReadErrors, EvidenceRetained: uint64(s.Evidence.Retained), EvidenceCapacity: uint64(s.Evidence.Capacity), EvidenceIncomplete: s.Evidence.Incomplete, DiagnosticCalls: uint64(s.Media.Tracked), SelectedAnsweredWithoutMedia: uint64(s.Media.SelectedAnsweredWithoutMedia), AttributedMediaPackets: s.Media.AttributedPackets, DiagnosticTrackingRejected: s.Media.TrackingRejected}
	p.ShadowSampleEvery = uint64(s.Evidence.SampleEvery)
	p.EvidenceKernelLost = s.Evidence.KernelLost
	p.SampledPreSelection = s.Shadow.Preselection
	p.SampledPublicationWindow = s.Shadow.PublicationWindow
	p.SampledRejectedAfterPublication = s.Shadow.RejectedAfterPublication
	p.SampledAdmitted = s.Shadow.Admitted
	p.SampledIncomplete = s.Shadow.Incomplete
	p.SampledAmbiguous = s.Shadow.Ambiguous
	p.SampledIdentityUnavailable = s.Shadow.TooLarge
	p.SampledLate = s.Shadow.Late
	p.CorrelationTrackingRejected = s.Shadow.TrackingRejected
	p.CorrelationPending = uint64(s.Shadow.Pending)
	p.MediaExpectationUnknown = uint64(s.Media.UnknownExpectation)
	p.MediaExpectationInactive = uint64(s.Media.InactiveSelected)
	p.MissingMediaAlerts = s.Media.Alerts
	p.DiagnosticAttributionDropped = s.Media.AttributionDropped
	p.DiagnosticObservationUncertain = uint64(s.Media.ObservationUncertain)
	p.EvidenceClockReadErrors = s.Evidence.ClockReadErrors
	for _, s := range s.Scopes {
		v := &management.MediaAdmissionScope{Domain: uint32(s.Domain), State: string(s.State), ConfirmedMode: uint32(s.LastConfirmed.Mode), ConfirmedGeneration: s.LastConfirmed.Generation, ControlUncertain: s.ControlUncertain, DesiredGeneration: s.DesiredGeneration, InstalledGeneration: s.InstalledGeneration, Owners: uint64(s.Owners), DesiredEndpoints: uint64(s.DesiredEndpoints), InstalledEndpoints: uint64(s.InstalledEndpoints), PendingUpdates: uint64(s.PendingUpdates), UpdateErrors: s.UpdateErrors, ControlErrors: s.ControlErrors, Recoveries: s.Recoveries, StaleUpdates: s.StaleUpdates, OpenDurationNs: uint64(s.OpenDuration), DecisionCounters: append([]uint64(nil), s.Counters[:]...), CounterReadFailed: s.CounterReadFailed}
		v.DegradedDurationNs = uint64(s.DegradedDuration)
		u := s.Uncertainty
		v.Uncertainty = &management.MediaAdmissionUncertainty{UnknownCalls: u.UnknownCalls, ConflictingHeaders: u.Reasons[mediaadmission.ReasonConflictingHeaders], FaultyPrack: u.Reasons[mediaadmission.ReasonFaultyPRACK], PartialSdp: u.Reasons[mediaadmission.ReasonPartialSDP], DelayedOffer: u.Reasons[mediaadmission.ReasonDelayedOffer], ForkAmbiguity: u.Reasons[mediaadmission.ReasonForkAmbiguity], EvidenceLoss: u.Reasons[mediaadmission.ReasonEvidenceLoss], IdenticalDuplicates: u.IdenticalDuplicates, ConflictingDuplicates: u.ConflictingDuplicates}
		if s.Reason != "" {
			v.Reason = "admission synchronization failed"
		}
		if !s.DegradedSince.IsZero() {
			v.DegradedSinceUnixNs = s.DegradedSince.UnixNano()
		}
		if !s.PublicationStarted.IsZero() {
			v.PublicationStartedUnixNs = s.PublicationStarted.UnixNano()
		}
		if !s.LastPublished.IsZero() {
			v.LastPublishedUnixNs = s.LastPublished.UnixNano()
		}
		p.Scopes = append(p.Scopes, v)
	}
	return p
}

package mediaadmission

// ShadowWindow describes verified attribution to one selected call lifetime.
// Its times must use CLOCK_MONOTONIC, matching the kernel. The caller must verify
// packet identity independently: the bounded fingerprint alone is insufficient.
// Zero publication means the eligible endpoint set had not been published.
type ShadowWindow struct {
	IdentityVerified                   bool
	SelectedNS, PublishedNS, RetiredNS uint64
	PublishedGeneration                uint64
}
type ShadowClassification string

const (
	ShadowUnclassified        ShadowClassification = "incomplete-evidence"
	ShadowAdmitted            ShadowClassification = "admitted-candidate"
	ShadowPreselection        ShadowClassification = "pre-selection"
	ShadowPublicationWindow   ShadowClassification = "selection-to-publication"
	ShadowUnexpectedRejection ShadowClassification = "rejected-after-publication"
)

func ClassifyShadow(sample ShadowSample, window ShadowWindow) ShadowClassification {
	if !window.IdentityVerified || sample.EventMonotonicNS == 0 || window.SelectedNS == 0 || (window.RetiredNS != 0 && sample.EventMonotonicNS >= window.RetiredNS) {
		return ShadowUnclassified
	}
	if sample.Reason != 0 {
		return ShadowAdmitted
	}
	if sample.EventMonotonicNS < window.SelectedNS {
		return ShadowPreselection
	}
	if window.PublishedNS == 0 || sample.EventMonotonicNS < window.PublishedNS || sample.Generation < window.PublishedGeneration {
		return ShadowPublicationWindow
	}
	return ShadowUnexpectedRejection
}

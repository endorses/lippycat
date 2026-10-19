package pipeline

import (
	"errors"

	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
)

var ErrContradictoryCaptureEvidence = errors.New("legacy and learned capture evidence are mutually exclusive")

// HasCaptureEvidence reports whether selection depends on a serialized evidence
// claim. Local CurrentCaptureSelection callbacks are deliberately independent.
func (e *PacketEnvelope) HasCaptureEvidence() bool {
	return e != nil && (len(e.CaptureSelectionProof) > 0 || e.LearnedCaptureEvidence != nil)
}

// ValidateCaptureEvidence enforces the shared evidence envelope contract. It
// does not validate attribution or authorize capture; those require the issuing
// authority's current state or the exact historical signed artifact.
func ValidateCaptureEvidence(e *PacketEnvelope) error {
	if e == nil {
		return errors.New("nil packet envelope")
	}
	if len(e.CaptureSelectionProof) > 0 && e.LearnedCaptureEvidence != nil {
		return ErrContradictoryCaptureEvidence
	}
	if e.LearnedCaptureEvidence != nil {
		return wire.ValidateEvidence(e.LearnedCaptureEvidence, wire.DefaultEvidenceLimits)
	}
	return nil
}

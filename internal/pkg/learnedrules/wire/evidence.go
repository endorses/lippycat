package wire

import (
	"unicode/utf8"

	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"google.golang.org/protobuf/proto"
)

// EvidenceLimits must be enforced before ownership resolution as well as before
// sealing an outbound batch. Capture evidence is a hint, never authorization.
type EvidenceLimits struct{ MaxCandidates, MaxBytes, MaxProofBytes, MaxStringBytes int }

var DefaultEvidenceLimits = EvidenceLimits{MaxCandidates: 64, MaxBytes: 1 << 20, MaxProofBytes: 1 << 20, MaxStringBytes: 4096}

// EvidenceRepresentable is part of installation capability, before a binding
// can become effective. The per-artifact ceiling matches the established legacy
// MediaRule bound (1 MiB); the complete typed envelope remains bounded to 1 MiB,
// including its references and framing. No proof bytes may be truncated.
func EvidenceRepresentable(binding learnedrules.Binding) bool {
	// This initial evidence contract has one protected artifact interpretation.
	// Other adapters may use reference evidence, but cannot borrow media authority.
	if len(binding.Proof) > 0 && (binding.AdapterID != "voip" || binding.ContextVersion != 1) {
		return false
	}
	return ValidateEvidence(&evidence.LearnedCaptureEvidence{Version: EvidenceVersion, Candidates: []*evidence.LearnedCandidate{Candidate(binding)}}, DefaultEvidenceLimits) == nil
}

func ValidateEvidence(e *evidence.LearnedCaptureEvidence, limits EvidenceLimits) error {
	if limits.MaxCandidates <= 0 || limits.MaxBytes <= 0 || limits.MaxProofBytes <= 0 || limits.MaxStringBytes <= 0 {
		return learnedrules.ErrInvalid
	}
	if e == nil || e.Version != EvidenceVersion {
		return learnedrules.ErrUnsupported
	}
	if len(e.ProtoReflect().GetUnknown()) > 0 {
		return learnedrules.ErrUnsupported
	}
	if len(e.Candidates) == 0 && !e.Overflow {
		return learnedrules.ErrInvalid
	}
	if len(e.Candidates) > limits.MaxCandidates || proto.Size(e) > limits.MaxBytes {
		return learnedrules.ErrCapacity
	}
	seen := map[string]bool{}
	for _, c := range e.Candidates {
		if c == nil || c.BindingRevision == 0 || c.ContextVersion == 0 || c.AuthorityGeneration == 0 || len(c.ProtoReflect().GetUnknown()) > 0 {
			return learnedrules.ErrInvalid
		}
		for _, text := range []string{c.BindingId, c.AdapterId, c.SubjectId, c.SubjectIncarnation, c.AuthorityId, c.AttributionContext} {
			if text == "" || !utf8.ValidString(text) || len(text) > limits.MaxStringBytes {
				return learnedrules.ErrInvalid
			}
		}
		if seen[c.BindingId] {
			return learnedrules.ErrInvalid
		}
		seen[c.BindingId] = true
		switch p := c.Proof.(type) {
		case *evidence.LearnedCandidate_ReferenceOnly:
			if !p.ReferenceOnly {
				return learnedrules.ErrInvalid
			}
		case *evidence.LearnedCandidate_LegacyMediaRule:
			if len(p.LegacyMediaRule) == 0 {
				return learnedrules.ErrInvalid
			}
			if len(p.LegacyMediaRule) > limits.MaxProofBytes {
				return learnedrules.ErrCapacity
			}
		default:
			return learnedrules.ErrUnsupported
		}
	}
	return nil
}
func Candidate(binding learnedrules.Binding) *evidence.LearnedCandidate {
	c := &evidence.LearnedCandidate{BindingId: binding.ID, BindingRevision: uint64(binding.Revision), AdapterId: binding.AdapterID, ContextVersion: binding.ContextVersion, SubjectId: binding.Subject.ID, SubjectIncarnation: binding.Subject.Incarnation, AuthorityId: binding.Session.ProcessorID, AuthorityGeneration: binding.Session.Generation, AttributionContext: binding.AttributionContext, Proof: &evidence.LearnedCandidate_ReferenceOnly{ReferenceOnly: true}}
	if len(binding.Proof) > 0 {
		c.Proof = &evidence.LearnedCandidate_LegacyMediaRule{LegacyMediaRule: append([]byte(nil), binding.Proof...)}
	}
	return c
}

// ReferenceMatches compares every captured immutable identity component. Context
// and authorization must still be validated from authoritative state or proof.
func ReferenceMatches(c *evidence.LearnedCandidate, b learnedrules.Binding) bool {
	return c != nil && c.BindingId == b.ID && c.BindingRevision == uint64(b.Revision) && c.AdapterId == b.AdapterID && c.ContextVersion == b.ContextVersion && c.SubjectId == b.Subject.ID && c.SubjectIncarnation == b.Subject.Incarnation && c.AuthorityId == b.Session.ProcessorID && c.AuthorityGeneration == b.Session.Generation && c.AttributionContext == b.AttributionContext
}

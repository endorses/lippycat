// Package captureadapter joins the learned runtime to packet producers without
// interpreting subject identity or inheriting protocol-specific output IDs.
package captureadapter

import (
	"bytes"
	"time"

	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

// Select creates owned candidate evidence from the production runtime matcher.
// Overflow is not a selection: the retained subset cannot prove capture scope.
func Select(runtime *core.Runtime, packet *pipeline.PacketEnvelope) (bool, error) {
	if runtime == nil || packet == nil {
		return false, nil
	}
	domain, ok := runtime.Domain(packet.Source.InterfaceName)
	if !ok {
		return false, nil
	}
	candidates := runtime.Match(packet.Packet(), packet.Source.InterfaceName)
	if candidates.Overflow {
		return false, core.ErrCapacity
	}
	if len(candidates.Bindings) == 0 {
		return false, nil
	}
	e := &evidence.LearnedCaptureEvidence{Version: wire.EvidenceVersion}
	for _, binding := range candidates.Bindings {
		if !withinCaptureInterval(binding, packet.CaptureTime) {
			return false, core.ErrInvalid
		}
		e.Candidates = append(e.Candidates, wire.Candidate(binding))
		if err := wire.ValidateEvidence(e, wire.DefaultEvidenceLimits); err != nil {
			return false, err
		}
	}
	packet.LearnedCaptureEvidence = e
	packet.CaptureSelectionProof = nil
	packet.Source.ObservationDomain = uint32(domain)
	packet.Source.ObservationDomainKnown = true
	return true, nil
}

// ValidateCurrent checks all immutable references against currently authorized
// bindings and the exact packet. It never recovers absent ordinary state from a
// packet claim and never assigns a subject or output authorization.
func ValidateCurrent(store *core.Store, packet *pipeline.PacketEnvelope, sourceID string) bool {
	if store == nil || packet == nil || packet.LearnedCaptureEvidence == nil || sourceID == "" || !packet.Source.ObservationDomainKnown || pipeline.ValidateCaptureEvidence(packet) != nil || packet.LearnedCaptureEvidence.Overflow {
		return false
	}
	facts, ok := core.PacketFacts(packet.Packet(), core.DomainID(packet.Source.ObservationDomain))
	if !ok {
		return false
	}
	state := store.Status()
	if !state.Ready {
		return false
	}
	matches := store.MatchForSource(sourceID, facts, max(1, state.Rules+1))
	if matches.Overflow {
		return false
	}
	for _, candidate := range packet.LearnedCaptureEvidence.Candidates {
		found := false
		for _, binding := range matches.Bindings {
			if !wire.ReferenceMatches(candidate, binding) || !withinCaptureInterval(binding, packet.CaptureTime) {
				continue
			}
			scoped := false
			for _, scope := range binding.Scope {
				if scope.HunterID == sourceID && uint32(scope.Domain) == packet.Source.ObservationDomain {
					scoped = true
					break
				}
			}
			if !scoped {
				continue
			}
			switch proof := candidate.Proof.(type) {
			case *evidence.LearnedCandidate_ReferenceOnly:
				if !proof.ReferenceOnly || len(binding.Proof) > 0 {
					continue
				}
			case *evidence.LearnedCandidate_LegacyMediaRule:
				if len(binding.Proof) == 0 || !bytes.Equal(proof.LegacyMediaRule, binding.Proof) {
					continue
				}
			default:
				continue
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return store.Status().Sequence == state.Sequence
}

func withinCaptureInterval(binding core.Binding, at time.Time) bool {
	return !at.IsZero() && !at.Before(binding.NotBefore) && at.Before(binding.ExpiresAt)
}

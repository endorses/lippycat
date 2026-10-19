//go:build processor || tap || all

package processor

import (
	"sort"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capturegrant"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"google.golang.org/protobuf/proto"
)

// capturedMediaProofs extracts original protected artifacts without depending on
// the current learned-store lifetime. Other adapter references provide no LI
// authority. Multiple media claims must describe the same selection context.
func capturedMediaProofs(packet *data.CapturedPacket) ([][]byte, error) {
	if packet == nil {
		return nil, core.ErrInvalid
	}
	if packet.LearnedCaptureEvidence == nil {
		if len(packet.CaptureSelectionProof) == 0 {
			return nil, nil
		}
		return [][]byte{packet.CaptureSelectionProof}, nil
	}
	if len(packet.CaptureSelectionProof) > 0 {
		return nil, core.ErrInvalid
	}
	evidence := packet.LearnedCaptureEvidence
	if err := wire.ValidateEvidence(evidence, wire.DefaultEvidenceLimits); err != nil {
		return nil, err
	}
	if evidence.Overflow {
		return nil, core.ErrCapacity
	}
	var proofCandidates []int
	var first int = -1
	for index, candidate := range evidence.Candidates {
		if len(candidate.GetLegacyMediaRule()) == 0 {
			continue
		}
		_, rule, err := voiprules.BindingFromLegacyCandidate(candidate)
		if err != nil {
			return nil, err
		}
		if first >= 0 {
			_, original, err := voiprules.BindingFromLegacyCandidate(evidence.Candidates[first])
			if err != nil || !proto.Equal(original.Call, rule.Call) {
				return nil, core.ErrInvalid
			}
		} else {
			first = index
		}
		proofCandidates = append(proofCandidates, index)
	}
	sort.Slice(proofCandidates, func(i, j int) bool {
		return evidence.Candidates[proofCandidates[i]].BindingId < evidence.Candidates[proofCandidates[j]].BindingId
	})
	proofs := make([][]byte, 0, len(proofCandidates))
	for _, index := range proofCandidates {
		proofs = append(proofs, evidence.Candidates[index].GetLegacyMediaRule())
	}
	return proofs, nil
}

func capturedMediaProof(packet *data.CapturedPacket) ([]byte, error) {
	proofs, err := capturedMediaProofs(packet)
	if err != nil || len(proofs) == 0 {
		return nil, err
	}
	return proofs[0], nil
}

// validateLearnedMediaArtifact authenticates protected capture in ordinary as
// well as LI builds. The LI adapter separately checks current task/delivery state.
func (p *Processor) validateLearnedMediaArtifact(encodedPolicy []byte, packet *data.CapturedPacket, sourceID string, rule *management.MediaRule) error {
	if p.sharedPolicy == nil || packet == nil || !packet.ObservationDomainKnown || len(encodedPolicy) == 0 || len(encodedPolicy) > filterpolicy.MaxSnapshotBytes {
		return core.ErrAuthority
	}
	signed := &management.SignedPolicySnapshot{}
	if proto.Unmarshal(encodedPolicy, signed) != nil || p.sharedPolicy.state.Verifier().Verify(signed) != nil || p.sharedPolicy.state.Verifier().VerifyMediaRule(rule) != nil {
		return core.ErrAuthority
	}
	decoded := gopacket.NewPacket(packet.Data, layers.LinkType(packet.LinkType), gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	return capturegrant.ValidateRule(signed.Snapshot, rule, sourceID, packet.ObservationDomain, decoded, time.Unix(0, packet.TimestampNs))
}

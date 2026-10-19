package learnedrules

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/learnedevidence"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLegacyCandidateReconstructsCapturedLifetimeWithoutStore(t *testing.T) {
	rule := adapterRule()
	rule.Call.CapturePolicyRevision = 9
	rule.Call.SelectionGrants = []SelectionRef{{ID: "opaque", Revision: 2}}
	rule.CaptureSignature = []byte("signature authenticated by the policy owner")
	binding := ToBinding(rule)
	candidate := wire.Candidate(binding)
	restored, encoded, err := BindingFromLegacyCandidate(candidate)
	require.NoError(t, err)
	require.Equal(t, binding.Subject, restored.Subject)
	require.Equal(t, binding.Session, restored.Session)
	require.Equal(t, binding.Proof, restored.Proof)
	require.Equal(t, rule.Call.CallID, encoded.Call.CallId)
	candidate.GetLegacyMediaRule()[0] ^= 1
	require.Equal(t, binding.Proof, restored.Proof, "returned artifact owns its bytes")
	for _, mutate := range []func(*learnedevidence.LearnedCandidate){
		func(c *learnedevidence.LearnedCandidate) { c.SubjectIncarnation = "reused" },
		func(c *learnedevidence.LearnedCandidate) { c.AuthorityGeneration++ },
		func(c *learnedevidence.LearnedCandidate) { c.BindingRevision++ },
		func(c *learnedevidence.LearnedCandidate) { c.AdapterId = "other" },
		func(c *learnedevidence.LearnedCandidate) {
			c.Proof = &learnedevidence.LearnedCandidate_ReferenceOnly{ReferenceOnly: true}
		},
	} {
		bad := proto.Clone(wire.Candidate(binding)).(*learnedevidence.LearnedCandidate)
		mutate(bad)
		_, _, err := BindingFromLegacyCandidate(bad)
		require.ErrorIs(t, err, core.ErrInvalid)
	}
}

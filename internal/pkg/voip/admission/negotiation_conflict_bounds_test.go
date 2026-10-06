package admission

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNegotiationConflictUnavailableBoundsSurviveLaterConflicts(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, location := range []string{"request", "response"} {
			t.Run(string(policy)+"/"+location, func(t *testing.T) {
				bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
				initial := retirementHealthyCall(t, bridge, registry, "invite-answer")
				for _, sequence := range []uint64{3, 4} {
					request, response := recoveryAtSequence(initial, "caller", "INVITE", sequence)
					values := []string{"invalid INVITE", "3 INVITE"}
					if sequence == 4 {
						values = []string{"10 INVITE", "4 INVITE"}
					}
					if location == "request" {
						request = recoveryDuplicateCSeq(t, request, values...)
					} else {
						response = recoveryDuplicateCSeq(t, response, values...)
					}
					_ = submitDerivation(t, bridge, registry, request)
					_ = submitDerivation(t, bridge, registry, response)
					assertDerivationState(t, bridge, controller, policy, true)
				}
				for _, sequence := range []uint64{11, 12} {
					request, response := recoveryAtSequence(initial, "caller", "INVITE", sequence)
					_ = submitDerivation(t, bridge, registry, request)
					require.Error(t, submitDerivation(t, bridge, registry, response), "a later bounded conflict cannot certify earlier unavailable bounds")
					assertDerivationState(t, bridge, controller, policy, true)
					retirementOwns(t, registry, initial.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
				}
			})
		}
	}
}

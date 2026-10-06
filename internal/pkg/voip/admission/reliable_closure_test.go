package admission

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func rejectedPRACK(prack pipeline.SIPResult) pipeline.SIPResult {
	prack.Method, prack.ResponseCode, prack.SDP = "RESPONSE", 481, nil
	return prack
}

func TestReliableRejectedPRACKBeforeAnswerCannotRecover(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, policy, nil)
			invite, response, prack := reliableSequence("rejection-before-answer")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, rejectedPRACK(prack))
			_ = submitDerivation(t, bridge, registry, prack)
			assertDerivationState(t, bridge, controller, policy, true)
			for index := 0; index < 2; index++ {
				_ = submitDerivation(t, bridge, registry, response)
				_ = submitDerivation(t, bridge, registry, prack)
				assertDerivationState(t, bridge, controller, policy, true)
			}
		})
	}
}

func TestReliableRollbackRetainsExactPRACKRejection(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, rejectionOrder := range []string{"before-rollback", "after-rollback"} {
			t.Run(string(policy)+"/"+rejectionOrder, func(t *testing.T) {
				bridge, registry, _, controller := recoveryFixture(t, policy, nil)
				invite, response, prack := reliableSequence("rollback-rejection")
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, response)
				require.NoError(t, submitDerivation(t, bridge, registry, prack))
				update := prack
				update.Method, update.CSeqMethod, update.CSeqNumber, update.ViaBranch, update.Headers = "UPDATE", "UPDATE", 3, "update", map[string]string{"cseq": "3 UPDATE"}
				update.SDP = derivationSDP("192.0.2.1", 30000, false)
				require.NoError(t, submitDerivation(t, bridge, registry, update))
				if rejectionOrder == "before-rollback" {
					_ = submitDerivation(t, bridge, registry, rejectedPRACK(prack))
				}
				failure := update
				failure.Method, failure.ResponseCode, failure.SDP = "RESPONSE", 486, nil
				_ = submitDerivation(t, bridge, registry, failure)
				if rejectionOrder == "after-rollback" {
					_ = submitDerivation(t, bridge, registry, rejectedPRACK(prack))
				}
				assertDerivationState(t, bridge, controller, policy, true)
				_ = submitDerivation(t, bridge, registry, prack)
				_ = submitDerivation(t, bridge, registry, response)
				assertDerivationState(t, bridge, controller, policy, true)
			})
		}
	}
}

func TestReliableDelayedOfferAfterBodylessFinalResponse(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, policy, nil)
			invite, response, prack := reliableSequence("delayed-reliable-after-final")
			_ = submitDerivation(t, bridge, registry, invite)
			final := response
			final.ResponseCode, final.SDP, final.Headers = 200, nil, map[string]string{"cseq": "1 INVITE"}
			_ = submitDerivation(t, bridge, registry, final)
			_ = submitDerivation(t, bridge, registry, response)
			require.NoError(t, submitDerivation(t, bridge, registry, prack))
			assertDerivationState(t, bridge, controller, policy, false)
			for index := 0; index < 2; index++ {
				require.NoError(t, submitDerivation(t, bridge, registry, final))
				require.NoError(t, submitDerivation(t, bridge, registry, response))
				require.NoError(t, submitDerivation(t, bridge, registry, prack))
				assertDerivationState(t, bridge, controller, policy, false)
			}
		})
	}
}

func TestReliablePRACKRejectionProvenanceIsBoundedAndReleased(t *testing.T) {
	for _, earlyRejection := range []bool{true, false} {
		t.Run(fmt.Sprint(earlyRejection), func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := reliableSequence("bounded-rejection")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			if earlyRejection {
				_ = submitDerivation(t, bridge, registry, rejectedPRACK(prack))
				_ = submitDerivation(t, bridge, registry, prack)
			} else {
				require.NoError(t, submitDerivation(t, bridge, registry, prack))
				bridge.mu.Lock()
				state := bridge.selected[invite.CallID].derivations[derivationSide{invite.FromTag, response.ToTag, invite.FromTag, false}]
				withProof, _ := derivationCost(derivationSide{invite.FromTag, response.ToTag, invite.FromTag, false}, state)
				withoutBranch := *state
				withoutBranch.prackBranch = ""
				withoutProof, _ := derivationCost(derivationSide{invite.FromTag, response.ToTag, invite.FromTag, false}, &withoutBranch)
				bridge.mu.Unlock()
				require.Equal(t, len(prack.ViaBranch), withProof-withoutProof, "retained exact answer branch is charged")
				_ = submitDerivation(t, bridge, registry, rejectedPRACK(prack))
			}
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			before := bridge.cfg.Metadata.Stats()
			for index := 0; index < 5; index++ {
				_ = submitDerivation(t, bridge, registry, rejectedPRACK(prack))
				_ = submitDerivation(t, bridge, registry, prack)
			}
			after := bridge.cfg.Metadata.Stats()
			require.Equal(t, before.SelectedContexts, after.SelectedContexts)
			require.Equal(t, before.SelectedBytes, after.SelectedBytes)
			require.Equal(t, before.SelectedEndpoints, after.SelectedEndpoints)
			registry.Remove(invite.CallID, callregistry.EndCompleted)
			require.NoError(t, bridge.retrySelected())
			assertRetiredLifetimeCharges(t, bridge, 1)
			assertClosedLifetimeCharges(t, bridge)
		})
	}
}

func TestReliablePRACKRejectionCannotAffectDifferentTransactionOrAcceptedUPDATE(t *testing.T) {
	for _, rejection := range []string{"wrong-branch", "wrong-cseq", "wrong-fork", "after-accepted-update"} {
		t.Run(rejection, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := reliableSequence("exact-rejection-" + rejection)
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			require.NoError(t, submitDerivation(t, bridge, registry, prack))
			failure := rejectedPRACK(prack)
			switch rejection {
			case "wrong-branch":
				failure.ViaBranch = "different-prack"
			case "wrong-cseq":
				failure.CSeqNumber, failure.Headers = 1, map[string]string{"cseq": "1 PRACK"}
			case "wrong-fork":
				failure.ToTag = "different-peer"
			case "after-accepted-update":
				update := prack
				update.Method, update.CSeqMethod, update.CSeqNumber, update.ViaBranch, update.Headers = "UPDATE", "UPDATE", 3, "update", map[string]string{"cseq": "3 UPDATE"}
				update.SDP = derivationSDP("192.0.2.1", 30000, false)
				require.NoError(t, submitDerivation(t, bridge, registry, update))
				answer := update
				answer.Method, answer.ResponseCode = "RESPONSE", 200
				answer.SDP = derivationSDP("192.0.2.2", 40000, false)
				require.NoError(t, submitDerivation(t, bridge, registry, answer))
			}
			_ = submitDerivation(t, bridge, registry, failure)
			if rejection == "wrong-fork" {
				// A selected different fork is independently uncertain, but cannot
				// invalidate this fork's exact validated answer.
				bridge.mu.Lock()
				state := bridge.selected[invite.CallID].derivations[derivationSide{invite.FromTag, response.ToTag, invite.FromTag, false}]
				complete := state.complete
				bridge.mu.Unlock()
				require.True(t, complete)
			} else {
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
			}
		})
	}
}

package admission

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func TestCompleteRequestRetainsUnknownPredecessorUntilAcceptedSupersession(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, outcome := range []string{"failure", "success"} {
			t.Run(string(policy)+"/"+outcome, func(t *testing.T) {
				bridge, registry, _, controller := recoveryFixture(t, policy, nil)
				initial := offer("rollback-unknown")
				initial.ToTag = "to"
				initial.SDP = derivationSDP("192.0.2.1", 10000, true)
				require.Error(t, submitDerivation(t, bridge, registry, initial))
				repair := initial
				repair.CSeqNumber, repair.ViaBranch = 2, "repair"
				repair.SDP = derivationSDP("192.0.2.1", 20000, false)
				require.Error(t, submitDerivation(t, bridge, registry, repair))
				assertDerivationState(t, bridge, controller, policy, true)
				bridge.mu.Lock()
				state := bridge.selected[initial.CallID].derivations[derivationSide{"from", "to", "from", false}]
				require.NotNil(t, state.previous)
				require.False(t, state.previous.complete)
				require.Nil(t, state.previous.previous)
				bridge.mu.Unlock()
				response := repair
				response.SDP = nil
				if outcome == "failure" {
					response.Method, response.ResponseCode = "486", 486
					require.Error(t, submitDerivation(t, bridge, registry, response))
					assertDerivationState(t, bridge, controller, policy, true)
					assertDerivationMedia(t, bridge, initial.CallID, "192.0.2.1:10000", "192.0.2.1:10001")
					require.Error(t, bridge.retrySelected(), "a registry snapshot cannot repair rejected supersession")
				} else {
					response.Method, response.ResponseCode = "200", 200
					response.SDP = derivationSDP("192.0.2.2", 30000, false)
					require.NoError(t, submitDerivation(t, bridge, registry, response))
					assertDerivationState(t, bridge, controller, policy, false)
					bridge.mu.Lock()
					state = bridge.selected[initial.CallID].derivations[derivationSide{"from", "to", "from", false}]
					require.Nil(t, state.previous, "exact observed acceptance retires rollback state")
					require.True(t, state.accepted)
					bridge.mu.Unlock()
					// Retransmission cannot remove successful-acceptance evidence.
					require.NoError(t, submitDerivation(t, bridge, registry, repair))
					response.Method, response.ResponseCode = "486", 486
					require.Error(t, submitDerivation(t, bridge, registry, response))
					assertDerivationState(t, bridge, controller, policy, true)
				}
			})
		}
	}
}

func TestUnrelatedMethodsCannotRepairOfferAnswerDerivation(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, method := range []string{"INFO", "OPTIONS", "MESSAGE", "ACK"} {
			for _, missing := range []bool{false, true} {
				label := "partial"
				if missing {
					label = "missing"
				}
				t.Run(string(policy)+"/"+method+"/"+label, func(t *testing.T) {
					bridge, registry, _, controller := recoveryFixture(t, policy, nil)
					message := offer("unrelated-method")
					message.ToTag = "to"
					if !missing {
						message.SDP = derivationSDP("192.0.2.1", 10000, true)
						require.Error(t, submitDerivation(t, bridge, registry, message))
					}
					message.Method, message.CSeqMethod = method, method
					message.CSeqNumber, message.ViaBranch = 2, "unrelated"
					message.SDP = derivationSDP("192.0.2.1", 20000, false)
					if err := submitDerivation(t, bridge, registry, message); err == nil {
						t.Fatal("unrelated SDP proved complete negotiation")
					}
					assertDerivationState(t, bridge, controller, policy, true)
					// Safe normalized endpoints retain the existing ordinary
					// lifetime-bound userspace attribution path.
					require.Equal(t, message.CallID, registry.ResolveMediaEndpoints("192.0.2.1:20000", "").CallID)
					if !missing {
						bridge.mu.Lock()
						state := bridge.selected[message.CallID].derivations[derivationSide{"from", "to", "from", false}]
						require.Equal(t, uint64(1), state.cseq)
						require.Equal(t, "INVITE", state.method)
						require.False(t, state.complete)
						bridge.mu.Unlock()
					}
				})
			}
		}
	}
}

func TestRequestMethodCannotBorrowNegotiationFromCSeqHeader(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, policy, nil)
			initial := offer("mismatched-request-method")
			initial.ToTag = "to"
			initial.SDP = derivationSDP("192.0.2.1", 10000, true)
			require.Error(t, submitDerivation(t, bridge, registry, initial))
			mismatch := initial
			mismatch.Method, mismatch.CSeqMethod = "INFO", "INVITE"
			mismatch.CSeqNumber, mismatch.ViaBranch = 2, "mismatch"
			mismatch.Headers = map[string]string{"cseq": "2 INVITE"}
			mismatch.SDP = derivationSDP("192.0.2.1", 20000, false)
			require.Error(t, submitDerivation(t, bridge, registry, mismatch))
			assertDerivationState(t, bridge, controller, policy, true)
			bridge.mu.Lock()
			state := bridge.selected[initial.CallID].derivations[derivationSide{"from", "to", "from", false}]
			require.Equal(t, uint64(1), state.cseq)
			require.False(t, state.complete)
			bridge.mu.Unlock()
		})
	}
}

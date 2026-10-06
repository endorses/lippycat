package admission

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

// faultyReliableSequence keeps all addresses synthetic and separates the stale
// PRACK endpoints from the later valid negotiation's endpoints.
func faultyReliableSequence(callID, fault string) (pipeline.SIPResult, pipeline.SIPResult, pipeline.SIPResult) {
	invite, response, prack := reliableSequence(callID)
	switch fault {
	case "mismatched-rack":
		prack.Headers["rack"] = "102 1 INVITE"
	case "unreliable-provisional":
		delete(response.Headers, "require")
	case "partial-prack":
		prack.SDP = derivationSDP("192.0.2.1", 10000, true)
	case "bodyless-prack-ack-answer":
		prack.SDP = nil
	}
	return invite, response, prack
}

func establishFaultyReliable(t *testing.T, bridge *Bridge, registry *callregistry.Core, response, invite pipeline.SIPResult, ackAnswer bool) {
	t.Helper()
	final := response
	final.ResponseCode, final.SDP = 200, nil
	final.Headers = map[string]string{"cseq": "1 INVITE"}
	_ = submitDerivation(t, bridge, registry, final)
	ack := invite
	ack.Method, ack.CSeqMethod, ack.ToTag, ack.ViaBranch = "ACK", "ACK", "to", "initial-ack"
	ack.Headers = map[string]string{"cseq": "1 ACK"}
	ack.SDP = nil
	if ackAnswer {
		ack.SDP = derivationSDP("192.0.2.1", 10000, false)
	}
	_ = submitDerivation(t, bridge, registry, ack)
}

func reliableReplacement(invite pipeline.SIPResult, method string) (pipeline.SIPResult, pipeline.SIPResult) {
	request := invite
	request.Method, request.CSeqMethod, request.CSeqNumber = method, method, 3
	request.ToTag, request.ViaBranch = "to", "replacement-branch"
	request.Headers = map[string]string{"cseq": "3 " + method}
	request.SDP = derivationSDP("192.0.2.1", 30000, false)
	answer := request
	answer.Method, answer.ResponseCode = "RESPONSE", 200
	answer.SDP = derivationSDP("192.0.2.2", 40000, false)
	return request, answer
}

func TestReliableFaultyPRACKConfirmedReplacement(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, fault := range []string{"mismatched-rack", "unreliable-provisional", "partial-prack", "bodyless-prack-ack-answer"} {
			for _, method := range []string{"INVITE", "UPDATE"} {
				t.Run(fmt.Sprintf("%s/%s/%s", policy, fault, method), func(t *testing.T) {
					bridge, registry, _, controller := recoveryFixture(t, policy, nil)
					invite, response, prack := faultyReliableSequence("replacement", fault)
					_ = submitDerivation(t, bridge, registry, invite)
					_ = submitDerivation(t, bridge, registry, response)
					_ = submitDerivation(t, bridge, registry, prack)
					establishFaultyReliable(t, bridge, registry, response, invite, fault == "bodyless-prack-ack-answer")
					assertDerivationState(t, bridge, controller, policy, true)
					require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
					request, answer := reliableReplacement(invite, method)
					_ = submitDerivation(t, bridge, registry, request)
					assertDerivationState(t, bridge, controller, policy, true)
					require.NoError(t, submitDerivation(t, bridge, registry, answer))
					assertDerivationState(t, bridge, controller, policy, false)
					assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001")
					require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
					require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
					require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:30000", "").CallID)
					require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.2:40000", "").CallID)
					// Neither stale SDP nor stale reliability proof may reclaim ownership.
					_ = submitDerivation(t, bridge, registry, response)
					_ = submitDerivation(t, bridge, registry, prack)
					_ = submitDerivation(t, bridge, registry, request)
					_ = submitDerivation(t, bridge, registry, answer)
					assertDerivationState(t, bridge, controller, policy, false)
					assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001")
					require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
				})
			}
		}
	}
}

func TestReliableFaultyPRACKInvalidReplacementRemainsUnknown(t *testing.T) {
	for _, method := range []string{"INVITE", "UPDATE"} {
		for _, invalid := range []string{"partial-request", "partial-answer", "unconfirmed", "rejected", "wrong-dialog", "wrong-transaction", "stale", "missing-establishment"} {
			t.Run(method+"/"+invalid, func(t *testing.T) {
				policy := mediaadmission.FailureClosed
				bridge, registry, _, controller := recoveryFixture(t, policy, nil)
				invite, response, prack := faultyReliableSequence("invalid-replacement", "partial-prack")
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, response)
				_ = submitDerivation(t, bridge, registry, prack)
				if invalid != "missing-establishment" {
					establishFaultyReliable(t, bridge, registry, response, invite, false)
				}
				request, answer := reliableReplacement(invite, method)
				switch invalid {
				case "partial-request":
					request.SDP = derivationSDP("192.0.2.1", 30000, true)
				case "partial-answer":
					answer.SDP = derivationSDP("192.0.2.2", 40000, true)
				case "rejected":
					answer.ResponseCode, answer.SDP = 488, nil
				case "wrong-dialog":
					request.ToTag, answer.ToTag = "other-peer", "other-peer"
				case "wrong-transaction":
					answer.ViaBranch = "unrelated-branch"
				case "stale":
					request.CSeqNumber, answer.CSeqNumber = 1, 1
					request.Headers, answer.Headers = map[string]string{"cseq": "1 " + method}, map[string]string{"cseq": "1 " + method}
				}
				_ = submitDerivation(t, bridge, registry, request)
				if invalid != "unconfirmed" {
					_ = submitDerivation(t, bridge, registry, answer)
				}
				assertDerivationState(t, bridge, controller, policy, true)
				require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID, "unresolved PRACK ownership must remain")
				require.NotNil(t, bridge.selected[invite.CallID])
			})
		}
	}
}

func TestReliableOutstandingEarlyOfferCannotBeAnsweredByUPDATE(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := faultyReliableSequence("early-update", "bodyless-prack-ack-answer")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	_ = submitDerivation(t, bridge, registry, prack)
	request, answer := reliableReplacement(invite, "UPDATE")
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, answer)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}

func TestReliableSupersessionRetainsSharedEndpointOwnership(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := faultyReliableSequence("shared-replacement", "partial-prack")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	_ = submitDerivation(t, bridge, registry, prack)
	establishFaultyReliable(t, bridge, registry, response, invite, false)
	request, answer := reliableReplacement(invite, "INVITE")
	request.SDP = derivationSDP("192.0.2.1", 10000, false)
	_ = submitDerivation(t, bridge, registry, request)
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:40000", "192.0.2.2:40001")
	require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
}

func TestReliableSupersessionPreservesIndependentCallUncertainty(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := faultyReliableSequence("recovering-call", "partial-prack")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	_ = submitDerivation(t, bridge, registry, prack)
	establishFaultyReliable(t, bridge, registry, response, invite, false)
	other := offer("independent-unknown-call")
	other.FromTag, other.ToTag, other.ViaBranch = "other-origin", "other-peer", "other-branch"
	other.SDP = derivationSDP("192.0.2.9", 50000, true)
	require.Error(t, submitDerivation(t, bridge, registry, other))
	require.Equal(t, 2, bridge.Stats().UnknownDerivations)
	request, answer := reliableReplacement(invite, "INVITE")
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, answer)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001")
	assertDerivationMedia(t, bridge, other.CallID, "192.0.2.9:50000", "192.0.2.9:50001")
	require.Equal(t, other.CallID, registry.ResolveMediaEndpoints("192.0.2.9:50000", "").CallID)
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
}

func TestReliableSupersessionIgnoresMalformedStaleRAck(t *testing.T) {
	bridge, registry, maps, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := faultyReliableSequence("malformed-stale-rack", "partial-prack")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	_ = submitDerivation(t, bridge, registry, prack)
	establishFaultyReliable(t, bridge, registry, response, invite, false)
	request, answer := reliableReplacement(invite, "UPDATE")
	_ = submitDerivation(t, bridge, registry, request)
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
	before := bridge.cfg.Metadata.Stats()
	prack.Headers = map[string]string{"cseq": "2 PRACK", "rack": "malformed"}
	prack.SDP = derivationSDP("192.0.2.7", 60000, false)
	_ = submitDerivation(t, bridge, registry, prack)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001")
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.7:60000", "").CallID)
	require.Equal(t, 4, maps.count())
	after := bridge.cfg.Metadata.Stats()
	require.Equal(t, before.SelectedContexts, after.SelectedContexts)
	require.Equal(t, before.SelectedBytes, after.SelectedBytes)
	require.Equal(t, before.SelectedEndpoints, after.SelectedEndpoints)
}

func TestReliableRejectedUPDATEAllowsNewerConfirmedRecovery(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, maps, controller := recoveryFixture(t, policy, nil)
			invite, response, prack := faultyReliableSequence("rejected-update-recovery", "partial-prack")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			establishFaultyReliable(t, bridge, registry, response, invite, false)
			request, answer := reliableReplacement(invite, "UPDATE")
			_ = submitDerivation(t, bridge, registry, request)
			rejected := answer
			rejected.ResponseCode, rejected.SDP = 488, nil
			_ = submitDerivation(t, bridge, registry, rejected)
			assertDerivationState(t, bridge, controller, policy, true)
			request.CSeqNumber, answer.CSeqNumber = 4, 4
			request.Headers, answer.Headers = map[string]string{"cseq": "4 UPDATE"}, map[string]string{"cseq": "4 UPDATE"}
			request.ViaBranch, answer.ViaBranch = "newer-replacement", "newer-replacement"
			_ = submitDerivation(t, bridge, registry, request)
			require.NoError(t, submitDerivation(t, bridge, registry, answer))
			assertDerivationState(t, bridge, controller, policy, false)
			require.Equal(t, 4, maps.count())
			require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
			require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:30000", "").CallID)
		})
	}
}

func TestReliableReplacementSuccessCapturedBeforeRequest(t *testing.T) {
	for _, method := range []string{"INVITE", "UPDATE"} {
		t.Run(method, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := faultyReliableSequence("response-first-recovery", "partial-prack")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			establishFaultyReliable(t, bridge, registry, response, invite, false)
			request, answer := reliableReplacement(invite, method)
			_ = submitDerivation(t, bridge, registry, answer)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			require.NoError(t, submitDerivation(t, bridge, registry, request))
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
			assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001")
			require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
		})
	}
}

func TestReliableSupersessionPreservesSameCallIndependentUncertainty(t *testing.T) {
	for _, context := range []string{"same-dialog-other-initiator", "other-dialog"} {
		t.Run(context, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := faultyReliableSequence("same-call-independent", "partial-prack")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			establishFaultyReliable(t, bridge, registry, response, invite, false)
			other, _ := reliableReplacement(invite, "UPDATE")
			other.ViaBranch = "independent-uncertainty"
			other.SDP = derivationSDP("192.0.2.9", 50000, true)
			if context == "same-dialog-other-initiator" {
				other.FromTag, other.ToTag = "to", invite.FromTag
			} else {
				other.ToTag = "different-dialog-peer"
			}
			require.Error(t, submitDerivation(t, bridge, registry, other))
			request, answer := reliableReplacement(invite, "INVITE")
			_ = submitDerivation(t, bridge, registry, request)
			_ = submitDerivation(t, bridge, registry, answer)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.9:50000", "").CallID)
			require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
			assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001", "192.0.2.9:50000", "192.0.2.9:50001")
		})
	}
}

func TestReliableSupersessionReleasesAccountingAndRetirement(t *testing.T) {
	bridge, registry, maps, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := faultyReliableSequence("supersession-accounting", "partial-prack")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	_ = submitDerivation(t, bridge, registry, prack)
	establishFaultyReliable(t, bridge, registry, response, invite, false)
	before := bridge.cfg.Metadata.Stats()
	request, answer := reliableReplacement(invite, "UPDATE")
	_ = submitDerivation(t, bridge, registry, request)
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	after := bridge.cfg.Metadata.Stats()
	require.Less(t, after.SelectedContexts, before.SelectedContexts)
	require.Less(t, after.SelectedBytes, before.SelectedBytes)
	require.Equal(t, 4, after.SelectedEndpoints)
	require.Equal(t, 4, maps.count())
	registry.Remove(invite.CallID, callregistry.EndCompleted)
	require.NoError(t, bridge.retrySelected())
	retired := bridge.cfg.Metadata.Stats()
	require.Zero(t, retired.SelectedContexts)
	require.Zero(t, retired.SelectedBytes)
	require.Zero(t, retired.SelectedEndpoints)
	require.Zero(t, maps.count())
	require.Zero(t, bridge.Stats().SelectedLifetimes)
	require.Zero(t, bridge.Stats().UnknownDerivations)
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:30000", "").CallID)
}

func TestReliablePartialReplacementChainRetiresAllSupersededEndpoints(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, method := range []string{"INVITE", "UPDATE"} {
			t.Run(fmt.Sprintf("%s/%s", policy, method), func(t *testing.T) {
				bridge, registry, maps, controller := recoveryFixture(t, policy, nil)
				invite, response, prack := faultyReliableSequence("replacement-chain", "partial-prack")
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, response)
				_ = submitDerivation(t, bridge, registry, prack)
				establishFaultyReliable(t, bridge, registry, response, invite, false)
				// INFO retains an independent endpoint requirement through supersession.
				independent := invite
				independent.Method, independent.CSeqMethod, independent.CSeqNumber = "INFO", "INFO", 2
				independent.ToTag, independent.ViaBranch = "to", "independent-info"
				independent.Headers = map[string]string{"cseq": "2 INFO"}
				independent.SDP = derivationSDP("192.0.2.9", 61000, false)
				_ = submitDerivation(t, bridge, registry, independent)
				require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.9:61000", "").CallID)
				request, answer := reliableReplacement(invite, "UPDATE")
				answer.SDP = derivationSDP("192.0.2.2", 40000, true)
				_ = submitDerivation(t, bridge, registry, request)
				_ = submitDerivation(t, bridge, registry, answer)
				request.CSeqNumber, answer.CSeqNumber = 4, 4
				request.ViaBranch, answer.ViaBranch = "intermediate-branch", "intermediate-branch"
				request.Headers, answer.Headers = map[string]string{"cseq": "4 UPDATE"}, map[string]string{"cseq": "4 UPDATE"}
				request.SDP = derivationSDP("192.0.2.1", 45000, false)
				answer.SDP = derivationSDP("192.0.2.2", 46000, true)
				_ = submitDerivation(t, bridge, registry, request)
				_ = submitDerivation(t, bridge, registry, answer)
				assertDerivationState(t, bridge, controller, policy, true)
				before := bridge.cfg.Metadata.Stats()
				require.Greater(t, before.SelectedEndpoints, 6, "superseded endpoint provenance remains charged")
				request.Method, request.CSeqMethod, answer.CSeqMethod = method, method, method
				request.CSeqNumber, answer.CSeqNumber = 5, 5
				request.ViaBranch, answer.ViaBranch = "final-branch", "final-branch"
				request.Headers, answer.Headers = map[string]string{"cseq": "5 " + method}, map[string]string{"cseq": "5 " + method}
				request.SDP = derivationSDP("192.0.2.1", 50000, false)
				answer.SDP = derivationSDP("192.0.2.2", 60000, false)
				_ = submitDerivation(t, bridge, registry, request)
				require.NoError(t, submitDerivation(t, bridge, registry, answer))
				assertDerivationState(t, bridge, controller, policy, false)
				assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:50000", "192.0.2.1:50001", "192.0.2.2:60000", "192.0.2.2:60001", "192.0.2.9:61000", "192.0.2.9:61001")
				for _, endpoint := range []string{"192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:20000", "192.0.2.2:20001", "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001", "192.0.2.1:45000", "192.0.2.1:45001", "192.0.2.2:46000", "192.0.2.2:46001"} {
					require.Empty(t, registry.ResolveMediaEndpoints(endpoint, "").CallID, endpoint)
					key, err := parseEndpoint(bridge.cfg.Domain, endpoint)
					require.NoError(t, err)
					maps.mu.Lock()
					present := maps.keys[key]
					maps.mu.Unlock()
					require.False(t, present, endpoint)
				}
				for _, endpoint := range []string{"192.0.2.1:50000", "192.0.2.1:50001", "192.0.2.2:60000", "192.0.2.2:60001", "192.0.2.9:61000", "192.0.2.9:61001"} {
					require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints(endpoint, "").CallID, endpoint)
				}
				require.Equal(t, 6, maps.count())
				after := bridge.cfg.Metadata.Stats()
				require.Equal(t, 6, after.SelectedEndpoints)
				require.Less(t, after.SelectedBytes, before.SelectedBytes)
				registry.Remove(invite.CallID, callregistry.EndCompleted)
				require.NoError(t, bridge.retrySelected())
				retired := bridge.cfg.Metadata.Stats()
				require.Zero(t, retired.SelectedContexts)
				require.Zero(t, retired.SelectedBytes)
				require.Zero(t, retired.SelectedEndpoints)
				require.Zero(t, maps.count())
			})
		}
	}
}

func TestReliableLateInitialRequestAllowsConfirmedReplacement(t *testing.T) {
	for _, method := range []string{"INVITE", "UPDATE"} {
		t.Run(method, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := faultyReliableSequence("late-initial-request", "partial-prack")
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			final := response
			final.ResponseCode, final.SDP = 200, nil
			final.Headers = map[string]string{"cseq": "1 INVITE"}
			_ = submitDerivation(t, bridge, registry, final)
			_ = submitDerivation(t, bridge, registry, invite)
			request, answer := reliableReplacement(invite, method)
			_ = submitDerivation(t, bridge, registry, request)
			require.NoError(t, submitDerivation(t, bridge, registry, answer))
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
			assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001")
			require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
		})
	}
}

func TestReliableLateInitialRequestCannotBindAmbiguousFork(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := faultyReliableSequence("ambiguous-late-request", "partial-prack")
	for _, peer := range []string{"to", "other-peer"} {
		fork := response
		fork.ToTag = peer
		_ = submitDerivation(t, bridge, registry, fork)
		final := fork
		final.ResponseCode, final.SDP = 200, nil
		final.Headers = map[string]string{"cseq": "1 INVITE"}
		_ = submitDerivation(t, bridge, registry, final)
	}
	_ = submitDerivation(t, bridge, registry, prack)
	_ = submitDerivation(t, bridge, registry, invite)
	require.True(t, bridge.selected[invite.CallID].contextLost)
	request, answer := reliableReplacement(invite, "UPDATE")
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, answer)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}

func TestReliableRetirementProvenanceLimitPreservesConservativeUncertainty(t *testing.T) {
	bridge, registry, maps, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := faultyReliableSequence("retirement-budget", "partial-prack")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	_ = submitDerivation(t, bridge, registry, prack)
	establishFaultyReliable(t, bridge, registry, response, invite, false)
	require.False(t, bridge.selected[invite.CallID].contextLost)
	// Six current media endpoints fit; historical provenance has its own cap.
	bridge.cfg.Limits.MaxEndpointsPerOwner = 6
	rejectedBefore := bridge.cfg.Metadata.Stats().SelectedRejected
	request, answer := reliableReplacement(invite, "UPDATE")
	for cseq := uint64(3); cseq <= 8; cseq++ {
		request.CSeqNumber, answer.CSeqNumber = cseq, cseq
		request.ViaBranch, answer.ViaBranch = fmt.Sprintf("budget-%d", cseq), fmt.Sprintf("budget-%d", cseq)
		request.Headers, answer.Headers = map[string]string{"cseq": fmt.Sprintf("%d UPDATE", cseq)}, map[string]string{"cseq": fmt.Sprintf("%d UPDATE", cseq)}
		request.SDP = derivationSDP("192.0.2.1", 30000+int(cseq)*1000, false)
		answer.SDP = derivationSDP("192.0.2.2", 40000+int(cseq)*1000, true)
		_ = submitDerivation(t, bridge, registry, request)
		_ = submitDerivation(t, bridge, registry, answer)
		if cseq <= 6 {
			require.False(t, bridge.selected[invite.CallID].contextLost, "sequence %d fits provenance cap", cseq)
		}
		if cseq == 6 {
			full := false
			for _, state := range bridge.selected[invite.CallID].derivations {
				full = full || len(state.retirementEndpoints) == 6
			}
			require.True(t, full, "retirement provenance reaches its charged limit before overflow")
		}
		if cseq == 7 {
			require.True(t, bridge.selected[invite.CallID].contextLost, "next response exceeds provenance cap")
		}
		require.Equal(t, rejectedBefore, bridge.cfg.Metadata.Stats().SelectedRejected, "metadata reservation remains within its separate limits")
	}
	require.True(t, bridge.selected[invite.CallID].contextLost)
	for _, state := range bridge.selected[invite.CallID].derivations {
		require.LessOrEqual(t, len(state.retirementEndpoints), bridge.cfg.Limits.MaxEndpointsPerOwner)
	}
	request.CSeqNumber, answer.CSeqNumber = 9, 9
	request.ViaBranch, answer.ViaBranch = "budget-final", "budget-final"
	request.Headers, answer.Headers = map[string]string{"cseq": "9 UPDATE"}, map[string]string{"cseq": "9 UPDATE"}
	request.SDP = derivationSDP("192.0.2.1", 50000, false)
	answer.SDP = derivationSDP("192.0.2.2", 60000, false)
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, answer)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID, "budget exhaustion cannot erase untracked ownership")
	registry.Remove(invite.CallID, callregistry.EndCompleted)
	require.NoError(t, bridge.retrySelected())
	retired := bridge.cfg.Metadata.Stats()
	require.Zero(t, retired.SelectedContexts)
	require.Zero(t, retired.SelectedBytes)
	require.Zero(t, retired.SelectedEndpoints)
	require.Zero(t, maps.count())
}

func TestReliableSupersessionPreservesSharedIndependentSDP(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, method := range []string{"INVITE", "UPDATE"} {
			t.Run(fmt.Sprintf("%s/%s", policy, method), func(t *testing.T) {
				bridge, registry, maps, controller := recoveryFixture(t, policy, nil)
				invite, response, prack := faultyReliableSequence("shared-independent-info", "partial-prack")
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, response)
				_ = submitDerivation(t, bridge, registry, prack)
				establishFaultyReliable(t, bridge, registry, response, invite, false)
				info := invite
				info.Method, info.CSeqMethod, info.CSeqNumber = "INFO", "INFO", 2
				info.ToTag, info.ViaBranch = "to", "independent-info"
				info.Headers = map[string]string{"cseq": "2 INFO"}
				info.SDP = derivationSDP("192.0.2.2", 20000, false)
				_ = submitDerivation(t, bridge, registry, info)
				request, answer := reliableReplacement(invite, method)
				_ = submitDerivation(t, bridge, registry, request)
				require.NoError(t, submitDerivation(t, bridge, registry, answer))
				assertDerivationState(t, bridge, controller, policy, false)
				assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001", "192.0.2.2:20000", "192.0.2.2:20001")
				for _, endpoint := range []string{"192.0.2.2:20000", "192.0.2.2:20001"} {
					require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints(endpoint, "").CallID, "independent SDP still requires shared endpoint")
					key, err := parseEndpoint(bridge.cfg.Domain, endpoint)
					require.NoError(t, err)
					maps.mu.Lock()
					present := maps.keys[key]
					maps.mu.Unlock()
					require.True(t, present)
				}
				require.Equal(t, 6, maps.count())
				require.Equal(t, 6, bridge.cfg.Metadata.Stats().SelectedEndpoints)
				_ = submitDerivation(t, bridge, registry, info)
				require.Equal(t, 6, bridge.cfg.Metadata.Stats().SelectedEndpoints, "retransmitted independent SDP is charged once")
				registry.Remove(invite.CallID, callregistry.EndCompleted)
				require.NoError(t, bridge.retrySelected())
				retired := bridge.cfg.Metadata.Stats()
				require.Zero(t, retired.SelectedContexts)
				require.Zero(t, retired.SelectedBytes)
				require.Zero(t, retired.SelectedEndpoints)
				require.Zero(t, maps.count())
			})
		}
	}
}

func TestReliableIndependentSDPEndpointUnionIsBoundedAndCharged(t *testing.T) {
	bridge, registry, _, _ := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := faultyReliableSequence("independent-union-budget", "partial-prack")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	_ = submitDerivation(t, bridge, registry, prack)
	establishFaultyReliable(t, bridge, registry, response, invite, false)
	call := bridge.selected[invite.CallID]
	require.False(t, call.contextLost)
	bridge.cfg.Limits.MaxEndpointsPerOwner = 6
	before := bridge.cfg.Metadata.Stats()
	first, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.9:61000")
	require.NoError(t, err)
	second, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.9:61001")
	require.NoError(t, err)
	third, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.9:62000")
	require.NoError(t, err)
	initial := []mediaadmission.EndpointKey{first, second}
	for port := 61002; port <= 61005; port++ {
		key, err := parseEndpoint(bridge.cfg.Domain, fmt.Sprintf("192.0.2.9:%d", port))
		require.NoError(t, err)
		initial = append(initial, key)
	}
	record := mediaadmission.MetadataRecord{Complete: true, Key: mediaadmission.DialogKey{FromTag: "from", ToTag: "to", CSeqMethod: "INFO"}, Endpoints: initial}
	// Exercise descriptor retention directly to isolate its cap from publication's
	// separate combined media-set limit.
	require.True(t, bridge.observeDerivation(call, record))
	require.False(t, call.contextLost)
	side := derivationSide{"from", "to", "", false}
	require.ElementsMatch(t, record.Endpoints, call.derivations[side].endpoints)
	charged := bridge.cfg.Metadata.Stats()
	require.Equal(t, before.SelectedContexts+1, charged.SelectedContexts)
	require.Equal(t, before.SelectedEndpoints+6, charged.SelectedEndpoints)
	require.Greater(t, charged.SelectedBytes, before.SelectedBytes)
	require.True(t, bridge.observeDerivation(call, record))
	require.Equal(t, charged, bridge.cfg.Metadata.Stats(), "identical independent endpoints do not grow accounting")
	record.Endpoints = []mediaadmission.EndpointKey{third}
	require.False(t, bridge.observeDerivation(call, record))
	require.True(t, call.contextLost, "new independent union exceeds its endpoint cap")
	require.ElementsMatch(t, initial, call.derivations[side].endpoints)
	require.Equal(t, charged, bridge.cfg.Metadata.Stats(), "overflow leaves the prior charged descriptor intact")
	registry.Remove(invite.CallID, callregistry.EndCompleted)
	require.NoError(t, bridge.retrySelected())
	retired := bridge.cfg.Metadata.Stats()
	require.Zero(t, retired.SelectedContexts)
	require.Zero(t, retired.SelectedBytes)
	require.Zero(t, retired.SelectedEndpoints)
}

func TestReliableIndependentSDPCannotResolveUnobservedNegotiation(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, _, _ := reliableSequence("independent-missing-negotiation")
	_ = submitDerivation(t, bridge, registry, invite)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	info := invite
	info.Method, info.CSeqMethod, info.CSeqNumber = "INFO", "INFO", 2
	info.ToTag, info.ViaBranch = "to", "independent-info"
	info.Headers = map[string]string{"cseq": "2 INFO"}
	info.SDP = derivationSDP("192.0.2.9", 61000, false)
	require.Error(t, submitDerivation(t, bridge, registry, info))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	require.Error(t, bridge.retrySelected(), "safe attribution cannot confirm an unobserved negotiation")
}

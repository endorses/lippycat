package admission

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

// recoveryDuplicateCSeq passes actual repeated wire headers through the parser,
// retaining its last-line compatibility value and its independent proof evidence.
func recoveryDuplicateCSeq(t *testing.T, message pipeline.SIPResult, values ...string) pipeline.SIPResult {
	t.Helper()
	start := message.Method + " sip:service@example.test SIP/2.0"
	if message.ResponseCode != 0 {
		start = fmt.Sprintf("SIP/2.0 %d Synthetic", message.ResponseCode)
	}
	wire := start + "\r\nCall-ID: " + message.CallID + "\r\n"
	for _, value := range values {
		wire += "CSeq: " + value + "\r\n"
	}
	wire += "Content-Length: 0\r\n\r\n"
	parsed, err := sip.Parse([]byte(wire), sip.ParseOptions{})
	require.NoError(t, err)
	message.Headers, message.CSeqNumber, message.CSeqMethod = parsed.Headers, parsed.CSeqNumber, parsed.CSeqMethod
	message.DuplicateReliableHeaders = parsed.DuplicateReliableHeaders
	message.ReliableHeaderEvidence = parsed.ReliableHeaderEvidence
	return message
}

func recoveryAtSequence(invite pipeline.SIPResult, initiator, method string, cseq uint64) (pipeline.SIPResult, pipeline.SIPResult) {
	request, response := reliableReplacement(invite, method)
	request.DuplicateReliableHeaders, response.DuplicateReliableHeaders = sip.ReliableHeaderDuplicates{}, sip.ReliableHeaderDuplicates{}
	request.ReliableHeaderEvidence, response.ReliableHeaderEvidence = sip.ReliableHeaderEvidence{}, sip.ReliableHeaderEvidence{}
	request.CSeqNumber, response.CSeqNumber = cseq, cseq
	request.Headers, response.Headers = map[string]string{"cseq": fmt.Sprintf("%d %s", cseq, method)}, map[string]string{"cseq": fmt.Sprintf("%d %s", cseq, method)}
	request.ViaBranch, response.ViaBranch = fmt.Sprintf("repair-%s-%d", initiator, cseq), fmt.Sprintf("repair-%s-%d", initiator, cseq)
	if initiator == "callee" {
		request.FromTag, request.ToTag, response.FromTag, response.ToTag = "to", "from", "to", "from"
		request.SDP, response.SDP = derivationSDP("192.0.2.2", 40000, false), derivationSDP("192.0.2.1", 30000, false)
	}
	return request, response
}

func TestNegotiationRecoveryIdenticalCSeqUsesValidatedOrdinaryProof(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, location := range []string{"request", "response", "both"} {
			t.Run(string(policy)+"/"+location, func(t *testing.T) {
				bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
				invite := offer("identical-duplicates")
				invite.Headers = map[string]string{"cseq": "1 INVITE"}
				answer := invite
				answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
				answer.SDP = derivationSDP("192.0.2.2", 20000, false)
				if location != "response" {
					invite = recoveryDuplicateCSeq(t, invite, "1 INVITE", "1 INVITE")
				}
				if location != "request" {
					answer = recoveryDuplicateCSeq(t, answer, "1 INVITE", "1 INVITE")
				}
				_ = submitDerivation(t, bridge, registry, invite)
				require.NoError(t, submitDerivation(t, bridge, registry, answer))
				assertDerivationState(t, bridge, controller, policy, false)
				retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
			})
		}
	}
}

func TestNegotiationRecoveryConflictingCSeqRequiresAboveMaximum(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, location := range []string{"request", "response"} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/reverse-%v", policy, location, reverse), func(t *testing.T) {
					bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
					invite := offer("conflicting-duplicates")
					invite.Headers = map[string]string{"cseq": "1 INVITE"}
					answer := invite
					answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
					answer.SDP = derivationSDP("192.0.2.2", 20000, false)
					values := []string{"9 INVITE", "1 INVITE"}
					if reverse {
						values[0], values[1] = values[1], values[0]
					}
					if location == "request" {
						invite = recoveryDuplicateCSeq(t, invite, values...)
					} else {
						answer = recoveryDuplicateCSeq(t, answer, values...)
					}
					_ = submitDerivation(t, bridge, registry, invite)
					_ = submitDerivation(t, bridge, registry, answer)
					assertDerivationState(t, bridge, controller, policy, true)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
					request, response := recoveryAtSequence(invite, "caller", "INVITE", 5)
					_ = submitDerivation(t, bridge, registry, request)
					_ = submitDerivation(t, bridge, registry, response)
					assertDerivationState(t, bridge, controller, policy, true)
					request, response = recoveryAtSequence(invite, "caller", "INVITE", 10)
					_ = submitDerivation(t, bridge, registry, request)
					require.NoError(t, submitDerivation(t, bridge, registry, response))
					assertDerivationState(t, bridge, controller, policy, false)
				})
			}
		}
	}
}

func TestNegotiationRecoveryReplacementConflictCannotSupersede(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite := retirementHealthyCall(t, bridge, registry, "invite-answer")
	request, answer := recoveryAtSequence(invite, "caller", "INVITE", 3)
	request = recoveryDuplicateCSeq(t, request, "9 INVITE", "3 INVITE")
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, answer)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	request, answer = recoveryAtSequence(invite, "caller", "UPDATE", 10)
	request = recoveryDuplicateCSeq(t, request, "11 UPDATE", "10 UPDATE")
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, answer)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	request, answer = recoveryAtSequence(invite, "caller", "UPDATE", 11)
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, answer)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	request, answer = recoveryAtSequence(invite, "caller", "UPDATE", 12)
	_ = submitDerivation(t, bridge, registry, request)
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
}

func TestNegotiationRecoveryEitherParticipantUsesOwnSequenceSpace(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, initiator := range []string{"caller", "callee"} {
			for _, method := range []string{"INVITE", "UPDATE"} {
				for _, responseFirst := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/response-first-%v", policy, initiator, method, responseFirst), func(t *testing.T) {
						bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
						invite, response, prack := faultyReliableSequence("separate-sequence-spaces", "partial-prack")
						invite.CSeqNumber, response.CSeqNumber, prack.CSeqNumber = 700, 700, 701
						invite.Headers = map[string]string{"cseq": "700 INVITE", "supported": "100rel"}
						response.Headers = map[string]string{"cseq": "700 INVITE", "require": "100rel", "rseq": "101"}
						prack.Headers = map[string]string{"cseq": "701 PRACK", "rack": "101 700 INVITE"}
						_ = submitDerivation(t, bridge, registry, invite)
						_ = submitDerivation(t, bridge, registry, response)
						_ = submitDerivation(t, bridge, registry, prack)
						final := response
						final.ResponseCode, final.SDP, final.Headers = 200, nil, map[string]string{"cseq": "700 INVITE"}
						_ = submitDerivation(t, bridge, registry, final)
						assertDerivationState(t, bridge, controller, policy, true)
						cseq := uint64(702)
						if initiator == "callee" {
							cseq = 3
						}
						request, answer := recoveryAtSequence(invite, initiator, method, cseq)
						if responseFirst {
							_ = submitDerivation(t, bridge, registry, answer)
							assertDerivationState(t, bridge, controller, policy, true)
							require.NoError(t, submitDerivation(t, bridge, registry, request))
						} else {
							_ = submitDerivation(t, bridge, registry, request)
							assertDerivationState(t, bridge, controller, policy, true)
							require.NoError(t, submitDerivation(t, bridge, registry, answer))
						}
						assertDerivationState(t, bridge, controller, policy, false)
						retirementOwns(t, registry, invite.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
					})
				}
			}
		}
	}
}

func TestNegotiationRecoveryCalleeInvalidExchangeCannotRepair(t *testing.T) {
	for _, invalid := range []string{"partial-request", "partial-answer", "unconfirmed", "rejected", "wrong-dialog", "wrong-transaction", "missing-establishment", "conflicting-request"} {
		t.Run(invalid, func(t *testing.T) {
			bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			invite, response, prack := faultyReliableSequence("invalid-callee-recovery", "partial-prack")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			if invalid != "missing-establishment" {
				establishFaultyReliable(t, bridge, registry, response, invite, false)
			}
			request, answer := recoveryAtSequence(invite, "callee", "INVITE", 3)
			switch invalid {
			case "partial-request":
				request.SDP = derivationSDP("192.0.2.2", 40000, true)
			case "partial-answer":
				answer.SDP = derivationSDP("192.0.2.1", 30000, true)
			case "rejected":
				answer.ResponseCode, answer.SDP = 488, nil
			case "wrong-dialog":
				request.FromTag, answer.FromTag = "unrelated-peer", "unrelated-peer"
			case "wrong-transaction":
				answer.ViaBranch = "unrelated-branch"
			case "conflicting-request":
				request = recoveryDuplicateCSeq(t, request, "9 INVITE", "3 INVITE")
			}
			_ = submitDerivation(t, bridge, registry, request)
			if invalid != "unconfirmed" {
				_ = submitDerivation(t, bridge, registry, answer)
			}
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
		})
	}
}

func TestNegotiationRecoveryRepeatedReliableSDPKeepsResolvedBody(t *testing.T) {
	for _, order := range []string{"response-first", "prack-first"} {
		for _, changed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/changed-%v", order, changed), func(t *testing.T) {
				bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
				invite, response, prack := reliableSequence("repeated-reliable-body")
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, response)
				require.NoError(t, submitDerivation(t, bridge, registry, prack))
				later := response
				later.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "102"}
				if changed {
					later.SDP = derivationSDP("192.0.2.2", 22000, false)
				}
				ack := prack
				ack.CSeqNumber, ack.ViaBranch, ack.SDP = 3, "later-prack", nil
				ack.Headers = map[string]string{"cseq": "3 PRACK", "rack": "102 1 INVITE"}
				if order == "response-first" {
					_ = submitDerivation(t, bridge, registry, later)
					assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
					_ = submitDerivation(t, bridge, registry, ack)
				} else {
					_ = submitDerivation(t, bridge, registry, ack)
					_ = submitDerivation(t, bridge, registry, later)
				}
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, changed)
			})
		}
	}
}

func TestNegotiationRecoveryWinningForkDoesNotMixLosingProof(t *testing.T) {
	for _, winnerFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("winner-first-%v", winnerFirst), func(t *testing.T) {
			bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			invite, winner, prack := reliableSequence("fork-selection")
			loser := winner
			loser.ToTag, loser.SDP = "losing-peer", derivationSDP("192.0.2.9", 25000, false)
			_ = submitDerivation(t, bridge, registry, invite)
			if winnerFirst {
				_ = submitDerivation(t, bridge, registry, winner)
				_ = submitDerivation(t, bridge, registry, loser)
			} else {
				_ = submitDerivation(t, bridge, registry, loser)
				_ = submitDerivation(t, bridge, registry, winner)
			}
			_ = submitDerivation(t, bridge, registry, prack)
			final := winner
			final.ResponseCode, final.SDP, final.Headers = 200, nil, map[string]string{"cseq": "1 INVITE"}
			require.NoError(t, submitDerivation(t, bridge, registry, final))
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
			retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
			// Losing fork's answer cannot overwrite the winner's resolved offer/answer.
			stale := prack
			stale.ToTag = "losing-peer"
			_ = submitDerivation(t, bridge, registry, stale)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
		})
	}
}

func TestNegotiationRecoveryMultipleSuccessfulForksRemainConservative(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite, response, prack := reliableSequence("multiple-successful-forks")
	_ = submitDerivation(t, bridge, registry, invite)
	for index, peer := range []string{"to", "other-peer"} {
		provisional := response
		provisional.ToTag, provisional.SDP = peer, derivationSDP("192.0.2.2", 20000+index*2000, false)
		_ = submitDerivation(t, bridge, registry, provisional)
		answer := prack
		answer.ToTag, answer.ViaBranch = peer, "prack-"+peer
		_ = submitDerivation(t, bridge, registry, answer)
		final := provisional
		final.ResponseCode, final.SDP, final.Headers = 200, nil, map[string]string{"cseq": "1 INVITE"}
		_ = submitDerivation(t, bridge, registry, final)
	}
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}

func TestNegotiationRecoveryExactTagLifetimeReuseRejectsOldPRACK(t *testing.T) {
	for _, order := range []string{"stale-before-new-response", "stale-after-new-response"} {
		t.Run(order, func(t *testing.T) {
			bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			invite, response, prack := reliableSequence("identical-tag-reuse")
			captured := time.Now().Add(-time.Minute)
			invite.Timestamp, response.Timestamp, prack.Timestamp = captured, captured, captured
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			require.NoError(t, submitDerivation(t, bridge, registry, prack))
			old, _ := registry.Call(invite.CallID)
			registry.Remove(invite.CallID, callregistry.EndCompleted)
			replacement := invite
			replacement.Timestamp = time.Now()
			_ = submitDerivation(t, bridge, registry, replacement)
			current, _ := registry.Call(invite.CallID)
			require.NotEqual(t, old.Lifetime, current.Lifetime)
			fresh := response
			fresh.Timestamp = replacement.Timestamp
			if strings.HasPrefix(order, "stale-before") {
				_ = submitDerivation(t, bridge, registry, prack)
				_ = submitDerivation(t, bridge, registry, fresh)
			} else {
				_ = submitDerivation(t, bridge, registry, fresh)
				_ = submitDerivation(t, bridge, registry, prack)
			}
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			// Even an identical replay stamped after reuse lacks fresh transaction
			// authority; a capture timestamp alone cannot establish new lifetime proof.
			replay := prack
			replay.Timestamp = time.Now()
			_ = submitDerivation(t, bridge, registry, replay)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
		})
	}
}

func TestNegotiationRecoveryPartialAndDelayedOfferUseCommonSupersession(t *testing.T) {
	for _, uncertainty := range []string{"partial-offer", "partial-answer", "missing-delayed-answer"} {
		for _, initiator := range []string{"caller", "callee"} {
			t.Run(uncertainty+"/"+initiator, func(t *testing.T) {
				bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
				invite := offer("common-negotiation-recovery")
				invite.Headers = map[string]string{"cseq": "1 INVITE"}
				answer := invite
				answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
				answer.SDP = derivationSDP("192.0.2.2", 20000, false)
				switch uncertainty {
				case "partial-offer":
					invite.SDP = derivationSDP("192.0.2.1", 10000, true)
				case "partial-answer":
					answer.SDP = derivationSDP("192.0.2.2", 20000, true)
				case "missing-delayed-answer":
					invite.SDP = nil
				}
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, answer)
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
				request, response := recoveryAtSequence(invite, initiator, "UPDATE", 3)
				_ = submitDerivation(t, bridge, registry, request)
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
				require.NoError(t, submitDerivation(t, bridge, registry, response))
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
			})
		}
	}
}

func TestNegotiationRecoveryDoesNotClearIndependentDialogConflict(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite := retirementHealthyCall(t, bridge, registry, "invite-answer")
	independent := invite
	independent.FromTag, independent.ToTag, independent.ViaBranch = "independent-origin", "independent-peer", "independent-invite"
	independent.SDP = derivationSDP("192.0.2.8", 18000, false)
	independent = recoveryDuplicateCSeq(t, independent, "9 INVITE", "1 INVITE")
	_ = submitDerivation(t, bridge, registry, independent)
	request, response := recoveryAtSequence(invite, "caller", "UPDATE", 20)
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, response)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	retirementOwns(t, registry, invite.CallID, "192.0.2.8:18000")
}

func TestNegotiationRecoveryCalleeFreshnessTracksItsOwnWatermark(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite := retirementHealthyCall(t, bridge, registry, "invite-answer")
	previous, previousAnswer := recoveryAtSequence(invite, "callee", "UPDATE", 50)
	_ = submitDerivation(t, bridge, registry, previous)
	require.NoError(t, submitDerivation(t, bridge, registry, previousAnswer))
	faulty, response, prack := faultyReliableSequence(invite.CallID, "partial-prack")
	faulty.CSeqNumber, response.CSeqNumber, prack.CSeqNumber = 700, 700, 701
	faulty.ToTag = "to"
	faulty.ViaBranch, response.ViaBranch = "later-caller-fault", "later-caller-fault"
	faulty.Headers = map[string]string{"cseq": "700 INVITE", "supported": "100rel"}
	response.Headers = map[string]string{"cseq": "700 INVITE", "require": "100rel", "rseq": "101"}
	prack.Headers = map[string]string{"cseq": "701 PRACK", "rack": "101 700 INVITE"}
	_ = submitDerivation(t, bridge, registry, faulty)
	_ = submitDerivation(t, bridge, registry, response)
	_ = submitDerivation(t, bridge, registry, prack)
	final := response
	final.ResponseCode, final.SDP, final.Headers = 200, nil, map[string]string{"cseq": "700 INVITE"}
	_ = submitDerivation(t, bridge, registry, final)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	_ = submitDerivation(t, bridge, registry, previous)
	_ = submitDerivation(t, bridge, registry, previousAnswer)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	request, answer := recoveryAtSequence(invite, "callee", "UPDATE", 51)
	_ = submitDerivation(t, bridge, registry, request)
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
}

func TestNegotiationRecoveryPendingOldProofCannotBeAdoptedAfterReuse(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite, response, prack := reliableSequence("pending-exact-tag-reuse")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	old, _ := registry.Call(invite.CallID)
	require.NoError(t, bridge.ObserveValidatedReceipt(&prack))
	registry.Remove(invite.CallID, callregistry.EndCompleted)
	// No selection consumed the old pending PRACK. A later selection with the
	// same tags and reliable transaction must not adopt its released reservation.
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	current, _ := registry.Call(invite.CallID)
	require.NotEqual(t, old.Lifetime, current.Lifetime)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}

func TestNegotiationRecoveryRetiredInitiatorWatermarkIsBoundedAndCharged(t *testing.T) {
	bridge, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	original := callregistry.Lifetime{Session: 1, Generation: 1}
	side := derivationSide{sender: "from", peer: "to", initiator: "from"}
	old := &selectedCall{lifetime: original, derivations: map[derivationSide]*derivationState{
		side: {cseq: 700, method: "INVITE", prackCSeq: 701},
		{sender: "to", peer: "from", initiator: "from"}: {cseq: 700, method: "INVITE"},
	}}
	before := bridge.cfg.Metadata.Stats()
	require.NoError(t, bridge.rememberLifetimeLocked("watermark-test", old))
	charged := bridge.cfg.Metadata.Stats()
	require.Len(t, bridge.proofHistory.initiators, 1)
	require.Equal(t, before.SelectedContexts, charged.SelectedContexts, "replay history has a separate budget")
	require.Equal(t, before.SelectedBytes, charged.SelectedBytes)
	require.Equal(t, before.SelectedEndpoints, charged.SelectedEndpoints, "history keeps no media ownership")
	require.NoError(t, bridge.rememberLifetimeLocked("watermark-test", old))
	require.Equal(t, charged, bridge.cfg.Metadata.Stats(), "repeated retirement does not duplicate charge")
	current := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 2}}
	key := mediaadmission.DialogKey{CallID: "watermark-test", FromTag: "from", ToTag: "to", CSeq: 701, CSeqMethod: "PRACK", CSeqValid: true, RAckValid: true, RAckCSeq: 700}
	require.False(t, bridge.checkKeyLifetimeLocked(current, key))
	require.True(t, current.lifetimeAmbiguous)
	key.CSeqMethod, key.CSeq = "INVITE", 701
	require.False(t, bridge.canConfirmedLifetimeLocked(current, key), "equal old own-side maximum is stale")
	key.CSeq = 702
	require.True(t, bridge.canConfirmedLifetimeLocked(current, key), "freshness guard does not compare the other participant")
	key.FromTag, key.CSeq = "to", 3
	require.True(t, bridge.canConfirmedLifetimeLocked(current, key), "caller maximum is not a callee watermark")
	key.LifetimeSession, key.LifetimeGeneration = original.Session, original.Generation
	require.False(t, bridge.checkKeyLifetimeLocked(current, key), "explicit old provenance overrides a higher sequence")
	require.False(t, bridge.canConfirmedLifetimeLocked(current, key))
	require.NoError(t, bridge.releaseLifetimeProofLocked())
	require.Equal(t, before, bridge.cfg.Metadata.Stats())
}

func TestNegotiationRecoveryRetiredWatermarkExhaustionExpires(t *testing.T) {
	bridge, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	cfg := bridge.cfg.Limits
	bridge.cfg.Limits.ReplayGuardCapacity = 1
	cfg.ReplayGuardCapacity = 1
	cfg.PendingDialogCapacity, cfg.PendingBytes = 1, lifetimeProofEntryBytes
	store, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	bridge.cfg.Metadata = store
	old := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 1}, derivations: map[derivationSide]*derivationState{
		{sender: "from", peer: "to", initiator: "from"}: {cseq: 1, method: "INVITE"},
	}}
	require.NoError(t, bridge.rememberLifetimeLocked("first-retired-call", old))
	require.ErrorIs(t, bridge.rememberLifetimeLocked("second-retired-call", old), mediaadmission.ErrCapacity)
	require.Len(t, bridge.proofHistory.initiators, 1, "capacity failure preserves the original anti-replay watermark")
	require.True(t, time.Now().Before(bridge.proofHistory.blockedUntil))
	current := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 2}}
	key := mediaadmission.DialogKey{CallID: "second-retired-call", FromTag: "from", CSeq: 9, CSeqMethod: "INVITE", CSeqValid: true}
	require.False(t, bridge.observeSelectedRecordLocked(current, mediaadmission.MetadataRecord{Key: key, Complete: true}), "missing replay evidence is quarantined without authorization")
	require.False(t, bridge.canConfirmedLifetimeLocked(current, key), "a clean message cannot recreate exhausted provenance")
	require.False(t, current.lifetimeAmbiguous)
	require.False(t, current.replayBlockedUntil.IsZero())
	bridge.expireLifetimeProofLocked(time.Now().Add(bridge.cfg.Limits.ReplayWindow + time.Second))
	require.True(t, bridge.checkKeyLifetimeLocked(current, key))
	require.True(t, bridge.canConfirmedLifetimeLocked(current, key))
	require.Equal(t, 0, store.Stats().SelectedContexts)
	require.Zero(t, store.Stats().SelectedBytes)
	require.NoError(t, bridge.releaseLifetimeProofLocked())
	require.Zero(t, store.Stats().SelectedContexts)
	require.Zero(t, store.Stats().SelectedBytes)
}

func TestNegotiationRecoveryRetirementTransfersFullReservation(t *testing.T) {
	bridge, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	side := derivationSide{sender: "from", peer: "to", initiator: "from"}
	state := &derivationState{cseq: 1, method: "INVITE", branch: "initial-transaction"}
	bytes, endpoints := derivationCost(side, state)
	cfg := bridge.cfg.Limits
	cfg.PendingDialogCapacity, cfg.PendingBytes = 1, bytes
	store, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	bridge.cfg.Metadata = store
	old := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 1}}
	require.True(t, bridge.putDerivation(old, side, state))
	require.Equal(t, 1, store.Stats().SelectedContexts)
	require.Equal(t, bytes, store.Stats().SelectedBytes)
	require.Equal(t, endpoints, store.Stats().SelectedEndpoints)
	require.NoError(t, bridge.retireLifetimeLocked("full-reservation-retirement", old))
	require.Empty(t, old.derivations)
	require.True(t, bridge.proofHistory.blockedUntil.IsZero(), "old live context releases before historical reservation")
	require.Zero(t, store.Stats().SelectedContexts)
	require.Zero(t, store.Stats().SelectedBytes)
	require.Zero(t, store.Stats().SelectedEndpoints)
	require.Zero(t, store.Stats().SelectedRejected)
	require.NoError(t, bridge.releaseLifetimeProofLocked())
	require.Zero(t, store.Stats().SelectedContexts)
	require.Zero(t, store.Stats().SelectedBytes)
}

func TestNegotiationRecoveryMissingRetiredEvidenceCannotInventFreshness(t *testing.T) {
	bridge, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	old := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 1}, contextLost: true}
	require.NoError(t, bridge.retireLifetimeLocked("missing-retired-evidence", old))
	require.True(t, bridge.proofHistory.blockedUntil.IsZero(), "missing bounds are scoped to their hashed call")
	require.True(t, bridge.retiredCallBlockedLocked("missing-retired-evidence"))
	current := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 2}}
	key := mediaadmission.DialogKey{CallID: "missing-retired-evidence", FromTag: "from", CSeq: 90, CSeqMethod: "INVITE", CSeqValid: true}
	require.False(t, bridge.checkKeyLifetimeLocked(current, key))
	require.False(t, bridge.canConfirmedLifetimeLocked(current, key))
	require.True(t, current.lifetimeAmbiguous)
	key.CallID = "unrelated-fresh-call"
	fresh := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 3}}
	require.True(t, bridge.checkKeyLifetimeLocked(fresh, key))
	require.True(t, bridge.canConfirmedLifetimeLocked(fresh, key))
	require.False(t, fresh.lifetimeAmbiguous)
}

func TestNegotiationRecoveryMalformedRetiredBoundsAreScopedToInitiator(t *testing.T) {
	bridge, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	old := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 1}, derivations: map[derivationSide]*derivationState{
		{sender: "from", peer: "to", initiator: "from"}: {cseq: 1, method: "INVITE", conflict: true, conflictBoundValid: false},
	}}
	before := bridge.cfg.Metadata.Stats()
	require.NoError(t, bridge.rememberLifetimeLocked("malformed-retired-bounds", old))
	require.True(t, bridge.proofHistory.blockedUntil.IsZero(), "malformed transaction does not cause global evidence loss")
	require.Equal(t, before.SelectedContexts, bridge.cfg.Metadata.Stats().SelectedContexts)
	require.Equal(t, before.SelectedBytes, bridge.cfg.Metadata.Stats().SelectedBytes)
	key := mediaadmission.DialogKey{CallID: "malformed-retired-bounds", FromTag: "from", CSeq: 100, CSeqMethod: "INVITE", CSeqValid: true}
	current := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 2}}
	require.False(t, bridge.checkKeyLifetimeLocked(current, key), "same initiator has no reliable freshness bound")
	require.False(t, bridge.canConfirmedLifetimeLocked(current, key))
	for _, separate := range []struct{ callID, fromTag string }{{"unrelated-fresh-call", "from"}, {"malformed-retired-bounds", "different-origin"}} {
		key.CallID, key.FromTag = separate.callID, separate.fromTag
		fresh := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 3}}
		require.True(t, bridge.checkKeyLifetimeLocked(fresh, key))
		require.True(t, bridge.canConfirmedLifetimeLocked(fresh, key), "this is only a freshness guard; dialog confirmation remains required")
		require.False(t, fresh.lifetimeAmbiguous)
	}
	require.NoError(t, bridge.releaseLifetimeProofLocked())
	require.Equal(t, before, bridge.cfg.Metadata.Stats())
}

func TestNegotiationRecoveryRepeatedAcknowledgmentRaisesRetiredWatermark(t *testing.T) {
	bridge, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	old := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 1}, derivations: map[derivationSide]*derivationState{
		{sender: "from", peer: "to", initiator: "from"}: {cseq: 1, method: "INVITE", prackCSeq: 2, repeatedAckSequence: 12},
	}}
	require.NoError(t, bridge.rememberLifetimeLocked("repeated-ack-watermark", old))
	current := &selectedCall{lifetime: callregistry.Lifetime{Session: 1, Generation: 2}}
	key := mediaadmission.DialogKey{CallID: "repeated-ack-watermark", FromTag: "from", CSeq: 12, CSeqMethod: "INVITE", CSeqValid: true}
	require.False(t, bridge.checkKeyLifetimeLocked(current, key))
	require.False(t, bridge.canConfirmedLifetimeLocked(current, key))
	key.CSeq = 13
	require.True(t, bridge.canConfirmedLifetimeLocked(current, key))
}

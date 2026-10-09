package admission

import (
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

func ordinaryACKReplacement(invite pipeline.SIPResult, initiator string) (pipeline.SIPResult, pipeline.SIPResult, pipeline.SIPResult) {
	request, response := recoveryAtSequence(invite, initiator, "INVITE", 20)
	request.SDP = nil
	ack := request
	ack.Method, ack.CSeqMethod, ack.ViaBranch = "ACK", "ACK", "ordinary-answer-ack"
	ack.Headers = map[string]string{"cseq": "20 ACK"}
	ack.SDP = derivationSDP("192.0.2.1", 30000, false)
	if initiator == "callee" {
		ack.SDP = derivationSDP("192.0.2.2", 40000, false)
	}
	return request, response, ack
}

func TestOrdinaryDelayedACKCompleteConfirmedRepair(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, initiator := range []string{"caller", "callee"} {
			for _, fault := range []string{"partial-offer", "conflicting-cseq", "faulty-prack"} {
				for _, responseFirst := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/response-first-%v", policy, initiator, fault, responseFirst), func(t *testing.T) {
						bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
						var invite pipeline.SIPResult
						if fault == "faulty-prack" {
							request, response, prack := faultyReliableSequence("ordinary-ack-repair", "partial-prack")
							invite = request
							_ = submitDerivation(t, bridge, registry, request)
							_ = submitDerivation(t, bridge, registry, response)
							_ = submitDerivation(t, bridge, registry, prack)
							establishFaultyReliable(t, bridge, registry, response, request, false)
						} else {
							invite = offer("ordinary-ack-repair")
							invite.Headers = map[string]string{"cseq": "1 INVITE"}
							if fault == "partial-offer" {
								invite.SDP = derivationSDP("192.0.2.1", 10000, true)
							} else {
								invite = recoveryDuplicateCSeq(t, invite, "9 INVITE", "1 INVITE")
							}
							answer := invite
							answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
							answer.Headers = map[string]string{"cseq": "1 INVITE"}
							answer.DuplicateReliableHeaders = pipeline.SIPResult{}.DuplicateReliableHeaders
							answer.ReliableHeaderEvidence = pipeline.SIPResult{}.ReliableHeaderEvidence
							answer.SDP = derivationSDP("192.0.2.2", 20000, false)
							_ = submitDerivation(t, bridge, registry, invite)
							_ = submitDerivation(t, bridge, registry, answer)
						}
						assertDerivationState(t, bridge, controller, policy, true)
						request, response, ack := ordinaryACKReplacement(invite, initiator)
						if responseFirst {
							_ = submitDerivation(t, bridge, registry, response)
							_ = submitDerivation(t, bridge, registry, request)
						} else {
							_ = submitDerivation(t, bridge, registry, request)
							_ = submitDerivation(t, bridge, registry, response)
						}
						assertDerivationState(t, bridge, controller, policy, true)
						require.NoError(t, submitDerivation(t, bridge, registry, ack))
						assertDerivationState(t, bridge, controller, policy, false)
						retirementOwns(t, registry, invite.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
						require.NoError(t, submitDerivation(t, bridge, registry, ack), "exact ACK retransmission remains valid")
						assertDerivationState(t, bridge, controller, policy, false)
					})
				}
			}
		}
	}
}

func TestOrdinaryDelayedACKInvalidRepairRemainsUnknown(t *testing.T) {
	for _, initiator := range []string{"caller", "callee"} {
		for _, invalid := range []string{"partial-ack", "partial-offer", "wrong-dialog", "wrong-sequence", "wrong-response-branch", "rejected-response", "conflicting-ack", "missing-request", "missing-response"} {
			t.Run(initiator+"/"+invalid, func(t *testing.T) {
				bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
				invite, response, prack := faultyReliableSequence("invalid-ordinary-ack-repair", "partial-prack")
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, response)
				_ = submitDerivation(t, bridge, registry, prack)
				establishFaultyReliable(t, bridge, registry, response, invite, false)
				request, offer, ack := ordinaryACKReplacement(invite, initiator)
				switch invalid {
				case "partial-ack":
					ack.SDP = derivationSDP("192.0.2.1", 30000, true)
				case "partial-offer":
					offer.SDP = derivationSDP("192.0.2.2", 40000, true)
				case "wrong-dialog":
					ack.ToTag = "unrelated-peer"
				case "wrong-sequence":
					ack.CSeqNumber, ack.Headers = 19, map[string]string{"cseq": "19 ACK"}
				case "wrong-response-branch":
					offer.ViaBranch = "unrelated-transaction"
				case "rejected-response":
					offer.ResponseCode, offer.SDP = 488, nil
				case "conflicting-ack":
					ack = recoveryDuplicateCSeq(t, ack, "21 ACK", "20 ACK")
				}
				if invalid != "missing-request" {
					_ = submitDerivation(t, bridge, registry, request)
				}
				if invalid != "missing-response" {
					_ = submitDerivation(t, bridge, registry, offer)
				}
				_ = submitDerivation(t, bridge, registry, ack)
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			})
		}
	}
}

func TestOrdinaryDelayedACKCannotReplaceRequiredReliablePRACK(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite, response, _ := reliableSequence("strict-required-prack")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	establishFaultyReliable(t, bridge, registry, response, invite, true)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}

// A parsed branch is a substring of the SIP header block. Persisting it must
// own only the charged short value, rather than the entire unrelated payload.
func TestOrdinaryDelayedACKRetainsOwnedBranchStorage(t *testing.T) {
	bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	initial := retirementHealthyCall(t, bridge, registry, "invite-answer")
	request, response, ack := ordinaryACKReplacement(initial, "caller")
	_ = submitDerivation(t, bridge, registry, request)
	_ = submitDerivation(t, bridge, registry, response)
	wire := "ACK sip:service@example.test SIP/2.0\r\nVia: SIP/2.0/UDP example.test;branch=owned-delayed-ack\r\nCSeq: 20 ACK\r\nX-Padding: " + strings.Repeat("x", 48*1024) + "\r\nContent-Length: 0\r\n\r\n"
	parsed, err := sip.Parse([]byte(wire), sip.ParseOptions{})
	require.NoError(t, err)
	ack.Headers, ack.ViaBranch = parsed.Headers, parsed.ViaBranch
	require.NoError(t, selectedReceiptFixture(bridge, ack), "direct validated metadata must own the branch even without pending staging")
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	stored := bridge.selected[initial.CallID].derivations[derivationSide{ack.FromTag, ack.ToTag, ack.FromTag, false}]
	require.NotNil(t, stored)
	require.Equal(t, parsed.ViaBranch, stored.delayedAckBranch)
	if unsafe.StringData(parsed.ViaBranch) == unsafe.StringData(stored.delayedAckBranch) {
		t.Fatal("retained ACK branch still shares the large parser header allocation")
	}
}

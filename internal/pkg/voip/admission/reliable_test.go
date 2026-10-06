package admission

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func reliableSequence(callID string) (pipeline.SIPResult, pipeline.SIPResult, pipeline.SIPResult) {
	invite := offer(callID)
	invite.SDP = nil
	invite.Headers = map[string]string{"cseq": "1 INVITE", "supported": "100rel"}
	response := invite
	response.Method, response.ResponseCode, response.ToTag = "RESPONSE", 183, "to"
	response.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "101"}
	response.SDP = derivationSDP("192.0.2.2", 20000, false)
	prack := invite
	prack.Method, prack.CSeqMethod, prack.CSeqNumber, prack.ViaBranch, prack.ToTag = "PRACK", "PRACK", 2, "prack-branch", "to"
	prack.Headers = map[string]string{"cseq": "2 PRACK", "rack": "101 1 INVITE"}
	prack.SDP = derivationSDP("192.0.2.1", 10000, false)
	return invite, response, prack
}

func TestReliableDelayedOfferPRACKRecovery(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, policy, nil)
			invite, response, prack := reliableSequence("reliable-answer")
			require.Error(t, submitDerivation(t, bridge, registry, invite))
			require.Error(t, submitDerivation(t, bridge, registry, response))
			assertDerivationState(t, bridge, controller, policy, true)
			require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
			require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.9:30000", "192.0.2.1:30002").CallID)
			require.NoError(t, submitDerivation(t, bridge, registry, prack))
			assertDerivationState(t, bridge, controller, policy, false)
			assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:20000", "192.0.2.2:20001")
			final := response
			final.ResponseCode, final.SDP, final.Headers = 200, nil, nil
			require.NoError(t, submitDerivation(t, bridge, registry, final))
			ack := invite
			ack.Method, ack.CSeqMethod, ack.ToTag, ack.ViaBranch = "ACK", "ACK", "to", "ack-branch"
			require.NoError(t, submitDerivation(t, bridge, registry, ack))
			assertDerivationState(t, bridge, controller, policy, false)
		})
	}
}

func TestReliableAnswerProofFailuresRemainUnknown(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, invalid := range []string{"missing-require", "missing-rseq", "zero-rseq", "first-rseq-overflow", "wrong-rseq", "missing-rack", "malformed-rack", "wrong-rack-cseq", "wrong-rack-method", "lowercase-method", "own-cseq-invalid", "own-cseq-not-higher", "wrong-fork", "wrong-origin", "partial-answer", "prack-new-offer", "response-branch", "unreliable-180"} {
			t.Run(string(policy)+"/"+invalid, func(t *testing.T) {
				bridge, registry, _, controller := recoveryFixture(t, policy, nil)
				invite, response, prack := reliableSequence(invalid)
				switch invalid {
				case "missing-require":
					delete(response.Headers, "require")
				case "missing-rseq":
					delete(response.Headers, "rseq")
				case "zero-rseq":
					response.Headers["rseq"] = "0"
				case "first-rseq-overflow":
					response.Headers["rseq"], prack.Headers["rack"] = "2147483648", "2147483648 1 INVITE"
				case "wrong-rseq":
					prack.Headers["rack"] = "102 1 INVITE"
				case "missing-rack":
					delete(prack.Headers, "rack")
				case "malformed-rack":
					prack.Headers["rack"] = "101 1 INVITE extra"
				case "wrong-rack-cseq":
					prack.Headers["rack"] = "101 3 INVITE"
				case "wrong-rack-method":
					prack.Headers["rack"] = "101 1 UPDATE"
				case "lowercase-method":
					prack.Headers["rack"] = "101 1 invite"
				case "own-cseq-invalid":
					prack.Headers["cseq"] = "2147483648 PRACK"
				case "own-cseq-not-higher":
					prack.Headers["cseq"], prack.CSeqNumber = "1 PRACK", 1
				case "wrong-fork":
					prack.ToTag = "other-peer"
				case "wrong-origin":
					prack.FromTag = "other-origin"
				case "partial-answer":
					prack.SDP = derivationSDP("192.0.2.1", 10000, true)
				case "prack-new-offer":
					invite.SDP = derivationSDP("192.0.2.1", 30000, false)
				case "response-branch":
					response.ViaBranch = "other-invite"
				case "unreliable-180":
					response.ResponseCode = 180
					delete(response.Headers, "require")
				}
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, response)
				require.Error(t, submitDerivation(t, bridge, registry, prack))
				assertDerivationState(t, bridge, controller, policy, true)
				require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID, "safe answer endpoints remain independently attributable")
				require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.9:30000", "192.0.2.1:30002").CallID)
			})
		}
	}
}

func TestReliableAnswerArrivalOrderAndRetransmissions(t *testing.T) {
	for _, order := range []string{"invite-response-answer", "invite-answer-response", "response-answer-invite", "answer-invite-response"} {
		t.Run(order, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := reliableSequence(order)
			messages := []pipeline.SIPResult{invite, response, prack}
			switch order {
			case "invite-answer-response":
				messages = []pipeline.SIPResult{invite, prack, response}
			case "response-answer-invite":
				messages = []pipeline.SIPResult{response, prack, invite}
			case "answer-invite-response":
				messages = []pipeline.SIPResult{prack, invite, response}
			}
			for index, message := range messages {
				_ = submitDerivation(t, bridge, registry, message)
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, index != len(messages)-1)
			}
			for index := 0; index < 3; index++ {
				require.NoError(t, submitDerivation(t, bridge, registry, response))
				require.NoError(t, submitDerivation(t, bridge, registry, prack))
				final := response
				final.ResponseCode = 200
				require.NoError(t, submitDerivation(t, bridge, registry, final))
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
			}
		})
	}
}

func TestReliableConflictingProofCannotOverwriteAnswer(t *testing.T) {
	for _, conflict := range []string{"response-rseq", "response-body", "answer-body", "answer-rack", "answer-branch", "final-body"} {
		t.Run(conflict, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
			invite, response, prack := reliableSequence(conflict)
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			require.NoError(t, submitDerivation(t, bridge, registry, prack))
			changed := response
			switch conflict {
			case "response-rseq":
				changed.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "103"}
			case "response-body":
				changed.SDP = append(append([]byte(nil), response.SDP...), []byte("a=sendrecv\r\n")...)
			case "answer-body":
				changed = prack
				changed.SDP = append(append([]byte(nil), prack.SDP...), []byte("a=sendrecv\r\n")...)
			case "answer-rack":
				changed = prack
				changed.Headers = map[string]string{"cseq": "2 PRACK", "rack": "102 1 INVITE"}
			case "answer-branch":
				changed = prack
				changed.ViaBranch = "conflicting-prack"
			case "final-body":
				changed.ResponseCode = 200
				changed.SDP = derivationSDP("192.0.2.2", 40000, false)
			}
			require.Error(t, submitDerivation(t, bridge, registry, changed))
			assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, true)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, true)
		})
	}
}

func TestReliablePRACKThenUPDATEIsANewOffer(t *testing.T) {
	for _, beforeAnswer := range []bool{true, false} {
		t.Run(fmt.Sprint(beforeAnswer), func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := reliableSequence("update-new-offer")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			if !beforeAnswer {
				require.NoError(t, submitDerivation(t, bridge, registry, prack))
			}
			update := prack
			update.Method, update.CSeqMethod, update.CSeqNumber, update.ViaBranch, update.Headers = "UPDATE", "UPDATE", 3, "update-branch", map[string]string{"cseq": "3 UPDATE"}
			update.SDP = derivationSDP("192.0.2.1", 30000, false)
			_ = submitDerivation(t, bridge, registry, update)
			answer := update
			answer.Method, answer.ResponseCode = "RESPONSE", 200
			answer.SDP = derivationSDP("192.0.2.2", 40000, false)
			_ = submitDerivation(t, bridge, registry, answer)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, beforeAnswer)
			if !beforeAnswer {
				assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:30000", "192.0.2.1:30001", "192.0.2.2:40000", "192.0.2.2:40001")
				require.NoError(t, submitDerivation(t, bridge, registry, prack))
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
			}
		})
	}
}

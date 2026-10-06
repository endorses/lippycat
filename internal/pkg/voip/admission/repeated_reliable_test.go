package admission

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRepeatedReliableAcknowledgmentRetainsExactLinkage(t *testing.T) {
	for _, order := range []string{"response-first", "ack-first"} {
		t.Run(order, func(t *testing.T) {
			bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			invite, response, prack := reliableSequence("repeat-linkage")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			require.NoError(t, submitDerivation(t, bridge, registry, prack))
			later := response
			later.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "102"}
			ack := prack
			ack.CSeqNumber, ack.ViaBranch, ack.SDP = 3, "repeated-ack", nil
			ack.Headers = map[string]string{"cseq": "3 PRACK", "rack": "102 1 INVITE"}
			if order == "ack-first" {
				require.NoError(t, submitDerivation(t, bridge, registry, ack))
			}
			if order == "response-first" {
				require.Error(t, submitDerivation(t, bridge, registry, later))
			} else {
				require.NoError(t, submitDerivation(t, bridge, registry, later))
			}
			bridge.mu.Lock()
			state := bridge.selected[invite.CallID]
			responseSide := derivationSide{"to", "from", "from", false}
			answerSide := derivationSide{"from", "to", "from", true}
			currentResponse := state.derivations[responseSide]
			require.Equal(t, uint32(101), currentResponse.rseq, "original body proof retains its exact RSeq")
			require.Equal(t, uint32(102), currentResponse.repeatedRSeq)
			require.Equal(t, order == "response-first", currentResponse.repeatedPending)
			bridge.mu.Unlock()
			if order == "response-first" {
				wrong := ack
				wrong.Headers = map[string]string{"cseq": "3 PRACK", "rack": "102 9 INVITE"}
				require.Error(t, submitDerivation(t, bridge, registry, wrong))
				bridge.mu.Lock()
				require.True(t, state.derivations[responseSide].repeatedPending)
				bridge.mu.Unlock()
				require.NoError(t, submitDerivation(t, bridge, registry, ack))
			}
			bridge.mu.Lock()
			require.False(t, state.derivations[responseSide].repeatedPending)
			require.Equal(t, uint32(101), state.derivations[answerSide].rackRSeq)
			require.Equal(t, uint64(3), state.derivations[answerSide].repeatedAckSequence)
			require.Equal(t, "repeated-ack", state.derivations[answerSide].repeatedAckBranch)
			// Expired auxiliary proof cannot acknowledge a new reliable transaction.
			answer := *state.derivations[answerSide]
			future := *state.derivations[responseSide]
			request := state.derivations[derivationSide{"from", "to", "from", false}]
			require.True(t, repeatedAckMatches(request, &future, &answer, time.Now()))
			answer.repeatedAckExpires = time.Now().Add(-time.Second)
			require.False(t, repeatedAckMatches(request, &future, &answer, time.Now()))
			answer.repeatedAckExpires = time.Now().Add(time.Minute)
			future.repeatedRSeq = 103
			require.False(t, repeatedAckMatches(request, &future, &answer, time.Now()))
			bridge.mu.Unlock()
		})
	}
}

func TestRepeatedReliableSequenceProgressionAndUpperHalf(t *testing.T) {
	for _, scenario := range []struct {
		name           string
		initial, later uint32
		valid          bool
	}{
		{"skipped-sequence", 101, 103, false},
		{"upper-half-after-valid-first", 1<<31 - 1, 1 << 31, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			invite, response, prack := reliableSequence("repeat-sequence")
			response.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": fmt.Sprint(scenario.initial)}
			prack.Headers = map[string]string{"cseq": "2 PRACK", "rack": fmt.Sprintf("%d 1 INVITE", scenario.initial)}
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			require.NoError(t, submitDerivation(t, bridge, registry, prack))
			later := response
			later.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": fmt.Sprint(scenario.later)}
			err := submitDerivation(t, bridge, registry, later)
			if !scenario.valid {
				require.Error(t, err)
				assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
				return
			}
			require.Error(t, err, "new reliable response awaits its own PRACK")
			ack := prack
			ack.CSeqNumber, ack.ViaBranch, ack.SDP = 3, "upper-ack", nil
			ack.Headers = map[string]string{"cseq": "3 PRACK", "rack": fmt.Sprintf("%d 1 INVITE", scenario.later)}
			require.NoError(t, submitDerivation(t, bridge, registry, ack))
			bridge.mu.Lock()
			state := bridge.selected[invite.CallID].derivations[derivationSide{"to", "from", "from", false}]
			require.Equal(t, scenario.initial, state.rseq)
			require.Equal(t, scenario.later, state.repeatedRSeq)
			require.False(t, state.repeatedPending)
			bridge.mu.Unlock()
		})
	}
}

func TestBodylessPRACKPreservesOrdinaryOfferedAnswer(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite := offer("ordinary-bodyless-prack")
	invite.Headers = map[string]string{"cseq": "1 INVITE"}
	require.NoError(t, submitDerivation(t, bridge, registry, invite))
	answer := invite
	answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 183, "to"
	answer.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "101"}
	answer.SDP = derivationSDP("192.0.2.2", 20000, false)
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
	ack := invite
	ack.Method, ack.CSeqMethod, ack.CSeqNumber, ack.ViaBranch, ack.ToTag, ack.SDP = "PRACK", "PRACK", 2, "ordinary-prack", "to", nil
	ack.Headers = map[string]string{"cseq": "2 PRACK", "rack": "101 1 INVITE"}
	require.NoError(t, submitDerivation(t, bridge, registry, ack))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
}

func TestRepeatedReliableOfferedAnswer(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, order := range []string{"response-first", "ack-first"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, order), func(t *testing.T) {
					bridge, registry, _ := retirementFixture(t, mode, policy)
					invite := offer("offered-repeat")
					invite.Headers = map[string]string{"cseq": "1 INVITE"}
					require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, invite, "")))
					response := invite
					response.Method, response.ResponseCode, response.ToTag = "RESPONSE", 183, "to"
					response.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "101"}
					response.SDP = derivationSDP("192.0.2.2", 20000, false)
					require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, response, "")))
					ack := invite
					ack.Method, ack.CSeqMethod, ack.CSeqNumber, ack.ViaBranch, ack.ToTag, ack.SDP = "PRACK", "PRACK", 2, "first-prack", "to", nil
					ack.Headers = map[string]string{"cseq": "2 PRACK", "rack": "101 1 INVITE"}
					require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, ack, "")))
					later := response
					later.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "102"}
					ack.CSeqNumber, ack.ViaBranch = 3, "second-prack"
					ack.Headers = map[string]string{"cseq": "3 PRACK", "rack": "102 1 INVITE"}
					if order == "ack-first" {
						require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, ack, "")))
					}
					_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, later, ""))
					bridge.mu.Lock()
					call := bridge.selected[invite.CallID]
					responseSide := derivationSide{"to", "from", "from", false}
					require.True(t, call.derivations[responseSide].complete)
					require.Equal(t, order == "response-first", call.derivations[responseSide].repeatedPending)
					bridge.mu.Unlock()
					if order == "response-first" {
						wrong := ack
						wrong.Headers = map[string]string{"cseq": "3 PRACK", "rack": "102 9 INVITE"}
						_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, wrong, ""))
						require.Equal(t, 1, bridge.Stats().UnknownDerivations)
						require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, ack, "")))
					}
					require.Zero(t, bridge.Stats().UnknownDerivations)
					// Same-RSeq and final answer retransmissions retain the original
					// canonical body and the separately acknowledged reliable repeat.
					require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, later, "")))
					final := response
					final.ResponseCode = 200
					final.Headers = map[string]string{"cseq": "1 INVITE"}
					require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, final, "")))
					finalAck := invite
					finalAck.Method, finalAck.CSeqMethod, finalAck.ToTag, finalAck.SDP = "ACK", "ACK", "to", nil
					finalAck.Headers = map[string]string{"cseq": "1 ACK"}
					require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, finalAck, "")))
					require.Zero(t, bridge.Stats().UnknownDerivations)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
				})
			}
		}
	}
}

func TestRepeatedReliableOfferedAnswerRejectsUnrelatedProof(t *testing.T) {
	for _, invalid := range []string{"changed-body", "wrong-rseq", "wrong-cseq", "wrong-method", "malformed-rack", "stale-prack", "separate-fork", "missing-prack", "skipped-rseq"} {
		t.Run(invalid, func(t *testing.T) {
			bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			invite, response, ack := reliableSequence("offered-repeat-invalid")
			invite.SDP, ack.SDP = derivationSDP("192.0.2.1", 10000, false), nil
			require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, invite, "")))
			require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, response, "")))
			require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, ack, "")))
			later := response
			later.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "102"}
			ack.CSeqNumber, ack.ViaBranch = 3, "later-prack"
			ack.Headers = map[string]string{"cseq": "3 PRACK", "rack": "102 1 INVITE"}
			switch invalid {
			case "changed-body":
				later.SDP = derivationSDP("192.0.2.2", 22000, false)
			case "wrong-rseq":
				ack.Headers["rack"] = "103 1 INVITE"
			case "wrong-cseq":
				ack.Headers["rack"] = "102 9 INVITE"
			case "wrong-method":
				ack.Headers["rack"] = "102 1 UPDATE"
			case "malformed-rack":
				ack.Headers["rack"] = "broken"
			case "stale-prack":
				ack.CSeqNumber = 2
				ack.Headers["cseq"] = "2 PRACK"
			case "separate-fork":
				ack.ToTag = "other-peer"
			case "skipped-rseq":
				later.Headers["rseq"], ack.Headers["rack"] = "103", "103 1 INVITE"
			}
			require.Error(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, later, "")))
			if invalid != "missing-prack" {
				_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, ack, ""))
			}
			require.Equal(t, 1, bridge.Stats().UnknownDerivations)
			// A final 200 with identical SDP cannot acknowledge an outstanding
			// reliable provisional or erase changed-answer uncertainty.
			final := later
			final.ResponseCode, final.Headers = 200, map[string]string{"cseq": "1 INVITE"}
			_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, final, ""))
			require.Equal(t, 1, bridge.Stats().UnknownDerivations)
			retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
		})
	}
}

func TestRepeatedReliablePRACKRejectionInvalidatesOnlyAuxiliaryProof(t *testing.T) {
	for _, offered := range []bool{false, true} {
		t.Run(fmt.Sprintf("offered-%t", offered), func(t *testing.T) {
			bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			invite, response, ack := reliableSequence("repeated-prack-rejected")
			if offered {
				invite.SDP, ack.SDP = derivationSDP("192.0.2.1", 10000, false), nil
			}
			_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, invite, ""))
			_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, response, ""))
			require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, ack, "")))
			response.Headers["rseq"] = "102"
			_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, response, ""))
			ack.CSeqNumber, ack.ViaBranch, ack.SDP = 3, "repeated-prack", nil
			ack.Headers = map[string]string{"cseq": "3 PRACK", "rack": "102 1 INVITE"}
			require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, ack, "")))
			require.Zero(t, bridge.Stats().UnknownDerivations)
			rejection := ack
			rejection.Method, rejection.ResponseCode = "RESPONSE", 481
			rejection.Headers = map[string]string{"cseq": "3 PRACK"}
			_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, rejection, ""))
			require.Equal(t, 1, bridge.Stats().UnknownDerivations)
			bridge.mu.Lock()
			call := bridge.selected[invite.CallID]
			require.True(t, call.derivations[derivationSide{"to", "from", "from", false}].repeatedPending)
			require.True(t, call.derivations[derivationSide{"from", "to", "from", false}].complete)
			bridge.mu.Unlock()
			retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
		})
	}
}

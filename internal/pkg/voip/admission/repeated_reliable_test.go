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
			require.NoError(t, submitDerivation(t, bridge, registry, later))
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
				require.NoError(t, submitDerivation(t, bridge, registry, wrong))
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
			require.NoError(t, err)
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

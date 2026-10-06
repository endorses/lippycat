package admission

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

// Parse the complete synthetic message so header classification and propagation
// use the same SIP event adapter as capture processing.
func parseAdmissionWire(t *testing.T, message pipeline.SIPResult, extra string) pipeline.SIPResult {
	t.Helper()
	start := message.Method + " sip:peer@example.test SIP/2.0"
	if message.ResponseCode != 0 {
		start = fmt.Sprintf("SIP/2.0 %d Synthetic", message.ResponseCode)
	}
	wire := fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP example.test;branch=%s\r\nFrom: <sip:caller@example.test>;tag=%s\r\nTo: <sip:peer@example.test>", start, message.ViaBranch, message.FromTag)
	if message.ToTag != "" {
		wire += ";tag=" + message.ToTag
	}
	wire += "\r\nCall-ID: " + message.CallID + "\r\n"
	for name, value := range message.Headers {
		wire += name + ": " + value + "\r\n"
	}
	wire += extra + fmt.Sprintf("Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n", len(message.SDP)) + string(message.SDP)
	event, err := sip.Parse([]byte(wire), sip.ParseOptions{})
	require.NoError(t, err)
	result := pipeline.SIPResultFromEvent(event, message.Packet)
	result.Timestamp = message.Timestamp
	return result
}

func TestMalformedReliableSingletonDoesNotPoisonOrdinaryAnswerOrRepair(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, header := range []string{"RSeq: 0\r\n", "RSeq: abc\r\n", "RAck: abc\r\n", "RAck: 0 1 INVITE\r\n"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, header), func(t *testing.T) {
					bridge, registry, _ := retirementFixture(t, mode, policy)
					invite := offer("malformed-ordinary")
					invite.Headers = map[string]string{"cseq": "1 INVITE"}
					answer := invite
					answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
					answer.SDP = derivationSDP("192.0.2.2", 20000, false)
					_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, invite, ""))
					require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, answer, header)))
					require.Zero(t, bridge.Stats().UnknownDerivations)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")

					request, response := recoveryAtSequence(invite, "caller", "INVITE", 2)
					request.SDP = derivationSDP("192.0.2.1", 30000, true)
					_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, request, ""))
					_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, response, ""))
					require.Equal(t, 1, bridge.Stats().UnknownDerivations)
					request, response = recoveryAtSequence(invite, "caller", "INVITE", 3)
					_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, request, ""))
					require.NoError(t, submitDerivation(t, bridge, registry, parseAdmissionWire(t, response, header)))
					require.Zero(t, bridge.Stats().UnknownDerivations)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
				})
			}
		}
	}
}

func TestMalformedReliableSingletonCannotSupplyPRACKProof(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, malformed := range []string{"rseq", "rack"} {
			t.Run(string(policy)+"/"+malformed, func(t *testing.T) {
				bridge, registry, _, controller := recoveryFixture(t, policy, nil)
				invite, response, prack := reliableSequence("malformed-proof")
				if malformed == "rseq" {
					response.Headers["rseq"] = "abc"
				} else {
					prack.Headers["rack"] = "abc"
				}
				response = parseAdmissionWire(t, response, "")
				prack = parseAdmissionWire(t, prack, "")
				require.False(t, bridge.key(response, nil).HeaderConflict)
				require.False(t, bridge.key(prack, nil).HeaderConflict)
				_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, invite, ""))
				_ = submitDerivation(t, bridge, registry, response)
				require.Error(t, submitDerivation(t, bridge, registry, prack))
				assertDerivationState(t, bridge, controller, policy, true)
				retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
			})
		}
	}
}

func TestMalformedReliableCountersCountHeaderGroupsIncludingRetransmissions(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite := offer("malformed-counters")
	invite.Headers = map[string]string{"cseq": "1 INVITE"}
	_ = submitDerivation(t, bridge, registry, parseAdmissionWire(t, invite, ""))
	answer := invite
	answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
	answer.SDP = derivationSDP("192.0.2.2", 20000, false)
	answer = parseAdmissionWire(t, answer, "RSeq: abc\r\nRAck: abc\r\n")
	for i := uint64(1); i <= 2; i++ {
		require.NoError(t, submitDerivation(t, bridge, registry, answer))
		stats := controller.Status()[0].Uncertainty
		require.Equal(t, i, stats.MalformedRSeq)
		require.Equal(t, i, stats.MalformedRAck)
		require.Zero(t, stats.ConflictingDuplicates)
		require.Zero(t, stats.UnknownCalls)
	}
	duplicate := parseAdmissionWire(t, invite, "RSeq: abc\r\nRSeq: abc\r\nRSeq: abc\r\nRAck: 101 1 INVITE\r\nRAck: abc\r\n")
	_ = submitDerivation(t, bridge, registry, duplicate)
	stats := controller.Status()[0].Uncertainty
	require.Equal(t, uint64(3), stats.MalformedRSeq, "three invalid lines constitute one malformed RSeq group")
	require.Equal(t, uint64(3), stats.MalformedRAck)
	require.Equal(t, uint64(2), stats.ConflictingDuplicates, "invalid duplicate RSeq and RAck are two conflicting groups")
}

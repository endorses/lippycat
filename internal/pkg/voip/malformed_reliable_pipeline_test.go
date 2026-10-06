package voip

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

func TestMalformedReliableHeaderThroughUDPAndFragmentedTCPPipeline(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, transport := range []string{"udp", "tcp"} {
			for _, header := range []string{"RSeq: 0\r\n", "RSeq: abc\r\n", "RAck: abc\r\n"} {
				t.Run(fmt.Sprintf("%s/%s/%s", policy, transport, header), func(t *testing.T) {
					controller, bridge, registry, process := reliablePipelineFixture(t, policy, transport)
					process(reliablePipelineMessage("INVITE sip:peer@example.invalid SIP/2.0", "", "invite", "1 INVITE", "", "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"))
					answer := process(reliablePipelineMessage("SIP/2.0 200 OK", "peer", "invite", "1 INVITE", header, "c=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n"))
					require.NoError(t, answer.MetadataError)
					require.Equal(t, sharedsip.ReliableHeaderConflicts{}, answer.SIP.ReliableHeaderEvidence.Conflicts)
					require.True(t, answer.SIP.ReliableHeaderEvidence.RSeqMalformed || answer.SIP.ReliableHeaderEvidence.RAckMalformed)
					require.Zero(t, bridge.Stats().UnknownDerivations)
					require.Equal(t, mediaadmission.StateEnforcing, controller.Status()[0].State)
					require.Equal(t, "parsed-reliable", registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
					require.Equal(t, "parsed-reliable", registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
				})
			}
			for _, malformed := range []string{"rseq", "rack"} {
				t.Run(string(policy)+"/"+transport+"/proof/"+malformed, func(t *testing.T) {
					controller, bridge, _, process := reliablePipelineFixture(t, policy, transport)
					rseq, rack := "101", "101 1 INVITE"
					if malformed == "rseq" {
						rseq = "abc"
					} else {
						rack = "abc"
					}
					process(reliablePipelineMessage("INVITE sip:peer@example.invalid SIP/2.0", "", "invite", "1 INVITE", "Supported: 100rel\r\n", ""))
					provisional := process(reliablePipelineMessage("SIP/2.0 183 Progress", "peer", "invite", "1 INVITE", "Require: 100rel\r\nRSeq: "+rseq+"\r\n", "c=IN IP4 192.0.2.2\r\nm=audio 20000 RTP/AVP 0\r\n"))
					prack := process(reliablePipelineMessage("PRACK sip:peer@example.invalid SIP/2.0", "peer", "prack", "2 PRACK", "RAck: "+rack+"\r\n", "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\n"))
					require.Equal(t, malformed == "rseq", provisional.SIP.ReliableHeaderEvidence.RSeqMalformed)
					require.Equal(t, malformed == "rack", prack.SIP.ReliableHeaderEvidence.RAckMalformed)
					require.Error(t, prack.MetadataError)
					require.Equal(t, 1, bridge.Stats().UnknownDerivations)
					expected := mediaadmission.StateDegradedOpen
					if policy == mediaadmission.FailureClosed {
						expected = mediaadmission.StateDegradedClosed
					}
					require.Equal(t, expected, controller.Status()[0].State)
				})
			}
		}
	}
}

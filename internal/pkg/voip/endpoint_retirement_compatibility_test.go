package voip

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	sipadmission "github.com/endorses/lippycat/internal/pkg/voip/admission"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func compatibilityPacket(t *testing.T, source, destination string, sport, dport uint16, payload []byte) capture.PacketInfo {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(source), DstIP: net.ParseIP(destination)}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	return capture.PacketInfo{Packet: packet, Interface: "example0"}
}

func compatibilitySDP(address string, port int) string {
	return fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d RTP/AVP 0\r\n", address, port)
}
func compatibilityMessage(callID, start, tag, branch, cseq, extra, body string) []byte {
	return []byte(strings.Replace(string(reliablePipelineMessage(start, tag, branch, cseq, extra, body)), "Call-ID: parsed-reliable", "Call-ID: "+callID, 1))
}

// This fixture uses the processor and SourceAdapter consumed by local tap output.
// Assertions cover the explicit resolution, lifetime and protobuf identity passed
// to per-call output and identity-based content delivery, without starting sinks.
func compatibilityProcessor(t *testing.T, mode mediaadmission.Mode, policy mediaadmission.FailurePolicy, observer bool) (*voipprocessor.Processor, *voipprocessor.SourceAdapter) {
	t.Helper()
	processor := voipprocessor.New(voipprocessor.DefaultConfig())
	t.Cleanup(processor.Close)
	if observer {
		cfg := mediaadmission.DefaultConfig()
		cfg.Enabled = true
		cfg.Mode = mode
		cfg.FailurePolicy = policy
		cfg.RetryInterval = time.Hour
		controller, err := mediaadmission.NewController(t.Context(), cfg, reliablePipelineBackend{})
		require.NoError(t, err)
		metadata, err := mediaadmission.NewMetadataStore(cfg)
		require.NoError(t, err)
		bridge, err := sipadmission.New(sipadmission.Config{Limits: cfg, Registry: processor.CallRegistry(), Controller: controller, Metadata: metadata})
		require.NoError(t, err)
		require.NoError(t, processor.SetMetadataObserver(bridge))
		t.Cleanup(func() { require.NoError(t, bridge.Close()); require.NoError(t, controller.Close(context.Background())) })
	}
	return processor, voipprocessor.NewSourceAdapter(processor)
}
func compatibilitySend(t *testing.T, adapter *voipprocessor.SourceAdapter, call, start, tag, branch, cseq, extra, body string) {
	t.Helper()
	result := adapter.ProcessPacketInfo(compatibilityPacket(t, "192.0.2.1", "192.0.2.2", 5060, 5060, compatibilityMessage(call, start, tag, branch, cseq, extra, body)))
	require.NotNil(t, result)
	require.Equal(t, call, result.GetCallID())
}
func compatibilityExchange(t *testing.T, adapter *voipprocessor.SourceAdapter, call, method string, seq, caller, peer int) {
	t.Helper()
	tag := "peer"
	if seq == 1 {
		tag = ""
	}
	branch := fmt.Sprintf("z9hG4bK-example-%d", seq)
	compatibilitySend(t, adapter, call, method+" sip:peer@example.invalid SIP/2.0", tag, branch, fmt.Sprintf("%d %s", seq, method), "", compatibilitySDP("192.0.2.1", caller))
	compatibilitySend(t, adapter, call, "SIP/2.0 200 OK", "peer", branch, fmt.Sprintf("%d %s", seq, method), "", compatibilitySDP("192.0.2.2", peer))
}
func compatibilityRTP(t *testing.T, adapter *voipprocessor.SourceAdapter, caller, peer int, call string, lifetime callregistry.Lifetime) {
	t.Helper()
	payload := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7}
	result := adapter.ProcessPacketInfo(compatibilityPacket(t, "192.0.2.1", "192.0.2.2", uint16(caller), uint16(peer), payload))
	require.NotNil(t, result)
	require.Equal(t, callregistry.MediaResolved, result.GetMediaResolution().Status)
	require.Equal(t, call, result.GetCallID())
	require.Equal(t, lifetime, result.GetCallLifetime())
	require.Equal(t, []string{call}, result.GetCallIDs())
	require.Equal(t, call, result.GetMetadata().GetSip().GetCallId())
	require.Equal(t, uint32(7), result.GetMetadata().GetRtp().GetSsrc())
}

func TestProcessorHealthyReoffersRetainTrailingMediaAttribution(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, method := range []string{"INVITE", "UPDATE"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, method), func(t *testing.T) {
					processor, adapter := compatibilityProcessor(t, mode, policy, true)
					compatibilityExchange(t, adapter, "original-call", "INVITE", 1, 10000, 20000)
					call, ok := processor.Call("original-call")
					require.True(t, ok)
					// Sharing an exact endpoint must not make this second call the sole owner
					// after the original changes ports; its opposite endpoint stays unique.
					compatibilitySend(t, adapter, "other-call", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-other", "1 INVITE", "", compatibilitySDP("192.0.2.1", 10000))
					compatibilitySend(t, adapter, "other-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-other", "1 INVITE", "", compatibilitySDP("192.0.2.2", 22000))
					compatibilityRTP(t, adapter, 10000, 20000, "original-call", call.Lifetime)
					for index, pair := range [][2]int{{30000, 40000}, {50000, 60000}, {10000, 20000}} {
						compatibilityExchange(t, adapter, "original-call", method, index+2, pair[0], pair[1])
						compatibilityRTP(t, adapter, 10000, 20000, "original-call", call.Lifetime)
						compatibilityRTP(t, adapter, pair[0], pair[1], "original-call", call.Lifetime)
					}
					before := processor.EndpointAssociationCount()
					compatibilityExchange(t, adapter, "original-call", method, 5, 0, 0)
					require.Equal(t, before, processor.EndpointAssociationCount(), "disabled media must add no endpoints")
					compatibilityRTP(t, adapter, 10000, 20000, "original-call", call.Lifetime)
					compatibilityExchange(t, adapter, "original-call", method, 6, 30000, 40000)
					compatibilityRTP(t, adapter, 10000, 20000, "original-call", call.Lifetime)
					processor.FinalizeCallLifetime("original-call", call.Lifetime)
					require.Empty(t, processor.CallIDsForEndpoint("192.0.2.2:20000"))
					require.Equal(t, []string{"other-call"}, processor.CallIDsForEndpoint("192.0.2.1:10000"))
				})
			}
		}
	}
}

func TestProcessorShadowFaultRecoveryMatchesOrdinaryAttribution(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, observer := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/observer=%t", policy, observer), func(t *testing.T) {
				processor, adapter := compatibilityProcessor(t, mediaadmission.ModeShadow, policy, observer)
				compatibilitySend(t, adapter, "shadow-call", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-initial", "1 INVITE", "Supported: 100rel\r\n", "")
				compatibilitySend(t, adapter, "shadow-call", "SIP/2.0 183 Progress", "peer", "z9hG4bK-initial", "1 INVITE", "Require: 100rel\r\nRSeq: 101\r\n", compatibilitySDP("192.0.2.2", 20000))
				compatibilitySend(t, adapter, "shadow-call", "PRACK sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-prack", "2 PRACK", "RAck: 102 1 INVITE\r\n", compatibilitySDP("192.0.2.1", 10000))
				compatibilitySend(t, adapter, "shadow-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", "", "")
				call, ok := processor.Call("shadow-call")
				require.True(t, ok)
				compatibilityRTP(t, adapter, 10000, 20000, "shadow-call", call.Lifetime)
				compatibilityExchange(t, adapter, "shadow-call", "UPDATE", 3, 30000, 40000)
				compatibilityRTP(t, adapter, 10000, 20000, "shadow-call", call.Lifetime)
				compatibilityRTP(t, adapter, 30000, 40000, "shadow-call", call.Lifetime)
			})
		}
	}
}

func TestProcessorHealthyLateOffersKeepHistoricalAttribution(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, negotiation := range []string{"reliable-prack", "ordinary-ack"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, negotiation), func(t *testing.T) {
					processor, adapter := compatibilityProcessor(t, mode, policy, true)
					compatibilitySend(t, adapter, "late-offer", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-initial", "1 INVITE", "Supported: 100rel\r\n", "")
					if negotiation == "reliable-prack" {
						compatibilitySend(t, adapter, "late-offer", "SIP/2.0 183 Progress", "peer", "z9hG4bK-initial", "1 INVITE", "Require: 100rel\r\nRSeq: 101\r\n", compatibilitySDP("192.0.2.2", 20000))
						compatibilitySend(t, adapter, "late-offer", "PRACK sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-prack", "2 PRACK", "RAck: 101 1 INVITE\r\n", compatibilitySDP("192.0.2.1", 10000))
						compatibilitySend(t, adapter, "late-offer", "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", "", "")
					} else {
						compatibilitySend(t, adapter, "late-offer", "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", "", compatibilitySDP("192.0.2.2", 20000))
						compatibilitySend(t, adapter, "late-offer", "ACK sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-ack", "1 ACK", "", compatibilitySDP("192.0.2.1", 10000))
					}
					call, ok := processor.Call("late-offer")
					require.True(t, ok)
					compatibilityRTP(t, adapter, 10000, 20000, "late-offer", call.Lifetime)
					compatibilityExchange(t, adapter, "late-offer", "INVITE", 3, 30000, 40000)
					compatibilityRTP(t, adapter, 10000, 20000, "late-offer", call.Lifetime)
				})
			}
		}
	}
}

func TestProcessorHealthyPRACKResponseFirstReofferRetainsOwnership(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, method := range []string{"INVITE", "UPDATE"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, method), func(t *testing.T) {
					processor, adapter := compatibilityProcessor(t, mode, policy, true)
					compatibilitySend(t, adapter, "response-first-call", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-initial", "1 INVITE", "Supported: 100rel\r\n", "")
					compatibilitySend(t, adapter, "response-first-call", "SIP/2.0 183 Progress", "peer", "z9hG4bK-initial", "1 INVITE", "Require: 100rel\r\nRSeq: 101\r\n", compatibilitySDP("192.0.2.2", 20000))
					compatibilitySend(t, adapter, "response-first-call", "PRACK sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-prack", "2 PRACK", "RAck: 101 1 INVITE\r\n", compatibilitySDP("192.0.2.1", 10000))
					compatibilitySend(t, adapter, "response-first-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", "", "")
					call, ok := processor.Call("response-first-call")
					require.True(t, ok)
					compatibilityExchange(t, adapter, "other-call", "INVITE", 1, 10000, 22000)
					check := func() {
						t.Helper()
						require.ElementsMatch(t, []string{"response-first-call", "other-call"}, processor.CallIDsForEndpoint("192.0.2.1:10000"))
						compatibilityRTP(t, adapter, 10000, 20000, "response-first-call", call.Lifetime)
					}
					check()
					// Capture may observe the complete success response before its request.
					// Replacing the response descriptor must not invalidate healthy PRACK proof
					// and turn this ordinary re-offer into destructive recovery.
					cseq := "3 " + method
					compatibilitySend(t, adapter, "response-first-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-reoffer", cseq, "", compatibilitySDP("192.0.2.2", 40000))
					check()
					compatibilitySend(t, adapter, "response-first-call", method+" sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-reoffer", cseq, "", compatibilitySDP("192.0.2.1", 30000))
					check()
					compatibilityRTP(t, adapter, 30000, 40000, "response-first-call", call.Lifetime)
				})
			}
		}
	}
}

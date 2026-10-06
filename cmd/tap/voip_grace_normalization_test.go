//go:build tap || all

package tap

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// Exercise constructors independently and the production startup graph. The
// completion value is checked before the processor can normalize its pointer.
func TestTapVoIPGraceNormalizationAtRoutingAndStartup(t *testing.T) {
	originalGrace := viper.Get("tap.per_call_pcap.grace_period")
	t.Cleanup(func() { viper.Set("tap.per_call_pcap.grace_period", originalGrace) })
	for _, startup := range []bool{false, true} {
		for _, pcap := range []bool{false, true} {
			for _, grace := range []time.Duration{0, -time.Second, 50 * time.Millisecond} {
				t.Run(fmt.Sprintf("startup-%v/pcap-%v/grace-%s", startup, pcap, grace), func(t *testing.T) {
					cfg := mediaadmission.DefaultConfig()
					cfg.Enabled = true
					cfg.RetryInterval = 5 * time.Millisecond
					controller, err := mediaadmission.NewController(t.Context(), cfg, &tapAdmissionMaps{keys: make(map[mediaadmission.EndpointKey]bool)})
					require.NoError(t, err)
					metadata, err := mediaadmission.NewMetadataStore(cfg)
					require.NoError(t, err)
					session := &admissionintegration.Session{Config: cfg, Controller: controller, Metadata: metadata}
					t.Cleanup(func() { require.NoError(t, session.Close()) })
					want := grace
					if want <= 0 {
						want = voip.DefaultConfig().PCAPGracePeriod
					}
					routingGrace := grace
					if startup {
						viper.Set("tap.per_call_pcap.grace_period", grace)
						completion := tapVoIPCompletionConfig()
						require.Equal(t, want, completion.GracePeriod, "normalize before processor construction")
						filterDir := t.TempDir()
						require.NoError(t, os.Chmod(filterDir, 0o700))
						config := processor.Config{FilterFile: filepath.Join(filterDir, "filters.yaml"), ListenAddr: "127.0.0.1:0", ProcessorID: "grace-synthetic", CallCompletionMonitorConfig: completion}
						if pcap {
							writer := processor.DefaultPcapWriterConfig()
							writer.Enabled, writer.OutputDir = true, t.TempDir()
							config.PcapWriterConfig = writer
						}
						runtime, err := newTapRuntime(config, "udp", protocolcatalog.MustLookup("voip"), tapRuntimeHooks{})
						require.NoError(t, err)
						t.Cleanup(func() { require.NoError(t, runtime.processor.Shutdown()) })
						require.Equal(t, want, completion.GracePeriod)
						routingGrace = completion.GracePeriod
					}
					pc := voipprocessor.DefaultConfig()
					pc.ApplicationFilter = tapAdmissionFilter{}
					routing, err := newTapVoIPRouting(pc, *voip.DefaultConfig(), 1, session, routingGrace, []string{"example0"})
					require.NoError(t, err)
					t.Cleanup(routing.Close)
					send := func(callID, start, tag, branch, cseq, body string) {
						t.Helper()
						require.NotNil(t, routing.adapter.ProcessPacketInfo(tapAdmissionPacket(t, "example0", retirementMessage(callID, start, tag, branch, cseq, "", body), false)))
					}
					// Incomplete initial offer then complete repair schedules admission grace.
					partial := retirementSDP("192.0.2.1", 10000) + "m=audio malformed RTP/AVP 0\r\n"
					send("repair-call", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-initial", "1 INVITE", partial)
					send("repair-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", retirementSDP("192.0.2.2", 20000))
					send("repair-call", "INVITE sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-repair", "2 INVITE", retirementSDP("192.0.2.1", 30000))
					send("repair-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-repair", "2 INVITE", retirementSDP("192.0.2.2", 40000))
					child := routing.children[0]
					var life callregistry.Lifetime
					for _, call := range child.ActiveCalls() {
						if call.CallID == "repair-call" {
							life = call.Lifetime
						}
					}
					require.NotZero(t, life)
					checkMedia := func() {
						t.Helper()
						result := routing.adapter.ProcessPacketInfo(retirementRTPPacket(t))
						require.Equal(t, callregistry.MediaResolved, result.GetMediaResolution().Status)
						require.Equal(t, "repair-call", result.GetCallID())
						require.Equal(t, life, result.GetCallLifetime())
					}
					checkMedia()
					// A distinct completed call exercises scoped completion grace separately.
					send("complete-call", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-complete", "1 INVITE", retirementSDP("192.0.2.1", 50000))
					send("complete-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-complete", "1 INVITE", retirementSDP("192.0.2.2", 60000))
					send("complete-call", "BYE sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-bye", "2 BYE", "")
					send("complete-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-bye", "2 BYE", "")
					require.Equal(t, "complete-call", routing.adapter.ProcessPacketInfo(graceRTPPacket(t, 50000, 60000)).GetCallID())
					if grace > 0 {
						require.Eventually(t, func() bool {
							return routing.adapter.ProcessPacketInfo(graceRTPPacket(t, 10000, 20000)).GetCallID() == "" && routing.adapter.ProcessPacketInfo(graceRTPPacket(t, 50000, 60000)).GetCallID() == ""
						}, time.Second, time.Millisecond)
					} else {
						require.Never(t, func() bool {
							return routing.adapter.ProcessPacketInfo(graceRTPPacket(t, 10000, 20000)).GetCallID() == "" || routing.adapter.ProcessPacketInfo(graceRTPPacket(t, 50000, 60000)).GetCallID() == ""
						}, 75*time.Millisecond, time.Millisecond)
						checkMedia()
					}
					require.Equal(t, "repair-call", routing.adapter.ProcessPacketInfo(graceRTPPacket(t, 30000, 40000)).GetCallID())
				})
			}
		}
	}
}

func graceRTPPacket(t *testing.T, caller, peer layers.UDPPort) capture.PacketInfo {
	t.Helper()
	info := retirementRTPPacket(t)
	ip := info.Packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := info.Packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	udp.SrcPort, udp.DstPort = caller, peer
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload(udp.Payload)))
	info.Packet = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	info.Packet.Metadata().Timestamp = time.Now()
	return info
}

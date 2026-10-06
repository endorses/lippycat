//go:build hunter || all

package hunt

import (
	"fmt"
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"net"

	"sync"
	"testing"
	"time"
)

func retirementMessage(callID, start, tag, branch, cseq, extra, body string) []byte {
	to := "<sip:peer@example.invalid>"
	if tag != "" {
		to += ";tag=" + tag
	}
	content := ""
	if body != "" {
		content = "Content-Type: application/sdp\r\n"
	}
	return []byte(fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP 192.0.2.1;branch=%s\r\nFrom: <sip:origin@example.invalid>;tag=origin\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %s\r\n%s%sContent-Length: %d\r\n\r\n%s", start, branch, to, callID, cseq, extra, content, len(body), body))
}
func retirementSDP(ip string, port int) string {
	return fmt.Sprintf("v=0\r\nc=IN IP4 %s\r\nm=audio %d RTP/AVP 0\r\n", ip, port)
}
func retirementRTPPacket(t *testing.T) capture.PacketInfo {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	udp := &layers.UDP{SrcPort: 10000, DstPort: 20000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	b := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp, gopacket.Payload([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 7})))
	packet := gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	return capture.PacketInfo{Packet: packet, Interface: "example0", LinkType: layers.LinkTypeRaw}
}
func TestHuntRetirementCompatibility(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, transport := range []string{"udp", "tcp"} {
				for _, scenario := range []string{"healthy-reinvite", "healthy-update", "hold", "healthy-prack", "delayed-offer", "faulty-prack"} {
					if scenario == "faulty-prack" && mode != mediaadmission.ModeShadow {
						continue
					}
					t.Run(fmt.Sprintf("%s/%s/%s/%s", mode, policy, transport, scenario), func(t *testing.T) {
						cfg := mediaadmission.DefaultConfig()
						cfg.Enabled = true
						cfg.Mode = mode
						cfg.FailurePolicy = policy
						cfg.RetryInterval = time.Hour
						controller, err := mediaadmission.NewController(t.Context(), cfg, &hunterAdmissionMap{entries: make(map[mediaadmission.EndpointKey]struct{})})
						require.NoError(t, err)
						metadata, err := mediaadmission.NewMetadataStore(cfg)
						require.NoError(t, err)
						session := &admissionintegration.Session{Config: cfg, Controller: controller, Metadata: metadata}
						t.Cleanup(func() { require.NoError(t, session.Close()) })
						sink := &retirementForwarder{}
						router, err := newAdmissionHunterRouter(t.Context(), sink, session, []string{"example0"}, *voip.DefaultConfig())
						require.NoError(t, err)
						t.Cleanup(func() { require.NoError(t, router.Close()) })
						router.SetApplicationFilter(&admissionMatch{selected: true})
						registry := router.domains[0].tracker.AdmissionRegistry()
						seq := uint32(1)
						send := func(callID, start, tag, branch, cseq, extra, body string) {
							t.Helper()
							raw := retirementMessage(callID, start, tag, branch, cseq, extra, body)
							if transport == "udp" {
								router.ProcessPacket(admissionUDPPacket(t, "example0", raw))
							} else {
								// Feed fragmented bytes into the same reassembly engine used by the router.
								cut := len(raw) / 2
								router.ProcessPacket(retirementTCPPacket(t, seq, raw[:cut]))
								seq += uint32(cut)
								router.ProcessPacket(retirementTCPPacket(t, seq, raw[cut:]))
								seq += uint32(len(raw) - cut)
								require.Eventually(t, func() bool { call, ok := registry.Call(callID); return ok && call.CallID == callID }, time.Second, time.Millisecond)
							}
							// A selected UDP bodyless initial INVITE remains buffered until SDP arrives.
							if transport != "udp" || body != "" || cseq != "1 INVITE" || start != "INVITE sip:peer@example.invalid SIP/2.0" {
								require.Eventually(t, func() bool { return sink.hasSIP(callID, cseq, start) }, time.Second, time.Millisecond)
							}
						}
						exchange := func(callID, method string, number, caller, peer int) {
							tag := "peer"
							if number == 1 {
								tag = ""
							}
							branch := fmt.Sprintf("z9hG4bK-%s-%d", callID, number)
							send(callID, method+" sip:peer@example.invalid SIP/2.0", tag, branch, fmt.Sprintf("%d %s", number, method), "", retirementSDP("192.0.2.1", caller))
							send(callID, "SIP/2.0 200 OK", "peer", branch, fmt.Sprintf("%d %s", number, method), "", retirementSDP("192.0.2.2", peer))
						}
						if scenario == "faulty-prack" || scenario == "healthy-prack" {
							send("original-call", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-initial", "1 INVITE", "Supported: 100rel\r\n", "")
							send("original-call", "SIP/2.0 183 Progress", "peer", "z9hG4bK-initial", "1 INVITE", "Require: 100rel\r\nRSeq: 101\r\n", retirementSDP("192.0.2.2", 20000))
							rack := "RAck: 101 1 INVITE\r\n"
							if scenario == "faulty-prack" {
								rack = "RAck: 102 1 INVITE\r\n"
							}
							send("original-call", "PRACK sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-prack", "2 PRACK", rack, retirementSDP("192.0.2.1", 10000))
							send("original-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", "", "")
						} else if scenario == "delayed-offer" {
							send("original-call", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-initial", "1 INVITE", "", "")
							send("original-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", "", retirementSDP("192.0.2.2", 20000))
							send("original-call", "ACK sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-ack", "1 ACK", "", retirementSDP("192.0.2.1", 10000))
						} else {
							exchange("original-call", "INVITE", 1, 10000, 20000)
						}
						call, exists := registry.Call("original-call")
						require.True(t, exists)
						exchange("other-call", "INVITE", 1, 10000, 22000)
						check := func() {
							t.Helper()
							packet := retirementRTPPacket(t)
							resolution := registry.ResolveMediaEndpoints("192.0.2.1:10000", "192.0.2.2:20000")
							require.Equal(t, callregistry.MediaResolved, resolution.Status)
							require.Equal(t, "original-call", resolution.CallID)
							require.Equal(t, call.Lifetime, resolution.Lifetime)
							before := sink.mediaCount()
							router.ProcessPacket(packet)
							require.Eventually(t, func() bool { return sink.mediaCount() > before }, time.Second, time.Millisecond)
							require.Equal(t, "original-call", sink.lastMediaCall())
							direct, inherited := sink.lastMediaProvenance()
							require.Empty(t, direct)
							require.Equal(t, []string{"selected"}, inherited)
						}
						check()
						method := "INVITE"
						if scenario == "healthy-update" || scenario == "faulty-prack" {
							method = "UPDATE"
						}
						caller, peer := 30000, 40000
						if scenario == "hold" {
							caller, peer = 0, 0
						}
						exchange("original-call", method, 3, caller, peer)
						check()
						exchange("original-call", method, 4, 10000, 20000)
						check()
					})
				}
			}
		}
	}
}

type retirementForwarder struct {
	mu        sync.Mutex
	packets   []*data.PacketMetadata
	direct    [][]string
	inherited [][]string
}

func (s *retirementForwarder) ForwardPacketWithMetadata(_ gopacket.Packet, meta *data.PacketMetadata, _ string, _ layers.LinkType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets = append(s.packets, meta)
	s.direct = append(s.direct, nil)
	s.inherited = append(s.inherited, nil)
	return nil
}
func (s *retirementForwarder) hasSIP(call, cseq, start string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	var number uint64
	var method string
	var response uint32
	if len(start) >= 7 && start[:7] == "SIP/2.0" {
		if _, err := fmt.Sscanf(start, "SIP/2.0 %d", &response); err != nil {
			return false
		}
	}
	if _, err := fmt.Sscanf(cseq, "%d %s", &number, &method); err != nil {
		return false
	}
	for _, p := range s.packets {
		if p.GetSip().GetCallId() == call && p.GetSip().GetCseqNumber() == number && p.GetSip().GetCseqMethod() == method && p.GetSip().GetResponseCode() == response {
			return true
		}
	}
	return false
}
func (s *retirementForwarder) mediaCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.packets {
		if p.GetRtp() != nil {
			n++
		}
	}
	return n
}
func (s *retirementForwarder) lastMediaCall() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.packets) - 1; i >= 0; i-- {
		if s.packets[i].GetRtp() != nil {
			return s.packets[i].GetSip().GetCallId()
		}
	}
	return ""
}
func retirementTCPPacket(t *testing.T, seq uint32, payload []byte) capture.PacketInfo {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: seq, ACK: true, PSH: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	b := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	packet.Metadata().Timestamp = time.Now()
	return capture.PacketInfo{Packet: packet, Interface: "example0", LinkType: layers.LinkTypeRaw}
}

func (s *retirementForwarder) ForwardPacketWithFilterProvenance(_ gopacket.Packet, meta *data.PacketMetadata, _ string, _ layers.LinkType, direct, inherited []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets = append(s.packets, meta)
	s.direct = append(s.direct, append([]string(nil), direct...))
	s.inherited = append(s.inherited, append([]string(nil), inherited...))
	return nil
}
func (s *retirementForwarder) lastMediaProvenance() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.packets) - 1; i >= 0; i-- {
		if s.packets[i].GetRtp() != nil {
			return append([]string(nil), s.direct[i]...), append([]string(nil), s.inherited[i]...)
		}
	}
	return nil, nil
}

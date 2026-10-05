package voip

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type selectionPacketSink struct {
	mu      sync.Mutex
	packets []*pipeline.PacketEnvelope
}

func (s *selectionPacketSink) HandlePacket(_ context.Context, env *pipeline.PacketEnvelope) pipeline.Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets = append(s.packets, env)
	return pipeline.Result{Outcome: pipeline.OutcomeAccepted}
}
func (*selectionPacketSink) Close(context.Context) error { return nil }
func (s *selectionPacketSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.packets)
}

type udpSelectionHarness struct {
	t                *testing.T
	tracker          *CallTracker
	buffer           *BufferManager
	outputs          *pipeline.PacketFanout
	sink             *selectionPacketSink
	ip, peer, family string
}

func newUDPSelectionHarness(t *testing.T, ipv6 bool) *udpSelectionHarness {
	t.Helper()
	sipusers.ClearAll()
	sipusers.AddSipUser("selected", &sipusers.SipUser{})
	t.Cleanup(sipusers.ClearAll)
	tracker := NewCallTrackerWithConfig(DefaultConfig())
	t.Cleanup(tracker.Shutdown)
	buffer := NewBufferManager(time.Minute, 100)
	t.Cleanup(buffer.Close)
	sink := &selectionPacketSink{}
	outputs, err := pipeline.NewPacketFanout(pipeline.SinkRegistration{Name: "test-output", Sink: sink})
	require.NoError(t, err)
	h := &udpSelectionHarness{t: t, tracker: tracker, buffer: buffer, outputs: outputs, sink: sink,
		ip: "192.0.2.1", peer: "192.0.2.2", family: "IP4"}
	if ipv6 {
		h.ip, h.peer, h.family = "2001:db8::1", "2001:db8::2", "IP6"
	}
	return h
}

func (h *udpSelectionHarness) packet(srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	h.t.Helper()
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}}
	var network gopacket.SerializableLayer
	if h.family == "IP6" {
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP(h.ip), DstIP: net.ParseIP(h.peer)}
		require.NoError(h.t, udp.SetNetworkLayerForChecksum(ip))
		eth.EthernetType, network = layers.EthernetTypeIPv6, ip
	} else {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP(h.ip), DstIP: net.ParseIP(h.peer)}
		require.NoError(h.t, udp.SetNetworkLayerForChecksum(ip))
		eth.EthernetType, network = layers.EthernetTypeIPv4, ip
	}
	b := gopacket.NewSerializeBuffer()
	require.NoError(h.t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, network, udp, gopacket.Payload(payload)))
	p := gopacket.NewPacket(b.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	p.Metadata().Timestamp = time.Now()
	p.Metadata().CaptureLength, p.Metadata().Length = len(p.Data()), len(p.Data())
	return p
}
func (h *udpSelectionHarness) feed(p gopacket.Packet) {
	h.t.Helper()
	handleUdpPacketsWithManagerAndOutputs(h.tracker, capture.PacketInfo{Packet: p, Interface: "test0", LinkType: layers.LinkTypeEthernet}, p.Layer(layers.LayerTypeUDP).(*layers.UDP), h.buffer, h.outputs)
}
func (h *udpSelectionHarness) sip(callID, user string, sdp bool) {
	h.t.Helper()
	body := ""
	if sdp {
		body = fmt.Sprintf("v=0\r\nc=IN %s %s\r\nm=audio 10000 RTP/AVP 0\r\n", h.family, h.ip)
	}
	contentType := ""
	if sdp {
		contentType = "Content-Type: application/sdp\r\n"
	}
	message := fmt.Sprintf("INVITE sip:peer@example.invalid SIP/2.0\r\nFrom: <sip:%s@example.invalid>;tag=synthetic\r\nTo: <sip:peer@example.invalid>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\n%sContent-Length: %d\r\n\r\n%s", user, callID, contentType, len(body), body)
	h.feed(h.packet(5060, 5060, []byte(message)))
}
func (h *udpSelectionHarness) media() gopacket.Packet {
	return h.packet(10000, 20000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0})
}
func (h *udpSelectionHarness) agePacketBuffer(callID string) {
	h.t.Helper()
	h.buffer.mu.Lock()
	b := h.buffer.buffers[callID]
	require.NotNil(h.t, b)
	b.mu.Lock()
	b.createdAt = time.Now().Add(-2 * h.buffer.maxAge)
	b.mu.Unlock()
	h.buffer.mu.Unlock()
	h.buffer.cleanupOldBuffers()
}

func TestUDPSelectionLifecycle(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		family := "IPv4"
		if ipv6 {
			family = "IPv6"
		}
		t.Run(family, func(t *testing.T) {
			for _, scenario := range []string{"selected", "unselected", "pending", "buffer expiry", "selection expiry", "expired selection cleanup", "retirement and reuse", "ambiguous ownership"} {
				t.Run(scenario, func(t *testing.T) {
					h := newUDPSelectionHarness(t, ipv6)
					const callID = "synthetic-call"
					switch scenario {
					case "unselected":
						h.sip(callID, "other", true)
					case "pending":
						h.sip(callID, "selected", false)
						require.Equal(t, 1, h.buffer.GetBufferCount())
						h.feed(h.media())
						require.Zero(t, h.sink.count())
						h.agePacketBuffer(callID)
						h.sip(callID, "other", true)
					default:
						h.sip(callID, "selected", true)
						require.Equal(t, 1, h.sink.count(), "selected signaling must be emitted")
						require.True(t, h.buffer.IsCallMatched(callID))
					}
					if scenario == "unselected" || scenario == "pending" {
						_, exists := h.tracker.registry.Call(callID)
						require.False(t, exists, "never-selected signaling must not populate authoritative endpoints")
					}
					switch scenario {
					case "buffer expiry":
						h.agePacketBuffer(callID)
						require.Zero(t, h.buffer.GetBufferCount())
					case "selection expiry", "expired selection cleanup":
						h.buffer.mu.Lock()
						h.buffer.matchedCalls[callID] = time.Now().Add(-h.buffer.matchedTTL - time.Second)
						h.buffer.mu.Unlock()
						if scenario == "expired selection cleanup" {
							h.buffer.cleanupOldBuffers()
						}
						require.False(t, h.buffer.IsCallMatched(callID))
					case "retirement and reuse":
						retired, err := h.tracker.removeCall(callID)
						require.NoError(t, err)
						require.True(t, retired)
						h.feed(h.media())
						require.Equal(t, 1, h.sink.count())
						h.sip(callID, "other", true)
						require.Equal(t, 1, h.sink.count(), "retired selection cannot select a reused Call-ID")
					case "ambiguous ownership":
						h.sip("synthetic-other", "selected", true)
						require.Equal(t, callregistry.MediaAmbiguous, h.tracker.ResolveMediaPacket(h.media()).Status)
					}
					before := h.sink.count()
					h.feed(h.media())
					if scenario == "selected" || scenario == "buffer expiry" {
						require.Equal(t, before+1, h.sink.count(), "selected media must continue")
					} else {
						require.Equal(t, before, h.sink.count(), "media must not escape through a fallback")
					}
					if scenario == "selection expiry" || scenario == "expired selection cleanup" {
						h.sip(callID, "other", true)
						require.Equal(t, before, h.sink.count(), "expired selection cannot authorize SIP")
					}
					if scenario == "retirement and reuse" {
						h.sip(callID, "selected", true)
						h.feed(h.media())
						require.Equal(t, before+2, h.sink.count(), "a new direct match may select a new lifetime")
					}
				})
			}
		})
	}
}

func TestUDPSelectionMixedSDPRecordsBufferDiagnostics(t *testing.T) {
	h := newUDPSelectionHarness(t, true)
	body := "v=0\r\nc=IN IP6 2001:db8::1\r\nm=audio 10000 RTP/AVP 0\r\nm=audio invalid RTP/AVP 0\r\nm=audio 11000 RTP/AVP 0\r\n"
	message := fmt.Sprintf("INVITE sip:peer@example.invalid SIP/2.0\r\nFrom: <sip:selected@example.invalid>;tag=synthetic\r\nTo: <sip:peer@example.invalid>\r\nCall-ID: mixed-synthetic\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	h.feed(h.packet(5060, 5060, []byte(message)))
	require.Equal(t, uint64(1), h.buffer.SDPParseStats().Bodies)
	require.Equal(t, uint64(1), h.buffer.SDPParseStats().Partial)
	before := h.sink.count()
	h.feed(h.media())
	h.feed(h.packet(11000, 20000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0}))
	require.Equal(t, before+2, h.sink.count(), "independent valid sections before and after an invalid section authorize selected media")
}

func TestBufferSDPConfiguredEndpointBound(t *testing.T) {
	tracker := NewCallTrackerWithConfig(DefaultConfig())
	t.Cleanup(tracker.Shutdown)
	bm := NewBufferManager(time.Minute, 10)
	t.Cleanup(bm.Close)
	bm.BindRegistry(tracker.AdmissionRegistry(), 2)
	body := "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\nm=audio 11000 RTP/AVP 0\r\n"
	bm.AddSIPPacket("bounded-synthetic", nil, &CallMetadata{SDPBody: body}, "test0", layers.LinkTypeEthernet)
	bm.mu.RLock()
	buffer := bm.buffers["bounded-synthetic"]
	bm.mu.RUnlock()
	require.True(t, buffer.IsRTPPort("192.0.2.1:10000"))
	require.True(t, buffer.IsRTPPort("192.0.2.1:10001"))
	require.False(t, buffer.IsRTPPort("192.0.2.1:11000"))
	require.False(t, buffer.IsRTPPort("10000"), "legacy diagnostic keys cannot displace exact endpoints at capacity")
	require.Equal(t, uint64(1), bm.SDPParseStats().ResourceLimited)
}

func TestBufferSDPAssociationsStayBoundedAcrossReinvites(t *testing.T) {
	tracker := NewCallTrackerWithConfig(DefaultConfig())
	t.Cleanup(tracker.Shutdown)
	bm := NewBufferManager(time.Minute, 10)
	t.Cleanup(bm.Close)
	bm.BindRegistry(tracker.AdmissionRegistry(), 2)
	observe := func(body string) {
		bm.AddSIPPacket("bounded-reinvite", nil, &CallMetadata{SDPBody: body}, "test0", layers.LinkTypeEthernet)
	}
	observe("m=audio 9000 RTP/AVP 0")
	observe("m=audio 9002 RTP/AVP 0")
	observe("c=IN IP4 192.0.2.1\nm=audio 10000 RTP/AVP 0")
	bm.mu.RLock()
	buffer := bm.buffers["bounded-reinvite"]
	bm.mu.RUnlock()
	require.True(t, buffer.IsRTPPort("192.0.2.1:10000"))
	require.True(t, buffer.IsRTPPort("192.0.2.1:10001"))
	require.False(t, buffer.IsRTPPort("9000"), "exact endpoint displaces earlier non-authoritative candidate")
	require.False(t, buffer.IsRTPPort("9002"))
	for port := 11000; port < 11100; port += 2 {
		observe(fmt.Sprintf("c=IN IP4 192.0.2.1\nm=audio %d RTP/AVP 0", port))
	}
	buffer.mu.RLock()
	retained := len(buffer.rtpPorts)
	buffer.mu.RUnlock()
	require.Equal(t, 2, retained)
	require.False(t, buffer.IsRTPPort("192.0.2.1:11000"))
	require.True(t, buffer.IsRTPPort("192.0.2.1:10000"), "capacity does not discard previously verified exact keys")
	require.Greater(t, bm.SDPAssociationRejected(), uint64(0))
	require.Zero(t, tracker.AdmissionRegistry().EndpointAssociationCount(), "temporary diagnostic indexing cannot fabricate authoritative ownership")
}

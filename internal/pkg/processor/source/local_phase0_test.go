package source

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

const (
	phase0CallID  = "synthetic-call@example.invalid"
	phase0MediaIP = "192.0.2.10"
)

// recordingApplicationFilter is deliberately ready for the media-safe
// operation introduced by the next phase. The extra method is not part of the
// current ApplicationFilter contract; keeping separate counters makes the
// Phase 0 characterization state which path LocalSource uses today.
type recordingApplicationFilter struct {
	mu sync.Mutex

	fullCalls        int
	packetLevelCalls int
	match            func(gopacket.Packet) (bool, []string)
	packetLevelMatch func(gopacket.Packet) (bool, []string)
}

func (f *recordingApplicationFilter) MatchPacket(packet gopacket.Packet) bool {
	matched, _ := f.MatchPacketWithIDs(packet)
	return matched
}

func (f *recordingApplicationFilter) MatchPacketWithIDs(packet gopacket.Packet) (bool, []string) {
	f.mu.Lock()
	f.fullCalls++
	match := f.match
	f.mu.Unlock()
	if match == nil {
		return false, nil
	}
	return match(packet)
}

func (f *recordingApplicationFilter) MatchPacketLevelWithIDs(packet gopacket.Packet) (bool, []string) {
	f.mu.Lock()
	f.packetLevelCalls++
	match := f.packetLevelMatch
	f.mu.Unlock()
	if match == nil {
		return false, nil
	}
	return match(packet)
}

func (f *recordingApplicationFilter) counts() (full, packetLevel int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fullCalls, f.packetLevelCalls
}

func (f *recordingApplicationFilter) resetCounts() {
	f.mu.Lock()
	f.fullCalls = 0
	f.packetLevelCalls = 0
	f.mu.Unlock()
}

func phase0SIPPayload(method, callID string, withSDP bool) []byte {
	startLine := method + " sip:service@example.invalid SIP/2.0\r\n"
	if method == "SIP/2.0" {
		startLine = "SIP/2.0 200 OK\r\n"
	}
	payload := startLine +
		"Via: SIP/2.0/UDP 192.0.2.10:5060\r\n" +
		"From: <sip:caller@example.invalid>;tag=synthetic-a\r\n" +
		"To: <sip:service@example.invalid>;tag=synthetic-b\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 " + method + "\r\n"
	if withSDP {
		payload += "Content-Type: application/sdp\r\n\r\n" +
			"v=0\r\n" +
			"o=- 1 1 IN IP4 " + phase0MediaIP + "\r\n" +
			"s=Synthetic call\r\n" +
			"c=IN IP4 " + phase0MediaIP + "\r\n" +
			"t=0 0\r\n" +
			"m=audio 20000 RTP/AVP 0\r\n"
	} else {
		payload += "\r\n"
	}
	return []byte(payload)
}

func phase0RTPPayload() []byte {
	return []byte{0x80, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb}
}

func phase0RTCPPayload() []byte {
	return []byte{0x80, 200, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 1, 0, 0, 0, 2}
}

func phase0UnclassifiedPayload() []byte {
	return []byte{0x13, 0x37, 0x00, 0xff, 0x42, 0x19}
}

func phase0UDPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort layers.UDPPort, payload []byte) capture.PacketInfo {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4(),
	}
	udp := &layers.UDP{SrcPort: srcPort, DstPort: dstPort}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, udp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	return capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, Interface: "synthetic0"}
}

func phase0SIPPacket(t *testing.T, method string, withSDP bool) capture.PacketInfo {
	return phase0UDPPacket(t, phase0MediaIP, "192.0.2.20", 5060, 5060, phase0SIPPayload(method, phase0CallID, withSDP))
}

func phase0RTPPacket(t *testing.T) capture.PacketInfo {
	return phase0UDPPacket(t, phase0MediaIP, "192.0.2.20", 20000, 30000, phase0RTPPayload())
}

func phase0RTCPPacket(t *testing.T) capture.PacketInfo {
	return phase0UDPPacket(t, phase0MediaIP, "192.0.2.20", 20000, 30001, phase0RTCPPayload())
}

func phase0UnclassifiedPacket(t *testing.T) capture.PacketInfo {
	return phase0UDPPacket(t, "198.51.100.10", "198.51.100.20", 40000, 40001, phase0UnclassifiedPayload())
}

func phase0PacketPayload(packet gopacket.Packet) []byte {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		return udpLayer.(*layers.UDP).Payload
	}
	if transport := packet.TransportLayer(); transport != nil {
		return transport.LayerPayload()
	}
	return nil
}

func runPhase0LocalSource(t *testing.T, filter ApplicationFilter, packets ...capture.PacketInfo) []*data.CapturedPacket {
	return runPhase0LocalSourceWithProcessorFilter(t, filter, nil, packets...)
}

func runPhase0LocalSourceWithProcessorFilter(t *testing.T, filter, processorFilter ApplicationFilter, packets ...capture.PacketInfo) []*data.CapturedPacket {
	t.Helper()
	cfg := DefaultLocalSourceConfig()
	cfg.BatchSize = len(packets) + 1
	cfg.BatchTimeout = time.Hour
	cfg.BatchBuffer = 2
	s := NewLocalSource(cfg)
	procCfg := voipprocessor.DefaultConfig()
	procCfg.ApplicationFilter = processorFilter
	procCfg.NeedFilterIDs = true
	proc := voipprocessor.New(procCfg)
	t.Cleanup(proc.Close)
	s.voipProcessor = voipprocessor.NewSourceAdapter(proc)
	s.appFilter = filter
	s.ctx = context.Background()

	input := make(chan capture.PacketInfo, len(packets))
	for _, packet := range packets {
		input <- packet
	}
	close(input)
	done := make(chan struct{})
	go func() {
		s.batchingWorkerWithInjection(input, false)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for LocalSource worker")
	}

	select {
	case batch := <-s.Batches():
		captured := make([]*data.CapturedPacket, 0, len(batch.Envelopes))
		for _, envelope := range batch.Envelopes {
			packet, err := grpcadapter.ToCapturedPacket(envelope)
			require.NoError(t, err)
			captured = append(captured, packet)
		}
		return captured
	default:
		return nil
	}
}

func TestLocalSourcePhase2_ClassifiedRTPInvokesPacketLevelMatcher(t *testing.T) {
	filter := &recordingApplicationFilter{match: func(packet gopacket.Packet) (bool, []string) {
		if bytes.HasPrefix(phase0PacketPayload(packet), []byte("INVITE ")) {
			return true, []string{"sip-filter"}
		}
		return false, nil
	}}

	packets := runPhase0LocalSource(t, filter, phase0SIPPacket(t, "INVITE", true), phase0RTPPacket(t))
	require.Len(t, packets, 2)
	require.NotNil(t, packets[1].Metadata.GetRtp(), "fixture must be classified as RTP")
	fullCalls, packetLevelCalls := filter.counts()
	require.Equal(t, 1, fullCalls, "the SIP verdict is evaluated once and reused")
	require.Equal(t, 1, packetLevelCalls, "classified RTP uses the packet-level matcher")
	require.Equal(t, []string{"sip-filter"}, packets[1].MatchedFilterIds, "RTP inherits the selected call's filter ID")
}

func TestLocalSourcePhase0_SIPDirectMatchAndInDialogInheritance(t *testing.T) {
	filter := &recordingApplicationFilter{match: func(packet gopacket.Packet) (bool, []string) {
		payload := phase0PacketPayload(packet)
		if bytes.HasPrefix(payload, []byte("INVITE ")) {
			return true, []string{"identity-filter"}
		}
		return false, nil
	}}

	packets := runPhase0LocalSourceWithProcessorFilter(t, filter, filter, phase0SIPPacket(t, "INVITE", false), phase0SIPPacket(t, "BYE", false))
	require.Len(t, packets, 2)
	require.Equal(t, []string{"identity-filter"}, packets[0].MatchedFilterIds)
	require.Equal(t, []string{"identity-filter"}, packets[1].MatchedFilterIds)
	require.Equal(t, "BYE", packets[1].Metadata.GetSip().Method)
	fullCalls, packetLevelCalls := filter.counts()
	require.Equal(t, 2, fullCalls, "each SIP packet reuses the processor verdict without a second source-level match")
	require.Zero(t, packetLevelCalls)
}

func TestLocalSourcePhase0_NonMatchingSIPIsDropped(t *testing.T) {
	filter := &recordingApplicationFilter{}
	require.Empty(t, runPhase0LocalSourceWithProcessorFilter(t, filter, filter, phase0SIPPacket(t, "INVITE", false)))
	fullCalls, packetLevelCalls := filter.counts()
	require.Equal(t, 1, fullCalls)
	require.Zero(t, packetLevelCalls)
}

func TestLocalSourcePhase0_RTPSelectionBaselines(t *testing.T) {
	t.Run("call inheritance", func(t *testing.T) {
		filter := &recordingApplicationFilter{match: func(packet gopacket.Packet) (bool, []string) {
			if bytes.HasPrefix(phase0PacketPayload(packet), []byte("INVITE ")) {
				return true, []string{"call-filter"}
			}
			return false, nil
		}}
		packets := runPhase0LocalSource(t, filter, phase0SIPPacket(t, "INVITE", true), phase0RTPPacket(t))
		require.Len(t, packets, 2)
		require.Equal(t, []string{"call-filter"}, packets[1].MatchedFilterIds)
	})

	t.Run("direct IP match", func(t *testing.T) {
		filter := &recordingApplicationFilter{match: func(packet gopacket.Packet) (bool, []string) {
			if bytes.HasPrefix(phase0PacketPayload(packet), []byte("INVITE ")) {
				// Permit SDP registration without caching an inherited ID.
				return true, nil
			}
			return false, nil
		}, packetLevelMatch: func(packet gopacket.Packet) (bool, []string) {
			if packet.NetworkLayer().NetworkFlow().Src().String() == phase0MediaIP &&
				packet.TransportLayer().TransportFlow().Src().String() == "20000" {
				return true, []string{"ip-filter"}
			}
			return false, nil
		}}
		packets := runPhase0LocalSource(t, filter, phase0SIPPacket(t, "INVITE", true), phase0RTPPacket(t))
		require.Len(t, packets, 2)
		require.NotNil(t, packets[1].Metadata.GetRtp())
		require.Equal(t, []string{"ip-filter"}, packets[1].MatchedFilterIds)
	})

	t.Run("unselected media drops", func(t *testing.T) {
		filter := &recordingApplicationFilter{}
		packets := runPhase0LocalSource(t, filter, phase0SIPPacket(t, "INVITE", true), phase0RTPPacket(t))
		require.Empty(t, packets)
		fullCalls, packetLevelCalls := filter.counts()
		require.Equal(t, 1, fullCalls)
		require.Equal(t, 1, packetLevelCalls)
	})
}

func TestLocalSourcePhase0_NoFilterPolicyForwardsUnclassifiedUDP(t *testing.T) {
	t.Run("nil filter allows", func(t *testing.T) {
		packets := runPhase0LocalSource(t, nil, phase0UnclassifiedPacket(t))
		require.Len(t, packets, 1)
		decoded := gopacket.NewPacket(packets[0].Data, layers.LinkTypeEthernet, gopacket.Default)
		require.Equal(t, phase0UnclassifiedPayload(), decoded.Layer(layers.LayerTypeUDP).(*layers.UDP).Payload)
	})

	t.Run("configured empty allow verdict", func(t *testing.T) {
		filter := &recordingApplicationFilter{match: func(gopacket.Packet) (bool, []string) { return true, nil }}
		require.Len(t, runPhase0LocalSource(t, filter, phase0UnclassifiedPacket(t)), 1)
		fullCalls, packetLevelCalls := filter.counts()
		require.Equal(t, 1, fullCalls)
		require.Zero(t, packetLevelCalls)
	})

	t.Run("configured empty deny verdict", func(t *testing.T) {
		filter := &recordingApplicationFilter{}
		require.Empty(t, runPhase0LocalSource(t, filter, phase0UnclassifiedPacket(t)))
		fullCalls, packetLevelCalls := filter.counts()
		require.Equal(t, 1, fullCalls)
		require.Zero(t, packetLevelCalls)
	})
}

func TestLocalSourcePhase2_ClassifiedRTCPInvokesPacketLevelMatcher(t *testing.T) {
	filter := &recordingApplicationFilter{match: func(packet gopacket.Packet) (bool, []string) {
		if bytes.HasPrefix(phase0PacketPayload(packet), []byte("INVITE ")) {
			return true, []string{"call-filter"}
		}
		return false, nil
	}}
	packets := runPhase0LocalSource(t, filter, phase0SIPPacket(t, "INVITE", true), phase0RTCPPacket(t))
	require.Len(t, packets, 2)
	require.NotNil(t, packets[1].Metadata.GetRtp(), "current detector represents associated RTCP as media metadata")
	fullCalls, packetLevelCalls := filter.counts()
	require.Equal(t, 1, fullCalls)
	require.Equal(t, 1, packetLevelCalls)
}

func TestPhase0SyntheticMediaBuilders(t *testing.T) {
	require.Equal(t, byte(2), phase0RTPPayload()[0]>>6)
	require.Equal(t, byte(2), phase0RTCPPayload()[0]>>6)
	require.NotEqual(t, byte(2), phase0UnclassifiedPayload()[0]>>6)
	require.NotNil(t, phase0RTCPPacket(t).Packet.TransportLayer())
}

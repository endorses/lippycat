package voip

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BenchmarkUDPPacketProcessing benchmarks UDP packet processing performance
func BenchmarkUDPPacketProcessing(b *testing.B) {
	// Create test UDP packet with SIP content
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 101},
	}

	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}
	udp.SetNetworkLayerForChecksum(ip)

	payload := []byte("INVITE sip:benchmark@example.com SIP/2.0\r\nCall-ID: benchmark-call-123\r\n\r\n")

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	if err != nil {
		b.Fatal("Failed to serialize test packet:", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			handleUdpPackets(pktInfo, udpLayer.(*layers.UDP))
		}
	}
}

// BenchmarkSIPHeaderParsing benchmarks SIP header parsing performance
func BenchmarkSIPHeaderParsing(b *testing.B) {
	sipMessage := []byte(`INVITE sip:user@example.com SIP/2.0
Call-ID: benchmark-call-id@example.com
From: <sip:caller@example.com>;tag=12345
To: <sip:user@example.com>
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK123456
Content-Type: application/sdp
Content-Length: 142

v=0
o=caller 123456 654321 IN IP4 192.168.1.100
s=-
c=IN IP4 192.168.1.100
t=0 0
m=audio 8000 RTP/AVP 0
a=rtpmap:0 PCMU/8000`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		headers, _ := parseSipHeaders(sipMessage)
		_ = headers["call-id"]
	}
}

// BenchmarkCallTracking benchmarks call creation and lookup performance
func BenchmarkCallTracking(b *testing.B) {
	// Clean up after benchmark
	defer func() {
		tracker := getTracker()
		tracker.mu.Lock()
		tracker.callMap = make(map[string]*CallInfo)
		tracker.portToCallID = make(map[string]string)
		tracker.mu.Unlock()
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		callID := "benchmark-call-" + string(rune(i%1000))
		GetOrCreateCall(callID, layers.LinkTypeEthernet)
	}
}

// BenchmarkCallIDExtraction benchmarks Call-ID extraction from various packet types
func BenchmarkCallIDExtraction(b *testing.B) {
	// Create a packet with stored Call-ID mapping
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID["5060"] = "benchmark-call-mapping"
	tracker.mu.Unlock()

	// Create test packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 101},
	}

	udp := &layers.UDP{
		SrcPort: 8000,
		DstPort: 5060,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}

	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload([]byte("RTP data")))
	if err != nil {
		b.Fatal("Failed to serialize test packet:", err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GetCallIDForPacket(packet)
	}

	// Clean up
	tracker.mu.Lock()
	delete(tracker.portToCallID, "5060")
	tracker.mu.Unlock()
}

// BenchmarkHighVolumeProcessing benchmarks processing many packets rapidly
func BenchmarkHighVolumeProcessing(b *testing.B) {
	// Create multiple test packets
	packets := make([]capture.PacketInfo, 100)
	for i := 0; i < 100; i++ {
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, byte(i)},
			DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    []byte{192, 168, 1, byte(i)},
			DstIP:    []byte{192, 168, 1, 101},
		}

		udp := &layers.UDP{
			SrcPort: 5060,
			DstPort: 5060,
		}
		udp.SetNetworkLayerForChecksum(ip)

		payload := []byte("INVITE sip:user" + string(rune(i)) + "@example.com SIP/2.0\r\nCall-ID: call-" + string(rune(i)) + "\r\n\r\n")

		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{ComputeChecksums: true}

		err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
		if err != nil {
			b.Fatal("Failed to serialize test packet:", err)
		}

		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		packets[i] = capture.PacketInfo{
			LinkType: layers.LinkTypeEthernet,
			Packet:   packet,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := packets[i%100]
		if udpLayer := pkt.Packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			handleUdpPackets(pkt, udpLayer.(*layers.UDP))
		}
	}
}

// BenchmarkConcurrentCallProcessing benchmarks concurrent call processing
func BenchmarkConcurrentCallProcessing(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			callID := "concurrent-call-" + string(rune(i%1000))
			GetOrCreateCall(callID, layers.LinkTypeEthernet)
			i++
		}
	})
}

// BenchmarkMemoryUsage benchmarks memory usage patterns
func BenchmarkMemoryUsage(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create and process a complete SIP transaction
		callID := "memory-test-call-" + string(rune(i%100))
		call := GetOrCreateCall(callID, layers.LinkTypeEthernet)

		// Simulate some processing
		call.SetCallInfoState("INVITE")
		call.SetCallInfoState("200")
		call.SetCallInfoState("ACK")

		// Extract port mapping
		ExtractPortFromSdp("m=audio 8000 RTP/AVP 0", callID)

		// Get Call-ID from packet simulation
		tracker := getTracker()
		tracker.mu.RLock()
		_ = tracker.portToCallID["8000"]
		tracker.mu.RUnlock()
	}
}

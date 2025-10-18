package test

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// createSyntheticPacket creates a synthetic UDP packet for testing
func createSyntheticPacket(index int) *data.CapturedPacket {
	// Create simple UDP packet
	payload := []byte(fmt.Sprintf("test packet %d", index))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{192, 168, 1, 2},
	}

	udp := &layers.UDP{
		SrcPort: 5060,
		DstPort: 5060,
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	_ = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))

	// Test packet field conversions (safe: test packet size is small, LinkType is enum)
	return &data.CapturedPacket{
		TimestampNs:    time.Now().UnixNano(),
		Data:           buf.Bytes(),
		CaptureLength:  uint32(len(buf.Bytes())),        // #nosec G115
		OriginalLength: uint32(len(buf.Bytes())),        // #nosec G115
		LinkType:       uint32(layers.LinkTypeEthernet), // #nosec G115
	}
}

// createSIPInvitePacket creates a SIP INVITE packet for testing
func createSIPInvitePacket() []byte {
	sipInvite := "INVITE sip:robb@example.com SIP/2.0\r\n"
	return []byte(sipInvite)
}

// createHTTPPacket creates an HTTP GET request packet for testing
func createHTTPPacket() []byte {
	httpReq := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	return []byte(httpReq)
}

// createDNSPacket creates a simplified DNS query packet for testing
func createDNSPacket() []byte {
	// Simplified DNS query packet
	return []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00}
}

// createTLSClientHello creates a simplified TLS ClientHello packet for testing
func createTLSClientHello() []byte {
	// Simplified TLS ClientHello
	return []byte{0x16, 0x03, 0x01, 0x00, 0x00}
}

// detectProtocol is a placeholder for protocol detection in tests
func detectProtocol(packet []byte) string {
	// Placeholder for protocol detection
	return "unknown"
}

package voip

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestHandleUdpPackets(t *testing.T) {
	// Clear existing state
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	tests := []struct {
		name    string
		srcPort layers.UDPPort
		dstPort layers.UDPPort
		payload []byte
	}{
		{
			name:    "SIP INVITE on port 5060",
			srcPort: 5060,
			dstPort: 5060,
			payload: []byte(`INVITE sip:user@example.com SIP/2.0
From: <sip:caller@example.com>;tag=123
To: <sip:user@example.com>
Call-ID: udp-test-invite@example.com
CSeq: 1 INVITE
Content-Length: 0

`),
		},
		{
			name:    "SIP REGISTER on port 5060",
			srcPort: 1234,
			dstPort: 5060,
			payload: []byte(`REGISTER sip:example.com SIP/2.0
From: <sip:user@example.com>;tag=456
To: <sip:user@example.com>
Call-ID: udp-test-register@example.com
CSeq: 2 REGISTER
Content-Length: 0

`),
		},
		{
			name:    "SIP response 200 OK",
			srcPort: 5060,
			dstPort: 1234,
			payload: []byte(`SIP/2.0 200 OK
From: <sip:caller@example.com>;tag=789
To: <sip:user@example.com>;tag=abc
Call-ID: udp-test-response@example.com
CSeq: 1 INVITE
Content-Length: 0

`),
		},
		{
			name:    "RTP packet on tracked port",
			srcPort: 8000,
			dstPort: 8001,
			payload: []byte{0x80, 0x08, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3}, // RTP header
		},
		{
			name:    "Non-SIP UDP packet",
			srcPort: 8080,
			dstPort: 8081,
			payload: []byte("Not a SIP message"),
		},
		{
			name:    "Empty payload",
			srcPort: 5060,
			dstPort: 5060,
			payload: []byte(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := createUDPPacket(tt.srcPort, tt.dstPort, tt.payload)

			pktInfo := capture.PacketInfo{
				LinkType: layers.LinkTypeEthernet,
				Packet:   packet,
			}

			// Test that the function doesn't panic
			assert.NotPanics(t, func() {
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					handleUdpPackets(pktInfo, udpLayer.(*layers.UDP))
				}
			}, "handleUdpPackets should not panic with %s", tt.name)
		})
	}
}

func TestHandleUdpPackets_RTPTracking(t *testing.T) {
	// Setup RTP port tracking
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.portToCallID["8000"] = "rtp-test-call-1"
	tracker.portToCallID["8002"] = "rtp-test-call-2"
	tracker.mu.Unlock()

	tests := []struct {
		name    string
		srcPort layers.UDPPort
		dstPort layers.UDPPort
		payload []byte
		isRTP   bool
	}{
		{
			name:    "RTP packet to tracked port",
			srcPort: 9999,
			dstPort: 8000,
			payload: []byte{0x80, 0x08, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3},
			isRTP:   true,
		},
		{
			name:    "RTP packet from tracked port",
			srcPort: 8002,
			dstPort: 9999,
			payload: []byte{0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			isRTP:   true,
		},
		{
			name:    "Non-RTP packet to untracked port",
			srcPort: 7777,
			dstPort: 8888,
			payload: []byte("Some random data"),
			isRTP:   false,
		},
		{
			name:    "SIP packet (should not be treated as RTP)",
			srcPort: 5060,
			dstPort: 5060,
			payload: []byte("INVITE sip:test@example.com SIP/2.0\r\nCall-ID: test\r\n\r\n"),
			isRTP:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := createUDPPacket(tt.srcPort, tt.dstPort, tt.payload)

			pktInfo := capture.PacketInfo{
				LinkType: layers.LinkTypeEthernet,
				Packet:   packet,
			}

			// Verify packet tracking
			isTracked := IsTracked(packet)
			if tt.isRTP {
				assert.True(t, isTracked, "RTP packet should be tracked")
			}

			// Test UDP handling
			assert.NotPanics(t, func() {
				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					handleUdpPackets(pktInfo, udpLayer.(*layers.UDP))
				}
			}, "handleUdpPackets should not panic with RTP packet")
		})
	}
}

func TestHandleUdpPackets_SIPParsing(t *testing.T) {
	// Test SIP message parsing within UDP handling
	sipMessage := `INVITE sip:user@example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: <sip:user@example.com>
From: "Caller" <sip:caller@example.com>;tag=1928301774
Call-ID: udp-sip-parsing-test@example.com
CSeq: 314159 INVITE
Contact: <sip:caller@192.168.1.100:5060>
Content-Type: application/sdp
Content-Length: 142

v=0
o=caller 2890844526 2890844527 IN IP4 192.168.1.100
s=-
c=IN IP4 192.168.1.100
t=0 0
m=audio 8000 RTP/AVP 0
a=rtpmap:0 PCMU/8000`

	packet := createUDPPacket(5060, 5060, []byte(sipMessage))

	pktInfo := capture.PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	// Clear existing state
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID = make(map[string]string)
	tracker.mu.Unlock()

	// Test UDP handling with SIP content
	assert.NotPanics(t, func() {
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			handleUdpPackets(pktInfo, udpLayer.(*layers.UDP))
		}
	}, "handleUdpPackets should handle SIP messages properly")

	// After processing, there might be port mappings created
	tracker.mu.Lock()
	hasPortMappings := len(tracker.portToCallID) > 0
	tracker.mu.Unlock()

	// The exact behavior depends on implementation, but it should not crash
	t.Logf("Port mappings created: %t", hasPortMappings)
}

// Helper function to create UDP packets for testing
func createUDPPacket(srcPort, dstPort layers.UDPPort, payload []byte) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		SrcIP:    []byte{192, 168, 1, 100},
		DstIP:    []byte{192, 168, 1, 200},
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

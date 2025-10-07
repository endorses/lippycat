package tui

import (
	"net"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestConvertPacketFast_SIPDetection verifies that SIP INVITE packets
// are correctly detected even in the fast conversion path
func TestConvertPacketFast_SIPDetection(t *testing.T) {
	tests := []struct {
		name           string
		sipPayload     []byte
		expectedProto  string
		useTCP         bool
	}{
		{
			name:          "UDP SIP INVITE",
			sipPayload:    []byte("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "UDP SIP REGISTER",
			sipPayload:    []byte("REGISTER sip:example.com SIP/2.0\r\n"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "UDP SIP ACK",
			sipPayload:    []byte("ACK sip:bob@example.com SIP/2.0\r\n"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "UDP SIP BYE",
			sipPayload:    []byte("BYE sip:bob@example.com SIP/2.0\r\n"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "UDP SIP response",
			sipPayload:    []byte("SIP/2.0 200 OK\r\n"),
			expectedProto: "SIP",
			useTCP:        false,
		},
		{
			name:          "TCP SIP INVITE",
			sipPayload:    []byte("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP"),
			expectedProto: "SIP",
			useTCP:        true,
		},
		{
			name:          "UDP non-SIP",
			sipPayload:    []byte("GET / HTTP/1.1\r\n"),
			expectedProto: "UDP",
			useTCP:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a packet
			eth := &layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				EthernetType: layers.EthernetTypeIPv4,
			}

			ip := &layers.IPv4{
				Version:  4,
				TTL:      64,
				IHL:      5,
				SrcIP:    net.IP{192, 168, 1, 1},
				DstIP:    net.IP{192, 168, 1, 2},
			}

			var packet gopacket.Packet
			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{ComputeChecksums: true}

			if tt.useTCP {
				ip.Protocol = layers.IPProtocolTCP
				tcp := &layers.TCP{
					SrcPort:    5060,
					DstPort:    5060,
					SYN:        false,
					ACK:        true,
					PSH:        true, // Data packet
					DataOffset: 5,    // 20 bytes header (5 * 4)
					Seq:        1000,
					Ack:        1000,
					Window:     65535,
				}
				tcp.SetNetworkLayerForChecksum(ip)
				err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp, gopacket.Payload(tt.sipPayload))
				assert.NoError(t, err)
			} else {
				ip.Protocol = layers.IPProtocolUDP
				udp := &layers.UDP{
					SrcPort: 5060,
					DstPort: 5060,
				}
				udp.SetNetworkLayerForChecksum(ip)
				err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(tt.sipPayload))
				assert.NoError(t, err)
			}

			packet = gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

			// Convert using fast path
			pktInfo := capture.PacketInfo{
				Packet:    packet,
				Interface: "test0",
			}

			display := convertPacketFast(pktInfo)

			// Verify protocol detection
			assert.Equal(t, tt.expectedProto, display.Protocol,
				"Protocol should be %s for %s", tt.expectedProto, tt.name)
		})
	}
}

// TestConvertPacketFast_NonSIPUDP verifies that non-SIP UDP packets
// are still correctly identified as UDP
func TestConvertPacketFast_NonSIPUDP(t *testing.T) {
	// Build a DNS query packet (UDP but not SIP)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		IHL:      5,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{8, 8, 8, 8},
	}

	udp := &layers.UDP{
		SrcPort: 12345,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Random payload (not SIP)
	payload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, eth, ip, udp, gopacket.Payload(payload))
	assert.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	pktInfo := capture.PacketInfo{
		Packet:    packet,
		Interface: "test0",
	}
	display := convertPacketFast(pktInfo)

	// Should be detected as UDP, not SIP
	assert.Equal(t, "UDP", display.Protocol)
	assert.Equal(t, "12345", display.SrcPort)
	assert.Equal(t, "53", display.DstPort)
}

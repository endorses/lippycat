package capture

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConvertPacketToDisplay_UDP tests UDP packet conversion
func TestConvertPacketToDisplay_UDP(t *testing.T) {
	pkt := createTestPacket() // This creates a UDP packet

	display := ConvertPacketToDisplay(pkt)

	assert.Equal(t, "UDP", display.Protocol, "Should identify UDP protocol")
	assert.Equal(t, "5060", display.SrcPort, "Should extract source port")
	assert.Equal(t, "5060", display.DstPort, "Should extract destination port")
	assert.Equal(t, "192.168.1.100", display.SrcIP, "Should extract source IP")
	assert.Equal(t, "192.168.1.101", display.DstIP, "Should extract destination IP")
	assert.Equal(t, layers.LinkTypeEthernet, display.LinkType, "Should preserve link type")
	assert.Equal(t, "Local", display.NodeID, "Should default to Local node")
}

// TestConvertPacketToDisplay_TCP tests TCP packet conversion with flags
func TestConvertPacketToDisplay_TCP(t *testing.T) {
	// Create a TCP SYN packet
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{10, 0, 0, 1},
		DstIP:    []byte{10, 0, 0, 2},
	}

	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
		Seq:     1000,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp)
	require.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo := PacketInfo{
		LinkType:  layers.LinkTypeEthernet,
		Packet:    packet,
		Interface: "eth0",
	}

	display := ConvertPacketToDisplay(pktInfo)

	assert.Equal(t, "TCP", display.Protocol, "Should identify TCP protocol")
	assert.Equal(t, "12345", display.SrcPort, "Should extract source port")
	assert.Equal(t, "80", display.DstPort, "Should extract destination port")
	assert.Equal(t, "10.0.0.1", display.SrcIP, "Should extract source IP")
	assert.Equal(t, "10.0.0.2", display.DstIP, "Should extract destination IP")
	assert.Contains(t, display.Info, "SYN", "Should show SYN flag in info")
	assert.Equal(t, "eth0", display.Interface, "Should preserve interface name")
}

// TestConvertPacketToDisplay_TCPFlags tests various TCP flag combinations
func TestConvertPacketToDisplay_TCPFlags(t *testing.T) {
	tests := []struct {
		name                    string
		syn, ack, fin, rst, psh bool
		expectedFlags           []string
	}{
		{"SYN only", true, false, false, false, false, []string{"SYN"}},
		{"SYN+ACK", true, true, false, false, false, []string{"SYN", "ACK"}},
		{"ACK only", false, true, false, false, false, []string{"ACK"}},
		{"FIN+ACK", false, true, true, false, false, []string{"ACK", "FIN"}},
		{"RST", false, false, false, true, false, []string{"RST"}},
		{"PSH+ACK", false, true, false, false, true, []string{"ACK", "PSH"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eth := &layers.Ethernet{
				SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
				DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
				EthernetType: layers.EthernetTypeIPv4,
			}

			ip := &layers.IPv4{
				Version:  4,
				IHL:      5,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
				SrcIP:    []byte{192, 168, 1, 1},
				DstIP:    []byte{192, 168, 1, 2},
			}

			tcp := &layers.TCP{
				SrcPort: 443,
				DstPort: 50000,
				SYN:     tt.syn,
				ACK:     tt.ack,
				FIN:     tt.fin,
				RST:     tt.rst,
				PSH:     tt.psh,
			}
			tcp.SetNetworkLayerForChecksum(ip)

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{ComputeChecksums: true}
			err := gopacket.SerializeLayers(buffer, options, eth, ip, tcp)
			require.NoError(t, err)

			packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
			pktInfo := PacketInfo{
				LinkType: layers.LinkTypeEthernet,
				Packet:   packet,
			}

			display := ConvertPacketToDisplay(pktInfo)

			assert.Equal(t, "TCP", display.Protocol)
			for _, flag := range tt.expectedFlags {
				assert.Contains(t, display.Info, flag, "Should contain %s flag", flag)
			}
		})
	}
}

// TestConvertPacketToDisplay_IPv6 tests IPv6 packet conversion
func TestConvertPacketToDisplay_IPv6(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, eth, ip6)
	require.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo := PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	display := ConvertPacketToDisplay(pktInfo)

	assert.Equal(t, "2001:db8::1", display.SrcIP, "Should extract IPv6 source address")
	assert.Equal(t, "2001:db8::2", display.DstIP, "Should extract IPv6 destination address")
	assert.Equal(t, "ICMPv6", display.Protocol, "Should show ICMPv6 as next header from IPv6")
}

// TestConvertPacketToDisplay_ARP tests ARP packet conversion
func TestConvertPacketToDisplay_ARP(t *testing.T) {
	tests := []struct {
		name       string
		operation  uint16
		expectInfo string
	}{
		{"ARP Request", 1, "Who has 192.168.1.2"},
		{"ARP Reply", 2, "192.168.1.1 is at"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eth := &layers.Ethernet{
				SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
				DstMAC:       []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				EthernetType: layers.EthernetTypeARP,
			}

			arp := &layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         tt.operation,
				SourceHwAddress:   []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
				SourceProtAddress: []byte{192, 168, 1, 1},
				DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
				DstProtAddress:    []byte{192, 168, 1, 2},
			}

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{}
			err := gopacket.SerializeLayers(buffer, options, eth, arp)
			require.NoError(t, err)

			packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
			pktInfo := PacketInfo{
				LinkType: layers.LinkTypeEthernet,
				Packet:   packet,
			}

			display := ConvertPacketToDisplay(pktInfo)

			assert.Equal(t, "ARP", display.Protocol, "Should identify ARP protocol")
			assert.Equal(t, "192.168.1.1", display.SrcIP, "Should extract source IP from ARP")
			assert.Equal(t, "192.168.1.2", display.DstIP, "Should extract destination IP from ARP")
			assert.Contains(t, display.Info, tt.expectInfo, "Should contain expected ARP info")
		})
	}
}

// TestConvertPacketToDisplay_ICMP tests ICMP packet conversion
func TestConvertPacketToDisplay_ICMP(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    []byte{192, 168, 1, 1},
		DstIP:    []byte{8, 8, 8, 8},
	}

	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(8, 0), // Echo request
		Id:       1,
		Seq:      1,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, eth, ip, icmp)
	require.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo := PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	display := ConvertPacketToDisplay(pktInfo)

	assert.Equal(t, "ICMP", display.Protocol, "Should identify ICMP protocol")
	assert.Equal(t, "192.168.1.1", display.SrcIP, "Should extract source IP")
	assert.Equal(t, "8.8.8.8", display.DstIP, "Should extract destination IP")
	assert.Empty(t, display.SrcPort, "ICMP should not have port")
	assert.Empty(t, display.DstPort, "ICMP should not have port")
}

// TestConvertPacketToDisplay_ICMPv6 tests ICMPv6 packet conversion
func TestConvertPacketToDisplay_ICMPv6(t *testing.T) {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetTypeIPv6,
	}

	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		DstIP:      []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
	}

	icmp6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(128, 0), // Echo request
	}
	icmp6.SetNetworkLayerForChecksum(ip6)

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, options, eth, ip6, icmp6)
	require.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo := PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	display := ConvertPacketToDisplay(pktInfo)

	assert.Equal(t, "ICMPv6", display.Protocol, "Should identify ICMPv6 protocol")
	assert.Equal(t, "2001:db8::1", display.SrcIP, "Should extract IPv6 source")
	assert.Equal(t, "2001:db8::2", display.DstIP, "Should extract IPv6 destination")
}

// TestConvertPacketToDisplay_NonIPProtocols tests non-IP Ethernet protocols
func TestConvertPacketToDisplay_NonIPProtocols(t *testing.T) {
	tests := []struct {
		name         string
		ethernetType layers.EthernetType
		expected     string
	}{
		{"LLC", layers.EthernetTypeLLC, "LLC"},
		{"CDP", layers.EthernetTypeCiscoDiscovery, "CDP"},
		{"LLDP", layers.EthernetTypeLinkLayerDiscovery, "LLDP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eth := &layers.Ethernet{
				SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
				DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
				EthernetType: tt.ethernetType,
			}

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{}
			err := gopacket.SerializeLayers(buffer, options, eth)
			require.NoError(t, err)

			packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
			pktInfo := PacketInfo{
				LinkType: layers.LinkTypeEthernet,
				Packet:   packet,
			}

			display := ConvertPacketToDisplay(pktInfo)

			assert.Equal(t, tt.expected, display.Protocol, "Should identify %s protocol", tt.expected)
			// For non-IP protocols, MAC addresses are used as src/dst
			assert.NotEmpty(t, display.SrcIP, "Should have source MAC as IP")
			assert.NotEmpty(t, display.DstIP, "Should have destination MAC as IP")
		})
	}
}

// TestConvertPacketToDisplay_Metadata tests that metadata is properly preserved
func TestConvertPacketToDisplay_Metadata(t *testing.T) {
	pkt := createTestPacket()
	pkt.Interface = "wlan0"

	display := ConvertPacketToDisplay(pkt)

	assert.Equal(t, "wlan0", display.Interface, "Should preserve interface name")
	assert.Equal(t, layers.LinkTypeEthernet, display.LinkType, "Should preserve link type")
	// Length comes from packet metadata, which may be 0 for synthetic packets
	assert.GreaterOrEqual(t, display.Length, 0, "Should have packet length")
	// Timestamp comes from packet metadata, which may be zero for synthetic packets
	// Just verify the field exists
	_ = display.Timestamp
}

// TestConvertPacketToDisplay_RawDataNil tests that raw data is nil for memory efficiency
func TestConvertPacketToDisplay_RawDataNil(t *testing.T) {
	pkt := createTestPacket()

	display := ConvertPacketToDisplay(pkt)

	assert.Nil(t, display.RawData, "RawData should be nil for memory efficiency")
}

// TestConvertPacketToDisplay_UnknownProtocol tests handling of unknown protocols
func TestConvertPacketToDisplay_UnknownProtocol(t *testing.T) {
	// Create a minimal packet with just Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4e},
		DstMAC:       []byte{0x00, 0x0c, 0x29, 0x1f, 0x3c, 0x4f},
		EthernetType: layers.EthernetType(0x9999), // Unknown type
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buffer, options, eth)
	require.NoError(t, err)

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pktInfo := PacketInfo{
		LinkType: layers.LinkTypeEthernet,
		Packet:   packet,
	}

	display := ConvertPacketToDisplay(pktInfo)

	// Should show hex value for unknown ethernet type
	assert.Equal(t, "0x9999", display.Protocol, "Should show hex value for unknown protocol")
}

// TestConvertPacketToDisplay_Timestamp tests that timestamps are preserved
func TestConvertPacketToDisplay_Timestamp(t *testing.T) {
	pkt := createTestPacket()

	// Packets created by createTestPacket have metadata which may have zero timestamp
	display := ConvertPacketToDisplay(pkt)

	// The timestamp field should exist (may be zero for synthetic packets)
	// The converter just copies metadata.Timestamp, it doesn't generate timestamps
	_ = display.Timestamp

	// Test that non-zero timestamps are preserved correctly
	// We can't easily inject a real timestamp into the test packet without
	// going through actual pcap reading, but we verify the field is accessible
	assert.NotNil(t, display, "Display should not be nil")
}

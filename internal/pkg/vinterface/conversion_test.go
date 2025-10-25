package vinterface

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertToEthernet_IPv4_TCP(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		SrcPort:  "5060",
		DstPort:  "5061",
		Protocol: "TCP",
		Info:     "SIP INVITE",
		LinkType: layers.LinkTypeEthernet,
	}

	frame, err := ConvertToEthernet(pkt)
	require.NoError(t, err)
	require.NotNil(t, frame)

	// Verify Ethernet header (14 bytes)
	assert.GreaterOrEqual(t, len(frame), 14, "Frame should have Ethernet header")

	// Parse frame to verify structure
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	// Check Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "Should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)
	assert.Equal(t, layers.EthernetTypeIPv4, eth.EthernetType)

	// Check IPv4 layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "Should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)
	assert.Equal(t, "192.168.1.100", ip.SrcIP.String())
	assert.Equal(t, "192.168.1.200", ip.DstIP.String())
	assert.Equal(t, layers.IPProtocolTCP, ip.Protocol)

	// Check TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "Should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)
	assert.Equal(t, layers.TCPPort(5060), tcp.SrcPort)
	assert.Equal(t, layers.TCPPort(5061), tcp.DstPort)
}

func TestConvertToEthernet_IPv4_UDP(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		SrcPort:  "5060",
		DstPort:  "5060",
		Protocol: "UDP",
		Info:     "SIP REGISTER",
		LinkType: layers.LinkTypeEthernet,
	}

	frame, err := ConvertToEthernet(pkt)
	require.NoError(t, err)
	require.NotNil(t, frame)

	// Parse frame to verify structure
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	// Check Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "Should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)
	assert.Equal(t, layers.EthernetTypeIPv4, eth.EthernetType)

	// Check IPv4 layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "Should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)
	assert.Equal(t, "10.0.0.1", ip.SrcIP.String())
	assert.Equal(t, "10.0.0.2", ip.DstIP.String())
	assert.Equal(t, layers.IPProtocolUDP, ip.Protocol)

	// Check UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	require.NotNil(t, udpLayer, "Should have UDP layer")
	udp := udpLayer.(*layers.UDP)
	assert.Equal(t, layers.UDPPort(5060), udp.SrcPort)
	assert.Equal(t, layers.UDPPort(5060), udp.DstPort)
}

func TestConvertToEthernet_IPv6_TCP(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "2001:db8::1",
		DstIP:    "2001:db8::2",
		SrcPort:  "5060",
		DstPort:  "5061",
		Protocol: "TCP",
		Info:     "SIP OPTIONS",
		LinkType: layers.LinkTypeEthernet,
	}

	frame, err := ConvertToEthernet(pkt)
	require.NoError(t, err)
	require.NotNil(t, frame)

	// Parse frame to verify structure
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	// Check Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "Should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)
	assert.Equal(t, layers.EthernetTypeIPv6, eth.EthernetType)

	// Check IPv6 layer
	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	require.NotNil(t, ipLayer, "Should have IPv6 layer")
	ip := ipLayer.(*layers.IPv6)
	assert.Equal(t, "2001:db8::1", ip.SrcIP.String())
	assert.Equal(t, "2001:db8::2", ip.DstIP.String())
	assert.Equal(t, layers.IPProtocolTCP, ip.NextHeader)

	// Check TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "Should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)
	assert.Equal(t, layers.TCPPort(5060), tcp.SrcPort)
	assert.Equal(t, layers.TCPPort(5061), tcp.DstPort)
}

func TestConvertToEthernet_IPv6_UDP(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "fe80::1",
		DstIP:    "fe80::2",
		SrcPort:  "5060",
		DstPort:  "5060",
		Protocol: "UDP",
		Info:     "RTP",
		LinkType: layers.LinkTypeEthernet,
	}

	frame, err := ConvertToEthernet(pkt)
	require.NoError(t, err)
	require.NotNil(t, frame)

	// Parse frame to verify structure
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	// Check Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	require.NotNil(t, ethLayer, "Should have Ethernet layer")
	eth := ethLayer.(*layers.Ethernet)
	assert.Equal(t, layers.EthernetTypeIPv6, eth.EthernetType)

	// Check IPv6 layer
	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	require.NotNil(t, ipLayer, "Should have IPv6 layer")
	ip := ipLayer.(*layers.IPv6)
	assert.Equal(t, "fe80::1", ip.SrcIP.String())
	assert.Equal(t, "fe80::2", ip.DstIP.String())
	assert.Equal(t, layers.IPProtocolUDP, ip.NextHeader)

	// Check UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	require.NotNil(t, udpLayer, "Should have UDP layer")
	udp := udpLayer.(*layers.UDP)
	assert.Equal(t, layers.UDPPort(5060), udp.SrcPort)
	assert.Equal(t, layers.UDPPort(5060), udp.DstPort)
}

func TestConvertToEthernet_WithRawData(t *testing.T) {
	// Create a real IP packet (without Ethernet header)
	srcIP := []byte{192, 168, 1, 100}
	dstIP := []byte{192, 168, 1, 200}

	// Minimal IPv4 header (20 bytes)
	ipHeader := []byte{
		0x45,       // Version (4) + IHL (5)
		0x00,       // DSCP + ECN
		0x00, 0x28, // Total length (40 bytes: 20 IP + 20 TCP)
		0x00, 0x00, // Identification
		0x40, 0x00, // Flags + Fragment offset
		0x40,       // TTL (64)
		0x06,       // Protocol (TCP)
		0x00, 0x00, // Checksum (will be computed)
	}
	ipHeader = append(ipHeader, srcIP...)
	ipHeader = append(ipHeader, dstIP...)

	// Minimal TCP header (20 bytes)
	tcpHeader := []byte{
		0x13, 0xc4, // Source port (5060)
		0x13, 0xc5, // Dest port (5061)
		0x00, 0x00, 0x00, 0x00, // Sequence number
		0x00, 0x00, 0x00, 0x00, // Acknowledgment number
		0x50, 0x02, // Data offset (5) + flags (SYN)
		0x20, 0x00, // Window size
		0x00, 0x00, // Checksum
		0x00, 0x00, // Urgent pointer
	}

	rawData := append(ipHeader, tcpHeader...)

	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		SrcPort:  "5060",
		DstPort:  "5061",
		Protocol: "TCP",
		RawData:  rawData,
		LinkType: layers.LinkTypeRaw, // Raw IP packet
	}

	frame, err := ConvertToEthernet(pkt)
	require.NoError(t, err)
	require.NotNil(t, frame)

	// Should have Ethernet header prepended (14 bytes) + original data
	assert.GreaterOrEqual(t, len(frame), 14+len(rawData))

	// Parse to verify
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	// Should have all layers
	assert.NotNil(t, packet.Layer(layers.LayerTypeEthernet))
	assert.NotNil(t, packet.Layer(layers.LayerTypeIPv4))
	assert.NotNil(t, packet.Layer(layers.LayerTypeTCP))
}

func TestConvertToEthernet_NilPacket(t *testing.T) {
	frame, err := ConvertToEthernet(nil)
	assert.Error(t, err)
	assert.Nil(t, frame)
	assert.Contains(t, err.Error(), "nil packet")
}

func TestConvertToEthernet_InvalidIPAddress(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "invalid",
		DstIP:    "192.168.1.200",
		SrcPort:  "5060",
		DstPort:  "5061",
		Protocol: "TCP",
		LinkType: layers.LinkTypeEthernet,
	}

	frame, err := ConvertToEthernet(pkt)
	assert.Error(t, err)
	assert.Nil(t, frame)
	assert.Contains(t, err.Error(), "invalid IP addresses")
}

func TestConvertToEthernet_InvalidPort(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		SrcPort:  "invalid",
		DstPort:  "5061",
		Protocol: "TCP",
		LinkType: layers.LinkTypeEthernet,
	}

	frame, err := ConvertToEthernet(pkt)
	assert.Error(t, err)
	assert.Nil(t, frame)
	assert.Contains(t, err.Error(), "invalid")
}

func TestConvertToIP_IPv4_TCP(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		SrcPort:  "5060",
		DstPort:  "5061",
		Protocol: "TCP",
		Info:     "SIP INVITE",
		LinkType: layers.LinkTypeRaw,
	}

	ipPacket, err := ConvertToIP(pkt)
	require.NoError(t, err)
	require.NotNil(t, ipPacket)

	// Parse as raw IP packet (no Ethernet layer)
	packet := gopacket.NewPacket(ipPacket, layers.LayerTypeIPv4, gopacket.Default)

	// Should NOT have Ethernet layer
	assert.Nil(t, packet.Layer(layers.LayerTypeEthernet))

	// Check IPv4 layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "Should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)
	assert.Equal(t, "192.168.1.100", ip.SrcIP.String())
	assert.Equal(t, "192.168.1.200", ip.DstIP.String())
	assert.Equal(t, layers.IPProtocolTCP, ip.Protocol)

	// Check TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "Should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)
	assert.Equal(t, layers.TCPPort(5060), tcp.SrcPort)
	assert.Equal(t, layers.TCPPort(5061), tcp.DstPort)
}

func TestConvertToIP_IPv4_UDP(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "10.0.0.1",
		DstIP:    "10.0.0.2",
		SrcPort:  "5060",
		DstPort:  "5060",
		Protocol: "UDP",
		Info:     "RTP",
		LinkType: layers.LinkTypeRaw,
	}

	ipPacket, err := ConvertToIP(pkt)
	require.NoError(t, err)
	require.NotNil(t, ipPacket)

	// Parse as raw IP packet
	packet := gopacket.NewPacket(ipPacket, layers.LayerTypeIPv4, gopacket.Default)

	// Should NOT have Ethernet layer
	assert.Nil(t, packet.Layer(layers.LayerTypeEthernet))

	// Check IPv4 layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "Should have IPv4 layer")
	ip := ipLayer.(*layers.IPv4)
	assert.Equal(t, "10.0.0.1", ip.SrcIP.String())
	assert.Equal(t, "10.0.0.2", ip.DstIP.String())
	assert.Equal(t, layers.IPProtocolUDP, ip.Protocol)

	// Check UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	require.NotNil(t, udpLayer, "Should have UDP layer")
	udp := udpLayer.(*layers.UDP)
	assert.Equal(t, layers.UDPPort(5060), udp.SrcPort)
	assert.Equal(t, layers.UDPPort(5060), udp.DstPort)
}

func TestConvertToIP_IPv6_TCP(t *testing.T) {
	pkt := &types.PacketDisplay{
		SrcIP:    "2001:db8::1",
		DstIP:    "2001:db8::2",
		SrcPort:  "5060",
		DstPort:  "5061",
		Protocol: "TCP",
		Info:     "SIP OPTIONS",
		LinkType: layers.LinkTypeRaw,
	}

	ipPacket, err := ConvertToIP(pkt)
	require.NoError(t, err)
	require.NotNil(t, ipPacket)

	// Parse as raw IPv6 packet
	packet := gopacket.NewPacket(ipPacket, layers.LayerTypeIPv6, gopacket.Default)

	// Should NOT have Ethernet layer
	assert.Nil(t, packet.Layer(layers.LayerTypeEthernet))

	// Check IPv6 layer
	ipLayer := packet.Layer(layers.LayerTypeIPv6)
	require.NotNil(t, ipLayer, "Should have IPv6 layer")
	ip := ipLayer.(*layers.IPv6)
	assert.Equal(t, "2001:db8::1", ip.SrcIP.String())
	assert.Equal(t, "2001:db8::2", ip.DstIP.String())
	assert.Equal(t, layers.IPProtocolTCP, ip.NextHeader)

	// Check TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	require.NotNil(t, tcpLayer, "Should have TCP layer")
	tcp := tcpLayer.(*layers.TCP)
	assert.Equal(t, layers.TCPPort(5060), tcp.SrcPort)
	assert.Equal(t, layers.TCPPort(5061), tcp.DstPort)
}

func TestConvertToIP_StripEthernetHeader(t *testing.T) {
	// Create a packet with Ethernet header in RawData
	ethHeader := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Src MAC
		0x08, 0x00, // EtherType (IPv4)
	}

	// Minimal IPv4 header
	ipHeader := []byte{
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		192, 168, 1, 100, // Src IP
		192, 168, 1, 200, // Dst IP
	}

	rawData := append(ethHeader, ipHeader...)

	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		Protocol: "TCP",
		RawData:  rawData,
		LinkType: layers.LinkTypeEthernet, // Has Ethernet header
	}

	ipPacket, err := ConvertToIP(pkt)
	require.NoError(t, err)
	require.NotNil(t, ipPacket)

	// Should have stripped Ethernet header (14 bytes)
	assert.Equal(t, len(rawData)-14, len(ipPacket))

	// First byte should be IP version (0x45 for IPv4 with IHL=5)
	assert.Equal(t, byte(0x45), ipPacket[0])
}

func TestConvertToIP_NilPacket(t *testing.T) {
	ipPacket, err := ConvertToIP(nil)
	assert.Error(t, err)
	assert.Nil(t, ipPacket)
	assert.Contains(t, err.Error(), "nil packet")
}

func TestExtractIPPacket_AlreadyIPPacket(t *testing.T) {
	// IP packet without Ethernet header
	ipData := []byte{
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		192, 168, 1, 100,
		192, 168, 1, 200,
	}

	result, err := extractIPPacket(ipData, layers.LinkTypeRaw)
	require.NoError(t, err)
	assert.Equal(t, ipData, result) // Should return as-is
}

func TestExtractIPPacket_WithEthernetHeader(t *testing.T) {
	ethHeader := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x00,
	}
	ipData := []byte{0x45, 0x00, 0x00, 0x28}

	fullData := append(ethHeader, ipData...)

	result, err := extractIPPacket(fullData, layers.LinkTypeEthernet)
	require.NoError(t, err)
	assert.Equal(t, ipData, result) // Should strip Ethernet header
}

func TestExtractIPPacket_TooShort(t *testing.T) {
	shortData := []byte{0x00, 0x01, 0x02} // Less than 14 bytes

	result, err := extractIPPacket(shortData, layers.LinkTypeEthernet)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "too short")
}

func TestPrependEthernetHeader_IPv4(t *testing.T) {
	ipData := []byte{
		0x45, 0x00, 0x00, 0x28, // IPv4 header
	}

	frame, err := prependEthernetHeader(ipData, layers.LinkTypeRaw)
	require.NoError(t, err)
	require.NotNil(t, frame)

	// Should have Ethernet header (14 bytes) + IP data
	assert.Equal(t, 14+len(ipData), len(frame))

	// Check EtherType for IPv4
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	assert.Equal(t, uint16(layers.EthernetTypeIPv4), etherType)
}

func TestPrependEthernetHeader_IPv6(t *testing.T) {
	ipData := []byte{
		0x60, 0x00, 0x00, 0x00, // IPv6 header (version 6)
	}

	frame, err := prependEthernetHeader(ipData, layers.LinkTypeRaw)
	require.NoError(t, err)
	require.NotNil(t, frame)

	// Check EtherType for IPv6
	etherType := uint16(frame[12])<<8 | uint16(frame[13])
	assert.Equal(t, uint16(layers.EthernetTypeIPv6), etherType)
}

func TestPrependEthernetHeader_AlreadyHasEthernet(t *testing.T) {
	// Frame already has Ethernet header
	fullFrame := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x28,
	}

	result, err := prependEthernetHeader(fullFrame, layers.LinkTypeEthernet)
	require.NoError(t, err)
	assert.Equal(t, fullFrame, result) // Should return as-is
}

func TestParsePorts_Valid(t *testing.T) {
	src, dst, err := parsePorts("5060", "5061")
	require.NoError(t, err)
	assert.Equal(t, uint16(5060), src)
	assert.Equal(t, uint16(5061), dst)
}

func TestParsePorts_Empty(t *testing.T) {
	src, dst, err := parsePorts("", "")
	require.NoError(t, err)
	assert.Equal(t, uint16(0), src)
	assert.Equal(t, uint16(0), dst)
}

func TestParsePorts_InvalidSource(t *testing.T) {
	src, dst, err := parsePorts("invalid", "5060")
	assert.Error(t, err)
	assert.Equal(t, uint16(0), src)
	assert.Equal(t, uint16(0), dst)
	assert.Contains(t, err.Error(), "invalid source port")
}

func TestParsePorts_InvalidDestination(t *testing.T) {
	src, dst, err := parsePorts("5060", "invalid")
	assert.Error(t, err)
	assert.Equal(t, uint16(0), src)
	assert.Equal(t, uint16(0), dst)
	assert.Contains(t, err.Error(), "invalid destination port")
}

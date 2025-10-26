package vinterface

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ConvertToEthernet converts a PacketDisplay to a raw Ethernet frame.
// This is used for TAP interface injection, which requires complete Layer 2 frames.
//
// The conversion follows this structure:
// - Ethernet header (14 bytes)
// - IP layer (IPv4 or IPv6) from RawData
// - Transport layer (TCP/UDP) from RawData
//
// If RawData is available and contains a complete packet, it's used directly
// with an Ethernet header prepended. Otherwise, the packet is reconstructed
// from PacketDisplay fields.
func ConvertToEthernet(pkt *types.PacketDisplay) ([]byte, error) {
	if pkt == nil {
		return nil, fmt.Errorf("nil packet")
	}

	// If we have raw data, use it directly (it should be IP layer and above)
	if len(pkt.RawData) > 0 {
		return prependEthernetHeader(pkt.RawData, pkt.LinkType)
	}

	// Otherwise, reconstruct from packet fields
	return reconstructPacket(pkt)
}

// ConvertToIP converts a PacketDisplay to a raw IP packet (without Ethernet header).
// This is used for TUN interface injection, which requires Layer 3 packets only.
//
// The conversion follows this structure:
// - IP layer (IPv4 or IPv6) from RawData
// - Transport layer (TCP/UDP) from RawData
//
// If RawData contains an Ethernet frame, the Ethernet header is stripped.
// Otherwise, the IP packet is reconstructed from PacketDisplay fields.
func ConvertToIP(pkt *types.PacketDisplay) ([]byte, error) {
	if pkt == nil {
		return nil, fmt.Errorf("nil packet")
	}

	// If we have raw data, extract the IP packet
	if len(pkt.RawData) > 0 {
		return extractIPPacket(pkt.RawData, pkt.LinkType)
	}

	// Otherwise, reconstruct IP packet from packet fields
	return reconstructIPPacket(pkt)
}

// extractIPPacket extracts the IP packet from raw data, stripping Ethernet or LinuxSLL header if present.
func extractIPPacket(rawData []byte, linkType layers.LinkType) ([]byte, error) {
	// Handle LinuxSLL (Linux cooked capture) - strip 16-byte SLL header
	if linkType == layers.LinkTypeLinuxSLL {
		if len(rawData) < 16 {
			return nil, fmt.Errorf("packet too short to contain LinuxSLL header: %d bytes", len(rawData))
		}
		// Return IP packet (everything after SLL header)
		return rawData[16:], nil
	}

	// Handle Ethernet - strip 14-byte Ethernet header
	if linkType == layers.LinkTypeEthernet {
		if len(rawData) < 14 {
			return nil, fmt.Errorf("packet too short to contain Ethernet header: %d bytes", len(rawData))
		}
		// Return IP packet (everything after Ethernet header)
		return rawData[14:], nil
	}

	// For other link types, assume it's already an IP packet
	return rawData, nil
}

// prependEthernetHeader adds an Ethernet header to raw IP packet data.
func prependEthernetHeader(rawData []byte, linkType layers.LinkType) ([]byte, error) {
	// If already has Ethernet header, return as-is
	if linkType == layers.LinkTypeEthernet && len(rawData) >= 14 {
		return rawData, nil
	}

	// Handle LinuxSLL (Linux cooked capture) - strip 16-byte SLL header
	ipPacket := rawData
	if linkType == layers.LinkTypeLinuxSLL {
		if len(rawData) < 16 {
			return nil, fmt.Errorf("packet too short for LinuxSLL header: %d bytes", len(rawData))
		}
		// Skip 16-byte SLL header to get to IP layer
		ipPacket = rawData[16:]
	}

	// Determine EtherType from IP version
	etherType := layers.EthernetTypeIPv4
	if len(ipPacket) > 0 {
		version := ipPacket[0] >> 4
		if version == 6 {
			etherType = layers.EthernetTypeIPv6
		}
	}

	// Create Ethernet header (14 bytes)
	frame := make([]byte, 14+len(ipPacket))

	// Destination MAC: 00:00:00:00:00:00 (wildcard)
	// Source MAC: 02:00:00:00:00:01 (locally administered unicast)
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = 0x00
	frame[3] = 0x00
	frame[4] = 0x00
	frame[5] = 0x00
	frame[6] = 0x02
	frame[7] = 0x00
	frame[8] = 0x00
	frame[9] = 0x00
	frame[10] = 0x00
	frame[11] = 0x01

	// EtherType
	binary.BigEndian.PutUint16(frame[12:14], uint16(etherType))

	// Copy IP payload
	copy(frame[14:], ipPacket)

	return frame, nil
}

// reconstructIPPacket builds an IP packet from PacketDisplay fields (without Ethernet header).
// This is a fallback for TUN interfaces when RawData is not available.
func reconstructIPPacket(pkt *types.PacketDisplay) ([]byte, error) {
	// Parse IP addresses
	srcIP := net.ParseIP(pkt.SrcIP)
	dstIP := net.ParseIP(pkt.DstIP)
	if srcIP == nil || dstIP == nil {
		return nil, fmt.Errorf("invalid IP addresses: src=%s dst=%s", pkt.SrcIP, pkt.DstIP)
	}

	// Determine if IPv4 or IPv6
	isIPv6 := srcIP.To4() == nil

	// Create packet buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Build layers from top to bottom
	var payload gopacket.Payload
	if pkt.Info != "" {
		payload = gopacket.Payload([]byte(pkt.Info))
	}

	// Create transport layer
	var transportLayer gopacket.SerializableLayer
	switch pkt.Protocol {
	case "TCP":
		srcPort, dstPort, err := parsePorts(pkt.SrcPort, pkt.DstPort)
		if err != nil {
			return nil, fmt.Errorf("invalid TCP ports: %w", err)
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
		}
		if isIPv6 {
			tcp.SetNetworkLayerForChecksum(&layers.IPv6{
				SrcIP: srcIP,
				DstIP: dstIP,
			})
		} else {
			tcp.SetNetworkLayerForChecksum(&layers.IPv4{
				SrcIP: srcIP,
				DstIP: dstIP,
			})
		}
		transportLayer = tcp

	case "UDP":
		srcPort, dstPort, err := parsePorts(pkt.SrcPort, pkt.DstPort)
		if err != nil {
			return nil, fmt.Errorf("invalid UDP ports: %w", err)
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		if isIPv6 {
			udp.SetNetworkLayerForChecksum(&layers.IPv6{
				SrcIP: srcIP,
				DstIP: dstIP,
			})
		} else {
			udp.SetNetworkLayerForChecksum(&layers.IPv4{
				SrcIP: srcIP,
				DstIP: dstIP,
			})
		}
		transportLayer = udp

	default:
		// For other protocols, just use payload
		transportLayer = nil
	}

	// Create network layer
	var networkLayer gopacket.SerializableLayer
	if isIPv6 {
		ipv6 := &layers.IPv6{
			Version:    6,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			HopLimit:   64,
			NextHeader: layers.IPProtocolTCP, // Default, will be fixed by FixLengths
		}
		if pkt.Protocol == "UDP" {
			ipv6.NextHeader = layers.IPProtocolUDP
		}
		networkLayer = ipv6
	} else {
		ipv4 := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP, // Default, will be fixed by FixLengths
		}
		if pkt.Protocol == "UDP" {
			ipv4.Protocol = layers.IPProtocolUDP
		}
		networkLayer = ipv4
	}

	// Serialize layers (NO Ethernet layer for TUN)
	var serializeLayers []gopacket.SerializableLayer
	serializeLayers = append(serializeLayers, networkLayer)
	if transportLayer != nil {
		serializeLayers = append(serializeLayers, transportLayer)
	}
	if len(payload) > 0 {
		serializeLayers = append(serializeLayers, payload)
	}

	if err := gopacket.SerializeLayers(buf, opts, serializeLayers...); err != nil {
		return nil, fmt.Errorf("failed to serialize IP packet: %w", err)
	}

	return buf.Bytes(), nil
}

// reconstructPacket builds a complete Ethernet frame from PacketDisplay fields.
// This is a fallback when RawData is not available.
func reconstructPacket(pkt *types.PacketDisplay) ([]byte, error) {
	// Parse IP addresses
	srcIP := net.ParseIP(pkt.SrcIP)
	dstIP := net.ParseIP(pkt.DstIP)
	if srcIP == nil || dstIP == nil {
		return nil, fmt.Errorf("invalid IP addresses: src=%s dst=%s", pkt.SrcIP, pkt.DstIP)
	}

	// Determine if IPv4 or IPv6
	isIPv6 := srcIP.To4() == nil

	// Create packet buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Build layers from top to bottom
	var payload gopacket.Payload
	if pkt.Info != "" {
		payload = gopacket.Payload([]byte(pkt.Info))
	}

	// Create transport layer
	var transportLayer gopacket.SerializableLayer
	switch pkt.Protocol {
	case "TCP":
		srcPort, dstPort, err := parsePorts(pkt.SrcPort, pkt.DstPort)
		if err != nil {
			return nil, fmt.Errorf("invalid TCP ports: %w", err)
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
		}
		if isIPv6 {
			tcp.SetNetworkLayerForChecksum(&layers.IPv6{
				SrcIP: srcIP,
				DstIP: dstIP,
			})
		} else {
			tcp.SetNetworkLayerForChecksum(&layers.IPv4{
				SrcIP: srcIP,
				DstIP: dstIP,
			})
		}
		transportLayer = tcp

	case "UDP":
		srcPort, dstPort, err := parsePorts(pkt.SrcPort, pkt.DstPort)
		if err != nil {
			return nil, fmt.Errorf("invalid UDP ports: %w", err)
		}
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		if isIPv6 {
			udp.SetNetworkLayerForChecksum(&layers.IPv6{
				SrcIP: srcIP,
				DstIP: dstIP,
			})
		} else {
			udp.SetNetworkLayerForChecksum(&layers.IPv4{
				SrcIP: srcIP,
				DstIP: dstIP,
			})
		}
		transportLayer = udp

	default:
		// For other protocols, just use payload
		transportLayer = nil
	}

	// Create network layer
	var networkLayer gopacket.SerializableLayer
	if isIPv6 {
		ipv6 := &layers.IPv6{
			Version:    6,
			SrcIP:      srcIP,
			DstIP:      dstIP,
			HopLimit:   64,
			NextHeader: layers.IPProtocolTCP, // Default, will be fixed by FixLengths
		}
		if pkt.Protocol == "UDP" {
			ipv6.NextHeader = layers.IPProtocolUDP
		}
		networkLayer = ipv6
	} else {
		ipv4 := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolTCP, // Default, will be fixed by FixLengths
		}
		if pkt.Protocol == "UDP" {
			ipv4.Protocol = layers.IPProtocolUDP
		}
		networkLayer = ipv4
	}

	// Create Ethernet layer
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}
	if isIPv6 {
		eth.EthernetType = layers.EthernetTypeIPv6
	}

	// Serialize layers
	var serializeLayers []gopacket.SerializableLayer
	serializeLayers = append(serializeLayers, eth, networkLayer)
	if transportLayer != nil {
		serializeLayers = append(serializeLayers, transportLayer)
	}
	if len(payload) > 0 {
		serializeLayers = append(serializeLayers, payload)
	}

	if err := gopacket.SerializeLayers(buf, opts, serializeLayers...); err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %w", err)
	}

	return buf.Bytes(), nil
}

// parsePorts converts string ports to uint16.
func parsePorts(srcPort, dstPort string) (uint16, uint16, error) {
	var src, dst uint16

	if srcPort != "" {
		if _, err := fmt.Sscanf(srcPort, "%d", &src); err != nil {
			return 0, 0, fmt.Errorf("invalid source port: %s", srcPort)
		}
	}

	if dstPort != "" {
		if _, err := fmt.Sscanf(dstPort, "%d", &dst); err != nil {
			return 0, 0, fmt.Errorf("invalid destination port: %s", dstPort)
		}
	}

	return src, dst, nil
}

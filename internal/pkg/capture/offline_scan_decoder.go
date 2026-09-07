package capture

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// decodeScan is private to synchronous locator preparation. SIP application
// parsing cannot affect normalization: its decoder terminates at SIP, whereas
// normalization only examines IP fragments, VXLAN and ESP. Locator keys retain
// raw bytes and CaptureInfo, never ApplicationLayer, ErrorLayer or Truncated.
// Replay still uses decode and reconstructs the complete application semantics.
func (p *offlinePacketDecoder) decodeScan(data []byte, link layers.LinkType) gopacket.Packet {
	if link == layers.LinkTypeEthernet && offlineScanSIPCandidate(data) {
		*p = offlinePacketDecoder{data: data}
		if p.decodeScanSIP(data) {
			return p
		}
	}
	return p.decode(data, link)
}

func (p *offlinePacketDecoder) decodeScanSIP(data []byte) bool {
	if p.ethernet.DecodeFromBytes(data, p) != nil {
		return false
	}
	payload, kind := p.ethernet.Payload, p.ethernet.EthernetType
	// Tags are needed only to locate the network header; these packets cannot
	// enter a rebuilding/retaining normalizer. Preserve their original raw frame.
	for tags := 0; kind == layers.EthernetTypeDot1Q || kind == layers.EthernetTypeQinQ; tags++ {
		if tags == 2 {
			return false
		}
		var tag layers.Dot1Q
		if tag.DecodeFromBytes(payload, p) != nil {
			return false
		}
		payload, kind = tag.Payload, tag.Type
	}
	var next gopacket.LayerType
	switch kind {
	case layers.EthernetTypeIPv4:
		if len(payload) < 20 || payload[0] != 0x45 || p.ipv4.DecodeFromBytes(payload, p) != nil {
			return false
		}
		p.network, payload, next = &p.ipv4, p.ipv4.Payload, p.ipv4.NextLayerType()
	case layers.EthernetTypeIPv6:
		if len(payload) < 40 || payload[0]>>4 != 6 || (payload[6] != byte(layers.IPProtocolTCP) && payload[6] != byte(layers.IPProtocolUDP)) || (payload[4] == 0 && payload[5] == 0) || p.ipv6.DecodeFromBytes(payload, p) != nil {
			return false
		}
		p.network, payload, next = &p.ipv6, p.ipv6.Payload, p.ipv6.NextLayerType()
	default:
		return false
	}
	var application gopacket.LayerType
	switch next {
	case layers.LayerTypeTCP:
		p.tcp.Options = p.options[:0]
		if p.tcp.DecodeFromBytes(payload, p) != nil {
			return false
		}
		p.transport, application = &p.tcp, p.tcp.NextLayerType()
	case layers.LayerTypeUDP:
		if p.udp.DecodeFromBytes(payload, p) != nil || p.udp.Length == 0 {
			return false
		}
		p.transport, application = &p.udp, p.udp.NextLayerType()
	default:
		return false
	}
	if p.metadata.Truncated || application != layers.LayerTypeSIP {
		return false
	}
	p.decoded[0], p.decoded[1], p.decoded[2] = &p.ethernet, p.network, p.transport
	p.count = 3
	return true
}

// Reject ordinary traffic before resetting reusable state or decoding headers.
// This is only a candidate check: decodeScanSIP still validates the complete
// headers before borrowing them. Port lookups use gopacket's current registry
// and destination-before-source precedence, including runtime registrations.
func offlineScanSIPCandidate(data []byte) bool {
	if len(data) < 14 {
		return false
	}
	kind := layers.EthernetType(binary.BigEndian.Uint16(data[12:14]))
	offset := 14
	for tags := 0; kind == layers.EthernetTypeDot1Q || kind == layers.EthernetTypeQinQ; tags++ {
		if tags == 2 || len(data)-offset < 4 {
			return false
		}
		kind = layers.EthernetType(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
	}
	var protocol byte
	switch kind {
	case layers.EthernetTypeIPv4:
		if len(data)-offset < 20 || data[offset] != 0x45 || binary.BigEndian.Uint16(data[offset+6:offset+8])&0x3fff != 0 {
			return false
		}
		protocol = data[offset+9]
		offset += 20
	case layers.EthernetTypeIPv6:
		if len(data)-offset < 40 || data[offset]>>4 != 6 {
			return false
		}
		protocol = data[offset+6]
		offset += 40
	default:
		return false
	}
	if len(data)-offset < 4 {
		return false
	}
	src, dst := binary.BigEndian.Uint16(data[offset:offset+2]), binary.BigEndian.Uint16(data[offset+2:offset+4])
	switch layers.IPProtocol(protocol) {
	case layers.IPProtocolUDP:
		transport := layers.UDP{SrcPort: layers.UDPPort(src), DstPort: layers.UDPPort(dst)}
		return transport.NextLayerType() == layers.LayerTypeSIP
	case layers.IPProtocolTCP:
		transport := layers.TCP{SrcPort: layers.TCPPort(src), DstPort: layers.TCPPort(dst)}
		return transport.NextLayerType() == layers.LayerTypeSIP
	default:
		return false
	}
}

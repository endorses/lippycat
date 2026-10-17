package packetdedup

import (
	"encoding/binary"

	"github.com/google/gopacket/layers"
)

// canonicalPacket supports complete, nonfragmented IPv4 without options and
// IPv6 without extension headers. Ethernet/VLAN framing, hop count and the IPv4
// checksum do not identify a packet. Everything else remains byte-for-byte
// significant. TCP is ambiguous: a retransmission can reuse all its identity.
func canonicalPacket(packet []byte, link layers.LinkType) ([]byte, Decision) {
	ip := packet
	switch link {
	case layers.LinkTypeRaw:
	case layers.LinkTypeEthernet:
		if len(ip) < 14 {
			return nil, RetainUnsupported
		}
		protocol := binary.BigEndian.Uint16(ip[12:14])
		ip = ip[14:]
		for tags := 0; protocol == 0x8100 || protocol == 0x88a8; tags++ {
			if tags >= 2 || len(ip) < 4 {
				return nil, RetainUnsupported
			}
			protocol = binary.BigEndian.Uint16(ip[2:4])
			ip = ip[4:]
		}
		if protocol != 0x0800 && protocol != 0x86dd {
			return nil, RetainUnsupported
		}
		if len(ip) == 0 || (protocol == 0x0800 && ip[0]>>4 != 4) || (protocol == 0x86dd && ip[0]>>4 != 6) {
			return nil, RetainUnsupported
		}
	default:
		return nil, RetainUnsupported
	}
	if len(ip) == 0 {
		return nil, RetainUnsupported
	}
	var transport []byte
	var protocol byte
	var ipv4Identity bool
	switch ip[0] >> 4 {
	case 4:
		if len(ip) < 20 || ip[0]&15 != 5 {
			return nil, RetainUnsupported
		}
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		fragment := binary.BigEndian.Uint16(ip[6:8])
		if total < 20 || total > len(ip) || fragment&0xbfff != 0 {
			return nil, RetainUnsupported
		}
		ip = ip[:total]
		transport = ip[20:]
		protocol = ip[9]
		ipv4Identity = binary.BigEndian.Uint16(ip[4:6]) != 0
	case 6:
		if len(ip) < 40 {
			return nil, RetainUnsupported
		}
		total := 40 + int(binary.BigEndian.Uint16(ip[4:6]))
		if total == 40 || total > len(ip) {
			return nil, RetainUnsupported
		}
		ip = ip[:total]
		transport = ip[40:]
		protocol = ip[6]
	default:
		return nil, RetainUnsupported
	}
	switch protocol {
	case 6:
		return nil, RetainAmbiguous
	case 17:
		if len(transport) < 8 || int(binary.BigEndian.Uint16(transport[4:6])) != len(transport) {
			return nil, RetainUnsupported
		}
		if !ipv4Identity && !mediaIdentity(transport[8:]) {
			return nil, RetainAmbiguous
		}
	case 1:
		if ip[0]>>4 != 4 || len(transport) < 8 {
			return nil, RetainUnsupported
		}
		if !ipv4Identity || (transport[0] != 0 && transport[0] != 8) || transport[1] != 0 {
			return nil, RetainAmbiguous
		}
	case 58:
		// ICMPv6 has no per-transmission identity. Echo id/sequence can be reused.
		return nil, RetainAmbiguous
	default:
		return nil, RetainUnsupported
	}
	normalized := append([]byte(nil), ip...)
	if normalized[0]>>4 == 4 {
		normalized[8] = 0
		normalized[10] = 0
		normalized[11] = 0
	} else {
		normalized[7] = 0
	}
	return normalized, Accept
}

// mediaIdentity requires an RTP identity (SSRC, sequence and media timestamp)
// or an RTCP sender report carrying a nonzero NTP timestamp. Other UDP without
// a usable IPv4 packet ID is retained; equality alone is not packet identity.
func mediaIdentity(payload []byte) bool {
	if len(payload) < 4 || payload[0]>>6 != 2 {
		return false
	}
	if payload[1] >= 192 && payload[1] <= 223 {
		if payload[1] != 200 || len(payload) < 28 || (binary.BigEndian.Uint64(payload[8:16]) == 0) {
			return false
		}
		firstSize := (int(binary.BigEndian.Uint16(payload[2:4])) + 1) * 4
		if firstSize < 28+24*int(payload[0]&31) || firstSize > len(payload) {
			return false
		}
		remaining := payload
		for len(remaining) > 0 {
			if len(remaining) < 4 || remaining[0]>>6 != 2 {
				return false
			}
			size := (int(binary.BigEndian.Uint16(remaining[2:4])) + 1) * 4
			if size < 4 || size > len(remaining) {
				return false
			}
			if remaining[0]&0x20 != 0 {
				padding := int(remaining[size-1])
				if size != len(remaining) || padding == 0 || padding > size-4 {
					return false
				}
			}
			remaining = remaining[size:]
		}
		return true
	}
	if len(payload) < 12 {
		return false
	}
	header := 12 + 4*int(payload[0]&15)
	if header > len(payload) {
		return false
	}
	if payload[0]&0x10 != 0 {
		if len(payload)-header < 4 {
			return false
		}
		extension := 4 + 4*int(binary.BigEndian.Uint16(payload[header+2:header+4]))
		if extension > len(payload)-header {
			return false
		}
		header += extension
	}
	if payload[0]&0x20 != 0 {
		padding := int(payload[len(payload)-1])
		if padding == 0 || padding > len(payload)-header {
			return false
		}
	}
	return true
}

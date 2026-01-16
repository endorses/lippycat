package capture

import (
	"fmt"
	"net"
	"strconv"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketFields contains extracted packet fields from gopacket parsing.
// Used as intermediate result that callers can enhance with additional metadata.
type PacketFields struct {
	SrcIP    string
	DstIP    string
	SrcPort  string
	DstPort  string
	Protocol string
	Info     string
	// HasTransport indicates if transport layer was found
	HasTransport bool
}

// ExtractPacketFields extracts common packet fields from a gopacket.Packet.
// This is the shared core logic used by all converters.
// Callers can enhance the result with protocol detection, VoIP metadata, etc.
func ExtractPacketFields(pkt gopacket.Packet) PacketFields {
	fields := PacketFields{
		SrcIP:    "unknown",
		DstIP:    "unknown",
		Protocol: "unknown",
	}

	// Check for ARP (common link-layer protocol)
	if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, ok := arpLayer.(*layers.ARP)
		fields.Protocol = "ARP"
		if ok && arp != nil {
			fields.SrcIP = FormatIPv4Bytes(arp.SourceProtAddress)
			fields.DstIP = FormatIPv4Bytes(arp.DstProtAddress)
			fields.Info = FormatARPInfo(arp, fields.SrcIP, fields.DstIP)
		}
		return fields
	}

	// Check for Linux SLL (cooked capture) - fast path
	if sllLayer := pkt.Layer(layers.LayerTypeLinuxSLL); sllLayer != nil {
		if pkt.NetworkLayer() == nil {
			sll, ok := sllLayer.(*layers.LinuxSLL)
			fields.Protocol = "LinuxSLL"
			if ok && sll != nil {
				fields.SrcIP = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
					sll.Addr[0], sll.Addr[1], sll.Addr[2], sll.Addr[3], sll.Addr[4], sll.Addr[5])
				fields.Info = fmt.Sprintf("Type: 0x%04x", uint16(sll.EthernetType))
				// Check if it's a decode failure
				if pkt.ErrorLayer() != nil {
					fields.Info = "Decode failed: " + pkt.ErrorLayer().Error().Error()
				}
			}
			return fields
		}
	}

	// Check Ethernet layer for non-IP protocols
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, ok := ethLayer.(*layers.Ethernet)
		if ok && eth != nil && pkt.NetworkLayer() == nil {
			fields.SrcIP = eth.SrcMAC.String()
			fields.DstIP = eth.DstMAC.String()
			fields.Protocol, fields.Info = EtherTypeToProtocol(eth.EthernetType)

			// Add broadcast indicator if applicable
			if eth.DstMAC.String() == "ff:ff:ff:ff:ff:ff" {
				if fields.Info != "" {
					fields.Info = fields.Info + " (broadcast)"
				} else {
					fields.Info = "Broadcast frame"
				}
			}
			return fields
		}
	}

	// Extract IPs from network layer
	if netLayer := pkt.NetworkLayer(); netLayer != nil {
		switch net := netLayer.(type) {
		case *layers.IPv4:
			fields.SrcIP = net.SrcIP.String()
			fields.DstIP = net.DstIP.String()
			if pkt.TransportLayer() == nil {
				fields.Protocol = net.Protocol.String()
			}
		case *layers.IPv6:
			fields.SrcIP = net.SrcIP.String()
			fields.DstIP = net.DstIP.String()
			if pkt.TransportLayer() == nil {
				fields.Protocol = net.NextHeader.String()
			}
		}
	}

	// Extract transport layer info
	if transLayer := pkt.TransportLayer(); transLayer != nil {
		fields.HasTransport = true
		switch trans := transLayer.(type) {
		case *layers.TCP:
			fields.Protocol = "TCP"
			fields.SrcPort = strconv.Itoa(int(trans.SrcPort))
			fields.DstPort = strconv.Itoa(int(trans.DstPort))
			flags := FormatTCPFlags(trans)
			fields.Info = fmt.Sprintf("%s -> %s [%s]", fields.SrcPort, fields.DstPort, flags)
		case *layers.UDP:
			fields.Protocol = "UDP"
			fields.SrcPort = strconv.Itoa(int(trans.SrcPort))
			fields.DstPort = strconv.Itoa(int(trans.DstPort))
			fields.Info = fmt.Sprintf("%s -> %s", fields.SrcPort, fields.DstPort)
		}
	} else {
		// Handle non-transport protocols (ICMP, IGMP)
		if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, ok := icmpLayer.(*layers.ICMPv4)
			fields.Protocol = "ICMP"
			if ok && icmp != nil {
				fields.Info = fmt.Sprintf("Type %d Code %d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
			} else {
				fields.Info = "ICMP packet"
			}
		} else if icmp6Layer := pkt.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
			icmp6, ok := icmp6Layer.(*layers.ICMPv6)
			fields.Protocol = "ICMPv6"
			if ok && icmp6 != nil {
				fields.Info = fmt.Sprintf("Type %d Code %d", icmp6.TypeCode.Type(), icmp6.TypeCode.Code())
			} else {
				fields.Info = "ICMPv6 packet"
			}
		} else if igmpLayer := pkt.Layer(layers.LayerTypeIGMP); igmpLayer != nil {
			igmp, ok := igmpLayer.(*layers.IGMP)
			fields.Protocol = "IGMP"
			if ok && igmp != nil {
				fields.Info = fmt.Sprintf("Type %d Group %s", igmp.Type, igmp.GroupAddress.String())
			} else {
				fields.Info = "IGMP packet"
			}
		} else if vrrpLayer := pkt.Layer(layers.LayerTypeVRRP); vrrpLayer != nil {
			vrrp, ok := vrrpLayer.(*layers.VRRPv2)
			fields.Protocol = "VRRP"
			if ok && vrrp != nil {
				fields.Info = FormatVRRPInfo(vrrp)
			} else {
				fields.Info = "VRRP packet"
			}
		}
	}

	return fields
}

// FormatTCPFlags returns a string representation of TCP flags.
// Used by multiple converters for consistent TCP flag display.
func FormatTCPFlags(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "SYN "
	}
	if tcp.ACK {
		flags += "ACK "
	}
	if tcp.FIN {
		flags += "FIN "
	}
	if tcp.RST {
		flags += "RST "
	}
	if tcp.PSH {
		flags += "PSH "
	}
	if tcp.URG {
		flags += "URG "
	}
	if flags == "" {
		return "NONE"
	}
	return flags[:len(flags)-1] // Remove trailing space
}

// EtherTypeToProtocol converts an EthernetType to protocol name and info string.
// Returns (protocol, info) for common link-layer protocols.
func EtherTypeToProtocol(etherType layers.EthernetType) (protocol string, info string) {
	switch etherType {
	case layers.EthernetTypeLLC:
		return "LLC", "Logical Link Control"
	case layers.EthernetTypeDot1Q:
		return "802.1Q", "VLAN tag"
	case layers.EthernetTypeCiscoDiscovery:
		return "CDP", "Cisco Discovery Protocol"
	case layers.EthernetTypeLinkLayerDiscovery:
		return "LLDP", "Link Layer Discovery Protocol"
	case layers.EthernetTypeEthernetCTP:
		return "EthernetCTP", "Configuration Test Protocol"
	case 0x888E: // 802.1X (EAP)
		return "802.1X", "Port-based authentication"
	default:
		// Non-standard EtherType - show hex value clearly
		return fmt.Sprintf("0x%04x", uint16(etherType)), "Vendor-specific EtherType"
	}
}

// FormatIPv4Bytes formats 4 bytes as an IPv4 address string.
func FormatIPv4Bytes(addr []byte) string {
	if len(addr) != 4 {
		return "invalid"
	}
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

// FormatARPInfo generates info string for ARP packet.
func FormatARPInfo(arp *layers.ARP, srcIP, dstIP string) string {
	switch arp.Operation {
	case 1:
		return "Who has " + dstIP + "?"
	case 2:
		return srcIP + " is at " + net.HardwareAddr(arp.SourceHwAddress).String()
	default:
		return fmt.Sprintf("Operation %d", arp.Operation)
	}
}

// FormatVRRPInfo generates info string for VRRP packet.
func FormatVRRPInfo(vrrp *layers.VRRPv2) string {
	// Priority 0 means master is resigning
	if vrrp.Priority == 0 {
		return fmt.Sprintf("VRID %d Pri 0 (resign)", vrrp.VirtualRtrID)
	}

	info := fmt.Sprintf("VRID %d Pri %d", vrrp.VirtualRtrID, vrrp.Priority)

	// Add first virtual IP if available
	if len(vrrp.IPAddress) > 0 {
		info += " " + vrrp.IPAddress[0].String()
		if len(vrrp.IPAddress) > 1 {
			info += fmt.Sprintf(" +%d", len(vrrp.IPAddress)-1)
		}
	}

	return info
}

// PayloadTypeToCodec maps RTP payload type to codec name.
// Based on IANA RTP Payload Types: https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml
func PayloadTypeToCodec(pt uint8) string {
	codecs := map[uint8]string{
		0:   "G.711 µ-law",
		3:   "GSM",
		4:   "G.723",
		5:   "DVI4 8kHz",
		6:   "DVI4 16kHz",
		7:   "LPC",
		8:   "G.711 A-law",
		9:   "G.722",
		10:  "L16 Stereo",
		11:  "L16 Mono",
		12:  "QCELP",
		13:  "Comfort Noise",
		14:  "MPA",
		15:  "G.728",
		16:  "DVI4 11kHz",
		17:  "DVI4 22kHz",
		18:  "G.729",
		25:  "CelB",
		26:  "JPEG",
		28:  "nv",
		31:  "H.261",
		32:  "MPV",
		33:  "MP2T",
		34:  "H.263",
		101: "telephone-event", // DTMF
	}

	if codec, ok := codecs[pt]; ok {
		return codec
	}

	// Dynamic payload types (96-127) require SDP negotiation to determine codec
	if pt >= 96 && pt <= 127 {
		return "Dynamic"
	}

	return "Unknown"
}

// FieldsToPacketDisplay creates a types.PacketDisplay from extracted fields
// and additional metadata from PacketInfo.
func FieldsToPacketDisplay(fields PacketFields, pktInfo PacketInfo) types.PacketDisplay {
	pkt := pktInfo.Packet
	return types.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     fields.SrcIP,
		DstIP:     fields.DstIP,
		SrcPort:   fields.SrcPort,
		DstPort:   fields.DstPort,
		Protocol:  fields.Protocol,
		Length:    pkt.Metadata().Length,
		Info:      fields.Info,
		RawData:   nil, // Callers can set this if needed
		Interface: pktInfo.Interface,
		LinkType:  pktInfo.LinkType,
		NodeID:    "Local",
	}
}

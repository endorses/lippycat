package capture

import (
	"fmt"
	"net"
	"strconv"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// ConvertPacketToDisplay converts a gopacket.Packet to types.PacketDisplay
// This provides a structured representation suitable for JSON output and other formats
func ConvertPacketToDisplay(pktInfo PacketInfo) types.PacketDisplay {
	pkt := pktInfo.Packet

	display := types.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     "unknown",
		DstIP:     "unknown",
		SrcPort:   "",
		DstPort:   "",
		Protocol:  "unknown",
		Length:    pkt.Metadata().Length,
		Info:      "",
		RawData:   nil, // Don't copy raw data for CLI output to save memory
		Interface: pktInfo.Interface,
		LinkType:  pktInfo.LinkType,
		NodeID:    "Local",
	}

	// Check for ARP (common link-layer protocol)
	if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, ok := arpLayer.(*layers.ARP)
		display.Protocol = "ARP"
		if ok && arp != nil {
			display.SrcIP = fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
			display.DstIP = fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3])
			switch arp.Operation {
			case 1:
				display.Info = "Who has " + display.DstIP
			case 2:
				display.Info = display.SrcIP + " is at " + net.HardwareAddr(arp.SourceHwAddress).String()
			}
		}
		return display
	}

	// Check for link-layer protocols
	if sllLayer := pkt.Layer(layers.LayerTypeLinuxSLL); sllLayer != nil {
		if pkt.NetworkLayer() == nil {
			display.Protocol = "LinuxSLL"
			return display
		}
	}

	// Check Ethernet layer for non-IP protocols
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, ok := ethLayer.(*layers.Ethernet)
		if ok && eth != nil && pkt.NetworkLayer() == nil {
			display.SrcIP = eth.SrcMAC.String()
			display.DstIP = eth.DstMAC.String()
			switch eth.EthernetType {
			case layers.EthernetTypeLLC:
				display.Protocol = "LLC"
			case layers.EthernetTypeCiscoDiscovery:
				display.Protocol = "CDP"
			case layers.EthernetTypeLinkLayerDiscovery:
				display.Protocol = "LLDP"
			default:
				display.Protocol = fmt.Sprintf("0x%04x", uint16(eth.EthernetType))
			}
			return display
		}
	}

	// Extract IPs from network layer
	if netLayer := pkt.NetworkLayer(); netLayer != nil {
		switch net := netLayer.(type) {
		case *layers.IPv4:
			display.SrcIP = net.SrcIP.String()
			display.DstIP = net.DstIP.String()
			if pkt.TransportLayer() == nil {
				display.Protocol = net.Protocol.String()
			}
		case *layers.IPv6:
			display.SrcIP = net.SrcIP.String()
			display.DstIP = net.DstIP.String()
			if pkt.TransportLayer() == nil {
				display.Protocol = net.NextHeader.String()
			}
		}
	}

	// Extract transport layer info
	if transLayer := pkt.TransportLayer(); transLayer != nil {
		switch trans := transLayer.(type) {
		case *layers.TCP:
			display.Protocol = "TCP"
			display.SrcPort = strconv.Itoa(int(trans.SrcPort))
			display.DstPort = strconv.Itoa(int(trans.DstPort))

			// Add TCP flags to info
			var flags []string
			if trans.SYN {
				flags = append(flags, "SYN")
			}
			if trans.ACK {
				flags = append(flags, "ACK")
			}
			if trans.FIN {
				flags = append(flags, "FIN")
			}
			if trans.RST {
				flags = append(flags, "RST")
			}
			if trans.PSH {
				flags = append(flags, "PSH")
			}
			if len(flags) > 0 {
				display.Info = fmt.Sprintf("Flags: %v", flags)
			}
		case *layers.UDP:
			display.Protocol = "UDP"
			display.SrcPort = strconv.Itoa(int(trans.SrcPort))
			display.DstPort = strconv.Itoa(int(trans.DstPort))
		}
	} else if pkt.Layer(layers.LayerTypeICMPv4) != nil {
		display.Protocol = "ICMP"
	} else if pkt.Layer(layers.LayerTypeICMPv6) != nil {
		display.Protocol = "ICMPv6"
	} else if pkt.Layer(layers.LayerTypeIGMP) != nil {
		display.Protocol = "IGMP"
	}

	return display
}

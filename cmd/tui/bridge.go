package tui

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/google/gopacket/layers"
)

// Object pools for reducing allocations
var (
	packetDisplayPool = sync.Pool{
		New: func() interface{} {
			return &components.PacketDisplay{}
		},
	}

	byteBufferPool = sync.Pool{
		New: func() interface{} {
			// Pre-allocate 1500 bytes (typical MTU)
			buf := make([]byte, 0, 1500)
			return &buf
		},
	}

	// String interning for protocol names (reduce memory footprint)
	protocolStrings = map[string]string{
		"TCP":       "TCP",
		"UDP":       "UDP",
		"SIP":       "SIP",
		"RTP":       "RTP",
		"DNS":       "DNS",
		"HTTP":      "HTTP",
		"HTTPS":     "HTTPS",
		"TLS":       "TLS",
		"SSL":       "SSL",
		"ICMP":      "ICMP",
		"ICMPv6":    "ICMPv6",
		"IGMP":      "IGMP",
		"ARP":       "ARP",
		"LLC":       "LLC",
		"LLDP":      "LLDP",
		"CDP":       "CDP",
		"802.1Q":    "802.1Q",
		"802.1X":    "802.1X",
		"OpenVPN":   "OpenVPN",
		"WireGuard": "WireGuard",
		"L2TP":      "L2TP",
		"PPTP":      "PPTP",
		"IKEv2":     "IKEv2",
		"IKEv1":     "IKEv1",
		"IKE":       "IKE",
		"Unknown":   "Unknown",
		"unknown":   "unknown",
	}
	protocolMu sync.RWMutex
)

// internProtocol returns an interned protocol string to reduce allocations
func internProtocol(protocol string) string {
	protocolMu.RLock()
	if interned, ok := protocolStrings[protocol]; ok {
		protocolMu.RUnlock()
		return interned
	}
	protocolMu.RUnlock()

	// Not found - add it (rare)
	protocolMu.Lock()
	// Check again in case another goroutine added it
	if interned, ok := protocolStrings[protocol]; ok {
		protocolMu.Unlock()
		return interned
	}
	// Limit pool size to prevent unbounded growth
	if len(protocolStrings) < 100 {
		protocolStrings[protocol] = protocol
	}
	protocolMu.Unlock()
	return protocol
}

// getPacketDisplay acquires a PacketDisplay from the pool
func getPacketDisplay() *components.PacketDisplay {
	return packetDisplayPool.Get().(*components.PacketDisplay)
}

// putPacketDisplay returns a PacketDisplay to the pool
func putPacketDisplay(pkt *components.PacketDisplay) {
	// Clear the packet before returning to pool
	*pkt = components.PacketDisplay{}
	packetDisplayPool.Put(pkt)
}

// getByteBuffer acquires a byte buffer from the pool
func getByteBuffer() *[]byte {
	return byteBufferPool.Get().(*[]byte)
}

// putByteBuffer returns a byte buffer to the pool
func putByteBuffer(buf *[]byte) {
	// Reset slice but keep capacity
	*buf = (*buf)[:0]
	byteBufferPool.Put(buf)
}

// StartPacketBridge creates a bridge between packet capture and TUI
// It converts capture.PacketInfo to PacketMsg for the TUI
// Uses intelligent sampling and throttling to handle high packet rates
func StartPacketBridge(packetChan <-chan capture.PacketInfo, program *tea.Program) {
	const (
		targetPacketsPerSecond = 200              // Target display rate
		batchInterval          = 100 * time.Millisecond // Batch interval
	)

	batch := make([]components.PacketDisplay, 0, 100)
	packetCount := int64(0)
	displayedCount := int64(0)
	startTime := time.Now()

	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	sendBatch := func() {
		if len(batch) > 0 {
			// Send entire batch as single message to reduce Update() calls
			program.Send(PacketBatchMsg{Packets: batch})
			displayedCount += int64(len(batch))
			batch = make([]components.PacketDisplay, 0, 100)
		}
	}

	// Calculate sampling ratio based on recent packet rate
	getSamplingRatio := func() float64 {
		elapsed := time.Since(startTime).Seconds()
		if elapsed < 1.0 {
			return 1.0 // No sampling for first second
		}

		currentRate := float64(packetCount) / elapsed
		if currentRate <= float64(targetPacketsPerSecond) {
			return 1.0 // Show all packets if under target
		}

		// Sample to achieve target rate
		ratio := float64(targetPacketsPerSecond) / currentRate
		if ratio < 0.01 {
			ratio = 0.01 // Show at least 1%
		}
		return ratio
	}

	for {
		select {
		case pktInfo, ok := <-packetChan:
			if !ok {
				// Channel closed, send remaining batch
				sendBatch()
				return
			}

			packetCount++

			// Adaptive sampling based on load
			samplingRatio := getSamplingRatio()

			// Use fast conversion for sampled packets, full for important ones
			var packet components.PacketDisplay
			if samplingRatio >= 1.0 || (float64(packetCount)*samplingRatio) >= float64(displayedCount+int64(len(batch))+1) {
				// This packet should be displayed
				if samplingRatio < 0.5 {
					// High load - use fast conversion
					packet = convertPacketFast(pktInfo)
				} else {
					// Normal load - full conversion
					packet = convertPacket(pktInfo)
				}
				batch = append(batch, packet)
			}

			// Send if batch is large enough
			if len(batch) >= 50 {
				sendBatch()
			}

		case <-ticker.C:
			// Send batch on interval
			sendBatch()
		}
	}
}

// convertPacketFast is a lightweight version for high-speed scenarios
// Still extracts basic protocol info, but skips expensive payload inspection
func convertPacketFast(pktInfo capture.PacketInfo) components.PacketDisplay {
	pkt := pktInfo.Packet
	// Use stack allocation for fast path - no pooling needed for fast conversion
	display := components.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     "unknown",
		DstIP:     "unknown",
		SrcPort:   "",
		DstPort:   "",
		Protocol:  "unknown",
		Length:    pkt.Metadata().Length,
		Info:      "",
		RawData:   nil, // Don't copy raw data for performance
		Interface: pktInfo.Interface,
	}

	// Check for ARP (common link-layer protocol)
	if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
		display.Protocol = internProtocol("ARP")
		return display
	}

	// Check for Linux SLL (cooked capture) - fast path
	if sllLayer := pkt.Layer(layers.LayerTypeLinuxSLL); sllLayer != nil {
		if pkt.NetworkLayer() == nil {
			display.Protocol = "LinuxSLL"
			return display
		}
	}

	// Check Ethernet layer for non-IP protocols
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		if eth != nil && pkt.NetworkLayer() == nil {
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
				// Non-standard EtherType - show hex value clearly
				display.Protocol = fmt.Sprintf("0x%04x", uint16(eth.EthernetType))
			}
			return display
		}
	}

	// Extract IPs
	if netLayer := pkt.NetworkLayer(); netLayer != nil {
		switch net := netLayer.(type) {
		case *layers.IPv4:
			display.SrcIP = net.SrcIP.String()
			display.DstIP = net.DstIP.String()
			// Set protocol from IP if no transport layer
			if pkt.TransportLayer() == nil {
				display.Protocol = net.Protocol.String()
			}
		case *layers.IPv6:
			display.SrcIP = net.SrcIP.String()
			display.DstIP = net.DstIP.String()
			// Set protocol from IPv6 if no transport layer
			if pkt.TransportLayer() == nil {
				display.Protocol = net.NextHeader.String()
			}
		}
	}

	// Extract basic protocol (cheap operation, no payload inspection)
	if transLayer := pkt.TransportLayer(); transLayer != nil {
		switch trans := transLayer.(type) {
		case *layers.TCP:
			display.Protocol = internProtocol("TCP")
			display.SrcPort = strconv.Itoa(int(trans.SrcPort))
			display.DstPort = strconv.Itoa(int(trans.DstPort))
		case *layers.UDP:
			display.Protocol = internProtocol("UDP")
			display.SrcPort = strconv.Itoa(int(trans.SrcPort))
			display.DstPort = strconv.Itoa(int(trans.DstPort))
		}
	} else if pkt.Layer(layers.LayerTypeICMPv4) != nil {
		display.Protocol = internProtocol("ICMP")
	} else if pkt.Layer(layers.LayerTypeICMPv6) != nil {
		display.Protocol = internProtocol("ICMPv6")
	} else if pkt.Layer(layers.LayerTypeIGMP) != nil {
		display.Protocol = internProtocol("IGMP")
	}

	return display
}

// convertPacket converts a gopacket.Packet to PacketDisplay
func convertPacket(pktInfo capture.PacketInfo) components.PacketDisplay {
	pkt := pktInfo.Packet

	// Get buffer from pool for raw data
	var rawData []byte
	if pkt.Data() != nil {
		bufPtr := getByteBuffer()
		*bufPtr = append(*bufPtr, pkt.Data()...)
		rawData = *bufPtr
		// Note: We don't return the buffer to pool here - it's owned by the PacketDisplay
		// The model will need to handle cleanup when packets age out
	}

	display := components.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     "unknown",
		DstIP:     "unknown",
		SrcPort:   "",
		DstPort:   "",
		Protocol:  "unknown",
		Length:    pkt.Metadata().Length,
		Info:      "",
		RawData:   rawData, // Use pooled buffer
		Interface: pktInfo.Interface,
	}

	// Check for link-layer protocols first (ARP, etc.)
	if arpLayer := pkt.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		display.Protocol = "ARP"
		if arp != nil {
			display.SrcIP = fmt.Sprintf("%d.%d.%d.%d", arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3])
			display.DstIP = fmt.Sprintf("%d.%d.%d.%d", arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3])
			switch arp.Operation {
			case 1:
				display.Info = "Who has " + display.DstIP + "?"
			case 2:
				display.Info = display.SrcIP + " is at " + fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", arp.SourceHwAddress[0], arp.SourceHwAddress[1], arp.SourceHwAddress[2], arp.SourceHwAddress[3], arp.SourceHwAddress[4], arp.SourceHwAddress[5])
			}
		}
		return display
	}

	// Check for Linux SLL (cooked capture) - used when capturing on "any" interface
	if sllLayer := pkt.Layer(layers.LayerTypeLinuxSLL); sllLayer != nil {
		sll, _ := sllLayer.(*layers.LinuxSLL)
		if sll != nil && pkt.NetworkLayer() == nil {
			// SLL packet with no network layer - likely malformed or non-IP
			display.Protocol = "LinuxSLL"
			display.SrcIP = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				sll.Addr[0], sll.Addr[1], sll.Addr[2], sll.Addr[3], sll.Addr[4], sll.Addr[5])
			display.Info = fmt.Sprintf("Type: 0x%04x", uint16(sll.EthernetType))

			// Check if it's a decode failure
			if pkt.ErrorLayer() != nil {
				display.Info = "Decode failed: " + pkt.ErrorLayer().Error().Error()
			}
			return display
		}
	}

	// Check for Ethernet layer to extract MAC addresses if no IP layer
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		if eth != nil {
			// Store MAC addresses in IP fields if we don't have IP layer
			if pkt.NetworkLayer() == nil {
				display.SrcIP = eth.SrcMAC.String()
				display.DstIP = eth.DstMAC.String()

				// Check for broadcast
				isBroadcast := eth.DstMAC.String() == "ff:ff:ff:ff:ff:ff"

				// Identify the ethernet protocol type
				switch eth.EthernetType {
				case layers.EthernetTypeLLC:
					display.Protocol = "LLC"
					display.Info = "Logical Link Control"
				case layers.EthernetTypeDot1Q:
					display.Protocol = "802.1Q"
					display.Info = "VLAN tag"
				case layers.EthernetTypeCiscoDiscovery:
					display.Protocol = "CDP"
					display.Info = "Cisco Discovery Protocol"
				case layers.EthernetTypeLinkLayerDiscovery: // 0x88CC
					display.Protocol = "LLDP"
					display.Info = "Link Layer Discovery Protocol"
				case layers.EthernetTypeEthernetCTP:
					display.Protocol = "EthernetCTP"
					display.Info = "Configuration Test Protocol"
				case 0x888E: // 802.1X (EAP)
					display.Protocol = "802.1X"
					display.Info = "Port-based authentication"
				default:
					// Non-standard EtherType - show hex value clearly
					display.Protocol = fmt.Sprintf("0x%04x", uint16(eth.EthernetType))
					display.Info = "Vendor-specific EtherType"
				}

				// Add broadcast indicator to info if applicable
				if isBroadcast {
					display.Info = display.Info + " (broadcast)"
				}
				return display
			}
		}
	}

	// Extract network layer info
	if netLayer := pkt.NetworkLayer(); netLayer != nil {
		switch net := netLayer.(type) {
		case *layers.IPv4:
			display.SrcIP = net.SrcIP.String()
			display.DstIP = net.DstIP.String()
			// Set protocol from IP layer if no transport layer
			if pkt.TransportLayer() == nil {
				display.Protocol = net.Protocol.String()
			}
		case *layers.IPv6:
			display.SrcIP = net.SrcIP.String()
			display.DstIP = net.DstIP.String()
			// Set protocol from IPv6 layer if no transport layer
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
			display.Info = fmt.Sprintf("%s → %s [%s]",
				display.SrcPort, display.DstPort, tcpFlags(trans))

		case *layers.UDP:
			display.Protocol = "UDP"
			display.SrcPort = strconv.Itoa(int(trans.SrcPort))
			display.DstPort = strconv.Itoa(int(trans.DstPort))
			display.Info = fmt.Sprintf("%s → %s", display.SrcPort, display.DstPort)
		}
	} else if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		// Handle ICMP separately since it's not a transport layer
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		display.Protocol = "ICMP"
		if icmp != nil {
			display.Info = fmt.Sprintf("Type %d Code %d", icmp.TypeCode.Type(), icmp.TypeCode.Code())
		} else {
			display.Info = "ICMP packet"
		}
	} else if icmp6Layer := pkt.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		icmp6, _ := icmp6Layer.(*layers.ICMPv6)
		display.Protocol = "ICMPv6"
		if icmp6 != nil {
			display.Info = fmt.Sprintf("Type %d Code %d", icmp6.TypeCode.Type(), icmp6.TypeCode.Code())
		} else {
			display.Info = "ICMPv6 packet"
		}
	} else if igmpLayer := pkt.Layer(layers.LayerTypeIGMP); igmpLayer != nil {
		// Handle IGMP (Internet Group Management Protocol)
		igmp, _ := igmpLayer.(*layers.IGMP)
		display.Protocol = "IGMP"
		if igmp != nil {
			display.Info = fmt.Sprintf("Type %d Group %s", igmp.Type, igmp.GroupAddress.String())
		} else {
			display.Info = "IGMP packet"
		}
	}

	// Use centralized detector for application layer protocols
	detectionResult := detector.GetDefault().Detect(pkt)
	if detectionResult != nil && detectionResult.Protocol != "unknown" {
		display.Protocol = detectionResult.Protocol

		// Generate display info from metadata
		switch detectionResult.Protocol {
		case "SIP":
			if firstLine, ok := detectionResult.Metadata["first_line"].(string); ok {
				if len(firstLine) > 60 {
					display.Info = firstLine[:60] + "..."
				} else {
					display.Info = firstLine
				}
			} else {
				display.Info = "SIP message"
			}
			// Convert metadata to VoIPData for compatibility
			display.VoIPData = metadataToVoIPData(detectionResult.Metadata)

		case "RTP":
			if codec, ok := detectionResult.Metadata["codec"].(string); ok {
				display.Info = codec
			} else {
				display.Info = "RTP stream"
			}
			// Convert metadata to VoIPData for compatibility
			display.VoIPData = metadataToVoIPData(detectionResult.Metadata)

		case "DNS":
			display.Info = "DNS Query/Response"

		case "gRPC", "HTTP2":
			display.Info = "gRPC/HTTP2"

		case "SSH":
			if versionStr, ok := detectionResult.Metadata["version_string"].(string); ok {
				display.Info = versionStr
			} else {
				display.Info = "SSH"
			}

		case "DHCP", "BOOTP":
			if msgType, ok := detectionResult.Metadata["message_type"].(string); ok {
				display.Info = msgType
			} else {
				display.Info = detectionResult.Protocol
			}

		case "NTP":
			if mode, ok := detectionResult.Metadata["mode"].(string); ok {
				display.Info = "NTP " + mode
			} else {
				display.Info = "NTP"
			}

		case "ICMP":
			if typeName, ok := detectionResult.Metadata["type_name"].(string); ok {
				display.Info = typeName
				if codeName, ok := detectionResult.Metadata["code_name"].(string); ok && codeName != "" {
					display.Info += " - " + codeName
				}
			} else {
				display.Info = "ICMP"
			}

		case "IGMP":
			// Extract IGMP message type from raw packet
			if igmpLayer := pkt.Layer(layers.LayerTypeIGMP); igmpLayer != nil {
				igmp := igmpLayer.(*layers.IGMPv1or2)
				switch igmp.Type {
				case layers.IGMPMembershipQuery:
					display.Info = "Membership Query"
				case layers.IGMPMembershipReportV1:
					display.Info = "Membership Report v1"
				case layers.IGMPMembershipReportV2:
					display.Info = "Membership Report v2"
				case layers.IGMPLeaveGroup:
					display.Info = "Leave Group"
				case layers.IGMPMembershipReportV3:
					display.Info = "Membership Report v3"
				default:
					display.Info = fmt.Sprintf("Type %d", igmp.Type)
				}
				// Add group address if present
				if igmp.GroupAddress != nil && !igmp.GroupAddress.IsUnspecified() {
					display.Info += fmt.Sprintf(" (%s)", igmp.GroupAddress.String())
				}
			} else {
				display.Info = "IGMP"
			}

		case "ARP":
			if op, ok := detectionResult.Metadata["operation"].(string); ok {
				if senderIP, ok := detectionResult.Metadata["sender_ip"].(string); ok {
					if targetIP, ok := detectionResult.Metadata["target_ip"].(string); ok {
						display.Info = fmt.Sprintf("%s: %s → %s", op, senderIP, targetIP)
					} else {
						display.Info = op
					}
				} else {
					display.Info = op
				}
			} else {
				display.Info = "ARP"
			}

		case "FTP":
			if msgType, ok := detectionResult.Metadata["type"].(string); ok {
				switch msgType {
				case "response":
					if code, ok := detectionResult.Metadata["code"].(int); ok {
						if msg, ok := detectionResult.Metadata["message"].(string); ok {
							display.Info = fmt.Sprintf("%d %s", code, msg)
						} else {
							display.Info = fmt.Sprintf("%d", code)
						}
					} else {
						display.Info = "Response"
					}
				case "command":
					if cmd, ok := detectionResult.Metadata["command"].(string); ok {
						display.Info = cmd
					} else {
						display.Info = "Command"
					}
				}
			} else {
				display.Info = "FTP"
			}

		case "SMTP":
			if msgType, ok := detectionResult.Metadata["type"].(string); ok {
				switch msgType {
				case "response":
					if code, ok := detectionResult.Metadata["code"].(int); ok {
						display.Info = fmt.Sprintf("%d", code)
					} else {
						display.Info = "Response"
					}
				case "command":
					if cmd, ok := detectionResult.Metadata["command"].(string); ok {
						display.Info = cmd
					} else {
						display.Info = "Command"
					}
				}
			} else {
				display.Info = "SMTP"
			}

		case "MySQL":
			if msgType, ok := detectionResult.Metadata["type"].(string); ok {
				switch msgType {
				case "handshake":
					if version, ok := detectionResult.Metadata["server_version"].(string); ok {
						display.Info = "Handshake: " + version
					} else {
						display.Info = "Handshake"
					}
				case "command":
					if cmdName, ok := detectionResult.Metadata["command_name"].(string); ok {
						display.Info = cmdName
					} else {
						display.Info = "Command"
					}
				default:
					display.Info = msgType
				}
			} else {
				display.Info = "MySQL"
			}

		case "PostgreSQL":
			if msgType, ok := detectionResult.Metadata["type"].(string); ok {
				if msg, ok := detectionResult.Metadata["message"].(string); ok {
					display.Info = msg
				} else if msgName, ok := detectionResult.Metadata["message_name"].(string); ok {
					display.Info = msgName
				} else {
					display.Info = msgType
				}
			} else {
				display.Info = "PostgreSQL"
			}

		case "SNMP":
			if version, ok := detectionResult.Metadata["version"].(string); ok {
				if pduType, ok := detectionResult.Metadata["pdu_type"].(string); ok {
					display.Info = version + " " + pduType
				} else {
					display.Info = version
				}
			} else {
				display.Info = "SNMP"
			}

		case "Redis":
			if cmd, ok := detectionResult.Metadata["command"].(string); ok {
				display.Info = cmd
			} else if msg, ok := detectionResult.Metadata["message"].(string); ok {
				display.Info = msg
			} else if respType, ok := detectionResult.Metadata["resp_type"].(string); ok {
				display.Info = respType
			} else {
				display.Info = "Redis"
			}

		case "MongoDB":
			if opName, ok := detectionResult.Metadata["op_name"].(string); ok {
				display.Info = opName
			} else {
				display.Info = "MongoDB"
			}

		case "Telnet":
			if iacCount, ok := detectionResult.Metadata["iac_count"].(int); ok {
				display.Info = fmt.Sprintf("Telnet negotiation (%d IAC)", iacCount)
			} else {
				display.Info = "Telnet"
			}

		case "POP3":
			if msgType, ok := detectionResult.Metadata["type"].(string); ok {
				if msgType == "response" {
					if status, ok := detectionResult.Metadata["status"].(string); ok {
						display.Info = status
					} else {
						display.Info = "Response"
					}
				} else if msgType == "command" {
					if cmd, ok := detectionResult.Metadata["command"].(string); ok {
						display.Info = cmd
					} else {
						display.Info = "Command"
					}
				}
			} else {
				display.Info = "POP3"
			}

		case "IMAP":
			if msgType, ok := detectionResult.Metadata["type"].(string); ok {
				if msgType == "response" {
					if respType, ok := detectionResult.Metadata["response_type"].(string); ok {
						display.Info = respType
					} else if status, ok := detectionResult.Metadata["status"].(string); ok {
						display.Info = status
					} else {
						display.Info = "Response"
					}
				} else if msgType == "command" {
					if cmd, ok := detectionResult.Metadata["command"].(string); ok {
						display.Info = cmd
					} else {
						display.Info = "Command"
					}
				}
			} else {
				display.Info = "IMAP"
			}

		case "OpenVPN":
			if typeName, ok := detectionResult.Metadata["type_name"].(string); ok {
				display.Info = typeName
			} else if opcodeName, ok := detectionResult.Metadata["opcode_name"].(string); ok {
				display.Info = opcodeName
			} else {
				display.Info = "OpenVPN"
			}

		case "WireGuard":
			if typeName, ok := detectionResult.Metadata["type_name"].(string); ok {
				display.Info = typeName
			} else {
				display.Info = "WireGuard"
			}

		case "L2TP":
			if packetType, ok := detectionResult.Metadata["packet_type"].(string); ok {
				if version, ok := detectionResult.Metadata["version"].(uint16); ok {
					display.Info = fmt.Sprintf("L2TPv%d %s", version, packetType)
				} else {
					display.Info = packetType
				}
			} else {
				display.Info = "L2TP"
			}

		case "PPTP":
			if ctrlType, ok := detectionResult.Metadata["control_type_name"].(string); ok {
				display.Info = ctrlType
			} else if category, ok := detectionResult.Metadata["category"].(string); ok {
				display.Info = category
			} else {
				display.Info = "PPTP"
			}

		case "IKEv2", "IKEv1", "IKE":
			if exchangeName, ok := detectionResult.Metadata["exchange_name"].(string); ok {
				if isResp, ok := detectionResult.Metadata["is_response"].(bool); ok {
					if isResp {
						display.Info = exchangeName + " (response)"
					} else {
						display.Info = exchangeName + " (request)"
					}
				} else {
					display.Info = exchangeName
				}
			} else if version, ok := detectionResult.Metadata["version"].(float64); ok {
				display.Info = fmt.Sprintf("IKEv%.1f", version)
			} else {
				display.Info = detectionResult.Protocol
			}

		default:
			display.Info = detectionResult.Protocol
		}
	}

	// Final fallback: if still unknown, list what layers we detected
	if display.Protocol == "unknown" && display.SrcIP == "unknown" {
		layers := pkt.Layers()
		if len(layers) > 0 {
			layerNames := make([]string, 0, len(layers))
			for _, layer := range layers {
				layerNames = append(layerNames, layer.LayerType().String())
			}
			display.Protocol = "Unknown"
			display.Info = "Layers: " + strings.Join(layerNames, ", ")
		} else {
			display.Protocol = "Malformed"
			display.Info = fmt.Sprintf("%d bytes", display.Length)
		}
	}

	return display
}

// tcpFlags returns a string representation of TCP flags
func tcpFlags(tcp *layers.TCP) string {
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

// isSIP checks if the payload looks like SIP
func isSIP(payload string) bool {
	sipMethods := []string{"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "SIP/2.0"}
	for _, method := range sipMethods {
		if len(payload) >= len(method) && payload[:len(method)] == method {
			return true
		}
	}
	return false
}

// extractSIPInfo extracts basic info from SIP message
func extractSIPInfo(payload string) string {
	lines := splitLines(payload)
	if len(lines) > 0 {
		// Return first line (request/response line)
		firstLine := lines[0]
		if len(firstLine) > 60 {
			return firstLine[:60] + "..."
		}
		return firstLine
	}
	return "SIP message"
}

// isGRPC checks if the payload might be gRPC/HTTP2
func isGRPC(payload []byte) bool {
	// Check for HTTP/2 connection preface
	if len(payload) >= 24 && string(payload[:24]) == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
		return true
	}

	// Check for HTTP/2 frame header (9 bytes minimum)
	// Frame format: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream ID
	if len(payload) >= 9 {
		frameType := payload[3]
		// Valid HTTP/2 frame types are 0x00-0x0A
		if frameType <= 0x0A {
			return true
		}
	}

	return false
}

// isDNS checks if the payload might be DNS
func isDNS(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}

	// DNS header: ID(2) + Flags(2) + Questions(2) + Answers(2) + Authority(2) + Additional(2)
	// Check for reasonable DNS flags and question count
	flags := uint16(payload[2])<<8 | uint16(payload[3])
	questionCount := uint16(payload[4])<<8 | uint16(payload[5])

	// DNS must have at least one question, and flags should look reasonable
	// Opcode (bits 11-14) should be <= 5, RCODE (bits 0-3) should be <= 10
	opcode := (flags >> 11) & 0x0F
	rcode := flags & 0x0F

	// Must have valid question count and reasonable opcode/rcode
	return questionCount > 0 && questionCount < 100 && opcode <= 5 && rcode <= 10
}

// splitLines splits a string by newlines
func splitLines(s string) []string {
	var lines []string
	var line string
	for _, c := range s {
		if c == '\n' || c == '\r' {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
		} else {
			line += string(c)
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseSIPPacket parses SIP packet and extracts metadata
func parseSIPPacket(payload string) *components.VoIPMetadata {
	metadata := &components.VoIPMetadata{
		Headers: make(map[string]string),
		IsRTP:   false,
	}

	lines := splitLines(payload)
	if len(lines) == 0 {
		return nil
	}

	// Parse SIP method (first line)
	metadata.Method = extractSIPMethod(lines[0])

	// Parse headers
	for _, line := range lines[1:] {
		if line == "" {
			break // End of headers
		}
		key, value := parseSIPHeader(line)
		if key != "" {
			metadata.Headers[key] = value

			// Extract common fields
			switch key {
			case "From":
				metadata.From = value
				metadata.User = extractUserFromURI(value)
			case "To":
				metadata.To = value
			case "Call-ID":
				metadata.CallID = value
			}
		}
	}

	return metadata
}

// parseRTPPacket parses RTP packet and extracts metadata
func parseRTPPacket(payload []byte) *components.VoIPMetadata {
	if len(payload) < 12 {
		return nil
	}

	// RTP header check (version should be 2)
	version := (payload[0] >> 6) & 0x03
	if version != 2 {
		return nil
	}

	metadata := &components.VoIPMetadata{
		IsRTP:   true,
		Headers: make(map[string]string),
	}

	// Extract SSRC (bytes 8-11)
	metadata.SSRC = uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])

	// Extract sequence number (bytes 2-3)
	metadata.SeqNumber = uint16(payload[2])<<8 | uint16(payload[3])

	// Extract payload type (byte 1, lower 7 bits)
	payloadType := payload[1] & 0x7F
	metadata.Codec = rtpPayloadTypeToCodec(payloadType)
	metadata.Method = metadata.Codec // Store codec in Method field for display

	return metadata
}

// extractSIPMethod extracts the SIP method from the first line
func extractSIPMethod(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == ' ' {
			return line[:i]
		}
	}
	return line
}

// parseSIPHeader parses a SIP header line
func parseSIPHeader(line string) (string, string) {
	for i := 0; i < len(line); i++ {
		if line[i] == ':' {
			key := line[:i]
			value := line[i+1:]
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			return key, value
		}
	}
	return "", ""
}

// extractUserFromURI extracts username from SIP URI
func extractUserFromURI(uri string) string {
	// Extract username from SIP URI: "Alice <sip:alice@domain.com>"
	start := -1
	for i := 0; i < len(uri); i++ {
		if uri[i] == ':' {
			start = i + 1
			break
		}
	}
	if start == -1 {
		return ""
	}

	for i := start; i < len(uri); i++ {
		if uri[i] == '@' {
			return uri[start:i]
		}
	}
	return ""
}

// rtpPayloadTypeToCodec maps RTP payload type to codec name
func rtpPayloadTypeToCodec(pt uint8) string {
	codecs := map[uint8]string{
		0:  "G.711 µ-law",
		8:  "G.711 A-law",
		9:  "G.722",
		18: "G.729",
		97: "Dynamic",
		98: "Dynamic",
		99: "Dynamic",
	}
	if codec, ok := codecs[pt]; ok {
		return codec
	}
	return "Unknown"
}

// metadataToVoIPData converts detector metadata to VoIPMetadata for compatibility
func metadataToVoIPData(metadata map[string]interface{}) *components.VoIPMetadata {
	voipData := &components.VoIPMetadata{
		Headers: make(map[string]string),
	}

	// Convert common fields
	if method, ok := metadata["method"].(string); ok {
		voipData.Method = method
	}
	if from, ok := metadata["from"].(string); ok {
		voipData.From = from
	}
	if to, ok := metadata["to"].(string); ok {
		voipData.To = to
	}
	if callID, ok := metadata["call_id"].(string); ok {
		voipData.CallID = callID
	}
	if user, ok := metadata["from_user"].(string); ok {
		voipData.User = user
	}

	// RTP-specific fields
	if ssrc, ok := metadata["ssrc"].(uint32); ok {
		voipData.SSRC = ssrc
		voipData.IsRTP = true
	}
	if seqNum, ok := metadata["sequence_number"].(uint16); ok {
		voipData.SeqNumber = seqNum
	}
	if codec, ok := metadata["codec"].(string); ok {
		voipData.Codec = codec
	}

	// Convert headers map
	if headers, ok := metadata["headers"].(map[string]string); ok {
		voipData.Headers = headers
	}

	return voipData
}

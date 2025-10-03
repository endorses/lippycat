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
		"TCP":     "TCP",
		"UDP":     "UDP",
		"SIP":     "SIP",
		"RTP":     "RTP",
		"DNS":     "DNS",
		"HTTP":    "HTTP",
		"HTTPS":   "HTTPS",
		"TLS":     "TLS",
		"SSL":     "SSL",
		"ICMP":    "ICMP",
		"ICMPv6":  "ICMPv6",
		"ARP":     "ARP",
		"LLC":     "LLC",
		"LLDP":    "LLDP",
		"CDP":     "CDP",
		"802.1Q":  "802.1Q",
		"802.1X":  "802.1X",
		"Unknown": "Unknown",
		"unknown": "unknown",
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
				display.Protocol = fmt.Sprintf("Eth:0x%04x", uint16(eth.EthernetType))
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
			if arp.Operation == 1 {
				display.Info = "Who has " + display.DstIP + "?"
			} else if arp.Operation == 2 {
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
				case layers.EthernetTypeDot1Q:
					display.Protocol = "802.1Q"
				case layers.EthernetTypeCiscoDiscovery:
					display.Protocol = "CDP"
				case layers.EthernetTypeLinkLayerDiscovery: // 0x88CC
					display.Protocol = "LLDP"
				case layers.EthernetTypeEthernetCTP:
					display.Protocol = "EthernetCTP"
				case 0x888E: // 802.1X (EAP)
					display.Protocol = "802.1X"
				case 0x8912: // Cisco proprietary
					display.Protocol = "Cisco"
				default:
					display.Protocol = fmt.Sprintf("Eth:0x%04x", uint16(eth.EthernetType))
				}

				if isBroadcast {
					display.Info = "Broadcast frame"
				} else {
					display.Info = "Non-IP frame"
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
	var udpLayer *layers.UDP
	if transLayer := pkt.TransportLayer(); transLayer != nil {
		switch trans := transLayer.(type) {
		case *layers.TCP:
			display.Protocol = "TCP"
			display.SrcPort = strconv.Itoa(int(trans.SrcPort))
			display.DstPort = strconv.Itoa(int(trans.DstPort))
			display.Info = fmt.Sprintf("%s → %s [%s]",
				display.SrcPort, display.DstPort, tcpFlags(trans))

		case *layers.UDP:
			udpLayer = trans // Save for RTP detection later
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
		}
	} else if icmp6Layer := pkt.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {
		icmp6, _ := icmp6Layer.(*layers.ICMPv6)
		display.Protocol = "ICMPv6"
		if icmp6 != nil {
			display.Info = fmt.Sprintf("Type %d Code %d", icmp6.TypeCode.Type(), icmp6.TypeCode.Code())
		}
	}

	// Extract application layer info
	if appLayer := pkt.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()

		// Try to detect SIP
		if len(payload) > 4 {
			payloadStr := string(payload[:min(100, len(payload))])
			if isSIP(payloadStr) {
				display.Protocol = "SIP"
				display.Info = extractSIPInfo(payloadStr)
				// Parse full SIP metadata
				display.VoIPData = parseSIPPacket(string(payload))
			} else if isGRPC(payload) {
				display.Protocol = "gRPC"
				display.Info = "gRPC/HTTP2"
			} else if isDNS(payload) {
				display.Protocol = "DNS"
				display.Info = "DNS Query/Response"
			}
		}
	}

	// Check for RTP (if UDP and in typical RTP port range)
	if display.Protocol == "UDP" && udpLayer != nil {
		srcPort := int(udpLayer.SrcPort)
		dstPort := int(udpLayer.DstPort)
		if (srcPort >= 10000 && srcPort <= 20000) || (dstPort >= 10000 && dstPort <= 20000) {
			if appLayer := pkt.ApplicationLayer(); appLayer != nil {
				if rtpData := parseRTPPacket(appLayer.Payload()); rtpData != nil {
					display.Protocol = "RTP"
					display.VoIPData = rtpData
					display.Info = rtpData.Codec
				}
			}
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

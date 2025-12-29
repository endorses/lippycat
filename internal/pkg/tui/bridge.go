//go:build tui || all
// +build tui all

package tui

import (
	"fmt"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/simd"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Offline call tracker for RTP-to-CallID mapping in offline mode
var (
	offlineCallTracker *OfflineCallTracker
	offlineTrackerMu   sync.RWMutex

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

	// Pre-allocated SIP method prefixes for fast detection (no allocations)
	sipMethodINVITE   = []byte("INVITE")
	sipMethodREGISTER = []byte("REGISTER")
	sipMethodOPTIONS  = []byte("OPTIONS")
	sipMethodACK      = []byte("ACK")
	sipMethodBYE      = []byte("BYE")
	sipMethodCANCEL   = []byte("CANCEL")
	sipResponse       = []byte("SIP/2.0")
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

// isSIPBytes performs fast SIP detection using SIMD-optimized byte comparison
// This is used in the fast conversion path to avoid full protocol detection overhead
func isSIPBytes(payload []byte) bool {
	if len(payload) < 3 {
		return false
	}

	// Check for common SIP methods and responses
	// Using pre-allocated byte slices and SIMD comparison for zero allocations
	if len(payload) >= len(sipMethodINVITE) && simd.BytesEqual(payload[:len(sipMethodINVITE)], sipMethodINVITE) {
		return true
	}
	if len(payload) >= len(sipMethodREGISTER) && simd.BytesEqual(payload[:len(sipMethodREGISTER)], sipMethodREGISTER) {
		return true
	}
	if len(payload) >= len(sipMethodOPTIONS) && simd.BytesEqual(payload[:len(sipMethodOPTIONS)], sipMethodOPTIONS) {
		return true
	}
	if len(payload) >= len(sipResponse) && simd.BytesEqual(payload[:len(sipResponse)], sipResponse) {
		return true
	}
	if len(payload) >= len(sipMethodACK) && simd.BytesEqual(payload[:len(sipMethodACK)], sipMethodACK) {
		return true
	}
	if len(payload) >= len(sipMethodBYE) && simd.BytesEqual(payload[:len(sipMethodBYE)], sipMethodBYE) {
		return true
	}
	if len(payload) >= len(sipMethodCANCEL) && simd.BytesEqual(payload[:len(sipMethodCANCEL)], sipMethodCANCEL) {
		return true
	}

	return false
}

// SetOfflineCallTracker sets the offline call tracker for use during offline mode
func SetOfflineCallTracker(tracker *OfflineCallTracker) {
	offlineTrackerMu.Lock()
	defer offlineTrackerMu.Unlock()
	offlineCallTracker = tracker
}

// GetOfflineCallTracker returns the current offline call tracker
func GetOfflineCallTracker() *OfflineCallTracker {
	offlineTrackerMu.RLock()
	defer offlineTrackerMu.RUnlock()
	return offlineCallTracker
}

// ClearOfflineCallTracker clears the offline call tracker
func ClearOfflineCallTracker() {
	offlineTrackerMu.Lock()
	defer offlineTrackerMu.Unlock()
	if offlineCallTracker != nil {
		offlineCallTracker.Clear()
		offlineCallTracker = nil
	}
}

// StartPacketBridge creates a bridge between packet capture and TUI
// It converts capture.PacketInfo to PacketMsg for the TUI
// Uses intelligent sampling and throttling to handle high packet rates
func StartPacketBridge(packetChan <-chan capture.PacketInfo, program *tea.Program) {
	const (
		targetPacketsPerSecond = 1000                      // Target display rate (increased for bulk transfers)
		batchInterval          = constants.TUITickInterval // Batch interval
		rateWindowSize         = 2 * time.Second           // Rolling window for rate calculation (react quickly)
	)

	batch := make([]components.PacketDisplay, 0, 100)
	packetCount := int64(0)
	displayedCount := int64(0)

	// Rolling window for recent packet rate calculation
	var recentPackets []time.Time
	lastRateCheck := time.Now()

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

	// Calculate sampling ratio based on RECENT packet rate (rolling 2s window)
	// This allows quick switching between fast/full mode
	getSamplingRatio := func() float64 {
		now := time.Now()

		// Update rolling window every 100ms to avoid overhead
		if now.Sub(lastRateCheck) > constants.TUITickInterval {
			// Remove packets older than window
			cutoff := now.Add(-rateWindowSize)
			i := 0
			for i < len(recentPackets) && recentPackets[i].Before(cutoff) {
				i++
			}
			recentPackets = recentPackets[i:]
			lastRateCheck = now
		}

		// Calculate rate from rolling window
		if len(recentPackets) < 10 {
			return 1.0 // Not enough data, use full mode
		}

		windowDuration := now.Sub(recentPackets[0]).Seconds()
		if windowDuration < 0.1 {
			return 1.0 // Too short, use full mode
		}

		currentRate := float64(len(recentPackets)) / windowDuration
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

			// Track packet timestamp for rolling window rate calculation
			recentPackets = append(recentPackets, time.Now())

			// Adaptive sampling based on load
			samplingRatio := getSamplingRatio()

			// Use fast conversion for sampled packets, full for important ones
			var packet components.PacketDisplay
			if samplingRatio >= 1.0 || (float64(packetCount)*samplingRatio) >= float64(displayedCount+int64(len(batch))+1) {
				// This packet should be displayed
				if samplingRatio < 0.2 {
					// Very high load - use fast conversion (only when rate > 5000 pps)
					packet = convertPacketFast(pktInfo)
				} else {
					// Normal/moderate load - full conversion with raw data
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
// Uses shared extraction logic with TUI-specific fast SIP detection
func convertPacketFast(pktInfo capture.PacketInfo) components.PacketDisplay {
	pkt := pktInfo.Packet

	// Use shared extraction for basic fields
	fields := capture.ExtractPacketFields(pkt)

	display := components.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     fields.SrcIP,
		DstIP:     fields.DstIP,
		SrcPort:   fields.SrcPort,
		DstPort:   fields.DstPort,
		Protocol:  internProtocol(fields.Protocol),
		Length:    pkt.Metadata().Length,
		Info:      "",  // Skip info in fast mode
		RawData:   nil, // Don't copy raw data for performance
		Interface: pktInfo.Interface,
		LinkType:  pktInfo.LinkType,
	}

	// Fast SIP detection for VoIP over TCP/UDP
	if fields.HasTransport {
		if transLayer := pkt.TransportLayer(); transLayer != nil {
			switch trans := transLayer.(type) {
			case *layers.TCP:
				if isSIPBytes(trans.LayerPayload()) {
					display.Protocol = internProtocol("SIP")
				}
			case *layers.UDP:
				if isSIPBytes(trans.LayerPayload()) {
					display.Protocol = internProtocol("SIP")
				}
			}
		}
	}

	return display
}

// convertPacket converts a gopacket.Packet to PacketDisplay
// Uses shared extraction logic enhanced with protocol detection
func convertPacket(pktInfo capture.PacketInfo) components.PacketDisplay {
	pkt := pktInfo.Packet

	// Use shared extraction for basic fields
	fields := capture.ExtractPacketFields(pkt)

	// Copy raw data for packet display
	var rawData []byte
	if pkt.Data() != nil {
		rawData = make([]byte, len(pkt.Data()))
		copy(rawData, pkt.Data())
	}

	display := components.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     fields.SrcIP,
		DstIP:     fields.DstIP,
		SrcPort:   fields.SrcPort,
		DstPort:   fields.DstPort,
		Protocol:  fields.Protocol,
		Length:    pkt.Metadata().Length,
		Info:      fields.Info,
		RawData:   rawData,
		Interface: pktInfo.Interface,
		LinkType:  pktInfo.LinkType,
	}

	// Use centralized detector for application layer protocols
	detectionResult := detector.GetDefault().Detect(pkt)
	if detectionResult != nil && detectionResult.Protocol != "unknown" {
		display.Protocol = detectionResult.Protocol

		// Generate display info from metadata
		display.Info = buildProtocolInfo(detectionResult, pkt, &display)
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

// buildProtocolInfo generates display info from detector metadata
func buildProtocolInfo(result *signatures.DetectionResult, pkt gopacket.Packet, display *components.PacketDisplay) string {
	switch result.Protocol {
	case "SIP":
		if firstLine, ok := result.Metadata["first_line"].(string); ok {
			if len(firstLine) > 60 {
				firstLine = firstLine[:60] + "..."
			}
			// Convert metadata to VoIPData for compatibility
			display.VoIPData = metadataToVoIPData(result.Metadata)

			// Feed SIP packet to offline tracker for RTP-to-CallID mapping
			if tracker := GetOfflineCallTracker(); tracker != nil && display.VoIPData != nil && display.VoIPData.CallID != "" {
				// Get payload for SDP parsing
				if appLayer := pkt.ApplicationLayer(); appLayer != nil {
					payload := string(appLayer.Payload())
					tracker.ProcessSIPPacket(display.VoIPData.CallID, display.SrcIP, display.DstIP, payload)
				}
			}
			return firstLine
		}
		display.VoIPData = metadataToVoIPData(result.Metadata)
		return "SIP message"

	case "RTP":
		display.VoIPData = metadataToVoIPData(result.Metadata)

		// Query offline tracker for CallID based on IP/port
		if tracker := GetOfflineCallTracker(); tracker != nil && display.VoIPData != nil {
			callID := tracker.GetCallIDForRTPPacket(display.SrcIP, display.SrcPort, display.DstIP, display.DstPort)
			if callID != "" {
				display.VoIPData.CallID = callID
			}
		}

		if codec, ok := result.Metadata["codec"].(string); ok {
			return codec
		}
		return "RTP stream"

	case "DNS":
		return "DNS Query/Response"

	case "gRPC", "HTTP2":
		return "gRPC/HTTP2"

	case "SSH":
		if versionStr, ok := result.Metadata["version_string"].(string); ok {
			return versionStr
		}
		return "SSH"

	case "DHCP", "BOOTP":
		if msgType, ok := result.Metadata["message_type"].(string); ok {
			return msgType
		}
		return result.Protocol

	case "NTP":
		if mode, ok := result.Metadata["mode"].(string); ok {
			return "NTP " + mode
		}
		return "NTP"

	case "ICMP":
		if typeName, ok := result.Metadata["type_name"].(string); ok {
			info := typeName
			if codeName, ok := result.Metadata["code_name"].(string); ok && codeName != "" {
				info += " - " + codeName
			}
			return info
		}
		return "ICMP"

	case "IGMP":
		return buildIGMPInfo(result)

	case "ARP":
		if op, ok := result.Metadata["operation"].(string); ok {
			if senderIP, ok := result.Metadata["sender_ip"].(string); ok {
				if targetIP, ok := result.Metadata["target_ip"].(string); ok {
					return fmt.Sprintf("%s: %s -> %s", op, senderIP, targetIP)
				}
			}
			return op
		}
		return "ARP"

	case "FTP":
		return buildFTPInfo(result)

	case "SMTP":
		return buildSMTPInfo(result)

	case "MySQL":
		return buildMySQLInfo(result)

	case "PostgreSQL":
		return buildPostgreSQLInfo(result)

	case "SNMP":
		if version, ok := result.Metadata["version"].(string); ok {
			if pduType, ok := result.Metadata["pdu_type"].(string); ok {
				return version + " " + pduType
			}
			return version
		}
		return "SNMP"

	case "Redis":
		if cmd, ok := result.Metadata["command"].(string); ok {
			return cmd
		}
		if msg, ok := result.Metadata["message"].(string); ok {
			return msg
		}
		if respType, ok := result.Metadata["resp_type"].(string); ok {
			return respType
		}
		return "Redis"

	case "MongoDB":
		if opName, ok := result.Metadata["op_name"].(string); ok {
			return opName
		}
		return "MongoDB"

	case "Telnet":
		if iacCount, ok := result.Metadata["iac_count"].(int); ok {
			return fmt.Sprintf("Telnet negotiation (%d IAC)", iacCount)
		}
		return "Telnet"

	case "POP3":
		return buildPOP3Info(result)

	case "IMAP":
		return buildIMAPInfo(result)

	case "OpenVPN":
		if typeName, ok := result.Metadata["type_name"].(string); ok {
			return typeName
		}
		if opcodeName, ok := result.Metadata["opcode_name"].(string); ok {
			return opcodeName
		}
		return "OpenVPN"

	case "WireGuard":
		if typeName, ok := result.Metadata["type_name"].(string); ok {
			return typeName
		}
		return "WireGuard"

	case "L2TP":
		if packetType, ok := result.Metadata["packet_type"].(string); ok {
			if version, ok := result.Metadata["version"].(uint16); ok {
				return fmt.Sprintf("L2TPv%d %s", version, packetType)
			}
			return packetType
		}
		return "L2TP"

	case "PPTP":
		if ctrlType, ok := result.Metadata["control_type_name"].(string); ok {
			return ctrlType
		}
		if category, ok := result.Metadata["category"].(string); ok {
			return category
		}
		return "PPTP"

	case "IKEv2", "IKEv1", "IKE":
		if exchangeName, ok := result.Metadata["exchange_name"].(string); ok {
			if isResp, ok := result.Metadata["is_response"].(bool); ok {
				if isResp {
					return exchangeName + " (response)"
				}
				return exchangeName + " (request)"
			}
			return exchangeName
		}
		if version, ok := result.Metadata["version"].(float64); ok {
			return fmt.Sprintf("IKEv%.1f", version)
		}
		return result.Protocol

	default:
		return result.Protocol
	}
}

// buildIGMPInfo extracts IGMP info from gopacket layer
func buildIGMPInfo(result *signatures.DetectionResult) string {
	// Default IGMP info
	return "IGMP"
}

// buildFTPInfo builds FTP info from metadata
func buildFTPInfo(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		switch msgType {
		case "response":
			if code, ok := result.Metadata["code"].(int); ok {
				if msg, ok := result.Metadata["message"].(string); ok {
					return fmt.Sprintf("%d %s", code, msg)
				}
				return fmt.Sprintf("%d", code)
			}
			return "Response"
		case "command":
			if cmd, ok := result.Metadata["command"].(string); ok {
				return cmd
			}
			return "Command"
		}
	}
	return "FTP"
}

// buildSMTPInfo builds SMTP info from metadata
func buildSMTPInfo(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		switch msgType {
		case "response":
			if code, ok := result.Metadata["code"].(int); ok {
				return fmt.Sprintf("%d", code)
			}
			return "Response"
		case "command":
			if cmd, ok := result.Metadata["command"].(string); ok {
				return cmd
			}
			return "Command"
		}
	}
	return "SMTP"
}

// buildMySQLInfo builds MySQL info from metadata
func buildMySQLInfo(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		switch msgType {
		case "handshake":
			if version, ok := result.Metadata["server_version"].(string); ok {
				return "Handshake: " + version
			}
			return "Handshake"
		case "command":
			if cmdName, ok := result.Metadata["command_name"].(string); ok {
				return cmdName
			}
			return "Command"
		default:
			return msgType
		}
	}
	return "MySQL"
}

// buildPostgreSQLInfo builds PostgreSQL info from metadata
func buildPostgreSQLInfo(result *signatures.DetectionResult) string {
	if _, ok := result.Metadata["type"].(string); ok {
		if msg, ok := result.Metadata["message"].(string); ok {
			return msg
		}
		if msgName, ok := result.Metadata["message_name"].(string); ok {
			return msgName
		}
	}
	return "PostgreSQL"
}

// buildPOP3Info builds POP3 info from metadata
func buildPOP3Info(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		if msgType == "response" {
			if status, ok := result.Metadata["status"].(string); ok {
				return status
			}
			return "Response"
		} else if msgType == "command" {
			if cmd, ok := result.Metadata["command"].(string); ok {
				return cmd
			}
			return "Command"
		}
	}
	return "POP3"
}

// buildIMAPInfo builds IMAP info from metadata
func buildIMAPInfo(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		if msgType == "response" {
			if respType, ok := result.Metadata["response_type"].(string); ok {
				return respType
			}
			if status, ok := result.Metadata["status"].(string); ok {
				return status
			}
			return "Response"
		} else if msgType == "command" {
			if cmd, ok := result.Metadata["command"].(string); ok {
				return cmd
			}
			return "Command"
		}
	}
	return "IMAP"
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
	if fromTag, ok := metadata["from_tag"].(string); ok {
		voipData.FromTag = fromTag
	}
	if toTag, ok := metadata["to_tag"].(string); ok {
		voipData.ToTag = toTag
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

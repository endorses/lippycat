package remotecapture

// File: client_conversion.go - Packet parsing and state conversion
//
// Handles conversion between protobuf messages and internal types,
// including packet parsing, call state conversion, and MOS calculation.

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// convertToPacketDisplay converts a CapturedPacket to PacketDisplay
func (c *Client) convertToPacketDisplay(pkt *data.CapturedPacket, hunterID string) types.PacketDisplay {
	// Determine link type from packet metadata (safe: link types are small enum values)
	linkType := layers.LinkType(pkt.LinkType) // #nosec G115
	if linkType == 0 {
		// Default to Ethernet if not specified
		linkType = layers.LinkTypeEthernet
	}

	// Parse packet using gopacket with correct link type
	packet := gopacket.NewPacket(pkt.Data, linkType, gopacket.Default)

	// Use shared extraction logic for basic fields
	fields := capture.ExtractPacketFields(packet)
	srcIP := fields.SrcIP
	dstIP := fields.DstIP
	srcPort := fields.SrcPort
	dstPort := fields.DstPort
	protocol := fields.Protocol
	info := fields.Info

	// Use pre-computed metadata from processor if available (centralized detection)
	if pkt.Metadata != nil && pkt.Metadata.Protocol != "" {
		protocol = pkt.Metadata.Protocol

		// Use metadata IPs/ports if available (avoid re-parsing packet)
		if pkt.Metadata.SrcIp != "" {
			srcIP = pkt.Metadata.SrcIp
		}
		if pkt.Metadata.DstIp != "" {
			dstIP = pkt.Metadata.DstIp
		}
		if pkt.Metadata.SrcPort > 0 {
			srcPort = fmt.Sprintf("%d", pkt.Metadata.SrcPort)
		}
		if pkt.Metadata.DstPort > 0 {
			dstPort = fmt.Sprintf("%d", pkt.Metadata.DstPort)
		}

		// Use pre-computed info string if available (processor already built it)
		if pkt.Metadata.Info != "" {
			info = pkt.Metadata.Info
		} else {
			// Fallback: extract protocol-specific info from metadata
			switch protocol {
			case "SIP":
				if pkt.Metadata.Sip != nil {
					if pkt.Metadata.Sip.Method != "" {
						info = pkt.Metadata.Sip.Method
					} else if pkt.Metadata.Sip.ResponseCode > 0 {
						info = fmt.Sprintf("%d", pkt.Metadata.Sip.ResponseCode)
					}
				}

			case "RTP":
				if pkt.Metadata.Rtp != nil {
					// Derive codec name from payload type (safe: RTP payload type is 0-127)
					if pkt.Metadata.Rtp.PayloadType > 0 {
						codec := capture.PayloadTypeToCodec(uint8(pkt.Metadata.Rtp.PayloadType)) // #nosec G115
						info = codec
					} else {
						info = "RTP stream"
					}
				}
			}
		}
	}

	// Fallback to application layer detection for DNS
	if packet.ApplicationLayer() != nil {
		payload := packet.ApplicationLayer().Payload()
		if len(payload) > 0 {
			// DNS detection (port 53 or DNS layer)
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				protocol = "DNS"
				info = "DNS Query/Response"
			} else if (srcPort == "53" || dstPort == "53") && protocol == "UDP" {
				protocol = "DNS"
				info = "DNS Query/Response"
			}
		}
	}

	// Parse timestamp
	ts := time.Unix(0, pkt.TimestampNs)

	// Use interface name from packet (set by hunter), or fall back to index-based lookup
	var ifaceName string
	if pkt.InterfaceName != "" {
		// Use interface name directly from packet (preferred method - works in hierarchical mode)
		ifaceName = pkt.InterfaceName
	} else {
		// Fallback to interface index lookup (legacy method for backwards compatibility)
		c.interfacesMu.RLock()
		hunterInterfaces, exists := c.interfaces[hunterID]
		c.interfacesMu.RUnlock()

		if exists && int(pkt.InterfaceIndex) < len(hunterInterfaces) {
			ifaceName = hunterInterfaces[pkt.InterfaceIndex]
		} else {
			ifaceName = fmt.Sprintf("iface%d", pkt.InterfaceIndex)
		}
	}

	// Build VoIP metadata if present
	var voipData *types.VoIPMetadata
	if pkt.Metadata != nil && (pkt.Metadata.Sip != nil || pkt.Metadata.Rtp != nil) {
		voipData = &types.VoIPMetadata{}

		// SIP metadata
		if pkt.Metadata.Sip != nil {
			voipData.CallID = pkt.Metadata.Sip.CallId
			voipData.Method = pkt.Metadata.Sip.Method
			voipData.Status = int(pkt.Metadata.Sip.ResponseCode)
			voipData.From = pkt.Metadata.Sip.FromUser
			voipData.To = pkt.Metadata.Sip.ToUser
			voipData.FromTag = pkt.Metadata.Sip.FromTag
			voipData.ToTag = pkt.Metadata.Sip.ToTag
			// ALWAYS mark as SIP if we have SIP metadata from hunter
			// Trust the hunter's analysis even if TUI parsing failed
			protocol = "SIP"
			// Replace info with SIP metadata if it's empty or a parse error
			if info == "" || strings.Contains(info, "Parse error") || strings.Contains(info, "Decode failed") || strings.Contains(info, "Unable to decode") {
				if pkt.Metadata.Sip.Method != "" {
					info = pkt.Metadata.Sip.Method
				} else if pkt.Metadata.Sip.ResponseCode > 0 {
					info = fmt.Sprintf("%d", pkt.Metadata.Sip.ResponseCode)
				}
			}
		}

		// RTP metadata
		if pkt.Metadata.Rtp != nil {
			voipData.IsRTP = true
			voipData.SSRC = pkt.Metadata.Rtp.Ssrc
			voipData.PayloadType = uint8(pkt.Metadata.Rtp.PayloadType) // #nosec G115 - RTP payload type is 7 bits (0-127)
			voipData.SequenceNum = uint16(pkt.Metadata.Rtp.Sequence)   // #nosec G115 - RTP sequence is 16 bits
			voipData.Timestamp = pkt.Metadata.Rtp.Timestamp
			// ALWAYS mark as RTP if we have RTP metadata from hunter
			// Trust the hunter's analysis even if TUI parsing failed
			protocol = "RTP"
			// Update info with codec if not already set
			if info == "" || info == fmt.Sprintf("%s -> %s", srcPort, dstPort) || strings.Contains(info, "Parse error") {
				codec := capture.PayloadTypeToCodec(voipData.PayloadType)
				info = fmt.Sprintf("SSRC=%d %s", voipData.SSRC, codec)
			}
		}
	}

	// Build DNS metadata if present
	var dnsData *types.DNSMetadata
	if pkt.Metadata != nil && pkt.Metadata.Dns != nil {
		dnsProto := pkt.Metadata.Dns
		dnsData = &types.DNSMetadata{
			TransactionID:       uint16(dnsProto.TransactionId), // #nosec G115 - DNS transaction ID is 16 bits
			IsResponse:          dnsProto.IsResponse,
			Opcode:              dnsProto.Opcode,
			ResponseCode:        dnsProto.ResponseCode,
			Authoritative:       dnsProto.Authoritative,
			Truncated:           dnsProto.Truncated,
			RecursionDesired:    dnsProto.RecursionDesired,
			RecursionAvailable:  dnsProto.RecursionAvailable,
			AuthenticatedData:   dnsProto.AuthenticatedData,
			CheckingDisabled:    dnsProto.CheckingDisabled,
			QuestionCount:       uint16(dnsProto.QuestionCount),   // #nosec G115
			AnswerCount:         uint16(dnsProto.AnswerCount),     // #nosec G115
			AuthorityCount:      uint16(dnsProto.AuthorityCount),  // #nosec G115
			AdditionalCount:     uint16(dnsProto.AdditionalCount), // #nosec G115
			QueryName:           dnsProto.QueryName,
			QueryType:           dnsProto.QueryType,
			QueryClass:          dnsProto.QueryClass,
			QueryResponseTimeMs: dnsProto.QueryResponseTimeMs,
			CorrelatedQuery:     dnsProto.CorrelatedQuery,
			TunnelingScore:      dnsProto.TunnelingScore,
			EntropyScore:        dnsProto.EntropyScore,
		}

		// Convert answers
		if len(dnsProto.Answers) > 0 {
			dnsData.Answers = make([]types.DNSAnswer, len(dnsProto.Answers))
			for i, a := range dnsProto.Answers {
				dnsData.Answers[i] = types.DNSAnswer{
					Name:  a.Name,
					Type:  a.Type,
					Class: a.Class,
					TTL:   a.Ttl,
					Data:  a.Data,
				}
			}
		}

		// Set protocol and info from DNS metadata
		protocol = "DNS"
		if dnsProto.IsResponse {
			if len(dnsData.Answers) > 0 {
				info = fmt.Sprintf("%s %s -> %s", dnsProto.QueryType, dnsProto.QueryName, dnsData.Answers[0].Data)
			} else {
				info = fmt.Sprintf("%s %s %s", dnsProto.QueryType, dnsProto.QueryName, dnsProto.ResponseCode)
			}
		} else {
			info = fmt.Sprintf("%s %s?", dnsProto.QueryType, dnsProto.QueryName)
		}
	}

	return types.PacketDisplay{
		Timestamp: ts,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Protocol:  protocol,
		Length:    int(pkt.CaptureLength),
		Info:      info,
		RawData:   pkt.Data,
		NodeID:    hunterID,  // Set node ID from batch
		Interface: ifaceName, // Interface where packet was captured
		VoIPData:  voipData,  // VoIP metadata if applicable
		DNSData:   dnsData,   // DNS metadata if applicable
		LinkType:  linkType,  // Link layer type
	}
}

// convertToHunterInfo converts ConnectedHunter to HunterInfo
func (c *Client) convertToHunterInfo(h *management.ConnectedHunter) types.HunterInfo {
	// Safe: duration seconds won't overflow int64 nanoseconds (would require ~292 years uptime)
	connectedAt := time.Now().UnixNano() - int64(h.ConnectedDurationSec*1e9) // #nosec G115

	return types.HunterInfo{
		ID:               h.HunterId,
		Hostname:         h.Hostname,
		RemoteAddr:       h.RemoteAddr,
		Status:           h.Status,
		ConnectedAt:      connectedAt,
		LastHeartbeat:    h.LastHeartbeatNs,
		PacketsCaptured:  h.Stats.PacketsCaptured,
		PacketsMatched:   h.Stats.PacketsMatched,
		PacketsForwarded: h.Stats.PacketsForwarded,
		PacketsDropped:   h.Stats.PacketsDropped,
		ActiveFilters:    h.Stats.ActiveFilters,
		CPUPercent:       float64(h.Stats.CpuPercent),
		MemoryRSSBytes:   h.Stats.MemoryRssBytes,
		MemoryLimitBytes: h.Stats.MemoryLimitBytes,
		Interfaces:       h.Interfaces,
		ProcessorAddr:    c.addr,         // Address of processor this client is connected to
		Capabilities:     h.Capabilities, // Hunter capabilities (filter types, etc.)
	}
}

// calculateMOS computes Mean Opinion Score from packet loss and jitter
// Uses the E-model (ITU-T G.107) simplified calculation
// MOS scale: 1.0 (bad) to 5.0 (excellent)
func calculateMOS(packetLoss, jitter float64) float64 {
	// Clamp inputs to reasonable ranges
	packetLoss = max(0, packetLoss)
	if packetLoss > 100 {
		packetLoss = 100
	}
	jitter = max(0, jitter)

	// Calculate R-factor (transmission rating factor)
	// R = R0 - Is - Id - Ie + A
	// Where:
	// R0 = 93.2 (base quality)
	// Is = simultaneous impairment (0 for VoIP)
	// Id = delay impairment (from jitter)
	// Ie = equipment impairment (from packet loss and codec)
	// A = advantage factor (0 for VoIP)

	// Delay impairment from jitter
	// Simplified: Id increases with jitter (threshold at 150ms)
	delayImpairment := 0.0
	if jitter > 150 {
		delayImpairment = (jitter - 150) / 10.0
	} else {
		delayImpairment = jitter / 40.0
	}

	// Equipment impairment from packet loss
	// Simplified: Ie = packet_loss_pct * factor
	equipmentImpairment := packetLoss * 2.5

	// Calculate R-factor
	rFactor := 93.2 - delayImpairment - equipmentImpairment

	// Clamp R-factor to valid range (0-100)
	rFactor = max(0, rFactor)
	if rFactor > 100 {
		rFactor = 100
	}

	// Convert R-factor to MOS
	// MOS = 1 + 0.035*R + 7*10^-6*R*(R-60)*(100-R)
	var mos float64
	if rFactor < 0 {
		mos = 1.0
	} else if rFactor > 100 {
		mos = 4.5
	} else {
		mos = 1.0 + 0.035*rFactor + 7e-6*rFactor*(rFactor-60)*(100-rFactor)
	}

	// Clamp MOS to valid range (1.0-5.0)
	if mos < 1.0 {
		mos = 1.0
	}
	if mos > 5.0 {
		mos = 5.0
	}

	return mos
}

// updateCallState updates call state from SIP packet metadata
func (c *Client) updateCallState(pkt *data.CapturedPacket, hunterID string) {
	sip := pkt.Metadata.Sip
	if sip == nil || sip.CallId == "" {
		return
	}

	c.callsMu.Lock()
	defer c.callsMu.Unlock()

	call, exists := c.calls[sip.CallId]
	if !exists {
		// Prefer full URIs if available, fallback to username only
		from := sip.FromUri
		if from == "" {
			from = sip.FromUser
		}
		to := sip.ToUri
		if to == "" {
			to = sip.ToUser
		}

		// New call
		call = &types.CallInfo{
			CallID:    sip.CallId,
			From:      from,
			To:        to,
			State:     "NEW",
			StartTime: time.Unix(0, pkt.TimestampNs),
			NodeID:    c.nodeID,
			Hunters:   []string{hunterID},
		}
		c.calls[sip.CallId] = call
	} else {
		// Update existing call
		if !contains(call.Hunters, hunterID) {
			call.Hunters = append(call.Hunters, hunterID)
		}
	}

	// Update state based on SIP method and response code
	call.PacketCount++
	timestamp := time.Unix(0, pkt.TimestampNs)
	deriveSIPState(call, sip.Method, sip.ResponseCode, timestamp)
}

// deriveSIPState updates call state based on SIP message
// This mirrors the logic in voip.CallAggregator.updateCallState
func deriveSIPState(call *types.CallInfo, method string, responseCode uint32, timestamp time.Time) {
	// Don't transition from terminal states
	switch call.State {
	case "ENDED", "FAILED", "CANCELLED", "BUSY":
		return
	}

	switch method {
	case "INVITE":
		if call.State == "NEW" {
			call.State = "TRYING"
		}
	case "ACK":
		if call.State == "TRYING" || call.State == "RINGING" || call.State == "PROGRESS" {
			call.State = "ACTIVE"
		}
	case "BYE":
		call.State = "ENDED"
		if call.EndTime.IsZero() {
			call.EndTime = timestamp
		}
	case "CANCEL":
		call.State = "CANCELLED"
		if call.EndTime.IsZero() {
			call.EndTime = timestamp
		}
	}

	// Handle provisional responses (1xx)
	if responseCode == 180 {
		if call.State == "TRYING" {
			call.State = "RINGING"
		}
	} else if responseCode == 183 {
		if call.State == "TRYING" || call.State == "RINGING" {
			call.State = "PROGRESS"
		}
	}

	// Handle success responses (2xx)
	if responseCode >= 200 && responseCode < 300 {
		if call.State == "TRYING" || call.State == "RINGING" || call.State == "PROGRESS" {
			call.State = "ACTIVE"
		}
	} else if responseCode == 486 {
		// 486 Busy Here
		call.State = "BUSY"
		if call.EndTime.IsZero() {
			call.EndTime = timestamp
		}
	} else if responseCode == 487 {
		// 487 Request Terminated (response to CANCEL)
		call.State = "CANCELLED"
		if call.EndTime.IsZero() {
			call.EndTime = timestamp
		}
	} else if responseCode >= 400 {
		// Other 4xx/5xx/6xx errors - store code for display
		call.State = "FAILED"
		call.LastResponseCode = responseCode
		if call.EndTime.IsZero() {
			call.EndTime = timestamp
		}
	}
}

// updateRTPQuality updates RTP quality metrics from packet metadata
func (c *Client) updateRTPQuality(pkt *data.CapturedPacket) {
	rtp := pkt.Metadata.Rtp
	sip := pkt.Metadata.Sip

	if rtp == nil || sip == nil || sip.CallId == "" {
		return
	}

	callID := sip.CallId

	c.callsMu.Lock()
	defer c.callsMu.Unlock()

	// Get or create call (RTP may arrive before SIP in some cases)
	call, exists := c.calls[callID]
	if !exists {
		// RTP packet without prior SIP - shouldn't happen normally but be defensive
		return
	}

	// Get or initialize RTP stats for this call
	stats, exists := c.rtpStats[callID]
	if !exists {
		stats = &rtpQualityStats{
			lastSeqNum:    uint16(rtp.Sequence), // #nosec G115 - RTP sequence is 16 bits
			lastTimestamp: rtp.Timestamp,
			totalPackets:  0,
			lostPackets:   0,
		}
		c.rtpStats[callID] = stats

		// Extract codec from payload type (first RTP packet)
		call.Codec = capture.PayloadTypeToCodec(uint8(rtp.PayloadType)) // #nosec G115 - RTP payload type is 7 bits (0-127)
	}

	// Detect packet loss from sequence number gaps
	if stats.totalPackets > 0 {
		expectedSeq := stats.lastSeqNum + 1
		actualSeq := uint16(rtp.Sequence) // #nosec G115 - RTP sequence is 16 bits

		// Handle sequence number wraparound (uint16 overflow)
		var gap int
		if actualSeq >= expectedSeq {
			gap = int(actualSeq - expectedSeq)
		} else {
			// Wraparound occurred
			gap = int(65535 - uint32(expectedSeq) + uint32(actualSeq) + 1)
		}

		if gap > 0 {
			// Detect out-of-order or lost packets
			if gap < 1000 { // Sanity check: ignore large gaps (likely restart)
				stats.lostPackets += gap
			}
		}
	}

	stats.lastSeqNum = uint16(rtp.Sequence) // #nosec G115 - RTP sequence is 16 bits
	stats.totalPackets++

	// Calculate packet loss percentage
	if stats.totalPackets > 0 {
		call.PacketLoss = (float64(stats.lostPackets) / float64(stats.totalPackets)) * 100.0
	}

	// Calculate jitter using RFC 3550 algorithm
	if stats.totalPackets > 1 && stats.lastTimestamp != 0 {
		// Calculate inter-arrival jitter
		// J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
		timestampDiff := int64(rtp.Timestamp) - int64(stats.lastTimestamp)
		timestampDiff = max(-timestampDiff, timestampDiff)

		// Convert to milliseconds (assuming 8kHz clock rate for most codecs)
		timestampDiffMs := float64(timestampDiff) / 8.0

		// Update jitter with smoothing factor (1/16 as per RFC 3550)
		call.Jitter = call.Jitter + (timestampDiffMs-call.Jitter)/16.0
	}

	stats.lastTimestamp = rtp.Timestamp

	// Calculate MOS (Mean Opinion Score) based on packet loss and jitter
	call.MOS = calculateMOS(call.PacketLoss, call.Jitter)
}

// maybeNotifyCallUpdates periodically notifies handler of call state updates
func (c *Client) maybeNotifyCallUpdates() {
	// Throttle updates to max every 500ms
	c.callsMu.RLock()
	lastUpdate := c.lastCallUpdate
	c.callsMu.RUnlock()

	if time.Since(lastUpdate) < 500*time.Millisecond {
		return
	}

	c.callsMu.Lock()
	c.lastCallUpdate = time.Now()

	// Copy calls to slice for notification
	calls := make([]types.CallInfo, 0, len(c.calls))
	for _, call := range c.calls {
		// Calculate duration for active calls
		if call.State == "ACTIVE" && call.EndTime.IsZero() {
			call.Duration = time.Since(call.StartTime)
		} else if !call.EndTime.IsZero() {
			call.Duration = call.EndTime.Sub(call.StartTime)
		}
		calls = append(calls, *call)
	}
	c.callsMu.Unlock()

	// Notify handler
	if c.handler != nil && len(calls) > 0 {
		c.handler.OnCallUpdate(calls)
	}
}

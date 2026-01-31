//go:build tui || all

package tui

import (
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
)

// TCP SIP message type counters
var (
	tcpSIPRequestsProcessed  int64
	tcpSIPResponsesProcessed int64
	tcpSIPRequestsWithSDP    int64
	tcpSIPResponsesWithSDP   int64
	tcpSIPMergesTriggered    int64 // Merges triggered from TCP SIP handler
)

// GetTCPSIPTypeStats returns TCP SIP request vs response statistics
func GetTCPSIPTypeStats() (requests, responses, requestsWithSDP, responsesWithSDP, mergesTriggered int64) {
	return atomic.LoadInt64(&tcpSIPRequestsProcessed),
		atomic.LoadInt64(&tcpSIPResponsesProcessed),
		atomic.LoadInt64(&tcpSIPRequestsWithSDP),
		atomic.LoadInt64(&tcpSIPResponsesWithSDP),
		atomic.LoadInt64(&tcpSIPMergesTriggered)
}

// TUISIPHandler handles SIP messages for TUI live capture mode.
// It marks TCP flows as SIP when complete messages are detected via TCP reassembly.
// This replaces the heuristic-based detection that caused false positives.
type TUISIPHandler struct{}

// NewTUISIPHandler creates a handler for TUI SIP detection
func NewTUISIPHandler() *TUISIPHandler {
	return &TUISIPHandler{}
}

// HandleSIPMessage processes a complete SIP message detected via TCP reassembly.
// It marks the flow as SIP so subsequent packets on this flow are displayed correctly.
// srcEndpoint and dstEndpoint are in "IP:port" format (e.g., "192.168.1.1:5060").
// netFlow is not used by TUI handler but required by the interface for other handlers.
func (h *TUISIPHandler) HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, _ gopacket.Flow) bool {
	if len(sipMessage) == 0 {
		return false
	}

	// Track whether this is a request or response, and extract method/status code
	isResponse := len(sipMessage) >= 7 && sipMessage[0] == 'S' && sipMessage[1] == 'I' && sipMessage[2] == 'P' && sipMessage[3] == '/'
	var method string
	var responseCode int
	if isResponse {
		atomic.AddInt64(&tcpSIPResponsesProcessed, 1)
		responseCode = extractResponseCodeFromSIP(sipMessage)
	} else {
		atomic.AddInt64(&tcpSIPRequestsProcessed, 1)
		method = extractMethodFromSIP(sipMessage)
	}

	// Increment SIP messages detected counter (diagnostic)
	incrementSIPMessagesDetected()

	// Extract IP and port from endpoints to use getTCPFlowKey
	// This ensures the same key format is used for marking and lookup
	srcIP := extractIPFromEndpoint(srcEndpoint)
	srcPort := extractPortFromEndpoint(srcEndpoint)
	dstIP := extractIPFromEndpoint(dstEndpoint)
	dstPort := extractPortFromEndpoint(dstEndpoint)

	// Use getTCPFlowKey which creates a symmetric, sorted key
	// This matches the format used in bridge.go for lookups
	flowKey := getTCPFlowKey(srcIP, dstIP, srcPort, dstPort)

	// Mark the flow as SIP (only need to mark once since key is symmetric)
	markTCPSIPFlow(flowKey)

	logger.Debug("TCP SIP message detected via reassembly",
		"call_id", voip.SanitizeCallIDForLogging(callID),
		"flow", srcEndpoint+"->"+dstEndpoint,
		"message_len", len(sipMessage),
		"is_response", isResponse,
		"method", method,
		"response_code", responseCode)

	// Feed the SIP message to LocalCallAggregator for call state tracking
	// This ensures TCP SIP responses update call state (e.g., 401 → Failed with error code)
	if callID != "" {
		if agg := GetLocalCallAggregator(); agg != nil {
			from, to := extractFromToFromSIP(sipMessage)
			pkt := &components.PacketDisplay{
				Timestamp: time.Now(), // TCP reassembly doesn't preserve original timestamp
				SrcIP:     srcIP,
				SrcPort:   srcPort,
				DstIP:     dstIP,
				DstPort:   dstPort,
				Protocol:  "SIP",
				VoIPData: &components.VoIPMetadata{
					CallID: callID,
					Method: method,
					Status: responseCode,
					From:   from,
					To:     to,
				},
			}
			agg.ProcessPacket(pkt)
		}
	}

	// Register with CallTracker if available (for RTP-to-CallID mapping)
	if callID != "" {
		if tracker := GetCallTracker(); tracker != nil {
			// Parse SIP message to extract media ports for RTP mapping
			// This is a lightweight parse - just looking for SDP m= lines
			mediaPorts := extractMediaPortsFromSIP(sipMessage)
			if len(mediaPorts) > 0 {
				// Track requests/responses with SDP
				if isResponse {
					atomic.AddInt64(&tcpSIPResponsesWithSDP, 1)
				} else {
					atomic.AddInt64(&tcpSIPRequestsWithSDP, 1)
				}

				// Extract the SDP c= line IP (connection address) - this is where RTP should go
				// In SBC/B2BUA environments, the signaling IP (srcIP) differs from media IP
				mediaIP := extractConnectionIPFromPayload(sipMessage)

				// Log TCP SIP with SDP
				msgType := "request"
				if isResponse {
					msgType = "response"
				}
				logger.Debug("TCP SIP with SDP ports",
					"call_id", voip.SanitizeCallIDForLogging(callID),
					"msg_type", msgType,
					"media_ip", mediaIP,
					"ports", mediaPorts,
					"src_ip", srcIP)

				// Register with BOTH IPs to handle different environments:
				// - SBC/B2BUA: media_ip is correct, srcIP is wrong
				// - Direct/simple: srcIP is correct, media_ip might be 0.0.0.0
				// Check for existing RTP-only calls and trigger merge if found
				var syntheticCallID string
				if mediaIP != "" && mediaIP != "0.0.0.0" {
					if sid := tracker.RegisterMediaPorts(callID, mediaIP, mediaPorts, isResponse); sid != "" && syntheticCallID == "" {
						syntheticCallID = sid
					}
				}
				if srcIP != "" && srcIP != mediaIP {
					if sid := tracker.RegisterMediaPorts(callID, srcIP, mediaPorts, isResponse); sid != "" && syntheticCallID == "" {
						syntheticCallID = sid
					}
				}

				// If we found an RTP-only call, trigger merge via LocalCallAggregator
				if syntheticCallID != "" {
					if agg := GetLocalCallAggregator(); agg != nil {
						agg.TriggerMerge(syntheticCallID, callID)
						atomic.AddInt64(&tcpSIPMergesTriggered, 1)
						logger.Debug("TCP SIP triggered RTP-only merge",
							"synthetic_call_id", syntheticCallID,
							"real_call_id", voip.SanitizeCallIDForLogging(callID))
					}
				}
			}

			// Extract and register From/To for call display
			from, to := extractFromToFromSIP(sipMessage)
			if from != "" || to != "" {
				tracker.RegisterCallPartyInfo(callID, from, to)
			}
		}
	}

	// Always return true - in TUI mode we display all SIP messages
	return true
}

// extractMediaPortsFromSIP does a lightweight parse of SIP message for m= lines
func extractMediaPortsFromSIP(msg []byte) []uint16 {
	var ports []uint16

	// Simple line-by-line scan for m= lines in SDP
	// Format: m=audio 49170 RTP/AVP 0
	lineStart := 0
	for i := 0; i <= len(msg); i++ {
		if i == len(msg) || msg[i] == '\n' {
			line := msg[lineStart:i]
			// Trim \r if present
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}

			// Check for m= line
			if len(line) > 2 && line[0] == 'm' && line[1] == '=' {
				port := parseMediaPort(line)
				if port > 0 {
					ports = append(ports, port)
				}
			}
			lineStart = i + 1
		}
	}

	return ports
}

// parseMediaPort extracts port number from SDP m= line
// Format: m=audio 49170 RTP/AVP 0
func parseMediaPort(line []byte) uint16 {
	// Skip "m=type "
	spaceIdx := -1
	for i := 2; i < len(line); i++ {
		if line[i] == ' ' {
			spaceIdx = i
			break
		}
	}
	if spaceIdx < 0 || spaceIdx >= len(line)-1 {
		return 0
	}

	// Parse port number
	port := uint16(0)
	for i := spaceIdx + 1; i < len(line); i++ {
		if line[i] >= '0' && line[i] <= '9' {
			port = port*10 + uint16(line[i]-'0')
		} else {
			break
		}
	}

	return port
}

// extractFromToFromSIP does a lightweight parse for From/To headers
func extractFromToFromSIP(msg []byte) (from, to string) {
	lineStart := 0
	inHeaders := true

	for i := 0; i <= len(msg) && inHeaders; i++ {
		if i == len(msg) || msg[i] == '\n' {
			line := msg[lineStart:i]
			// Trim \r if present
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}

			// Empty line = end of headers
			if len(line) == 0 {
				break
			}

			// Check for From/To headers
			if len(line) > 5 {
				if (line[0] == 'F' || line[0] == 'f') && (line[1] == 'r' || line[1] == 'R') &&
					(line[2] == 'o' || line[2] == 'O') && (line[3] == 'm' || line[3] == 'M') && line[4] == ':' {
					from = extractSIPURI(line[5:])
				} else if (line[0] == 'T' || line[0] == 't') && (line[1] == 'o' || line[1] == 'O') && line[2] == ':' {
					to = extractSIPURI(line[3:])
				}
			}

			// Compact form: f: and t:
			if len(line) > 2 {
				if (line[0] == 'f' || line[0] == 'F') && line[1] == ':' {
					from = extractSIPURI(line[2:])
				} else if (line[0] == 't' || line[0] == 'T') && line[1] == ':' {
					to = extractSIPURI(line[2:])
				}
			}

			lineStart = i + 1
		}
	}

	return from, to
}

// extractSIPURI extracts the URI from a From/To header value
// Example: "Alice" <sip:alice@example.com>;tag=123 -> sip:alice@example.com
func extractSIPURI(value []byte) string {
	// Skip leading whitespace
	start := 0
	for start < len(value) && (value[start] == ' ' || value[start] == '\t') {
		start++
	}
	value = value[start:]

	// Look for <uri>
	ltIdx := -1
	gtIdx := -1
	for i, b := range value {
		if b == '<' {
			ltIdx = i
		} else if b == '>' && ltIdx >= 0 {
			gtIdx = i
			break
		}
	}

	if ltIdx >= 0 && gtIdx > ltIdx {
		return string(value[ltIdx+1 : gtIdx])
	}

	// No angle brackets, take until semicolon or end
	for i, b := range value {
		if b == ';' || b == ',' {
			return string(value[:i])
		}
	}

	return string(value)
}

// extractResponseCodeFromSIP extracts the status code from SIP response
// Format: "SIP/2.0 <code> <reason>"
func extractResponseCodeFromSIP(msg []byte) int {
	// Must start with "SIP/"
	if len(msg) < 12 || msg[0] != 'S' || msg[1] != 'I' || msg[2] != 'P' || msg[3] != '/' {
		return 0
	}

	// Find first space after "SIP/2.0"
	spaceIdx := -1
	for i := 4; i < len(msg) && i < 20; i++ {
		if msg[i] == ' ' {
			spaceIdx = i
			break
		}
	}
	if spaceIdx < 0 || spaceIdx >= len(msg)-1 {
		return 0
	}

	// Parse 3-digit status code
	code := 0
	for i := spaceIdx + 1; i < len(msg) && i < spaceIdx+4; i++ {
		if msg[i] >= '0' && msg[i] <= '9' {
			code = code*10 + int(msg[i]-'0')
		} else {
			break
		}
	}

	return code
}

// extractMethodFromSIP extracts the method from SIP request
// Format: "<METHOD> sip:... SIP/2.0"
func extractMethodFromSIP(msg []byte) string {
	// Find first space
	spaceIdx := -1
	for i := 0; i < len(msg) && i < 20; i++ {
		if msg[i] == ' ' {
			spaceIdx = i
			break
		}
	}
	if spaceIdx <= 0 {
		return ""
	}

	return string(msg[:spaceIdx])
}

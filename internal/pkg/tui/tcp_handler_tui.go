//go:build tui || all

package tui

import (
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
)

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
func (h *TUISIPHandler) HandleSIPMessage(sipMessage []byte, callID string, flow gopacket.Flow) bool {
	if len(sipMessage) == 0 {
		return false
	}

	// Extract flow endpoints for cache key
	// flow.Src() and flow.Dst() give us the TCP endpoints
	srcEndpoint := flow.Src().String()
	dstEndpoint := flow.Dst().String()

	// Create flow key (same format as getTCPFlowKey but from gopacket.Flow)
	// We need to mark both directions
	flowKey := srcEndpoint + "->" + dstEndpoint
	reverseFlowKey := dstEndpoint + "->" + srcEndpoint

	// Mark both directions as SIP flows
	markTCPSIPFlow(flowKey)
	markTCPSIPFlow(reverseFlowKey)

	logger.Debug("TCP SIP message detected via reassembly",
		"call_id", voip.SanitizeCallIDForLogging(callID),
		"flow", flow.String(),
		"message_len", len(sipMessage))

	// Register with CallTracker if available (for RTP-to-CallID mapping)
	if callID != "" {
		if tracker := GetCallTracker(); tracker != nil {
			// Parse SIP message to extract media ports for RTP mapping
			// This is a lightweight parse - just looking for SDP m= lines
			mediaPorts := extractMediaPortsFromSIP(sipMessage)
			if len(mediaPorts) > 0 {
				// Use source IP from flow as the RTP endpoint
				// In SIP, the media ports advertised are typically for the sender
				srcIP := extractIPFromEndpoint(srcEndpoint)
				if srcIP != "" {
					tracker.RegisterMediaPorts(callID, srcIP, mediaPorts)
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

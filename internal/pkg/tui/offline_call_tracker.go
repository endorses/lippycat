//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// OfflineCallTracker tracks RTP-to-CallID mappings for offline PCAP analysis
// It parses SDP from SIP packets to extract RTP connection information
type OfflineCallTracker struct {
	// Map: (srcIP:srcPort -> dstIP:dstPort) -> CallID
	rtpFlowToCallID map[string]string
	// Map: CallID -> list of RTP flows
	callIDToFlows map[string][]string
	mu            sync.RWMutex
}

// NewOfflineCallTracker creates a new offline call tracker
func NewOfflineCallTracker() *OfflineCallTracker {
	return &OfflineCallTracker{
		rtpFlowToCallID: make(map[string]string),
		callIDToFlows:   make(map[string][]string),
	}
}

// ProcessSIPPacket processes a SIP packet to extract RTP connection info from SDP
func (t *OfflineCallTracker) ProcessSIPPacket(callID, srcIP, dstIP, payload string) {
	if callID == "" {
		return
	}

	// Extract SDP body from SIP message
	sdpBody := extractSDPBody(payload)
	if sdpBody == "" {
		return
	}

	// Parse RTP ports and connection info from SDP
	rtpPorts := extractRTPPortsFromSDP(sdpBody)
	connectionIP := extractConnectionIPFromSDP(sdpBody)

	if len(rtpPorts) == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// For each RTP port, create bidirectional flow mappings
	for _, port := range rtpPorts {
		// Determine which IP is sending RTP (typically the one that sent the SDP)
		// This is usually in the 200 OK response (dstIP) or INVITE (srcIP)
		// We'll create mappings for both directions to handle different scenarios

		var rtpSourceIP string
		if connectionIP != "" && connectionIP != "0.0.0.0" {
			// Use the connection IP from SDP if available
			rtpSourceIP = connectionIP
		} else {
			// Fall back to the source IP of the SIP packet
			rtpSourceIP = srcIP
		}

		// Create flow keys for both directions
		// Direction 1: RTP source -> original destination
		flowKey1 := fmt.Sprintf("%s:%s->%s:any", rtpSourceIP, port, dstIP)
		// Direction 2: Original destination -> RTP source (for bidirectional flows)
		flowKey2 := fmt.Sprintf("%s:any->%s:%s", dstIP, rtpSourceIP, port)

		// Also handle the reverse scenario where dstIP is the RTP source
		flowKey3 := fmt.Sprintf("%s:%s->%s:any", dstIP, port, srcIP)
		flowKey4 := fmt.Sprintf("%s:any->%s:%s", srcIP, dstIP, port)

		t.rtpFlowToCallID[flowKey1] = callID
		t.rtpFlowToCallID[flowKey2] = callID
		t.rtpFlowToCallID[flowKey3] = callID
		t.rtpFlowToCallID[flowKey4] = callID

		// Track flows for this call
		t.callIDToFlows[callID] = append(t.callIDToFlows[callID], flowKey1, flowKey2, flowKey3, flowKey4)

		logger.Debug("Registered RTP flow for offline tracking",
			"call_id", callID,
			"rtp_port", port,
			"connection_ip", rtpSourceIP,
			"flow_keys", []string{flowKey1, flowKey2, flowKey3, flowKey4})
	}
}

// GetCallIDForRTPPacket returns the CallID for an RTP packet based on IP/port
func (t *OfflineCallTracker) GetCallIDForRTPPacket(srcIP, srcPort, dstIP, dstPort string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Try exact port match first
	flowKey1 := fmt.Sprintf("%s:%s->%s:%s", srcIP, srcPort, dstIP, dstPort)
	if callID, ok := t.rtpFlowToCallID[flowKey1]; ok {
		return callID
	}

	// Try source IP:port -> destination IP (wildcard dest port)
	flowKey2 := fmt.Sprintf("%s:%s->%s:any", srcIP, srcPort, dstIP)
	if callID, ok := t.rtpFlowToCallID[flowKey2]; ok {
		return callID
	}

	// Try destination IP -> source IP:port (wildcard source port)
	flowKey3 := fmt.Sprintf("%s:any->%s:%s", dstIP, srcIP, srcPort)
	if callID, ok := t.rtpFlowToCallID[flowKey3]; ok {
		return callID
	}

	// Try reverse direction
	flowKey4 := fmt.Sprintf("%s:%s->%s:any", dstIP, dstPort, srcIP)
	if callID, ok := t.rtpFlowToCallID[flowKey4]; ok {
		return callID
	}

	flowKey5 := fmt.Sprintf("%s:any->%s:%s", srcIP, dstIP, dstPort)
	if callID, ok := t.rtpFlowToCallID[flowKey5]; ok {
		return callID
	}

	return ""
}

// Clear removes all tracked mappings
func (t *OfflineCallTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.rtpFlowToCallID = make(map[string]string)
	t.callIDToFlows = make(map[string][]string)
}

// extractSDPBody extracts the SDP body from a SIP message
func extractSDPBody(payload string) string {
	lines := strings.Split(payload, "\n")

	// Find the empty line that separates headers from body
	bodyStart := false
	var bodyBuilder strings.Builder

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if bodyStart {
			// We're in the body section
			bodyBuilder.WriteString(line)
			bodyBuilder.WriteString("\n")
		} else if trimmed == "" {
			// Empty line marks the start of body
			bodyStart = true
		}
	}

	body := bodyBuilder.String()

	// Verify it's actually SDP (should start with v=)
	if strings.HasPrefix(strings.TrimSpace(body), "v=") {
		return body
	}

	return ""
}

// extractRTPPortsFromSDP extracts RTP ports from SDP body
func extractRTPPortsFromSDP(sdp string) []string {
	ports := make([]string, 0, 2)

	// Look for m=audio lines
	// Format: m=audio <port> RTP/AVP <payload_types>
	lines := strings.Split(sdp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for m=audio
		if strings.HasPrefix(line, "m=audio ") {
			// Extract port (second field)
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				port := fields[1]
				// Validate port
				if isValidPort(port) {
					ports = append(ports, port)
				}
			}
		}
	}

	return ports
}

// extractConnectionIPFromSDP extracts the connection IP from SDP c= line
func extractConnectionIPFromSDP(sdp string) string {
	// Look for c= line
	// Format: c=IN IP4 <ip_address>
	lines := strings.Split(sdp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "c=") {
			// Parse: c=IN IP4 10.0.0.1
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2]
			}
		}
	}

	return ""
}

// isValidPort validates that a string represents a valid UDP/TCP port number
func isValidPort(portStr string) bool {
	if portStr == "" {
		return false
	}

	// Check if it's a number
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

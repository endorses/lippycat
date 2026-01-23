//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"sync"
)

// CallPartyInfo stores From/To information for a call
type CallPartyInfo struct {
	From string
	To   string
}

// OfflineCallTracker tracks RTP-to-CallID mappings for offline PCAP analysis
// It parses SDP from SIP packets to extract RTP connection information
type OfflineCallTracker struct {
	// Map: IP:port -> CallID (simplified: just store media endpoint)
	rtpEndpointToCallID map[string]string
	// Map: CallID -> list of endpoints
	callIDToEndpoints map[string][]string
	// Map: CallID -> From/To party info
	callPartyInfo map[string]*CallPartyInfo
	mu            sync.RWMutex
}

// NewOfflineCallTracker creates a new offline call tracker
func NewOfflineCallTracker() *OfflineCallTracker {
	return &OfflineCallTracker{
		rtpEndpointToCallID: make(map[string]string),
		callIDToEndpoints:   make(map[string][]string),
		callPartyInfo:       make(map[string]*CallPartyInfo),
	}
}

// RegisterMediaPorts registers RTP media ports from SIP detector metadata
// This is the preferred method as it uses already-parsed SDP data from the detector
func (t *OfflineCallTracker) RegisterMediaPorts(callID, rtpIP string, ports []uint16) {
	if callID == "" || len(ports) == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, port := range ports {
		endpoint := fmt.Sprintf("%s:%d", rtpIP, port)
		t.rtpEndpointToCallID[endpoint] = callID
		t.callIDToEndpoints[callID] = append(t.callIDToEndpoints[callID], endpoint)
	}
}

// RegisterCallPartyInfo stores From/To information for a call
func (t *OfflineCallTracker) RegisterCallPartyInfo(callID, from, to string) {
	if callID == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Only store if we don't have info yet, or update if new info is better
	existing := t.callPartyInfo[callID]
	if existing == nil {
		t.callPartyInfo[callID] = &CallPartyInfo{From: from, To: to}
	} else {
		// Update if existing values are empty
		if existing.From == "" && from != "" {
			existing.From = from
		}
		if existing.To == "" && to != "" {
			existing.To = to
		}
	}
}

// GetCallPartyInfo returns the From/To information for a call
func (t *OfflineCallTracker) GetCallPartyInfo(callID string) (from, to string) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if info := t.callPartyInfo[callID]; info != nil {
		return info.From, info.To
	}
	return "", ""
}

// ProcessSIPPacket processes a SIP packet to extract RTP connection info from SDP
// Deprecated: Use RegisterMediaPorts with detector metadata instead
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

	// Determine the RTP endpoint IP from SDP
	// The c= line in SDP specifies where RTP should be sent
	var rtpIP string
	if connectionIP != "" && connectionIP != "0.0.0.0" {
		rtpIP = connectionIP
	} else {
		// Fall back to the source IP of the SIP packet
		rtpIP = srcIP
	}

	// Register each port as an RTP endpoint for this call
	// Simple mapping: IP:port -> CallID
	// This works because RTP packets will have either src or dst matching this endpoint
	for _, port := range rtpPorts {
		endpoint := fmt.Sprintf("%s:%s", rtpIP, port)

		t.rtpEndpointToCallID[endpoint] = callID
		t.callIDToEndpoints[callID] = append(t.callIDToEndpoints[callID], endpoint)
	}
}

// GetCallIDForRTPPacket returns the CallID for an RTP packet based on IP/port
func (t *OfflineCallTracker) GetCallIDForRTPPacket(srcIP, srcPort, dstIP, dstPort string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// SDP ports are RECEIVE ports - RTP sent TO this port
	// So we primarily match on DESTINATION of RTP packets

	// Check if destination endpoint matches exactly (this is the most reliable)
	dstEndpoint := fmt.Sprintf("%s:%s", dstIP, dstPort)
	if callID, ok := t.rtpEndpointToCallID[dstEndpoint]; ok {
		return callID
	}

	// Check if source endpoint matches (less common - would mean we captured the receive side)
	srcEndpoint := fmt.Sprintf("%s:%s", srcIP, srcPort)
	if callID, ok := t.rtpEndpointToCallID[srcEndpoint]; ok {
		return callID
	}

	// Fallback: match by source IP only (RTP sender = SDP sender)
	// Only use this if there's exactly ONE call from this IP to avoid ambiguity
	var matchedCallID string
	matchCount := 0
	for endpoint, callID := range t.rtpEndpointToCallID {
		if idx := strings.LastIndex(endpoint, ":"); idx > 0 {
			registeredIP := endpoint[:idx]
			if registeredIP == srcIP {
				if matchedCallID == "" || matchedCallID == callID {
					matchedCallID = callID
					matchCount++
				} else {
					// Multiple different calls from same IP - can't disambiguate
					matchCount++
				}
			}
		}
	}

	// Only return if we found exactly one unique call from this IP
	if matchCount > 0 && matchedCallID != "" {
		// Check if all matches point to the same call
		uniqueCall := true
		for endpoint, callID := range t.rtpEndpointToCallID {
			if idx := strings.LastIndex(endpoint, ":"); idx > 0 {
				registeredIP := endpoint[:idx]
				if registeredIP == srcIP && callID != matchedCallID {
					uniqueCall = false
					break
				}
			}
		}
		if uniqueCall {
			return matchedCallID
		}
	}

	return ""
}

// Clear removes all tracked mappings
func (t *OfflineCallTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.rtpEndpointToCallID = make(map[string]string)
	t.callIDToEndpoints = make(map[string][]string)
	t.callPartyInfo = make(map[string]*CallPartyInfo)
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

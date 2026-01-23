//go:build tui || all

package tui

import (
	"container/list"
	"fmt"
	"strings"
	"sync"
)

// DefaultMaxTrackedCalls is the default maximum number of calls to track
const DefaultMaxTrackedCalls = 5000

// CallPartyInfo stores From/To information for a call
type CallPartyInfo struct {
	From string
	To   string
}

// CallTracker tracks RTP-to-CallID mappings for TUI capture modes (live and offline)
// It parses SDP from SIP packets to extract RTP connection information.
// Uses LRU eviction to prevent unbounded memory growth.
type CallTracker struct {
	// Map: IP:port -> CallID (simplified: just store media endpoint)
	rtpEndpointToCallID map[string]string
	// Map: CallID -> list of endpoints
	callIDToEndpoints map[string][]string
	// Map: CallID -> From/To party info
	callPartyInfo map[string]*CallPartyInfo
	// LRU tracking by CallID
	lruList  *list.List               // LRU list (front = most recently used)
	lruIndex map[string]*list.Element // callID -> list element for O(1) lookup
	maxCalls int                      // Maximum calls to keep
	mu       sync.RWMutex
}

// NewCallTracker creates a new call tracker for RTP-to-CallID mapping
func NewCallTracker() *CallTracker {
	return NewCallTrackerWithCapacity(DefaultMaxTrackedCalls)
}

// NewCallTrackerWithCapacity creates a new call tracker with specified capacity
func NewCallTrackerWithCapacity(maxCalls int) *CallTracker {
	if maxCalls <= 0 {
		maxCalls = DefaultMaxTrackedCalls
	}
	return &CallTracker{
		rtpEndpointToCallID: make(map[string]string),
		callIDToEndpoints:   make(map[string][]string),
		callPartyInfo:       make(map[string]*CallPartyInfo),
		lruList:             list.New(),
		lruIndex:            make(map[string]*list.Element),
		maxCalls:            maxCalls,
	}
}

// touchCallLocked moves a call to the front of the LRU list (most recently used).
// If the call doesn't exist in the LRU, it adds it.
// Must be called with mu held.
func (t *CallTracker) touchCallLocked(callID string) {
	if elem, ok := t.lruIndex[callID]; ok {
		// Move existing call to front
		t.lruList.MoveToFront(elem)
	} else {
		// Evict LRU (least recently used) if at capacity
		if t.lruList.Len() >= t.maxCalls {
			oldest := t.lruList.Back()
			if oldest != nil {
				oldestCallID := oldest.Value.(string)
				t.evictCallLocked(oldestCallID)
				t.lruList.Remove(oldest)
				delete(t.lruIndex, oldestCallID)
			}
		}
		// Add new call to front
		elem := t.lruList.PushFront(callID)
		t.lruIndex[callID] = elem
	}
}

// evictCallLocked removes all data associated with a call.
// Must be called with mu held.
func (t *CallTracker) evictCallLocked(callID string) {
	// Remove all endpoints for this call
	endpoints := t.callIDToEndpoints[callID]
	for _, endpoint := range endpoints {
		delete(t.rtpEndpointToCallID, endpoint)
	}
	delete(t.callIDToEndpoints, callID)
	delete(t.callPartyInfo, callID)
}

// RegisterMediaPorts registers RTP media ports from SIP detector metadata.
// This is the preferred method as it uses already-parsed SDP data from the detector.
// Returns a synthetic CallID (rtp-*) if the endpoint was previously registered for an
// RTP-only call, allowing the caller to merge the calls.
func (t *CallTracker) RegisterMediaPorts(callID, rtpIP string, ports []uint16) (syntheticCallID string) {
	if callID == "" || len(ports) == 0 {
		return ""
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Check if any endpoint already has a synthetic (RTP-only) CallID
	for _, port := range ports {
		endpoint := fmt.Sprintf("%s:%d", rtpIP, port)
		if existingCallID, ok := t.rtpEndpointToCallID[endpoint]; ok {
			if strings.HasPrefix(existingCallID, "rtp-") && syntheticCallID == "" {
				syntheticCallID = existingCallID
			}
		}
	}

	// If we found a synthetic call, clean up its endpoint mappings
	// (they will be re-registered under the real CallID)
	if syntheticCallID != "" {
		t.evictCallLocked(syntheticCallID)
		// Also remove from LRU
		if elem, ok := t.lruIndex[syntheticCallID]; ok {
			t.lruList.Remove(elem)
			delete(t.lruIndex, syntheticCallID)
		}
	}

	// Touch the call in LRU (adds if new, evicts oldest if at capacity)
	t.touchCallLocked(callID)

	// Register endpoints for the real CallID
	for _, port := range ports {
		endpoint := fmt.Sprintf("%s:%d", rtpIP, port)
		t.rtpEndpointToCallID[endpoint] = callID
		t.callIDToEndpoints[callID] = append(t.callIDToEndpoints[callID], endpoint)
	}

	return syntheticCallID
}

// RegisterRTPOnlyEndpoints registers RTP endpoints for an RTP-only (synthetic) call.
// This allows the endpoint to be matched when SIP arrives later.
func (t *CallTracker) RegisterRTPOnlyEndpoints(syntheticCallID, srcIP, srcPort, dstIP, dstPort string) {
	if syntheticCallID == "" || !strings.HasPrefix(syntheticCallID, "rtp-") {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Touch the call in LRU
	t.touchCallLocked(syntheticCallID)

	// Register both source and destination endpoints
	// SDP typically specifies the destination port (where to send RTP)
	srcEndpoint := fmt.Sprintf("%s:%s", srcIP, srcPort)
	dstEndpoint := fmt.Sprintf("%s:%s", dstIP, dstPort)

	t.rtpEndpointToCallID[srcEndpoint] = syntheticCallID
	t.rtpEndpointToCallID[dstEndpoint] = syntheticCallID
	t.callIDToEndpoints[syntheticCallID] = append(t.callIDToEndpoints[syntheticCallID], srcEndpoint, dstEndpoint)
}

// RegisterCallPartyInfo stores From/To information for a call
func (t *CallTracker) RegisterCallPartyInfo(callID, from, to string) {
	if callID == "" {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Touch the call in LRU (adds if new, evicts oldest if at capacity)
	t.touchCallLocked(callID)

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
func (t *CallTracker) GetCallPartyInfo(callID string) (from, to string) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if info := t.callPartyInfo[callID]; info != nil {
		return info.From, info.To
	}
	return "", ""
}

// ProcessSIPPacket processes a SIP packet to extract RTP connection info from SDP
// Deprecated: Use RegisterMediaPorts with detector metadata instead
func (t *CallTracker) ProcessSIPPacket(callID, srcIP, dstIP, payload string) {
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

	// Touch the call in LRU (adds if new, evicts oldest if at capacity)
	t.touchCallLocked(callID)

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
func (t *CallTracker) GetCallIDForRTPPacket(srcIP, srcPort, dstIP, dstPort string) string {
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

// GetTrackedCallCount returns the number of tracked calls
func (t *CallTracker) GetTrackedCallCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lruList.Len()
}

// Clear removes all tracked mappings
func (t *CallTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.rtpEndpointToCallID = make(map[string]string)
	t.callIDToEndpoints = make(map[string][]string)
	t.callPartyInfo = make(map[string]*CallPartyInfo)
	t.lruList = list.New()
	t.lruIndex = make(map[string]*list.Element)
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

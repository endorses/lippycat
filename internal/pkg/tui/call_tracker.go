//go:build tui || all

package tui

import (
	"container/list"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
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
//
// Correlation strategy: Pure IP:port hash lookup
//  1. Try destination IP:port (RTP sent TO registered endpoint)
//  2. Try source IP:port (RTP sent FROM registered endpoint)
//
// No fallbacks - exact IP:port match only.
type CallTracker struct {
	// Map: IP:port -> CallID
	rtpEndpointToCallID map[string]string
	// Map: CallID -> list of endpoints (for cleanup on eviction)
	callIDToEndpoints map[string][]string
	// Map: CallID -> From/To party info
	callPartyInfo map[string]*CallPartyInfo
	// LRU tracking by CallID
	lruList  *list.List               // LRU list (front = most recently used)
	lruIndex map[string]*list.Element // callID -> list element for O(1) lookup
	maxCalls int                      // Maximum calls to keep
	mu       sync.RWMutex
	// Throttled LRU touch for RTP lookups (avoid lock contention at high packet rates)
	lastRTPTouch sync.Map // map[string]int64 (callID -> unix nano timestamp)
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
	// Remove endpoints for this call, but ONLY if they still point to this call.
	// This prevents deleting endpoints that were reassigned to a different call.
	endpoints := t.callIDToEndpoints[callID]
	for _, endpoint := range endpoints {
		if mappedCallID, ok := t.rtpEndpointToCallID[endpoint]; ok && mappedCallID == callID {
			delete(t.rtpEndpointToCallID, endpoint)
		}
	}
	delete(t.callIDToEndpoints, callID)
	delete(t.callPartyInfo, callID)
}

// extractIPFromEndpoint extracts the IP from an "IP:port" endpoint string.
func extractIPFromEndpoint(endpoint string) string {
	if idx := strings.LastIndex(endpoint, ":"); idx > 0 {
		return endpoint[:idx]
	}
	return ""
}

// extractPortFromEndpoint extracts the port from an "IP:port" endpoint string.
func extractPortFromEndpoint(endpoint string) string {
	if idx := strings.LastIndex(endpoint, ":"); idx > 0 && idx < len(endpoint)-1 {
		return endpoint[idx+1:]
	}
	return ""
}

// RegisterMediaPorts registers RTP media ports from SIP detector metadata.
// This is the preferred method as it uses already-parsed SDP data from the detector.
// The isResponse parameter indicates whether this SDP came from a response (200 OK)
// or a request (INVITE) - this is used to track caller vs callee for IP-pair correlation.
// Returns a synthetic CallID (rtp-*) if the endpoint was previously registered for an
// RTP-only call, allowing the caller to merge the calls.
func (t *CallTracker) RegisterMediaPorts(callID, rtpIP string, ports []uint16, isResponse bool) (syntheticCallID string) {
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

	// If we found a synthetic call, TRANSFER its endpoints to the real call
	// (instead of just evicting, which loses the other party's endpoint)
	var syntheticEndpoints []string
	if syntheticCallID != "" {
		// Copy the synthetic call's endpoints before evicting
		syntheticEndpoints = append(syntheticEndpoints, t.callIDToEndpoints[syntheticCallID]...)

		// Now evict the synthetic call
		t.evictCallLocked(syntheticCallID)
		// Also remove from LRU
		if elem, ok := t.lruIndex[syntheticCallID]; ok {
			t.lruList.Remove(elem)
			delete(t.lruIndex, syntheticCallID)
		}
	}

	// Touch the call in LRU (adds if new, evicts oldest if at capacity)
	t.touchCallLocked(callID)

	// Helper to register an endpoint for the real CallID
	registerEndpoint := func(endpoint, source string) {
		t.rtpEndpointToCallID[endpoint] = callID

		// Only add to callIDToEndpoints if not already present (deduplicate)
		alreadyRegistered := false
		for _, existing := range t.callIDToEndpoints[callID] {
			if existing == endpoint {
				alreadyRegistered = true
				break
			}
		}
		if !alreadyRegistered {
			t.callIDToEndpoints[callID] = append(t.callIDToEndpoints[callID], endpoint)
			// Add to diagnostic buffer
			addDiagEvent("REG", callID, endpoint, source)
			logger.Debug("CallTracker registered endpoint",
				"call_id", callID,
				"endpoint", endpoint,
				"source", source,
				"total_endpoints_for_call", len(t.callIDToEndpoints[callID]))
		}
	}

	// First, transfer all endpoints from the synthetic call (includes BOTH parties' RTP ports)
	for _, endpoint := range syntheticEndpoints {
		registerEndpoint(endpoint, "merge")
	}

	// Then register the new SDP endpoints
	reqResp := "req"
	if isResponse {
		reqResp = "rsp"
	}
	for _, port := range ports {
		endpoint := fmt.Sprintf("%s:%d", rtpIP, port)
		registerEndpoint(endpoint, reqResp)
	}

	return syntheticCallID
}

// RegisterRTPOnlyEndpoints registers RTP endpoints for an RTP-only (synthetic) call.
// This allows the endpoint to be matched when SIP arrives later.
// Also stores party info (IP:port pairs as From/To) for display purposes.
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

	// Only register endpoints if they don't already belong to a real SIP call.
	// This prevents synthetic RTP-only calls from stealing endpoints from properly
	// correlated SIP calls.
	srcRegistered := false
	dstRegistered := false

	if existingSrc, ok := t.rtpEndpointToCallID[srcEndpoint]; ok && !strings.HasPrefix(existingSrc, "rtp-") {
		logger.Debug("RegisterRTPOnlyEndpoints: skipping src endpoint (belongs to SIP call)",
			"endpoint", srcEndpoint,
			"existing_call", existingSrc,
			"synthetic_call", syntheticCallID)
	} else {
		t.rtpEndpointToCallID[srcEndpoint] = syntheticCallID
		srcRegistered = true
	}

	if existingDst, ok := t.rtpEndpointToCallID[dstEndpoint]; ok && !strings.HasPrefix(existingDst, "rtp-") {
		logger.Debug("RegisterRTPOnlyEndpoints: skipping dst endpoint (belongs to SIP call)",
			"endpoint", dstEndpoint,
			"existing_call", existingDst,
			"synthetic_call", syntheticCallID)
	} else {
		t.rtpEndpointToCallID[dstEndpoint] = syntheticCallID
		dstRegistered = true
	}

	// Only add to callIDToEndpoints if we actually registered something
	// and the endpoint is not already in the list (deduplicate)
	if srcRegistered {
		alreadyHasSrc := false
		for _, ep := range t.callIDToEndpoints[syntheticCallID] {
			if ep == srcEndpoint {
				alreadyHasSrc = true
				break
			}
		}
		if !alreadyHasSrc {
			t.callIDToEndpoints[syntheticCallID] = append(t.callIDToEndpoints[syntheticCallID], srcEndpoint)
		}
	}
	if dstRegistered {
		alreadyHasDst := false
		for _, ep := range t.callIDToEndpoints[syntheticCallID] {
			if ep == dstEndpoint {
				alreadyHasDst = true
				break
			}
		}
		if !alreadyHasDst {
			t.callIDToEndpoints[syntheticCallID] = append(t.callIDToEndpoints[syntheticCallID], dstEndpoint)
		}
	}

	// Store party info for RTP-only calls (used as fallback in convertToTUICall)
	// Use IP:port as From/To since we don't have SIP headers
	if t.callPartyInfo[syntheticCallID] == nil {
		t.callPartyInfo[syntheticCallID] = &CallPartyInfo{
			From: srcEndpoint,
			To:   dstEndpoint,
		}
	}
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

		// Only add to callIDToEndpoints if not already present (deduplicate)
		alreadyRegistered := false
		for _, existing := range t.callIDToEndpoints[callID] {
			if existing == endpoint {
				alreadyRegistered = true
				break
			}
		}
		if !alreadyRegistered {
			t.callIDToEndpoints[callID] = append(t.callIDToEndpoints[callID], endpoint)
		}
	}
}

// RTP lookup counters for diagnostics
var (
	rtpLookupAttempts int64
	rtpLookupDstMatch int64
	rtpLookupSrcMatch int64
	rtpLookupFailed   int64
)

// DiagEvent represents a diagnostic event for debugging RTP-SIP correlation
type DiagEvent struct {
	Type      string // "REG" for registration, "MISS" for RTP miss
	Timestamp int64  // Unix nano
	CallID    string
	Endpoint  string // IP:port
	Extra     string // Additional info (e.g., "src" or "dst" for misses)
}

// Diagnostic ring buffer for recent events
var (
	diagEvents    [20]DiagEvent // Last 20 events
	diagEventsIdx int
	diagEventsMu  sync.Mutex
)

// addDiagEvent adds a diagnostic event to the ring buffer
func addDiagEvent(eventType, callID, endpoint, extra string) {
	diagEventsMu.Lock()
	defer diagEventsMu.Unlock()
	diagEvents[diagEventsIdx] = DiagEvent{
		Type:      eventType,
		Timestamp: time.Now().UnixNano(),
		CallID:    callID,
		Endpoint:  endpoint,
		Extra:     extra,
	}
	diagEventsIdx = (diagEventsIdx + 1) % len(diagEvents)
}

// GetRecentDiagEvents returns recent diagnostic events (newest first)
func GetRecentDiagEvents() []DiagEvent {
	diagEventsMu.Lock()
	defer diagEventsMu.Unlock()

	result := make([]DiagEvent, 0, len(diagEvents))
	for i := 0; i < len(diagEvents); i++ {
		idx := (diagEventsIdx - 1 - i + len(diagEvents)) % len(diagEvents)
		if diagEvents[idx].Type != "" {
			result = append(result, diagEvents[idx])
		}
	}
	return result
}

// GetRTPLookupStats returns RTP lookup statistics
// Returns: attempts, dstMatch, srcMatch, failed
func GetRTPLookupStats() (attempts, dstMatch, srcMatch, failed int64) {
	return atomic.LoadInt64(&rtpLookupAttempts),
		atomic.LoadInt64(&rtpLookupDstMatch),
		atomic.LoadInt64(&rtpLookupSrcMatch),
		atomic.LoadInt64(&rtpLookupFailed)
}

// rtpLRUTouchInterval is the minimum interval between LRU touches for RTP lookups.
// This throttles write lock acquisitions to avoid contention at high packet rates.
const rtpLRUTouchInterval = time.Second

// GetCallIDForRTPPacket returns the CallID for an RTP packet based on IP/port.
// Uses pure IP:port hash lookup:
//  1. Try destination IP:port (RTP sent TO registered endpoint)
//  2. Try source IP:port (RTP sent FROM registered endpoint)
//
// No fallbacks - exact IP:port match only.
// On successful match, touches the LRU (throttled to once per second per call)
// to prevent eviction of calls with active RTP.
func (t *CallTracker) GetCallIDForRTPPacket(srcIP, srcPort, dstIP, dstPort string) string {
	atomic.AddInt64(&rtpLookupAttempts, 1)

	dstEndpoint := fmt.Sprintf("%s:%s", dstIP, dstPort)
	srcEndpoint := fmt.Sprintf("%s:%s", srcIP, srcPort)

	// Read-lock for lookup
	t.mu.RLock()
	callID, found := t.rtpEndpointToCallID[dstEndpoint]
	if found {
		atomic.AddInt64(&rtpLookupDstMatch, 1)
	} else if callID, found = t.rtpEndpointToCallID[srcEndpoint]; found {
		atomic.AddInt64(&rtpLookupSrcMatch, 1)
	}
	mapSizes := [2]int{len(t.rtpEndpointToCallID), len(t.callIDToEndpoints)}
	t.mu.RUnlock()

	if found {
		// Throttled LRU touch - at most once per second per call to avoid lock contention
		now := time.Now().UnixNano()
		if last, ok := t.lastRTPTouch.Load(callID); !ok || now-last.(int64) > int64(rtpLRUTouchInterval) {
			t.mu.Lock()
			if elem, ok := t.lruIndex[callID]; ok {
				t.lruList.MoveToFront(elem)
			}
			t.mu.Unlock()
			t.lastRTPTouch.Store(callID, now)
		}
		return callID
	}

	atomic.AddInt64(&rtpLookupFailed, 1)
	// Log lookup failures with map state for debugging
	logger.Debug("GetCallIDForRTPPacket: lookup failed",
		"src_endpoint", srcEndpoint,
		"dst_endpoint", dstEndpoint,
		"rtpEndpointToCallID_size", mapSizes[0],
		"callIDToEndpoints_size", mapSizes[1])
	// Record miss in diagnostic buffer (only every 100th miss to avoid spam)
	if atomic.LoadInt64(&rtpLookupFailed)%100 == 1 {
		addDiagEvent("MISS", "", srcEndpoint, dstEndpoint)
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

// GetEndpointsForCall returns the registered RTP endpoints (IP:port) for a call.
// This is useful for debugging SIP-to-RTP correlation issues.
// Touching the LRU keeps actively-displayed calls from being evicted.
func (t *CallTracker) GetEndpointsForCall(callID string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	endpoints := t.callIDToEndpoints[callID]
	if len(endpoints) == 0 {
		return nil
	}

	// Touch the LRU to keep this call from being evicted while it's being displayed.
	// Only touch if the call already exists in the LRU (don't add phantom entries).
	if _, ok := t.lruIndex[callID]; ok {
		t.lruList.MoveToFront(t.lruIndex[callID])
	}

	// Return a copy to avoid races
	result := make([]string, len(endpoints))
	copy(result, endpoints)
	return result
}

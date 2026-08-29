//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// DefaultMaxTrackedCalls is the default maximum number of calls to track
const (
	DefaultMaxTrackedCalls       = 5000
	maxMediaEndpointsPerCall     = 64
	maxMediaEndpointAssociations = DefaultMaxTrackedCalls * maxMediaEndpointsPerCall
)

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
	registry *callregistry.Core
	// Map: CallID -> From/To party info
	callPartyInfo map[string]*CallPartyInfo
	mu            sync.RWMutex
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
		registry: callregistry.New(callregistry.Config{
			MaxCalls: maxCalls, MaxEndpointsPerCall: maxMediaEndpointsPerCall,
			MaxEndpointAssociations: maxMediaEndpointAssociations,
		}),
		callPartyInfo: make(map[string]*CallPartyInfo),
	}
}

// touchCallLocked moves a call to the front of the LRU list (most recently used).
// If the call doesn't exist in the LRU, it adds it.
// Must be called with mu held.
func (t *CallTracker) touchCallLocked(callID string) {
	if _, ok := t.registry.Call(callID); ok {
		t.registry.Touch(callID, time.Now())
		return
	}
	before := t.registry.ActiveCalls()
	t.registry.Upsert(callregistry.Call{CallID: callID, Created: time.Now(), LastUpdated: time.Now()})
	if len(before) > 0 {
		for _, call := range before {
			if _, ok := t.registry.Call(call.CallID); !ok {
				delete(t.callPartyInfo, call.CallID)
				t.lastRTPTouch.Delete(call.CallID)
			}
		}
	}
}

// evictCallLocked removes all data associated with a call.
// Must be called with mu held.
func (t *CallTracker) evictCallLocked(callID string) {
	t.registry.Remove(callID, callregistry.EndEvicted)
	delete(t.callPartyInfo, callID)
	t.lastRTPTouch.Delete(callID)
}

// registerEndpointLocked adds one bounded, deduplicated endpoint association.
func (t *CallTracker) registerEndpointLocked(callID, endpoint string) bool {
	before := len(t.registry.EndpointsForCall(callID))
	return t.registry.TryAssociateEndpoint(callID, endpoint) && len(t.registry.EndpointsForCall(callID)) > before
}

func firstRealCallID(callIDs []string) string {
	for _, callID := range callIDs {
		if !strings.HasPrefix(callID, "rtp-") {
			return callID
		}
	}
	return ""
}

// callIDForEndpointLocked preserves the historical preference for the most
// recently active owner while retaining every shared B2BUA association.
func (t *CallTracker) callIDForEndpointLocked(endpoint string) string {
	if callID, ok := t.registry.MostRecentCallIDForEndpoint(endpoint); ok {
		return callID
	}
	return ""
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
		for _, existingCallID := range t.registry.CallIDsForEndpoint(endpoint) {
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
		syntheticEndpoints = append(syntheticEndpoints, t.registry.EndpointsForCall(syntheticCallID)...)

		// Now evict the synthetic call
		t.evictCallLocked(syntheticCallID)
	}

	// Touch the call in LRU (adds if new, evicts oldest if at capacity)
	t.touchCallLocked(callID)

	// Helper to register an endpoint for the real CallID
	registerEndpoint := func(endpoint, source string) {
		if t.registerEndpointLocked(callID, endpoint) {
			// Add to diagnostic buffer
			addDiagEvent("REG", callID, endpoint, source)
			logger.Debug("CallTracker registered endpoint",
				"call_id", callID,
				"endpoint", endpoint,
				"source", source,
				"total_endpoints_for_call", len(t.registry.EndpointsForCall(callID)))
		}
	}

	// First, transfer all endpoints from the synthetic call (includes BOTH parties' RTP ports)
	for _, endpoint := range syntheticEndpoints {
		registerEndpoint(endpoint, "merge")
	}

	// Then register the new SDP endpoints.
	// Also register RTCP port (RTP+1) per RFC 3550 convention so RTCP
	// packets can be correlated without an explicit a=rtcp: SDP attribute.
	reqResp := "req"
	if isResponse {
		reqResp = "rsp"
	}
	for _, port := range ports {
		endpoint := fmt.Sprintf("%s:%d", rtpIP, port)
		registerEndpoint(endpoint, reqResp)
		rtcpEndpoint := fmt.Sprintf("%s:%d", rtpIP, port+1)
		registerEndpoint(rtcpEndpoint, reqResp+"-rtcp")
	}

	return syntheticCallID
}

// RegisterRTPOnlyEndpoints registers RTP endpoints for an RTP-only (synthetic) call.
// This allows the endpoint to be matched when SIP arrives later.
// Also stores party info (IP:port pairs as From/To) for display purposes.
//
// Returns the real SIP call ID if any endpoint already belongs to a real call,
// allowing the caller to use that instead of the synthetic ID. This handles
// race conditions where SIP registers endpoints just before RTP arrives.
func (t *CallTracker) RegisterRTPOnlyEndpoints(syntheticCallID, srcIP, srcPort, dstIP, dstPort string) (existingRealCallID string) {
	if syntheticCallID == "" || !strings.HasPrefix(syntheticCallID, "rtp-") {
		return ""
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// Register both source and destination endpoints
	// SDP typically specifies the destination port (where to send RTP)
	srcEndpoint := fmt.Sprintf("%s:%s", srcIP, srcPort)
	dstEndpoint := fmt.Sprintf("%s:%s", dstIP, dstPort)

	// Check if any endpoint already belongs to a real SIP call.
	// If so, return that call ID so the caller can use it instead of synthetic.
	// This handles the race where SIP registers endpoints just before RTP arrives.
	if existingSrc := firstRealCallID(t.registry.CallIDsForEndpoint(srcEndpoint)); existingSrc != "" {
		logger.Debug("RegisterRTPOnlyEndpoints: src endpoint belongs to SIP call, returning real call ID",
			"endpoint", srcEndpoint,
			"real_call", existingSrc,
			"synthetic_call", syntheticCallID)
		return existingSrc
	}
	if existingDst := firstRealCallID(t.registry.CallIDsForEndpoint(dstEndpoint)); existingDst != "" {
		logger.Debug("RegisterRTPOnlyEndpoints: dst endpoint belongs to SIP call, returning real call ID",
			"endpoint", dstEndpoint,
			"real_call", existingDst,
			"synthetic_call", syntheticCallID)
		return existingDst
	}

	// No real call owns these endpoints yet - register for the synthetic call
	// Touch the call in LRU
	t.touchCallLocked(syntheticCallID)

	t.registerEndpointLocked(syntheticCallID, srcEndpoint)
	t.registerEndpointLocked(syntheticCallID, dstEndpoint)

	// Store party info for RTP-only calls (used as fallback in convertToTUICall)
	// Use IP:port as From/To since we don't have SIP headers
	if t.callPartyInfo[syntheticCallID] == nil {
		t.callPartyInfo[syntheticCallID] = &CallPartyInfo{
			From: srcEndpoint,
			To:   dstEndpoint,
		}
	}

	return ""
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

		t.registerEndpointLocked(callID, endpoint)
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
	callID := t.callIDForEndpointLocked(dstEndpoint)
	found := callID != ""
	if found {
		atomic.AddInt64(&rtpLookupDstMatch, 1)
	} else {
		callID = t.callIDForEndpointLocked(srcEndpoint)
		found = callID != ""
		if found {
			atomic.AddInt64(&rtpLookupSrcMatch, 1)
		}
	}
	mapSizes := [2]int{len(t.registry.ActiveCalls()), len(t.registry.ActiveCalls())}
	t.mu.RUnlock()

	if found {
		// Throttled LRU touch - at most once per second per call to avoid lock contention
		now := time.Now().UnixNano()
		if last, ok := t.lastRTPTouch.Load(callID); !ok || now-last.(int64) > int64(rtpLRUTouchInterval) {
			t.registry.Touch(callID, time.Now())
			t.lastRTPTouch.Store(callID, now)
		}
		return callID
	}

	atomic.AddInt64(&rtpLookupFailed, 1)
	// Log lookup failures with map state for debugging
	logger.Debug("GetCallIDForRTPPacket: lookup failed",
		"src_endpoint", srcEndpoint,
		"dst_endpoint", dstEndpoint,
		"rtpEndpointToCallIDs_size", mapSizes[0],
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
	return len(t.registry.ActiveCalls())
}

// IsCallActive reports whether the tracker currently owns state for callID.
// The TCP reassembler uses this query to retain idle streams belonging to a
// known SIP dialog without reaching into package-global VoIP state.
func (t *CallTracker) IsCallActive(callID string) bool {
	if callID == "" {
		return false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()
	_, active := t.registry.Call(callID)
	return active
}

// Clear removes all tracked mappings
func (t *CallTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.registry.Clear()
	t.callPartyInfo = make(map[string]*CallPartyInfo)
	t.lastRTPTouch.Range(func(key, _ any) bool { t.lastRTPTouch.Delete(key); return true })
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

	endpoints := t.registry.EndpointsForCall(callID)
	if len(endpoints) == 0 {
		return nil
	}

	// Touch the LRU to keep this call from being evicted while it's being displayed.
	// Only touch if the call already exists in the LRU (don't add phantom entries).
	t.registry.Touch(callID, time.Now())

	// Return a copy to avoid races
	result := make([]string, len(endpoints))
	copy(result, endpoints)
	return result
}

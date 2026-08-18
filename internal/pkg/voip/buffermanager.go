package voip

import (
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// BufferManager manages per-call packet buffers
type BufferManager struct {
	buffers      map[string]*CallBuffer // callID -> buffer (temporary until filter decision)
	matchedCalls map[string]time.Time   // callID -> matchTime (persists after buffer cleanup)
	mu           sync.RWMutex
	maxAge       time.Duration // Max time to buffer before decision
	maxSize      int           // Max packets per buffer
	matchedTTL   time.Duration // How long to remember matched calls (default: 24h)
	janitorCh    chan struct{} // Signal channel for janitor
	stopCh       chan struct{} // Stop channel
}

// DefaultMatchedTTL is how long to remember matched calls after filter decision.
// This allows BYE messages to be correctly associated with calls even after
// the temporary buffer has been cleaned up. 24 hours covers very long calls.
const DefaultMatchedTTL = 24 * time.Hour

// NewBufferManager creates a new buffer manager
func NewBufferManager(maxAge time.Duration, maxSize int) *BufferManager {
	bm := &BufferManager{
		buffers:      make(map[string]*CallBuffer),
		matchedCalls: make(map[string]time.Time),
		maxAge:       maxAge,
		maxSize:      maxSize,
		matchedTTL:   DefaultMatchedTTL,
		janitorCh:    make(chan struct{}),
		stopCh:       make(chan struct{}),
	}

	// Start janitor goroutine for cleanup
	go bm.janitor()

	return bm
}

// AddSIPPacket records a SIP packet for a call.
//
// It returns true when the call has already been matched, in which case the
// packet is NOT buffered and the caller must write/forward it immediately.
// Buffering only exists to hold packets until the filter decision is made; once
// that decision is "matched", every further packet of the call must flow
// straight through. Gating that on the packet carrying SDP would silently drop
// all non-SDP signalling (100 Trying, 180 Ringing, ACK, BYE, 4xx/5xx).
//
// A nil packet is allowed: callers that have already delivered the packet
// themselves use it to seed the buffer's metadata and RTP ports.
func (bm *BufferManager) AddSIPPacket(callID string, packet gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) bool {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	_, alreadyMatched := bm.matchedCalls[callID]

	buffer, exists := bm.buffers[callID]
	if !exists {
		buffer = NewCallBuffer(callID)
		buffer.SetInterfaceName(interfaceName)
		buffer.SetLinkType(linkType)
		if alreadyMatched {
			// The janitor reaps buffers by age, so a long call outlives its
			// buffer. Restore the decision on the replacement buffer so RTP
			// association keeps working for the rest of the call.
			buffer.SetFilterResult(true)
		}
		bm.buffers[callID] = buffer
	}

	buffer.SetMetadata(metadata)

	// Extract RTP ports from SDP if present. Re-INVITEs and delayed-offer
	// answers can introduce new ports mid-call, so this runs for every packet
	// carrying SDP, matched or not.
	if metadata.SDPBody != "" {
		ports := extractRTPPortsFromSDP(metadata.SDPBody)
		for _, port := range ports {
			buffer.AddRTPPort(port)
		}
	}

	if alreadyMatched || (buffer.IsFilterChecked() && buffer.IsMatched()) {
		return true // Caller writes/forwards immediately; nothing to buffer
	}

	if packet != nil {
		buffer.AddSIPPacket(packet)
	}
	return false
}

// AddRTPPacket adds an RTP packet to the buffer if call is being tracked
// Returns true if packet should be forwarded immediately (call already matched)
func (bm *BufferManager) AddRTPPacket(callID string, port string, packet gopacket.Packet) bool {
	bm.mu.RLock()
	buffer, exists := bm.buffers[callID]
	bm.mu.RUnlock()

	if !exists || !buffer.IsRTPPort(port) {
		return false
	}

	// If filter already checked and matched, don't buffer (forward directly)
	if buffer.IsFilterChecked() && buffer.IsMatched() {
		return true // Caller should forward immediately
	}

	// Buffer the packet
	bm.mu.Lock()
	buffer.AddRTPPacket(packet)
	bm.mu.Unlock()

	return false // Buffered, don't forward yet
}

// GetCallIDForRTPPort looks up which call a given RTP port belongs to
func (bm *BufferManager) GetCallIDForRTPPort(port string) (string, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	for callID, buffer := range bm.buffers {
		if buffer.IsRTPPort(port) {
			return callID, true
		}
	}
	return "", false
}

// CheckFilter evaluates filter and returns decision + buffered packets if matched
func (bm *BufferManager) CheckFilter(callID string, filterFunc func(*CallMetadata) bool) (matched bool, packets []gopacket.Packet) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	buffer, exists := bm.buffers[callID]
	if !exists || buffer.GetMetadata() == nil {
		return false, nil
	}

	// Check filter
	matched = filterFunc(buffer.GetMetadata())
	buffer.SetFilterResult(matched)

	if matched {
		// Record in matchedCalls so BYE can be processed even after buffer cleanup
		bm.matchedCalls[callID] = time.Now()

		// Hand over all buffered packets and empty the buffer, so a later
		// filter check for the same call cannot re-emit them.
		packets = buffer.DrainPackets()
		logger.Info("Call matched filter, flushing buffer",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", len(packets),
			"from", buffer.GetMetadata().From,
			"to", buffer.GetMetadata().To)
	} else {
		// Discard buffer
		delete(bm.buffers, callID)
		logger.Debug("Call did not match filter, discarding buffer",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", buffer.GetPacketCount())
	}

	return matched, packets
}

// CheckFilterWithCallback evaluates filter and calls callback for each packet if matched
// This allows different handling strategies (file write, gRPC forward, etc.)
func (bm *BufferManager) CheckFilterWithCallback(
	callID string,
	filterFunc func(*CallMetadata) bool,
	onMatch func(callID string, packets []gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType),
) bool {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	buffer, exists := bm.buffers[callID]
	if !exists || buffer.GetMetadata() == nil {
		return false
	}

	// Check filter
	matched := filterFunc(buffer.GetMetadata())
	buffer.SetFilterResult(matched)

	if matched {
		// Record in matchedCalls so BYE can be processed even after buffer cleanup
		bm.matchedCalls[callID] = time.Now()

		// Take all buffered packets and empty the buffer, so a later filter
		// check for the same call cannot re-emit them.
		packets := buffer.DrainPackets()
		logger.Info("Call matched filter, invoking callback",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", len(packets),
			"from", buffer.GetMetadata().From,
			"to", buffer.GetMetadata().To)

		// Call the handler callback
		if onMatch != nil {
			onMatch(callID, packets, buffer.GetMetadata(), buffer.GetInterfaceName(), buffer.GetLinkType())
		}
	} else {
		// Discard buffer
		delete(bm.buffers, callID)
		logger.Debug("Call did not match filter, discarding buffer",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", buffer.GetPacketCount())
	}

	return matched
}

// MarkCallMatched records a call as matched without buffering a packet.
//
// TCP paths deliver each SIP message as the reassembler completes it, so they
// have nothing to flush — but the call must still be remembered as matched, or
// later in-dialog messages (ACK, BYE, responses) and the call's RTP would be
// re-evaluated on their own headers and dropped when they carry no identity the
// filter matches.
func (bm *BufferManager) MarkCallMatched(callID string, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	buffer, exists := bm.buffers[callID]
	if !exists {
		buffer = NewCallBuffer(callID)
		buffer.SetInterfaceName(interfaceName)
		buffer.SetLinkType(linkType)
		bm.buffers[callID] = buffer
	}

	if metadata != nil {
		buffer.SetMetadata(metadata)
		if metadata.SDPBody != "" {
			for _, port := range extractRTPPortsFromSDP(metadata.SDPBody) {
				buffer.AddRTPPort(port)
			}
		}
	}

	buffer.SetFilterResult(true)
	bm.matchedCalls[callID] = time.Now()
}

// IsCallMatched checks if a call has been evaluated and matched the filter.
// This checks both the persistent matchedCalls map (for calls whose buffers
// have been cleaned up) and the active buffers (for recent calls).
func (bm *BufferManager) IsCallMatched(callID string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	// First check the persistent matchedCalls map - this survives buffer cleanup
	if _, exists := bm.matchedCalls[callID]; exists {
		return true
	}

	// Fall back to buffer check for recent calls
	buffer, exists := bm.buffers[callID]
	if !exists {
		return false
	}

	return buffer.IsFilterChecked() && buffer.IsMatched()
}

// DiscardBuffer removes a buffer without flushing
func (bm *BufferManager) DiscardBuffer(callID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.buffers, callID)
}

// GetBufferCount returns the number of active buffers
func (bm *BufferManager) GetBufferCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.buffers)
}

// janitor periodically cleans up old buffers
func (bm *BufferManager) janitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.cleanupOldBuffers()
		case <-bm.stopCh:
			return
		}
	}
}

// cleanupOldBuffers removes buffers that are too old or too large,
// and cleans up old entries from the matchedCalls map.
func (bm *BufferManager) cleanupOldBuffers() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()

	// Clean up old buffers (temporary packet storage before filter decision)
	for callID, buffer := range bm.buffers {
		age := buffer.GetAge()
		packetCount := buffer.GetPacketCount()

		// Check age
		if age > bm.maxAge {
			logger.Warn("Discarding buffer due to age",
				"call_id", SanitizeCallIDForLogging(callID),
				"age_seconds", int(age.Seconds()),
				"packet_count", packetCount)
			delete(bm.buffers, callID)
			continue
		}

		// Check size
		if packetCount > bm.maxSize {
			logger.Warn("Discarding buffer due to size",
				"call_id", SanitizeCallIDForLogging(callID),
				"packet_count", packetCount,
				"max_size", bm.maxSize)
			delete(bm.buffers, callID)
		}
	}

	// Clean up old matchedCalls entries (persistent call tracking)
	for callID, matchTime := range bm.matchedCalls {
		if now.Sub(matchTime) > bm.matchedTTL {
			logger.Debug("Removing expired matched call entry",
				"call_id", SanitizeCallIDForLogging(callID),
				"age_hours", int(now.Sub(matchTime).Hours()))
			delete(bm.matchedCalls, callID)
		}
	}
}

// Close stops the buffer manager
// Safe to call multiple times (idempotent)
func (bm *BufferManager) Close() {
	select {
	case <-bm.stopCh:
		// Already closed
		return
	default:
		close(bm.stopCh)
	}
}

// extractRTPPortsFromSDP extracts RTP ports and IP:PORT endpoints from SDP body
// Returns both IP:PORT (for precise matching) and port-only (for NAT fallback)
func extractRTPPortsFromSDP(sdp string) []string {
	endpoints := make([]string, 0, 4)

	// First, extract the session-level connection address (c= line)
	// Can be overridden per media line
	sessionIP := ""
	lines := strings.Split(sdp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "c=IN IP4 ") || strings.HasPrefix(line, "c=IN IP6 ") {
			// Format: c=IN IP4 <ip> or c=IN IP6 <ip>
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				sessionIP = fields[2]
				break // Use first c= line as session-level
			}
		}
	}

	// Now extract media ports and combine with IP
	currentIP := sessionIP
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Update connection IP if we see a media-level c= line
		if strings.HasPrefix(line, "c=IN IP4 ") || strings.HasPrefix(line, "c=IN IP6 ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				currentIP = fields[2]
			}
			continue
		}

		// Check for m=audio
		if strings.HasPrefix(line, "m=audio ") {
			// Extract port (second field)
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				port := fields[1]
				// Validate port
				if isValidPort(port) {
					if currentIP != "" {
						// Register IP:port endpoint
						endpoint := currentIP + ":" + port
						endpoints = append(endpoints, endpoint)
						logger.Debug("Extracted RTP endpoint from SDP",
							"ip", currentIP,
							"port", port,
							"endpoint", endpoint)
					}
					// Also register port-only for backward compatibility
					// (some RTP may come from unexpected IPs due to NAT)
					endpoints = append(endpoints, port)
				}
			}
		}
	}

	return endpoints
}

package voip

import (
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// BufferManager manages per-call packet buffers
type BufferManager struct {
	buffers   map[string]*CallBuffer // callID -> buffer
	mu        sync.RWMutex
	maxAge    time.Duration // Max time to buffer before decision
	maxSize   int           // Max packets per buffer
	janitorCh chan struct{} // Signal channel for janitor
	stopCh    chan struct{} // Stop channel
}

// NewBufferManager creates a new buffer manager
func NewBufferManager(maxAge time.Duration, maxSize int) *BufferManager {
	bm := &BufferManager{
		buffers:   make(map[string]*CallBuffer),
		maxAge:    maxAge,
		maxSize:   maxSize,
		janitorCh: make(chan struct{}),
		stopCh:    make(chan struct{}),
	}

	// Start janitor goroutine for cleanup
	go bm.janitor()

	return bm
}

// AddSIPPacket adds a SIP packet to the buffer
func (bm *BufferManager) AddSIPPacket(callID string, packet gopacket.Packet, metadata *CallMetadata) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	buffer, exists := bm.buffers[callID]
	if !exists {
		buffer = NewCallBuffer(callID)
		bm.buffers[callID] = buffer
	}

	buffer.AddSIPPacket(packet)
	buffer.SetMetadata(metadata)

	// Extract RTP ports from SDP if present
	if metadata.SDPBody != "" {
		ports := extractRTPPortsFromSDP(metadata.SDPBody)
		for _, port := range ports {
			buffer.AddRTPPort(port)
		}
	}
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
		// Return all buffered packets for flushing
		packets = buffer.GetAllPackets()
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
	onMatch func(callID string, packets []gopacket.Packet, metadata *CallMetadata),
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
		// Get all buffered packets
		packets := buffer.GetAllPackets()
		logger.Info("Call matched filter, invoking callback",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", len(packets),
			"from", buffer.GetMetadata().From,
			"to", buffer.GetMetadata().To)

		// Call the handler callback
		if onMatch != nil {
			onMatch(callID, packets, buffer.GetMetadata())
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

// IsCallMatched checks if a call has been evaluated and matched the filter
func (bm *BufferManager) IsCallMatched(callID string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

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

// cleanupOldBuffers removes buffers that are too old or too large
func (bm *BufferManager) cleanupOldBuffers() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

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
					logger.Debug("Extracted RTP port from SDP",
						"port", port)
				}
			}
		}
	}

	return ports
}

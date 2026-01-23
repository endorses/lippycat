//go:build tui || all

package tui

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/simd"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// timeRingBuffer is a fixed-size circular buffer for storing timestamps.
// Used for rolling window rate calculation with O(1) operations and fixed memory.
type timeRingBuffer struct {
	data     []time.Time
	capacity int
	head     int // Next write position
	count    int // Number of valid entries
}

// newTimeRingBuffer creates a ring buffer with the given capacity.
func newTimeRingBuffer(capacity int) *timeRingBuffer {
	return &timeRingBuffer{
		data:     make([]time.Time, capacity),
		capacity: capacity,
	}
}

// push adds a timestamp to the buffer, overwriting oldest if full.
func (rb *timeRingBuffer) push(t time.Time) {
	rb.data[rb.head] = t
	rb.head = (rb.head + 1) % rb.capacity
	if rb.count < rb.capacity {
		rb.count++
	}
}

// trimBefore removes all entries before the cutoff time.
// Returns the number of valid entries remaining.
func (rb *timeRingBuffer) trimBefore(cutoff time.Time) int {
	if rb.count == 0 {
		return 0
	}

	// Find how many entries from the tail are before cutoff
	trimCount := 0
	for trimCount < rb.count {
		// Calculate tail position
		tailIdx := (rb.head - rb.count + trimCount + rb.capacity) % rb.capacity
		if !rb.data[tailIdx].Before(cutoff) {
			break
		}
		trimCount++
	}

	rb.count -= trimCount
	return rb.count
}

// oldest returns the oldest timestamp in the buffer, or zero time if empty.
func (rb *timeRingBuffer) oldest() time.Time {
	if rb.count == 0 {
		return time.Time{}
	}
	tailIdx := (rb.head - rb.count + rb.capacity) % rb.capacity
	return rb.data[tailIdx]
}

// len returns the number of valid entries.
func (rb *timeRingBuffer) len() int {
	return rb.count
}

// Call tracker for RTP-to-CallID mapping in TUI capture modes
var (
	callTracker   *CallTracker
	callTrackerMu sync.RWMutex

	// String interning for protocol names (reduce memory footprint)
	protocolStrings = map[string]string{
		"TCP":       "TCP",
		"UDP":       "UDP",
		"SIP":       "SIP",
		"RTP":       "RTP",
		"DNS":       "DNS",
		"HTTP":      "HTTP",
		"HTTPS":     "HTTPS",
		"TLS":       "TLS",
		"SSL":       "SSL",
		"ICMP":      "ICMP",
		"ICMPv6":    "ICMPv6",
		"IGMP":      "IGMP",
		"ARP":       "ARP",
		"LLC":       "LLC",
		"LLDP":      "LLDP",
		"CDP":       "CDP",
		"802.1Q":    "802.1Q",
		"802.1X":    "802.1X",
		"OpenVPN":   "OpenVPN",
		"WireGuard": "WireGuard",
		"L2TP":      "L2TP",
		"PPTP":      "PPTP",
		"IKEv2":     "IKEv2",
		"IKEv1":     "IKEv1",
		"IKE":       "IKE",
		"Unknown":   "Unknown",
		"unknown":   "unknown",
	}
	protocolMu sync.RWMutex

	// Pre-allocated SIP method prefixes for fast detection (no allocations)
	sipMethodINVITE   = []byte("INVITE")
	sipMethodREGISTER = []byte("REGISTER")
	sipMethodOPTIONS  = []byte("OPTIONS")
	sipMethodACK      = []byte("ACK")
	sipMethodBYE      = []byte("BYE")
	sipMethodCANCEL   = []byte("CANCEL")
	sipResponse       = []byte("SIP/2.0")
)

// internProtocol returns an interned protocol string to reduce allocations
func internProtocol(protocol string) string {
	protocolMu.RLock()
	if interned, ok := protocolStrings[protocol]; ok {
		protocolMu.RUnlock()
		return interned
	}
	protocolMu.RUnlock()

	// Not found - add it (rare)
	protocolMu.Lock()
	// Check again in case another goroutine added it
	if interned, ok := protocolStrings[protocol]; ok {
		protocolMu.Unlock()
		return interned
	}
	// Limit pool size to prevent unbounded growth
	if len(protocolStrings) < 100 {
		protocolStrings[protocol] = protocol
	}
	protocolMu.Unlock()
	return protocol
}

// isSIPBytes performs fast SIP detection using SIMD-optimized byte comparison
// This is used in the fast conversion path to avoid full protocol detection overhead
func isSIPBytes(payload []byte) bool {
	if len(payload) < 3 {
		return false
	}

	// Check for common SIP methods and responses
	// Using pre-allocated byte slices and SIMD comparison for zero allocations
	if len(payload) >= len(sipMethodINVITE) && simd.BytesEqual(payload[:len(sipMethodINVITE)], sipMethodINVITE) {
		return true
	}
	if len(payload) >= len(sipMethodREGISTER) && simd.BytesEqual(payload[:len(sipMethodREGISTER)], sipMethodREGISTER) {
		return true
	}
	if len(payload) >= len(sipMethodOPTIONS) && simd.BytesEqual(payload[:len(sipMethodOPTIONS)], sipMethodOPTIONS) {
		return true
	}
	if len(payload) >= len(sipResponse) && simd.BytesEqual(payload[:len(sipResponse)], sipResponse) {
		return true
	}
	if len(payload) >= len(sipMethodACK) && simd.BytesEqual(payload[:len(sipMethodACK)], sipMethodACK) {
		return true
	}
	if len(payload) >= len(sipMethodBYE) && simd.BytesEqual(payload[:len(sipMethodBYE)], sipMethodBYE) {
		return true
	}
	if len(payload) >= len(sipMethodCANCEL) && simd.BytesEqual(payload[:len(sipMethodCANCEL)], sipMethodCANCEL) {
		return true
	}

	return false
}

// SetCallTracker sets the call tracker for RTP-to-CallID mapping
func SetCallTracker(tracker *CallTracker) {
	callTrackerMu.Lock()
	defer callTrackerMu.Unlock()
	callTracker = tracker
}

// GetCallTracker returns the current call tracker
func GetCallTracker() *CallTracker {
	callTrackerMu.RLock()
	defer callTrackerMu.RUnlock()
	return callTracker
}

// ClearCallTracker clears the call tracker
func ClearCallTracker() {
	callTrackerMu.Lock()
	defer callTrackerMu.Unlock()
	if callTracker != nil {
		callTracker.Clear()
		callTracker = nil
	}
}

// BridgeStats contains statistics about the packet bridge for diagnostics.
// These stats help identify backpressure issues where the TUI can't keep up
// with packet ingestion rate.
type BridgeStats struct {
	PacketsReceived  int64 // Total packets received from capture
	PacketsDisplayed int64 // Packets sent to TUI for display
	BatchesSent      int64 // Batches successfully queued for TUI
	BatchesDropped   int64 // Batches dropped due to TUI backpressure
	QueueDepth       int64 // Current batch queue depth (0-tuiQueueSize)
	MaxQueueDepth    int64 // Peak queue depth seen
	SamplingRatio    int64 // Current sampling ratio * 1000 (e.g., 1000 = 100%, 500 = 50%)
	RecentDropRate   int64 // Recent drop rate * 1000 (last 5s window, for throttling)
}

// recentDropTracker tracks batch drops over a sliding window for throttling
type recentDropTracker struct {
	mu           sync.Mutex
	windowSize   time.Duration
	events       []dropEvent
	totalSent    int
	totalDropped int
}

type dropEvent struct {
	timestamp time.Time
	dropped   bool
}

var dropTracker = &recentDropTracker{
	windowSize: 5 * time.Second,
	events:     make([]dropEvent, 0, 1000),
}

// pendingPacketBuffer holds packets ready for the TUI to pull.
// This decouples packet production from TUI rendering - the TUI
// pulls packets when it's ready rather than being pushed to.
type pendingPacketBuffer struct {
	mu      sync.Mutex
	packets []components.PacketDisplay
}

var pendingPackets = &pendingPacketBuffer{
	packets: make([]components.PacketDisplay, 0, 2000),
}

// addPackets adds packets to the pending buffer (called by bridge consumer)
func (pb *pendingPacketBuffer) addPackets(packets []components.PacketDisplay) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	pb.packets = append(pb.packets, packets...)

	// Cap buffer size to prevent unbounded growth (only for live capture).
	// In offline mode (VoIP with CallTracker), we preserve all packets.
	// Note: Pause is now handled upstream (source + bridge), so no pause check needed here.
	hasCallTracker := GetCallTracker() != nil
	if !hasCallTracker {
		const maxPending = 5000
		if len(pb.packets) > maxPending {
			pb.packets = pb.packets[len(pb.packets)-maxPending:]
		}
	}
}

// drainPackets returns up to maxPackets pending packets.
// Called by TUI on a timer to pull new packets.
// Limiting per-tick processing prevents UI stutter during high traffic.
func (pb *pendingPacketBuffer) drainPackets(maxPackets int) []components.PacketDisplay {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if len(pb.packets) == 0 {
		return nil
	}

	// Take at most maxPackets from the front (oldest first)
	count := len(pb.packets)
	if count > maxPackets {
		count = maxPackets
	}

	result := make([]components.PacketDisplay, count)
	copy(result, pb.packets[:count])

	// Keep remaining packets in buffer
	if count < len(pb.packets) {
		remaining := make([]components.PacketDisplay, len(pb.packets)-count)
		copy(remaining, pb.packets[count:])
		pb.packets = remaining
	} else {
		pb.packets = pb.packets[:0] // Reuse backing array
	}

	return result
}

// DrainPendingPackets returns pending packets for the TUI to process.
// This is the public API called by the TUI's tick handler.
// For live capture: Limited to 50 packets per tick to prevent UI stutter.
// For offline capture: Returns ALL pending packets to ensure complete processing.
func DrainPendingPackets() []components.PacketDisplay {
	// In offline mode, drain all packets to ensure none are lost
	hasCallTracker := GetCallTracker() != nil
	if hasCallTracker {
		return pendingPackets.drainPackets(100000) // Large number = all packets
	}
	// Live mode: limit to prevent UI stutter
	const maxPacketsPerTick = 50
	return pendingPackets.drainPackets(maxPacketsPerTick)
}

// recordBatchResult records a batch send result (success or drop)
func (dt *recentDropTracker) recordBatchResult(dropped bool) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	now := time.Now()
	dt.events = append(dt.events, dropEvent{timestamp: now, dropped: dropped})
	if dropped {
		dt.totalDropped++
	} else {
		dt.totalSent++
	}

	// Trim old events
	cutoff := now.Add(-dt.windowSize)
	trimIdx := 0
	for trimIdx < len(dt.events) && dt.events[trimIdx].timestamp.Before(cutoff) {
		if dt.events[trimIdx].dropped {
			dt.totalDropped--
		} else {
			dt.totalSent--
		}
		trimIdx++
	}
	if trimIdx > 0 {
		dt.events = dt.events[trimIdx:]
	}

	// Compact if too much slack
	if cap(dt.events) > 2000 && len(dt.events) < cap(dt.events)/4 {
		newEvents := make([]dropEvent, len(dt.events), 1000)
		copy(newEvents, dt.events)
		dt.events = newEvents
	}
}

// getRecentDropRate returns the drop rate over the recent window (0-1000 scale)
func (dt *recentDropTracker) getRecentDropRate() int64 {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	// Trim stale events first
	now := time.Now()
	cutoff := now.Add(-dt.windowSize)
	trimIdx := 0
	for trimIdx < len(dt.events) && dt.events[trimIdx].timestamp.Before(cutoff) {
		if dt.events[trimIdx].dropped {
			dt.totalDropped--
		} else {
			dt.totalSent--
		}
		trimIdx++
	}
	if trimIdx > 0 {
		dt.events = dt.events[trimIdx:]
	}

	total := dt.totalSent + dt.totalDropped
	if total < 10 {
		return 0 // Not enough data
	}
	return int64(dt.totalDropped) * 1000 / int64(total)
}

// bridgeStats holds global bridge statistics for diagnostics
var bridgeStats BridgeStats

// GetBridgeStats returns a copy of the current bridge statistics.
func GetBridgeStats() BridgeStats {
	return BridgeStats{
		PacketsReceived:  atomic.LoadInt64(&bridgeStats.PacketsReceived),
		PacketsDisplayed: atomic.LoadInt64(&bridgeStats.PacketsDisplayed),
		BatchesSent:      atomic.LoadInt64(&bridgeStats.BatchesSent),
		BatchesDropped:   atomic.LoadInt64(&bridgeStats.BatchesDropped),
		QueueDepth:       atomic.LoadInt64(&bridgeStats.QueueDepth),
		MaxQueueDepth:    atomic.LoadInt64(&bridgeStats.MaxQueueDepth),
		SamplingRatio:    atomic.LoadInt64(&bridgeStats.SamplingRatio),
		RecentDropRate:   dropTracker.getRecentDropRate(),
	}
}

// ResetBridgeStats resets bridge statistics to zero.
func ResetBridgeStats() {
	atomic.StoreInt64(&bridgeStats.PacketsReceived, 0)
	atomic.StoreInt64(&bridgeStats.PacketsDisplayed, 0)
	atomic.StoreInt64(&bridgeStats.BatchesSent, 0)
	atomic.StoreInt64(&bridgeStats.BatchesDropped, 0)
	atomic.StoreInt64(&bridgeStats.QueueDepth, 0)
	atomic.StoreInt64(&bridgeStats.MaxQueueDepth, 0)
	atomic.StoreInt64(&bridgeStats.SamplingRatio, 1000) // Default to 100%
}

// StartPacketBridge creates a bridge between packet capture and TUI.
// It converts capture.PacketInfo to PacketMsg for the TUI.
// Uses intelligent sampling and throttling to handle high packet rates.
//
// The bridge uses a buffered channel and separate consumer goroutine to
// prevent blocking when the TUI's Update() loop falls behind. This avoids
// the producer-consumer deadlock that can occur with direct program.Send().
//
// The pause signal allows the bridge to block when capture is paused,
// reducing CPU usage to near-idle.
func StartPacketBridge(packetChan <-chan capture.PacketInfo, program *tea.Program, pause *PauseSignal) {
	const (
		targetPacketsPerSecond = 1000                      // Target display rate (increased for bulk transfers)
		batchInterval          = constants.TUITickInterval // Batch interval
		rateWindowSize         = 2 * time.Second           // Rolling window for rate calculation (react quickly)
		tuiQueueSize           = 10                        // Buffered channel capacity for TUI batches
		// Ring buffer capacity: 2s window at max 10k pps = 20k entries, with some headroom
		ringBufferCapacity = 25000
	)

	batch := make([]components.PacketDisplay, 0, 100)
	packetCount := int64(0)
	displayedCount := int64(0)

	// Ring buffer for rolling window rate calculation (fixed memory, O(1) operations)
	recentPackets := newTimeRingBuffer(ringBufferCapacity)
	lastRateCheck := time.Now()

	// Cache sampling ratio to avoid recalculating for every packet
	cachedSamplingRatio := 1.0
	lastSamplingUpdateCount := int64(0)
	const samplingUpdateEveryN = 1000 // Update sampling ratio every 1000 packets

	ticker := time.NewTicker(batchInterval)
	defer ticker.Stop()

	// Buffered channel to decouple packet conversion from TUI rendering.
	// This prevents program.Send() from blocking the bridge when TUI is slow.
	tuiBatchChan := make(chan PacketBatchMsg, tuiQueueSize)

	// Consumer goroutine: reads from tuiBatchChan and adds to pending buffer.
	// The TUI pulls from the pending buffer on its own timer, so this never blocks.
	// When paused, packets are discarded (the bridge is blocked, so minimal packets arrive).
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)

		for {
			select {
			case msg, ok := <-tuiBatchChan:
				if !ok {
					// Channel closed
					return
				}
				// Discard packets when paused (bridge is blocked, so minimal arrive)
				if pause != nil && pause.IsPaused() {
					continue
				}
				// Add to pending buffer (never blocks - TUI pulls when ready)
				pendingPackets.addPackets(msg.Packets)
			}
		}
	}()

	// sendBatch queues a batch for the TUI consumer.
	// For live capture: Uses non-blocking send to prevent deadlock when TUI is slow.
	// For offline capture: Uses blocking send to ensure all packets are processed.
	sendBatch := func() {
		if len(batch) > 0 {
			msg := PacketBatchMsg{Packets: batch}

			// Check if we're in offline mode (reading from PCAP files)
			// In offline mode, we MUST NOT drop packets - use blocking send
			hasCallTracker := GetCallTracker() != nil

			if hasCallTracker {
				// Blocking send - wait until TUI is ready (offline mode)
				tuiBatchChan <- msg
				atomic.AddInt64(&bridgeStats.BatchesSent, 1)
				atomic.AddInt64(&bridgeStats.PacketsDisplayed, int64(len(batch)))
				dropTracker.recordBatchResult(false)
			} else {
				// Non-blocking send - drop if TUI is slow (live capture)
				select {
				case tuiBatchChan <- msg:
					// Successfully queued
					atomic.AddInt64(&bridgeStats.BatchesSent, 1)
					atomic.AddInt64(&bridgeStats.PacketsDisplayed, int64(len(batch)))
					dropTracker.recordBatchResult(false)
				default:
					// TUI is behind - drop batch to prevent blocking
					atomic.AddInt64(&bridgeStats.BatchesDropped, 1)
					dropTracker.recordBatchResult(true)
					logger.Debug("TUI backpressure: dropped packet batch",
						"batch_size", len(batch),
						"total_dropped", atomic.LoadInt64(&bridgeStats.BatchesDropped))
				}
			}
			displayedCount += int64(len(batch))
			batch = make([]components.PacketDisplay, 0, 100)

			// Update queue depth stats
			depth := int64(len(tuiBatchChan))
			atomic.StoreInt64(&bridgeStats.QueueDepth, depth)
			// Update max if current depth is higher
			for {
				maxDepth := atomic.LoadInt64(&bridgeStats.MaxQueueDepth)
				if depth <= maxDepth {
					break
				}
				if atomic.CompareAndSwapInt64(&bridgeStats.MaxQueueDepth, maxDepth, depth) {
					break
				}
			}
		}
	}

	// Calculate sampling ratio based on RECENT packet rate (rolling 2s window)
	// This allows quick switching between fast/full mode
	getSamplingRatio := func() float64 {
		now := time.Now()

		// Update rolling window every 100ms to avoid overhead
		if now.Sub(lastRateCheck) > constants.TUITickInterval {
			// Remove packets older than window using ring buffer O(1) trim
			cutoff := now.Add(-rateWindowSize)
			recentPackets.trimBefore(cutoff)
			lastRateCheck = now
		}

		// Calculate rate from rolling window
		count := recentPackets.len()
		if count < 10 {
			atomic.StoreInt64(&bridgeStats.SamplingRatio, 1000) // 100%
			return 1.0                                          // Not enough data, use full mode
		}

		oldest := recentPackets.oldest()
		windowDuration := now.Sub(oldest).Seconds()
		if windowDuration < 0.1 {
			atomic.StoreInt64(&bridgeStats.SamplingRatio, 1000) // 100%
			return 1.0                                          // Too short, use full mode
		}

		currentRate := float64(count) / windowDuration
		if currentRate <= float64(targetPacketsPerSecond) {
			atomic.StoreInt64(&bridgeStats.SamplingRatio, 1000) // 100%
			return 1.0                                          // Show all packets if under target
		}

		// Sample to achieve target rate
		ratio := float64(targetPacketsPerSecond) / currentRate
		if ratio < 0.01 {
			ratio = 0.01 // Show at least 1%
		}

		// Store sampling ratio as integer (ratio * 1000 for precision)
		atomic.StoreInt64(&bridgeStats.SamplingRatio, int64(ratio*1000))
		return ratio
	}

	for {
		// Check pause state at loop start - block until resumed
		if pause != nil && pause.IsPaused() {
			sendBatch()  // Flush current batch before blocking
			pause.Wait() // Block until resumed
			continue
		}

		select {
		case <-pause.C():
			// Pause signaled mid-select, loop back to check and block
			continue

		case pktInfo, ok := <-packetChan:
			if !ok {
				// Channel closed, send remaining batch and shutdown consumer
				sendBatch()
				close(tuiBatchChan)
				<-consumerDone // Wait for consumer to finish
				return
			}

			packetCount++
			atomic.AddInt64(&bridgeStats.PacketsReceived, 1)

			// Update rate tracking and sampling ratio every N packets (not every packet)
			// This reduces overhead from 100k+ time.Now() calls/sec to 100 calls/sec
			if packetCount-lastSamplingUpdateCount >= samplingUpdateEveryN {
				recentPackets.push(time.Now())
				cachedSamplingRatio = getSamplingRatio()
				lastSamplingUpdateCount = packetCount
			}

			// Check if we're in offline mode (reading from PCAP files)
			// In offline mode, process ALL packets - no sampling needed
			hasCallTracker := GetCallTracker() != nil

			// Use cached sampling ratio (only for live capture)
			samplingRatio := cachedSamplingRatio
			if hasCallTracker {
				samplingRatio = 1.0 // Process all packets in offline mode
			}

			// Use fast conversion for sampled packets, full for important ones
			var packet components.PacketDisplay
			shouldDisplay := samplingRatio >= 1.0 || (float64(packetCount)*samplingRatio) >= float64(displayedCount+int64(len(batch))+1)

			if shouldDisplay {
				// Full conversion to extract all metadata (SDP, etc.)
				packet = convertPacket(pktInfo)
				batch = append(batch, packet)
			}

			// Send if batch is large enough
			if len(batch) >= 50 {
				sendBatch()
			}

		case <-ticker.C:
			// Send batch on interval
			sendBatch()
		}
	}
}

// convertPacketFast is a lightweight version for high-speed scenarios
// Uses shared extraction logic with TUI-specific fast SIP detection
func convertPacketFast(pktInfo capture.PacketInfo) components.PacketDisplay {
	pkt := pktInfo.Packet

	// Use shared extraction for basic fields
	fields := capture.ExtractPacketFields(pkt)

	display := components.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     fields.SrcIP,
		DstIP:     fields.DstIP,
		SrcPort:   fields.SrcPort,
		DstPort:   fields.DstPort,
		Protocol:  internProtocol(fields.Protocol),
		Length:    pkt.Metadata().Length,
		Info:      "",  // Skip info in fast mode
		RawData:   nil, // Don't copy raw data for performance
		Interface: pktInfo.Interface,
		LinkType:  pktInfo.LinkType,
	}

	// Fast SIP detection for VoIP over TCP/UDP
	if fields.HasTransport {
		if transLayer := pkt.TransportLayer(); transLayer != nil {
			switch trans := transLayer.(type) {
			case *layers.TCP:
				if isSIPBytes(trans.LayerPayload()) {
					display.Protocol = internProtocol("SIP")
				}
			case *layers.UDP:
				if isSIPBytes(trans.LayerPayload()) {
					display.Protocol = internProtocol("SIP")
				}
			}
		}
	}

	return display
}

// convertPacket converts a gopacket.Packet to PacketDisplay
// Uses shared extraction logic enhanced with protocol detection
func convertPacket(pktInfo capture.PacketInfo) components.PacketDisplay {
	pkt := pktInfo.Packet

	// Use shared extraction for basic fields
	fields := capture.ExtractPacketFields(pkt)

	// Copy raw data for packet display
	var rawData []byte
	if pkt.Data() != nil {
		rawData = make([]byte, len(pkt.Data()))
		copy(rawData, pkt.Data())
	}

	display := components.PacketDisplay{
		Timestamp: pkt.Metadata().Timestamp,
		SrcIP:     fields.SrcIP,
		DstIP:     fields.DstIP,
		SrcPort:   fields.SrcPort,
		DstPort:   fields.DstPort,
		Protocol:  fields.Protocol,
		Length:    pkt.Metadata().Length,
		Info:      fields.Info,
		RawData:   rawData,
		Interface: pktInfo.Interface,
		LinkType:  pktInfo.LinkType,
	}

	// Use centralized detector for application layer protocols
	detectionResult := detector.GetDefault().Detect(pkt)
	if detectionResult != nil && detectionResult.Protocol != "unknown" {
		display.Protocol = detectionResult.Protocol

		// Generate display info from metadata
		display.Info = buildProtocolInfo(detectionResult, pkt, &display)
	}

	// Final fallback: if still unknown, list what layers we detected
	if display.Protocol == "unknown" && display.SrcIP == "unknown" {
		layers := pkt.Layers()
		if len(layers) > 0 {
			layerNames := make([]string, 0, len(layers))
			for _, layer := range layers {
				layerNames = append(layerNames, layer.LayerType().String())
			}
			display.Protocol = "Unknown"
			display.Info = "Layers: " + strings.Join(layerNames, ", ")
		} else {
			display.Protocol = "Malformed"
			display.Info = fmt.Sprintf("%d bytes", display.Length)
		}
	}

	return display
}

// buildProtocolInfo generates display info from detector metadata
func buildProtocolInfo(result *signatures.DetectionResult, pkt gopacket.Packet, display *components.PacketDisplay) string {
	switch result.Protocol {
	case "SIP":
		// Convert metadata to VoIPData for compatibility
		display.VoIPData = metadataToVoIPData(result.Metadata)

		// Feed SIP packet to offline tracker for RTP-to-CallID mapping
		// Use media_ports and media_ip from detector metadata (parsed from SDP)
		if tracker := GetCallTracker(); tracker != nil && display.VoIPData != nil && display.VoIPData.CallID != "" {
			if mediaPorts, ok := result.Metadata["media_ports"].([]uint16); ok && len(mediaPorts) > 0 {
				// Determine RTP endpoint IP:
				// 1. Prefer media_ip from SDP c= line (most accurate)
				// 2. Fall back to SIP packet source IP
				rtpIP := display.SrcIP
				if mediaIP, ok := result.Metadata["media_ip"].(string); ok && mediaIP != "" {
					rtpIP = mediaIP
				}
				// RegisterMediaPorts returns a synthetic CallID if the endpoint was
				// previously registered for an RTP-only call (enables call merging)
				if syntheticCallID := tracker.RegisterMediaPorts(display.VoIPData.CallID, rtpIP, mediaPorts); syntheticCallID != "" {
					display.VoIPData.MergeFromCallID = syntheticCallID
				}
			}
			// Store From/To info for RTP-created calls to inherit
			if display.VoIPData.From != "" || display.VoIPData.To != "" {
				tracker.RegisterCallPartyInfo(display.VoIPData.CallID, display.VoIPData.From, display.VoIPData.To)
			}
		}

		if firstLine, ok := result.Metadata["first_line"].(string); ok {
			if len(firstLine) > 60 {
				firstLine = firstLine[:60] + "..."
			}
			return firstLine
		}
		return "SIP message"

	case "RTP":
		display.VoIPData = metadataToVoIPData(result.Metadata)

		// Query offline tracker for CallID based on IP/port
		if tracker := GetCallTracker(); tracker != nil && display.VoIPData != nil {
			callID := tracker.GetCallIDForRTPPacket(display.SrcIP, display.SrcPort, display.DstIP, display.DstPort)
			if callID != "" {
				display.VoIPData.CallID = callID
			}
		}

		// If no CallID from SIP, generate synthetic CallID for RTP-only tracking
		// This allows RTP streams to appear in call list even without SIP signaling
		if display.VoIPData != nil && display.VoIPData.CallID == "" && display.VoIPData.SSRC != 0 {
			// Generate synthetic CallID from SSRC
			display.VoIPData.CallID = fmt.Sprintf("rtp-%08x", display.VoIPData.SSRC)

			// Register endpoints so SIP can find and merge this call later
			if tracker := GetCallTracker(); tracker != nil {
				tracker.RegisterRTPOnlyEndpoints(display.VoIPData.CallID, display.SrcIP, display.SrcPort, display.DstIP, display.DstPort)
			}
		}

		// For all RTP-only calls (synthetic CallID), ensure From/To are set
		// This handles both newly created calls AND subsequent packets for existing calls
		if display.VoIPData != nil && strings.HasPrefix(display.VoIPData.CallID, "rtp-") {
			// Use IP:port for From/To since RTP-only calls don't have SIP headers
			display.VoIPData.From = fmt.Sprintf("%s:%s", display.SrcIP, display.SrcPort)
			display.VoIPData.To = fmt.Sprintf("%s:%s", display.DstIP, display.DstPort)
			// Mark as RTP-only by setting a special method indicator
			display.VoIPData.Method = "RTP-ONLY"
		}

		if codec, ok := result.Metadata["codec"].(string); ok {
			return codec
		}
		return "RTP stream"

	case "DNS":
		return "DNS Query/Response"

	case "gRPC", "HTTP2":
		return "gRPC/HTTP2"

	case "SSH":
		if versionStr, ok := result.Metadata["version_string"].(string); ok {
			return versionStr
		}
		return "SSH"

	case "DHCP", "BOOTP":
		if msgType, ok := result.Metadata["message_type"].(string); ok {
			return msgType
		}
		return result.Protocol

	case "NTP":
		if mode, ok := result.Metadata["mode"].(string); ok {
			return "NTP " + mode
		}
		return "NTP"

	case "ICMP":
		if typeName, ok := result.Metadata["type_name"].(string); ok {
			info := typeName
			if codeName, ok := result.Metadata["code_name"].(string); ok && codeName != "" {
				info += " - " + codeName
			}
			return info
		}
		return "ICMP"

	case "IGMP":
		return buildIGMPInfo(result)

	case "ARP":
		if op, ok := result.Metadata["operation"].(string); ok {
			if senderIP, ok := result.Metadata["sender_ip"].(string); ok {
				if targetIP, ok := result.Metadata["target_ip"].(string); ok {
					return fmt.Sprintf("%s: %s -> %s", op, senderIP, targetIP)
				}
			}
			return op
		}
		return "ARP"

	case "FTP":
		return buildFTPInfo(result)

	case "SMTP":
		return buildSMTPInfo(result)

	case "MySQL":
		return buildMySQLInfo(result)

	case "PostgreSQL":
		return buildPostgreSQLInfo(result)

	case "SNMP":
		if version, ok := result.Metadata["version"].(string); ok {
			if pduType, ok := result.Metadata["pdu_type"].(string); ok {
				return version + " " + pduType
			}
			return version
		}
		return "SNMP"

	case "Redis":
		if cmd, ok := result.Metadata["command"].(string); ok {
			return cmd
		}
		if msg, ok := result.Metadata["message"].(string); ok {
			return msg
		}
		if respType, ok := result.Metadata["resp_type"].(string); ok {
			return respType
		}
		return "Redis"

	case "MongoDB":
		if opName, ok := result.Metadata["op_name"].(string); ok {
			return opName
		}
		return "MongoDB"

	case "Telnet":
		if iacCount, ok := result.Metadata["iac_count"].(int); ok {
			return fmt.Sprintf("Telnet negotiation (%d IAC)", iacCount)
		}
		return "Telnet"

	case "POP3":
		return buildPOP3Info(result)

	case "IMAP":
		return buildIMAPInfo(result)

	case "OpenVPN":
		if typeName, ok := result.Metadata["type_name"].(string); ok {
			return typeName
		}
		if opcodeName, ok := result.Metadata["opcode_name"].(string); ok {
			return opcodeName
		}
		return "OpenVPN"

	case "WireGuard":
		if typeName, ok := result.Metadata["type_name"].(string); ok {
			return typeName
		}
		return "WireGuard"

	case "L2TP":
		if packetType, ok := result.Metadata["packet_type"].(string); ok {
			if version, ok := result.Metadata["version"].(uint16); ok {
				return fmt.Sprintf("L2TPv%d %s", version, packetType)
			}
			return packetType
		}
		return "L2TP"

	case "PPTP":
		if ctrlType, ok := result.Metadata["control_type_name"].(string); ok {
			return ctrlType
		}
		if category, ok := result.Metadata["category"].(string); ok {
			return category
		}
		return "PPTP"

	case "IKEv2", "IKEv1", "IKE":
		if exchangeName, ok := result.Metadata["exchange_name"].(string); ok {
			if isResp, ok := result.Metadata["is_response"].(bool); ok {
				if isResp {
					return exchangeName + " (response)"
				}
				return exchangeName + " (request)"
			}
			return exchangeName
		}
		if version, ok := result.Metadata["version"].(float64); ok {
			return fmt.Sprintf("IKEv%.1f", version)
		}
		return result.Protocol

	default:
		return result.Protocol
	}
}

// buildIGMPInfo extracts IGMP info from gopacket layer
func buildIGMPInfo(result *signatures.DetectionResult) string {
	// Default IGMP info
	return "IGMP"
}

// buildFTPInfo builds FTP info from metadata
func buildFTPInfo(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		switch msgType {
		case "response":
			if code, ok := result.Metadata["code"].(int); ok {
				if msg, ok := result.Metadata["message"].(string); ok {
					return fmt.Sprintf("%d %s", code, msg)
				}
				return fmt.Sprintf("%d", code)
			}
			return "Response"
		case "command":
			if cmd, ok := result.Metadata["command"].(string); ok {
				return cmd
			}
			return "Command"
		}
	}
	return "FTP"
}

// buildSMTPInfo builds SMTP info from metadata
func buildSMTPInfo(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		switch msgType {
		case "response":
			if code, ok := result.Metadata["code"].(int); ok {
				return fmt.Sprintf("%d", code)
			}
			return "Response"
		case "command":
			if cmd, ok := result.Metadata["command"].(string); ok {
				return cmd
			}
			return "Command"
		}
	}
	return "SMTP"
}

// buildMySQLInfo builds MySQL info from metadata
func buildMySQLInfo(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		switch msgType {
		case "handshake":
			if version, ok := result.Metadata["server_version"].(string); ok {
				return "Handshake: " + version
			}
			return "Handshake"
		case "command":
			if cmdName, ok := result.Metadata["command_name"].(string); ok {
				return cmdName
			}
			return "Command"
		default:
			return msgType
		}
	}
	return "MySQL"
}

// buildPostgreSQLInfo builds PostgreSQL info from metadata
func buildPostgreSQLInfo(result *signatures.DetectionResult) string {
	if _, ok := result.Metadata["type"].(string); ok {
		if msg, ok := result.Metadata["message"].(string); ok {
			return msg
		}
		if msgName, ok := result.Metadata["message_name"].(string); ok {
			return msgName
		}
	}
	return "PostgreSQL"
}

// buildPOP3Info builds POP3 info from metadata
func buildPOP3Info(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		if msgType == "response" {
			if status, ok := result.Metadata["status"].(string); ok {
				return status
			}
			return "Response"
		} else if msgType == "command" {
			if cmd, ok := result.Metadata["command"].(string); ok {
				return cmd
			}
			return "Command"
		}
	}
	return "POP3"
}

// buildIMAPInfo builds IMAP info from metadata
func buildIMAPInfo(result *signatures.DetectionResult) string {
	if msgType, ok := result.Metadata["type"].(string); ok {
		if msgType == "response" {
			if respType, ok := result.Metadata["response_type"].(string); ok {
				return respType
			}
			if status, ok := result.Metadata["status"].(string); ok {
				return status
			}
			return "Response"
		} else if msgType == "command" {
			if cmd, ok := result.Metadata["command"].(string); ok {
				return cmd
			}
			return "Command"
		}
	}
	return "IMAP"
}

// metadataToVoIPData converts detector metadata to VoIPMetadata for compatibility
func metadataToVoIPData(metadata map[string]interface{}) *components.VoIPMetadata {
	voipData := &components.VoIPMetadata{
		Headers: make(map[string]string),
	}

	// Convert common fields
	if method, ok := metadata["method"].(string); ok {
		voipData.Method = method
	}
	if from, ok := metadata["from"].(string); ok {
		voipData.From = from
	}
	if to, ok := metadata["to"].(string); ok {
		voipData.To = to
	}
	if callID, ok := metadata["call_id"].(string); ok {
		voipData.CallID = callID
	}
	if user, ok := metadata["from_user"].(string); ok {
		voipData.User = user
	}
	if fromTag, ok := metadata["from_tag"].(string); ok {
		voipData.FromTag = fromTag
	}
	if toTag, ok := metadata["to_tag"].(string); ok {
		voipData.ToTag = toTag
	}

	// SIP response status code (e.g., 200 for "200 OK")
	if statusCode, ok := metadata["status_code"].(string); ok {
		if code, err := strconv.Atoi(statusCode); err == nil {
			voipData.Status = code
		}
	}

	// RTP-specific fields
	if ssrc, ok := metadata["ssrc"].(uint32); ok {
		voipData.SSRC = ssrc
		voipData.IsRTP = true
	}
	if seqNum, ok := metadata["sequence_number"].(uint16); ok {
		voipData.SeqNumber = seqNum
	}
	if codec, ok := metadata["codec"].(string); ok {
		voipData.Codec = codec
	}

	// Convert headers map
	if headers, ok := metadata["headers"].(map[string]string); ok {
		voipData.Headers = headers
	}

	return voipData
}

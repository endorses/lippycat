package voip

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// CallState represents the state of a VoIP call
type CallState int

const (
	CallStateNew CallState = iota
	CallStateRinging
	CallStateActive
	CallStateEnded
	CallStateFailed
)

func (cs CallState) String() string {
	switch cs {
	case CallStateNew:
		return "NEW"
	case CallStateRinging:
		return "RINGING"
	case CallStateActive:
		return "ACTIVE"
	case CallStateEnded:
		return "ENDED"
	case CallStateFailed:
		return "FAILED"
	default:
		return "UNKNOWN"
	}
}

// AggregatedCall represents a call tracked by the processor
type AggregatedCall struct {
	CallID         string
	From           string
	To             string
	State          CallState
	StartTime      time.Time
	EndTime        time.Time
	LastPacketTime time.Time // Timestamp of last packet seen for this call
	RTPStats       *RTPQualityStats
	Hunters        []string // Which hunters saw this call
	PacketCount    int
	SIPMethod      string // Last SIP method seen
}

// RTPQualityStats contains RTP quality metrics
type RTPQualityStats struct {
	PacketLoss    float64
	Jitter        float64
	MOS           float64 // Mean Opinion Score
	Codec         string
	TotalPackets  int
	LostPackets   int
	LastSeqNum    uint16
	LastTimestamp uint32
}

// CallAggregator aggregates call state from packet streams
type CallAggregator struct {
	calls     map[string]*AggregatedCall // callID -> call state
	callRing  []string                   // Ring buffer of CallIDs in chronological order
	ringHead  int                        // Current position in ring buffer
	ringCount int                        // Number of calls in ring buffer
	maxCalls  int                        // Maximum calls to keep (ring buffer size)
	mu        sync.RWMutex
}

// NewCallAggregator creates a new call aggregator with default capacity (1000 calls)
func NewCallAggregator() *CallAggregator {
	return NewCallAggregatorWithCapacity(1000)
}

// NewCallAggregatorWithCapacity creates a new call aggregator with specified ring buffer capacity.
// This is primarily useful for testing eviction behavior with smaller buffers.
func NewCallAggregatorWithCapacity(maxCalls int) *CallAggregator {
	if maxCalls <= 0 {
		maxCalls = 1000
	}
	return &CallAggregator{
		calls:     make(map[string]*AggregatedCall),
		callRing:  make([]string, maxCalls),
		ringHead:  0,
		ringCount: 0,
		maxCalls:  maxCalls,
	}
}

// ProcessPacket updates call state based on a received packet
func (ca *CallAggregator) ProcessPacket(packet *data.CapturedPacket, hunterID string) {
	if packet.Metadata == nil {
		return
	}

	// Extract timestamp from packet
	timestamp := time.Unix(0, packet.TimestampNs)

	// Handle SIP packets
	if packet.Metadata.Sip != nil {
		ca.processSIPPacket(packet, hunterID, timestamp)
	}

	// Handle RTP packets
	if packet.Metadata.Rtp != nil {
		ca.processRTPPacket(packet, hunterID, timestamp)
	}
}

// ProcessPacketDisplay updates call state from a PacketDisplay (for TUI offline mode)
func (ca *CallAggregator) ProcessPacketDisplay(pkt *types.PacketDisplay, nodeID string) {
	if pkt.VoIPData == nil {
		return
	}

	voip := pkt.VoIPData
	// Use packet timestamp from capture
	timestamp := pkt.Timestamp

	// Handle SIP packets
	if voip.CallID != "" && (voip.Method != "" || voip.Status > 0) {
		// Convert types.VoIPMetadata to data.SIPMetadata format
		// Validate Status can fit in uint32 (int is either 32 or 64 bit depending on platform)
		var responseCode uint32
		if voip.Status < 0 || (uint64(voip.Status) > uint64(^uint32(0))) {
			logger.Warn("SIP response code out of uint32 range, clamping",
				"original_status", voip.Status,
				"clamped_to", 0)
			responseCode = 0
		} else {
			responseCode = uint32(voip.Status)
		}

		sipMeta := &data.SIPMetadata{
			CallId:       voip.CallID,
			Method:       voip.Method,
			ResponseCode: responseCode,
			FromUser:     voip.From,
			ToUser:       voip.To,
			FromUri:      voip.From, // VoIPMetadata doesn't distinguish between user and URI
			ToUri:        voip.To,
		}

		// Create a minimal CapturedPacket for compatibility
		capturedPkt := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: sipMeta,
			},
		}

		ca.processSIPPacket(capturedPkt, nodeID, timestamp)
	}

	// Handle RTP packets
	if voip.IsRTP && voip.CallID != "" {
		// Convert types.VoIPMetadata to data.RTPMetadata format
		rtpMeta := &data.RTPMetadata{
			Ssrc:        voip.SSRC,
			PayloadType: uint32(voip.PayloadType),
			Sequence:    uint32(voip.SequenceNum),
			Timestamp:   voip.Timestamp,
		}

		// Create a minimal CapturedPacket with both SIP (for CallID) and RTP metadata
		capturedPkt := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId: voip.CallID,
				},
				Rtp: rtpMeta,
			},
		}

		// Pass codec through via the packet's detail map (for offline mode)
		if voip.Codec != "" && voip.Codec != "Unknown" {
			ca.processRTPPacketWithCodec(capturedPkt, nodeID, timestamp, voip.Codec)
		} else {
			ca.processRTPPacket(capturedPkt, nodeID, timestamp)
		}
	}
}

func (ca *CallAggregator) processSIPPacket(packet *data.CapturedPacket, hunterID string, timestamp time.Time) {
	sip := packet.Metadata.Sip
	if sip.CallId == "" {
		return
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	call, exists := ca.calls[sip.CallId]
	if !exists {
		// Prefer full URIs if available, fallback to username only
		from := sip.FromUri
		if from == "" {
			from = sip.FromUser
		}
		to := sip.ToUri
		if to == "" {
			to = sip.ToUser
		}

		call = &AggregatedCall{
			CallID:         sip.CallId,
			From:           from,
			To:             to,
			State:          CallStateNew,
			StartTime:      timestamp, // Use packet timestamp instead of time.Now()
			LastPacketTime: timestamp, // Initialize with first packet timestamp
			Hunters:        make([]string, 0),
			// Note: RTPStats is intentionally not initialized here.
			// It will be created when the first RTP packet arrives,
			// allowing proper codec detection from RTP payload type.
		}

		// Add to ring buffer (FIFO)
		if ca.ringCount >= ca.maxCalls {
			// Ring buffer is full, remove oldest call
			oldestCallID := ca.callRing[ca.ringHead]
			delete(ca.calls, oldestCallID)
			logger.Debug("Removed oldest call from ring buffer (buffer full)",
				"call_id", oldestCallID)
		} else {
			ca.ringCount++
		}

		// Add new call to ring buffer
		ca.callRing[ca.ringHead] = sip.CallId
		ca.ringHead = (ca.ringHead + 1) % ca.maxCalls

		ca.calls[sip.CallId] = call
		logger.Debug("New call detected",
			"call_id", sip.CallId,
			"from", sip.FromUser,
			"to", sip.ToUser,
			"hunter", hunterID)
	} else {
		// Call already exists (may have been created from RTP)
		// Update From/To if they're empty and we have SIP data
		from := sip.FromUri
		if from == "" {
			from = sip.FromUser
		}
		to := sip.ToUri
		if to == "" {
			to = sip.ToUser
		}

		if call.From == "" && from != "" {
			call.From = from
			logger.Debug("Updated call From from SIP packet",
				"call_id", sip.CallId,
				"from", from)
		}
		if call.To == "" && to != "" {
			call.To = to
			logger.Debug("Updated call To from SIP packet",
				"call_id", sip.CallId,
				"to", to)
		}
	}

	// Add hunter if not already tracking
	if !contains(call.Hunters, hunterID) {
		call.Hunters = append(call.Hunters, hunterID)
	}

	// Update last packet time
	call.LastPacketTime = timestamp

	// Update state based on SIP method
	call.SIPMethod = sip.Method
	ca.updateCallState(call, sip.Method, sip.ResponseCode, timestamp)
	call.PacketCount++
}

func (ca *CallAggregator) updateCallState(call *AggregatedCall, method string, responseCode uint32, timestamp time.Time) {
	oldState := call.State

	switch method {
	case "INVITE":
		if call.State == CallStateNew {
			call.State = CallStateRinging
		}
	case "ACK":
		if call.State == CallStateRinging {
			call.State = CallStateActive
		}
	case "BYE":
		call.State = CallStateEnded
		call.EndTime = timestamp // Use packet timestamp instead of time.Now()
	case "CANCEL":
		call.State = CallStateFailed
		call.EndTime = timestamp // Use packet timestamp instead of time.Now()
	}

	// Handle responses
	if responseCode >= 200 && responseCode < 300 {
		if call.State == CallStateRinging {
			call.State = CallStateActive
		}
	} else if responseCode >= 400 {
		call.State = CallStateFailed
		call.EndTime = timestamp // Use packet timestamp instead of time.Now()
	}

	// Log state transitions
	if oldState != call.State {
		logger.Info("Call state transition",
			"call_id", call.CallID,
			"from_state", oldState.String(),
			"to_state", call.State.String(),
			"method", method,
			"response_code", responseCode)
	}
}

// processRTPPacketWithCodec processes an RTP packet with pre-extracted codec information
func (ca *CallAggregator) processRTPPacketWithCodec(packet *data.CapturedPacket, hunterID string, timestamp time.Time, codec string) {
	ca.processRTPPacketInternal(packet, hunterID, timestamp, codec)
}

func (ca *CallAggregator) processRTPPacket(packet *data.CapturedPacket, hunterID string, timestamp time.Time) {
	ca.processRTPPacketInternal(packet, hunterID, timestamp, "")
}

func (ca *CallAggregator) processRTPPacketInternal(packet *data.CapturedPacket, hunterID string, timestamp time.Time, preExtractedCodec string) {
	rtp := packet.Metadata.Rtp
	if rtp == nil {
		return
	}

	// Get CallID from SIP metadata (hunter includes this for RTP association)
	sip := packet.Metadata.Sip
	if sip == nil || sip.CallId == "" {
		logger.Debug("RTP packet without CallID, skipping quality tracking",
			"ssrc", rtp.Ssrc,
			"hunter", hunterID)
		return
	}

	callID := sip.CallId

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Find or create the associated call
	call, exists := ca.calls[callID]
	if !exists {
		// Create a minimal call entry from RTP - SIP details will be filled in later if/when SIP arrives
		call = &AggregatedCall{
			CallID:         callID,
			State:          CallStateActive, // Assume active since we're seeing RTP
			StartTime:      timestamp,
			LastPacketTime: timestamp,
			Hunters:        []string{hunterID},
			// Note: From/To will be empty until SIP packet arrives
			// Note: RTPStats is intentionally not initialized here - will be done below
		}
		ca.calls[callID] = call
		logger.Debug("Created call entry from RTP packet",
			"call_id", callID,
			"ssrc", rtp.Ssrc,
			"hunter", hunterID)
	}

	// Update last packet time
	call.LastPacketTime = timestamp

	// Initialize RTP stats if not already done
	if call.RTPStats == nil {
		// Validate RTP sequence number fits in uint16
		var lastSeq uint16
		if rtp.Sequence > uint32(^uint16(0)) {
			logger.Warn("RTP sequence number out of uint16 range, truncating",
				"original_seq", rtp.Sequence,
				"truncated_to", uint16(rtp.Sequence))
			lastSeq = uint16(rtp.Sequence) // Truncate to lower 16 bits
		} else {
			lastSeq = uint16(rtp.Sequence)
		}

		call.RTPStats = &RTPQualityStats{
			Codec:         "Unknown",
			LastSeqNum:    lastSeq,
			LastTimestamp: rtp.Timestamp,
		}
		logger.Debug("Initialized RTP stats for call",
			"call_id", callID,
			"initial_seq", lastSeq)
	}

	stats := call.RTPStats

	// Extract codec - prefer pre-extracted codec (from packet detector in offline mode)
	if stats.Codec == "Unknown" || stats.Codec == "" {
		if preExtractedCodec != "" && preExtractedCodec != "Unknown" {
			stats.Codec = preExtractedCodec
			logger.Debug("Using pre-extracted codec from packet detector",
				"call_id", callID,
				"codec", stats.Codec)
		} else {
			// Validate payload type fits in uint8
			var payloadType uint8
			if rtp.PayloadType > uint32(^uint8(0)) {
				logger.Warn("RTP payload type out of uint8 range, setting to Unknown",
					"original_type", rtp.PayloadType)
				payloadType = 255 // Use max uint8 value for unknown
			} else {
				payloadType = uint8(rtp.PayloadType)
			}
			stats.Codec = payloadTypeToCodec(payloadType)
			logger.Debug("Detected codec from RTP payload type",
				"call_id", callID,
				"payload_type", payloadType,
				"codec", stats.Codec)
		}
	}

	// Detect packet loss from sequence number gaps
	if stats.TotalPackets > 0 {
		// Validate RTP sequence number fits in uint16
		var actualSeq uint16
		if rtp.Sequence > uint32(^uint16(0)) {
			logger.Warn("RTP sequence number out of uint16 range, truncating for gap detection",
				"original_seq", rtp.Sequence,
				"truncated_to", uint16(rtp.Sequence))
			actualSeq = uint16(rtp.Sequence) // Truncate to lower 16 bits
		} else {
			actualSeq = uint16(rtp.Sequence)
		}

		expectedSeq := stats.LastSeqNum + 1

		// Handle sequence number wraparound (uint16 overflow)
		var gap int
		if actualSeq >= expectedSeq {
			gap = int(actualSeq - expectedSeq)
		} else {
			// Wraparound occurred
			gap = int(65535 - uint32(expectedSeq) + uint32(actualSeq) + 1)
		}

		if gap > 0 {
			// Detect out-of-order or lost packets
			if gap < 1000 { // Sanity check: ignore large gaps (likely restart)
				stats.LostPackets += gap
				logger.Debug("Detected packet loss",
					"call_id", callID,
					"expected_seq", expectedSeq,
					"actual_seq", actualSeq,
					"gap", gap,
					"total_lost", stats.LostPackets)
			}
		}

		// Update LastSeqNum for next comparison
		stats.LastSeqNum = actualSeq
	} else {
		// First packet - just initialize LastSeqNum
		if rtp.Sequence > uint32(^uint16(0)) {
			logger.Warn("RTP sequence number out of uint16 range, truncating",
				"original_seq", rtp.Sequence,
				"truncated_to", uint16(rtp.Sequence))
			stats.LastSeqNum = uint16(rtp.Sequence) // Truncate to lower 16 bits
		} else {
			stats.LastSeqNum = uint16(rtp.Sequence)
		}
	}

	stats.TotalPackets++

	// Calculate packet loss percentage
	if stats.TotalPackets > 0 {
		stats.PacketLoss = (float64(stats.LostPackets) / float64(stats.TotalPackets)) * 100.0
	}

	// Calculate jitter using RFC 3550 algorithm
	if stats.TotalPackets > 1 && stats.LastTimestamp != 0 {
		// Calculate inter-arrival jitter
		// J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
		// where D is the difference in packet spacing

		timestampDiff := int64(rtp.Timestamp) - int64(stats.LastTimestamp)
		timestampDiff = max(-timestampDiff, timestampDiff)

		// Convert to milliseconds (assuming 8kHz clock rate for most codecs)
		timestampDiffMs := float64(timestampDiff) / 8.0

		// Update jitter with smoothing factor (1/16 as per RFC 3550)
		stats.Jitter = stats.Jitter + (timestampDiffMs-stats.Jitter)/16.0
	}

	stats.LastTimestamp = rtp.Timestamp

	// Calculate MOS (Mean Opinion Score) based on packet loss and jitter
	stats.MOS = calculateMOS(stats.PacketLoss, stats.Jitter)

	call.PacketCount++

	logger.Debug("Updated RTP stats",
		"call_id", callID,
		"codec", stats.Codec,
		"total_packets", stats.TotalPackets,
		"lost_packets", stats.LostPackets,
		"packet_loss_pct", stats.PacketLoss,
		"jitter_ms", stats.Jitter,
		"mos", stats.MOS)
}

// GetCalls returns all tracked calls
func (ca *CallAggregator) GetCalls() []AggregatedCall {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	calls := make([]AggregatedCall, 0, len(ca.calls))
	for _, call := range ca.calls {
		// Create a deep copy to avoid race conditions
		calls = append(calls, ca.deepCopyCall(call))
	}

	return calls
}

// GetActiveCalls returns only active calls (not ended or failed)
func (ca *CallAggregator) GetActiveCalls() []AggregatedCall {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	calls := make([]AggregatedCall, 0)
	for _, call := range ca.calls {
		if call.State != CallStateEnded && call.State != CallStateFailed {
			// Create a deep copy to avoid race conditions
			calls = append(calls, ca.deepCopyCall(call))
		}
	}

	return calls
}

// GetCall returns a specific call by ID
func (ca *CallAggregator) GetCall(callID string) (*AggregatedCall, bool) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	call, exists := ca.calls[callID]
	if !exists {
		return nil, false
	}

	// Return a deep copy to avoid race conditions
	callCopy := ca.deepCopyCall(call)
	return &callCopy, true
}

// GetCallCount returns the total number of tracked calls
func (ca *CallAggregator) GetCallCount() int {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return len(ca.calls)
}

// deepCopyCall creates a deep copy of an AggregatedCall to avoid race conditions.
// Caller must hold at least a read lock (ca.mu.RLock()).
func (ca *CallAggregator) deepCopyCall(call *AggregatedCall) AggregatedCall {
	callCopy := AggregatedCall{
		CallID:         call.CallID,
		From:           call.From,
		To:             call.To,
		State:          call.State,
		StartTime:      call.StartTime,
		EndTime:        call.EndTime,
		LastPacketTime: call.LastPacketTime,
		PacketCount:    call.PacketCount,
		SIPMethod:      call.SIPMethod,
	}

	// Deep copy pointer fields (RTPStats)
	if call.RTPStats != nil {
		rtpCopy := *call.RTPStats
		callCopy.RTPStats = &rtpCopy
	}

	// Deep copy slice fields (Hunters)
	if len(call.Hunters) > 0 {
		callCopy.Hunters = make([]string, len(call.Hunters))
		copy(callCopy.Hunters, call.Hunters)
	}

	return callCopy
}

// CleanupEndedCalls removes ended calls older than the specified duration
// NOTE: Ring buffer now handles call cleanup (FIFO when buffer is full)
// This function is kept for API compatibility but does not expire calls based on time
func (ca *CallAggregator) CleanupEndedCalls(maxAge time.Duration) int {
	return 0
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// payloadTypeToCodec maps RTP payload type to codec name
// Based on IANA RTP Payload Types: https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml
func payloadTypeToCodec(pt uint8) string {
	codecs := map[uint8]string{
		0:   "G.711 µ-law",
		3:   "GSM",
		4:   "G.723",
		5:   "DVI4 8kHz",
		6:   "DVI4 16kHz",
		7:   "LPC",
		8:   "G.711 A-law",
		9:   "G.722",
		10:  "L16 Stereo",
		11:  "L16 Mono",
		12:  "QCELP",
		13:  "Comfort Noise",
		14:  "MPA",
		15:  "G.728",
		16:  "DVI4 11kHz",
		17:  "DVI4 22kHz",
		18:  "G.729",
		25:  "CelB",
		26:  "JPEG",
		28:  "nv",
		31:  "H.261",
		32:  "MPV",
		33:  "MP2T",
		34:  "H.263",
		101: "telephone-event", // DTMF
	}

	if codec, ok := codecs[pt]; ok {
		return codec
	}

	// Dynamic payload types (96-127) require SDP negotiation to determine codec
	if pt >= 96 && pt <= 127 {
		return "Dynamic"
	}

	return "Unknown"
}

// calculateMOS computes Mean Opinion Score from packet loss and jitter
// Uses the E-model (ITU-T G.107) simplified calculation
// MOS scale: 1.0 (bad) to 5.0 (excellent)
func calculateMOS(packetLoss, jitter float64) float64 {
	// Clamp inputs to reasonable ranges
	packetLoss = max(0, packetLoss)
	if packetLoss > 100 {
		packetLoss = 100
	}
	jitter = max(0, jitter)

	// Calculate R-factor (transmission rating factor)
	// R = R0 - Is - Id - Ie + A
	// Where:
	// R0 = 93.2 (base quality)
	// Is = simultaneous impairment (0 for VoIP)
	// Id = delay impairment (from jitter)
	// Ie = equipment impairment (from packet loss and codec)
	// A = advantage factor (0 for VoIP)

	// Delay impairment from jitter
	// Simplified: Id increases with jitter (threshold at 150ms)
	delayImpairment := 0.0
	if jitter > 150 {
		delayImpairment = (jitter - 150) / 10.0
	} else {
		delayImpairment = jitter / 40.0
	}

	// Equipment impairment from packet loss
	// Simplified: Ie = packet_loss_pct * factor
	equipmentImpairment := packetLoss * 2.5

	// Calculate R-factor
	rFactor := 93.2 - delayImpairment - equipmentImpairment

	// Clamp R-factor to valid range (0-100)
	rFactor = max(0, rFactor)
	if rFactor > 100 {
		rFactor = 100
	}

	// Convert R-factor to MOS
	// MOS = 1 + 0.035*R + 7*10^-6*R*(R-60)*(100-R)
	var mos float64
	if rFactor < 0 {
		mos = 1.0
	} else if rFactor > 100 {
		mos = 4.5
	} else {
		mos = 1.0 + 0.035*rFactor + 7e-6*rFactor*(rFactor-60)*(100-rFactor)
	}

	// Clamp MOS to valid range (1.0-5.0)
	if mos < 1.0 {
		mos = 1.0
	}
	if mos > 5.0 {
		mos = 5.0
	}

	return mos
}

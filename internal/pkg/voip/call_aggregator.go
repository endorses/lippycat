package voip

import (
	"container/list"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// Merge diagnostic counters
var (
	mergeAttempts       int64 // Times mergeRTPOnlyCall was called
	mergeSyntheticFound int64 // Synthetic call was found
	mergeRealFound      int64 // Real call was found
	mergeSuccess        int64 // Merge completed successfully
)

// From/To diagnostic counters
var (
	callsCreatedTotal     int64 // Total calls created from INVITE
	callsCreatedEmptyFrom int64 // Calls created with empty From
	callsCreatedEmptyTo   int64 // Calls created with empty To
	callsUpdatedFrom      int64 // Calls where From was updated from empty
	callsUpdatedTo        int64 // Calls where To was updated from empty
)

// GetFromToStats returns From/To diagnostic statistics
func GetFromToStats() (total, emptyFrom, emptyTo, updatedFrom, updatedTo int64) {
	return atomic.LoadInt64(&callsCreatedTotal),
		atomic.LoadInt64(&callsCreatedEmptyFrom),
		atomic.LoadInt64(&callsCreatedEmptyTo),
		atomic.LoadInt64(&callsUpdatedFrom),
		atomic.LoadInt64(&callsUpdatedTo)
}

// GetMergeAggregatorStats returns merge statistics from CallAggregator
func GetMergeAggregatorStats() (attempts, syntheticFound, realFound, success int64) {
	return atomic.LoadInt64(&mergeAttempts),
		atomic.LoadInt64(&mergeSyntheticFound),
		atomic.LoadInt64(&mergeRealFound),
		atomic.LoadInt64(&mergeSuccess)
}

// CallState represents the state of a VoIP call
type CallState int

const (
	CallStateNew      CallState = iota
	CallStateTrying             // INVITE sent, waiting for response
	CallStateRinging            // 180 Ringing - phone is actually ringing
	CallStateProgress           // 183 Session Progress - early media established
	CallStateActive
	CallStateEnding // BYE received, in timewait period (still accepting RTP)
	CallStateEnded
	CallStateFailed    // Actual failure (4xx/5xx errors except 486)
	CallStateCancelled // INVITE cancelled before answer (CANCEL method)
	CallStateBusy      // Callee busy (486 Busy Here)
	CallStateRTPOnly   // RTP stream detected without SIP signaling
)

// DefaultBYETimewait is the default timewait period after BYE (30 seconds)
// During this period, the call continues accepting RTP packets for trailing media.
const DefaultBYETimewait = 30 * time.Second

func (cs CallState) String() string {
	switch cs {
	case CallStateNew:
		return "NEW"
	case CallStateTrying:
		return "TRYING"
	case CallStateRinging:
		return "RINGING"
	case CallStateProgress:
		return "PROGRESS"
	case CallStateActive:
		return "ACTIVE"
	case CallStateEnding:
		return "ENDING"
	case CallStateEnded:
		return "ENDED"
	case CallStateFailed:
		return "FAILED"
	case CallStateCancelled:
		return "CANCELLED"
	case CallStateBusy:
		return "BUSY"
	case CallStateRTPOnly:
		return "RTP-ONLY"
	default:
		return "UNKNOWN"
	}
}

// AggregatedCall represents a call tracked by the processor
type AggregatedCall struct {
	CallID           string
	From             string
	To               string
	State            CallState
	StartTime        time.Time
	EndTime          time.Time
	LastPacketTime   time.Time // Timestamp of last packet seen for this call
	TimewaitStart    time.Time // When BYE timewait period started (for CallStateEnding)
	LastResponseCode uint32    // Last SIP response code (especially for failed/busy calls)
	RTPStats         *RTPQualityStats
	Hunters          []string // Which hunters saw this call
	PacketCount      int
	SIPMethod        string // Last SIP method seen
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
	calls       map[string]*AggregatedCall // callID -> call state
	lruList     *list.List                 // LRU list (front = most recently used)
	lruIndex    map[string]*list.Element   // callID -> list element for O(1) lookup
	maxCalls    int                        // Maximum calls to keep
	byeTimewait time.Duration              // How long to wait after BYE before transitioning to ENDED
	mu          sync.RWMutex
	cachedCalls []AggregatedCall // Cached sorted copy of calls
	callsDirty  bool             // True if cache needs rebuild
}

// NewCallAggregator creates a new call aggregator with default capacity (1000 calls)
func NewCallAggregator() *CallAggregator {
	return NewCallAggregatorWithCapacity(1000)
}

// NewCallAggregatorWithCapacity creates a new call aggregator with specified capacity.
// This is primarily useful for testing eviction behavior with smaller buffers.
func NewCallAggregatorWithCapacity(maxCalls int) *CallAggregator {
	if maxCalls <= 0 {
		maxCalls = 1000
	}
	return &CallAggregator{
		calls:       make(map[string]*AggregatedCall),
		lruList:     list.New(),
		lruIndex:    make(map[string]*list.Element),
		maxCalls:    maxCalls,
		byeTimewait: DefaultBYETimewait,
		callsDirty:  true, // Start dirty so first GetCalls builds cache
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

	// Handle SIP packets (but not RTP-ONLY synthetic calls)
	if voip.CallID != "" && voip.Method != "RTP-ONLY" && (voip.Method != "" || voip.Status > 0) {
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

		// Process SIP packet first to create/update the call
		ca.processSIPPacket(capturedPkt, nodeID, timestamp)

		// Now merge from RTP-only call if needed (after real call exists)
		if voip.MergeFromCallID != "" {
			ca.mergeRTPOnlyCall(voip.MergeFromCallID, voip.CallID)
		}
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
		// Include From/To for all calls - this enables CallAggregator to populate
		// From/To when creating calls from RTP with SIP CallIDs
		sipMeta := &data.SIPMetadata{
			CallId:  voip.CallID,
			FromUri: voip.From,
			ToUri:   voip.To,
		}
		// For RTP-only calls (synthetic CallID), mark the method
		if strings.HasPrefix(voip.CallID, "rtp-") {
			sipMeta.Method = "RTP-ONLY"
		}

		capturedPkt := &data.CapturedPacket{
			Metadata: &data.PacketMetadata{
				Sip: sipMeta,
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
		// Only create new calls for INVITE requests
		// Other methods (OPTIONS, REGISTER, SUBSCRIBE, BYE, ACK, etc.) don't create calls
		// Responses also don't create calls - they can only update existing calls
		// (If we miss the INVITE, we'll create the call from RTP when SDP is parsed)
		if sip.Method != "INVITE" {
			return
		}

		ca.callsDirty = true // Invalidate cache on mutation

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

		// Evict LRU (least recently used) if at capacity
		if ca.lruList.Len() >= ca.maxCalls {
			// Remove from back (least recently used)
			oldest := ca.lruList.Back()
			if oldest != nil {
				oldestCallID := oldest.Value.(string)
				ca.lruList.Remove(oldest)
				delete(ca.lruIndex, oldestCallID)
				delete(ca.calls, oldestCallID)
				logger.Debug("Evicted LRU call (buffer full)",
					"call_id", oldestCallID)
			}
		}

		// Add new call to front (most recently used)
		elem := ca.lruList.PushFront(sip.CallId)
		ca.lruIndex[sip.CallId] = elem

		ca.calls[sip.CallId] = call

		// Track From/To population statistics
		atomic.AddInt64(&callsCreatedTotal, 1)
		if from == "" {
			atomic.AddInt64(&callsCreatedEmptyFrom, 1)
		}
		if to == "" {
			atomic.AddInt64(&callsCreatedEmptyTo, 1)
		}

		// Log with full From/To values for debugging
		if from == "" || to == "" {
			logger.Warn("New call created with empty From/To",
				"call_id", SanitizeCallIDForLogging(sip.CallId),
				"from_uri", sip.FromUri,
				"from_user", sip.FromUser,
				"to_uri", sip.ToUri,
				"to_user", sip.ToUser,
				"method", sip.Method,
				"hunter", hunterID)
		} else {
			logger.Debug("New call detected",
				"call_id", SanitizeCallIDForLogging(sip.CallId),
				"from", from,
				"to", to,
				"method", sip.Method,
				"hunter", hunterID)
		}
	} else {
		ca.callsDirty = true // Invalidate cache on mutation
		// Move existing call to front (most recently used)
		if elem, ok := ca.lruIndex[sip.CallId]; ok {
			ca.lruList.MoveToFront(elem)
		}
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
			atomic.AddInt64(&callsUpdatedFrom, 1)
			logger.Info("Updated call From from SIP packet",
				"call_id", SanitizeCallIDForLogging(sip.CallId),
				"from", from,
				"method", sip.Method)
		}
		if call.To == "" && to != "" {
			call.To = to
			atomic.AddInt64(&callsUpdatedTo, 1)
			logger.Info("Updated call To from SIP packet",
				"call_id", SanitizeCallIDForLogging(sip.CallId),
				"to", to,
				"method", sip.Method)
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
			call.State = CallStateTrying
		}
	case "ACK":
		if call.State == CallStateTrying || call.State == CallStateRinging || call.State == CallStateProgress {
			call.State = CallStateActive
		}
	case "BYE":
		// Transition to ENDING state with timewait instead of immediate ENDED.
		// This allows trailing RTP packets to be captured after BYE.
		// The call will transition to ENDED after the timewait period expires
		// (checked by IsTimewaitExpired and CompleteTimewait methods).
		// Don't transition from terminal states (Failed, Cancelled, Busy, Ended, Ending).
		switch call.State {
		case CallStateEnding, CallStateEnded, CallStateFailed, CallStateCancelled, CallStateBusy:
			// Already in a terminal state, ignore BYE
		default:
			call.State = CallStateEnding
			call.TimewaitStart = timestamp
			call.EndTime = timestamp // EndTime is set when BYE is received
		}
	case "CANCEL":
		// Don't transition from terminal states
		switch call.State {
		case CallStateEnded, CallStateFailed, CallStateCancelled, CallStateBusy:
			// Already in a terminal state, ignore CANCEL
		default:
			call.State = CallStateCancelled
			call.EndTime = timestamp // Use packet timestamp instead of time.Now()
		}
	}

	// Handle provisional responses (1xx)
	if responseCode == 180 {
		// 180 Ringing - phone is actually ringing
		if call.State == CallStateTrying {
			call.State = CallStateRinging
		}
	} else if responseCode == 183 {
		// 183 Session Progress - early media established
		if call.State == CallStateTrying || call.State == CallStateRinging {
			call.State = CallStateProgress
		}
	}

	// Handle success responses (2xx)
	if responseCode >= 200 && responseCode < 300 {
		if call.State == CallStateTrying || call.State == CallStateRinging || call.State == CallStateProgress {
			call.State = CallStateActive
		}
	} else if responseCode == 486 {
		// 486 Busy Here - callee is busy
		call.State = CallStateBusy
		call.EndTime = timestamp
	} else if responseCode == 487 {
		// 487 Request Terminated - server's response to CANCEL
		call.State = CallStateCancelled
		call.EndTime = timestamp
	} else if responseCode >= 400 {
		// Other 4xx/5xx errors - store the code for display (e.g., "E:401", "E:503")
		call.State = CallStateFailed
		call.LastResponseCode = responseCode
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
	ca.callsDirty = true // Invalidate cache on potential mutation

	// Find or create the associated call
	call, exists := ca.calls[callID]
	if !exists {
		// Determine if this is an RTP-only call (synthetic CallID)
		isRTPOnly := strings.HasPrefix(callID, "rtp-")
		callState := CallStateActive
		if isRTPOnly {
			callState = CallStateRTPOnly
		}

		// Extract From/To from SIP metadata if available
		// For RTP-only calls: contains IP:port pairs set by bridge.go
		// For SIP-correlated calls: contains party info from CallTracker lookup
		var from, to string
		if sip != nil {
			from = sip.FromUri
			to = sip.ToUri
		}

		// Create a minimal call entry from RTP
		call = &AggregatedCall{
			CallID:         callID,
			State:          callState,
			From:           from,
			To:             to,
			StartTime:      timestamp,
			LastPacketTime: timestamp,
			Hunters:        []string{hunterID},
			// Note: RTPStats is intentionally not initialized here - will be done below
		}

		// Evict LRU (least recently used) if at capacity
		if ca.lruList.Len() >= ca.maxCalls {
			// Remove from back (least recently used)
			oldest := ca.lruList.Back()
			if oldest != nil {
				oldestCallID := oldest.Value.(string)
				ca.lruList.Remove(oldest)
				delete(ca.lruIndex, oldestCallID)
				delete(ca.calls, oldestCallID)
				logger.Debug("Evicted LRU call (buffer full, RTP path)",
					"call_id", oldestCallID)
			}
		}

		// Add new call to front (most recently used)
		elem := ca.lruList.PushFront(callID)
		ca.lruIndex[callID] = elem

		ca.calls[callID] = call
		logger.Debug("Created call entry from RTP packet",
			"call_id", callID,
			"ssrc", rtp.Ssrc,
			"hunter", hunterID)
	} else {
		// Move existing call to front (most recently used)
		if elem, ok := ca.lruIndex[callID]; ok {
			ca.lruList.MoveToFront(elem)
		}
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
}

// GetCalls returns all tracked calls sorted by StartTime (chronological order).
// LRU is the eviction policy only; display order is always chronological.
// Uses caching to avoid repeated deep-copy and sort operations.
func (ca *CallAggregator) GetCalls() []AggregatedCall {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Rebuild cache if dirty
	if ca.callsDirty {
		ca.cachedCalls = make([]AggregatedCall, 0, len(ca.calls))
		for _, call := range ca.calls {
			// Create a deep copy to avoid race conditions
			ca.cachedCalls = append(ca.cachedCalls, ca.deepCopyCall(call))
		}

		// Sort by StartTime for chronological display order, then by CallID as tiebreaker
		sort.Slice(ca.cachedCalls, func(i, j int) bool {
			if ca.cachedCalls[i].StartTime.Equal(ca.cachedCalls[j].StartTime) {
				return ca.cachedCalls[i].CallID < ca.cachedCalls[j].CallID
			}
			return ca.cachedCalls[i].StartTime.Before(ca.cachedCalls[j].StartTime)
		})

		ca.callsDirty = false
	}

	// Return a deep copy of each call to avoid races when callers modify the returned data
	// (AggregatedCall contains pointer/slice fields that would be shared with shallow copy)
	result := make([]AggregatedCall, len(ca.cachedCalls))
	for i := range ca.cachedCalls {
		result[i] = ca.deepCopyCall(&ca.cachedCalls[i])
	}
	return result
}

// GetActiveCalls returns only active calls (not ended, failed, cancelled, or busy).
// Note: Calls in ENDING state (BYE timewait) are included as they are still accepting packets.
func (ca *CallAggregator) GetActiveCalls() []AggregatedCall {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	calls := make([]AggregatedCall, 0)
	for _, call := range ca.calls {
		if call.State != CallStateEnded && call.State != CallStateFailed &&
			call.State != CallStateCancelled && call.State != CallStateBusy {
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
		CallID:           call.CallID,
		From:             call.From,
		To:               call.To,
		State:            call.State,
		LastResponseCode: call.LastResponseCode,
		StartTime:        call.StartTime,
		EndTime:          call.EndTime,
		LastPacketTime:   call.LastPacketTime,
		TimewaitStart:    call.TimewaitStart,
		PacketCount:      call.PacketCount,
		SIPMethod:        call.SIPMethod,
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

// TriggerMerge is a public method to trigger merging of an RTP-only call into a real SIP call.
// This is called by the TUI's TCP reassembly handler when SIP with SDP is detected
// and an existing RTP-only call is found for that endpoint.
func (ca *CallAggregator) TriggerMerge(syntheticCallID, realCallID string) {
	ca.mergeRTPOnlyCall(syntheticCallID, realCallID)
}

// mergeRTPOnlyCall merges data from an RTP-only (synthetic) call into a real SIP call.
// This is called when SIP signaling arrives for an endpoint that was already
// tracked as an RTP-only stream. The RTP stats, packet counts, and timing from
// the synthetic call are transferred to the real call, and the synthetic call is removed.
func (ca *CallAggregator) mergeRTPOnlyCall(syntheticCallID, realCallID string) {
	if syntheticCallID == "" || realCallID == "" || syntheticCallID == realCallID {
		return
	}

	atomic.AddInt64(&mergeAttempts, 1)

	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.callsDirty = true // Invalidate cache on potential mutation

	syntheticCall, exists := ca.calls[syntheticCallID]
	if !exists {
		logger.Debug("Synthetic call not found for merge",
			"synthetic_call_id", syntheticCallID,
			"real_call_id", realCallID)
		return
	}
	atomic.AddInt64(&mergeSyntheticFound, 1)

	// Get or create the real call
	realCall, realExists := ca.calls[realCallID]
	if !realExists {
		// Real call doesn't exist yet - this happens for late-offer calls where
		// 200 OK (response) arrives with SDP but INVITE was missed or had no SDP.
		// Instead of losing the data, rename the synthetic call to the real CallID.
		logger.Debug("Real call not found during merge, renaming synthetic call",
			"synthetic_call_id", syntheticCallID,
			"real_call_id", realCallID)

		// Rename the synthetic call to use the real CallID
		syntheticCall.CallID = realCallID

		// Update state from RTP-only to Active since we now have SIP correlation
		if syntheticCall.State == CallStateRTPOnly {
			syntheticCall.State = CallStateActive
		}

		// Update maps: remove old key, add new key
		delete(ca.calls, syntheticCallID)
		ca.calls[realCallID] = syntheticCall

		// Update LRU index
		if elem, ok := ca.lruIndex[syntheticCallID]; ok {
			elem.Value = realCallID // Update the value in the list element
			delete(ca.lruIndex, syntheticCallID)
			ca.lruIndex[realCallID] = elem
		}

		atomic.AddInt64(&mergeSuccess, 1)
		logger.Info("Renamed RTP-only call to SIP call (late-offer)",
			"synthetic_call_id", syntheticCallID,
			"real_call_id", realCallID,
			"packets", syntheticCall.PacketCount)
		return // Already handled, don't delete below
	} else {
		atomic.AddInt64(&mergeRealFound, 1)
		// Merge data from synthetic to real call
		// Use earlier start time
		if syntheticCall.StartTime.Before(realCall.StartTime) {
			realCall.StartTime = syntheticCall.StartTime
		}

		// Transfer RTP stats if the real call doesn't have any yet
		if realCall.RTPStats == nil && syntheticCall.RTPStats != nil {
			realCall.RTPStats = syntheticCall.RTPStats
		} else if realCall.RTPStats != nil && syntheticCall.RTPStats != nil {
			// Merge stats - add packet counts
			realCall.RTPStats.TotalPackets += syntheticCall.RTPStats.TotalPackets
			realCall.RTPStats.LostPackets += syntheticCall.RTPStats.LostPackets
			// Recalculate packet loss percentage
			if realCall.RTPStats.TotalPackets > 0 {
				realCall.RTPStats.PacketLoss = (float64(realCall.RTPStats.LostPackets) / float64(realCall.RTPStats.TotalPackets)) * 100.0
			}
			// Keep codec if real call doesn't have one
			if realCall.RTPStats.Codec == "" || realCall.RTPStats.Codec == "Unknown" {
				realCall.RTPStats.Codec = syntheticCall.RTPStats.Codec
			}
		}

		// Add packet count
		realCall.PacketCount += syntheticCall.PacketCount

		// Merge hunters list
		for _, hunter := range syntheticCall.Hunters {
			if !contains(realCall.Hunters, hunter) {
				realCall.Hunters = append(realCall.Hunters, hunter)
			}
		}

		atomic.AddInt64(&mergeSuccess, 1)
		logger.Info("Merged RTP-only call into SIP call",
			"synthetic_call_id", syntheticCallID,
			"real_call_id", realCallID,
			"merged_packets", syntheticCall.PacketCount)
	}

	// Remove synthetic call from tracking
	delete(ca.calls, syntheticCallID)
	if elem, ok := ca.lruIndex[syntheticCallID]; ok {
		ca.lruList.Remove(elem)
		delete(ca.lruIndex, syntheticCallID)
	}
}

// CleanupEndedCalls removes ended calls older than the specified duration
// NOTE: Ring buffer now handles call cleanup (FIFO when buffer is full)
// This function is kept for API compatibility but does not expire calls based on time
func (ca *CallAggregator) CleanupEndedCalls(maxAge time.Duration) int {
	return 0
}

// SetBYETimewait sets the timewait duration for calls after BYE is received.
// This allows trailing RTP packets to be captured before the call fully ends.
func (ca *CallAggregator) SetBYETimewait(d time.Duration) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.byeTimewait = d
}

// GetBYETimewait returns the current BYE timewait duration.
func (ca *CallAggregator) GetBYETimewait() time.Duration {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.byeTimewait
}

// IsTimewaitExpired checks if a call in ENDING state has completed its timewait period.
// Returns false if the call is not in ENDING state or timewait has not expired.
func (ca *CallAggregator) IsTimewaitExpired(callID string) bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	call, exists := ca.calls[callID]
	if !exists {
		return false
	}

	if call.State != CallStateEnding {
		return false
	}

	// Check if timewait has expired
	return time.Since(call.TimewaitStart) >= ca.byeTimewait
}

// CompleteTimewait transitions a call from ENDING to ENDED state if timewait has expired.
// Returns true if the transition was made, false otherwise.
func (ca *CallAggregator) CompleteTimewait(callID string) bool {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	call, exists := ca.calls[callID]
	if !exists {
		return false
	}

	if call.State != CallStateEnding {
		return false
	}

	// Check if timewait has expired
	if time.Since(call.TimewaitStart) < ca.byeTimewait {
		return false
	}

	// Transition to ENDED
	oldState := call.State
	call.State = CallStateEnded
	ca.callsDirty = true

	logger.Info("Call timewait completed",
		"call_id", callID,
		"from_state", oldState.String(),
		"to_state", call.State.String(),
		"timewait_duration", time.Since(call.TimewaitStart))

	return true
}

// GetEndingCalls returns a list of call IDs that are in ENDING state (BYE timewait).
// This is useful for monitoring and completing timewait periods.
func (ca *CallAggregator) GetEndingCalls() []string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	var callIDs []string
	for callID, call := range ca.calls {
		if call.State == CallStateEnding {
			callIDs = append(callIDs, callID)
		}
	}
	return callIDs
}

// ProcessTimewaitExpiry checks all calls in ENDING state and transitions
// those with expired timewait to ENDED state. Returns the number of calls transitioned.
func (ca *CallAggregator) ProcessTimewaitExpiry() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	count := 0
	for callID, call := range ca.calls {
		if call.State != CallStateEnding {
			continue
		}

		// Check if timewait has expired
		if time.Since(call.TimewaitStart) >= ca.byeTimewait {
			oldState := call.State
			call.State = CallStateEnded
			ca.callsDirty = true
			count++

			logger.Info("Call timewait completed (batch)",
				"call_id", callID,
				"from_state", oldState.String(),
				"to_state", call.State.String(),
				"timewait_duration", time.Since(call.TimewaitStart))
		}
	}

	return count
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

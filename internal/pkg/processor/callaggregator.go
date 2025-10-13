package processor

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
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
	CallID      string
	From        string
	To          string
	State       CallState
	StartTime   time.Time
	EndTime     time.Time
	RTPStats    *RTPQualityStats
	Hunters     []string // Which hunters saw this call
	PacketCount int
	SIPMethod   string // Last SIP method seen
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
	calls map[string]*AggregatedCall // callID -> call state
	mu    sync.RWMutex
}

// NewCallAggregator creates a new call aggregator
func NewCallAggregator() *CallAggregator {
	return &CallAggregator{
		calls: make(map[string]*AggregatedCall),
	}
}

// ProcessPacket updates call state based on a received packet
func (ca *CallAggregator) ProcessPacket(packet *data.CapturedPacket, hunterID string) {
	if packet.Metadata == nil {
		return
	}

	// Handle SIP packets
	if packet.Metadata.Sip != nil {
		ca.processSIPPacket(packet, hunterID)
	}

	// Handle RTP packets
	if packet.Metadata.Rtp != nil {
		ca.processRTPPacket(packet, hunterID)
	}
}

func (ca *CallAggregator) processSIPPacket(packet *data.CapturedPacket, hunterID string) {
	sip := packet.Metadata.Sip
	if sip.CallId == "" {
		return
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()

	call, exists := ca.calls[sip.CallId]
	if !exists {
		call = &AggregatedCall{
			CallID:    sip.CallId,
			From:      sip.FromUser,
			To:        sip.ToUser,
			State:     CallStateNew,
			StartTime: time.Now(),
			Hunters:   make([]string, 0),
			RTPStats: &RTPQualityStats{
				Codec: "unknown",
			},
		}
		ca.calls[sip.CallId] = call
		logger.Debug("New call detected",
			"call_id", sip.CallId,
			"from", sip.FromUser,
			"to", sip.ToUser,
			"hunter", hunterID)
	}

	// Add hunter if not already tracking
	if !contains(call.Hunters, hunterID) {
		call.Hunters = append(call.Hunters, hunterID)
	}

	// Update state based on SIP method
	call.SIPMethod = sip.Method
	ca.updateCallState(call, sip.Method, sip.ResponseCode)
	call.PacketCount++
}

func (ca *CallAggregator) updateCallState(call *AggregatedCall, method string, responseCode uint32) {
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
		call.EndTime = time.Now()
	case "CANCEL":
		call.State = CallStateFailed
		call.EndTime = time.Now()
	}

	// Handle responses
	if responseCode >= 200 && responseCode < 300 {
		if call.State == CallStateRinging {
			call.State = CallStateActive
		}
	} else if responseCode >= 400 {
		call.State = CallStateFailed
		call.EndTime = time.Now()
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

func (ca *CallAggregator) processRTPPacket(packet *data.CapturedPacket, hunterID string) {
	rtp := packet.Metadata.Rtp

	// Try to find call by looking for matching CallID in metadata
	// Note: This requires the packet metadata to include CallID from port mapping
	// For Phase 1, we'll implement basic RTP stats without call association
	// Full RTP association will be implemented in Phase 1.3 when hunter integration is complete

	// For now, just log RTP packets
	logger.Debug("RTP packet received",
		"ssrc", rtp.Ssrc,
		"payload_type", rtp.PayloadType,
		"sequence", rtp.Sequence,
		"hunter", hunterID)

	// TODO: Implement RTP quality metrics calculation
	// - Packet loss detection (sequence number gaps)
	// - Jitter calculation (timestamp variance)
	// - MOS score computation
}

// GetCalls returns all tracked calls
func (ca *CallAggregator) GetCalls() []AggregatedCall {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	calls := make([]AggregatedCall, 0, len(ca.calls))
	for _, call := range ca.calls {
		// Create a copy to avoid race conditions
		callCopy := *call
		calls = append(calls, callCopy)
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
			callCopy := *call
			calls = append(calls, callCopy)
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

	// Return a copy
	callCopy := *call
	return &callCopy, true
}

// GetCallCount returns the total number of tracked calls
func (ca *CallAggregator) GetCallCount() int {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return len(ca.calls)
}

// CleanupEndedCalls removes ended calls older than the specified duration
func (ca *CallAggregator) CleanupEndedCalls(maxAge time.Duration) int {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	now := time.Now()
	removed := 0

	for callID, call := range ca.calls {
		if (call.State == CallStateEnded || call.State == CallStateFailed) &&
			!call.EndTime.IsZero() &&
			now.Sub(call.EndTime) > maxAge {
			delete(ca.calls, callID)
			removed++
			logger.Debug("Cleaned up ended call",
				"call_id", callID,
				"state", call.State.String(),
				"age_seconds", int(now.Sub(call.EndTime).Seconds()))
		}
	}

	if removed > 0 {
		logger.Info("Cleaned up ended calls", "count", removed)
	}

	return removed
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

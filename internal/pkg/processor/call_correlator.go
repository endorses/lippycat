package processor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// CallState represents the state of a correlated call
type CallState int

const (
	CallStateTrying CallState = iota
	CallStateRinging
	CallStateEstablished
	CallStateEnded
)

func (cs CallState) String() string {
	switch cs {
	case CallStateTrying:
		return "TRYING"
	case CallStateRinging:
		return "RINGING"
	case CallStateEstablished:
		return "ESTABLISHED"
	case CallStateEnded:
		return "ENDED"
	default:
		return "UNKNOWN"
	}
}

// CallLeg represents one leg of a multi-hop call
type CallLeg struct {
	CallID       string
	HunterID     string
	SrcIP        string
	DstIP        string
	Method       string
	ResponseCode uint32
	PacketCount  int
	StartTime    time.Time
	LastSeen     time.Time
}

// CorrelatedCall represents a call tracked across multiple hops
type CorrelatedCall struct {
	CorrelationID string              // Hash of normalized tag pair
	TagPair       [2]string           // Normalized [tag1, tag2] (sorted)
	FromUser      string              // From user (participant A)
	ToUser        string              // To user (participant B)
	CallLegs      map[string]*CallLeg // Key: CallID, Value: leg details
	StartTime     time.Time
	LastSeen      time.Time
	State         CallState // TRYING, RINGING, ESTABLISHED, ENDED
}

// CallCorrelator correlates call legs across B2BUA boundaries
type CallCorrelator struct {
	calls         map[string]*CorrelatedCall // Key: CorrelationID
	callsByTag    map[string]string          // Key: individual tag -> CorrelationID (for quick lookup)
	mu            sync.RWMutex
	cleanupTicker *time.Ticker
	stopCleanup   chan struct{}
}

// NewCallCorrelator creates a new call correlator
func NewCallCorrelator() *CallCorrelator {
	cc := &CallCorrelator{
		calls:       make(map[string]*CorrelatedCall),
		callsByTag:  make(map[string]string),
		stopCleanup: make(chan struct{}),
	}

	// Start cleanup goroutine
	cc.cleanupTicker = time.NewTicker(5 * time.Minute)
	go cc.cleanupLoop()

	return cc
}

// Stop stops the correlator cleanup goroutine
func (cc *CallCorrelator) Stop() {
	cc.cleanupTicker.Stop()
	close(cc.stopCleanup)
}

// ProcessPacket processes a packet and updates correlation state
func (cc *CallCorrelator) ProcessPacket(packet *data.CapturedPacket, hunterID string) {
	if packet.Metadata == nil || packet.Metadata.Sip == nil {
		return
	}

	sip := packet.Metadata.Sip
	timestamp := time.Unix(0, packet.TimestampNs)

	// Extract tags
	fromTag := sip.FromTag
	toTag := sip.ToTag

	// Handle early dialog: defer correlation until ToTag is available
	if toTag == "" {
		logger.Debug("SIP packet without ToTag (early dialog), skipping correlation",
			"call_id", sip.CallId,
			"method", sip.Method,
			"from_tag", fromTag)
		return
	}

	// Generate correlation ID from normalized tag pair
	correlationID := generateCorrelationID(fromTag, toTag)
	if correlationID == "" {
		return
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Find or create correlated call
	call, exists := cc.calls[correlationID]
	if !exists {
		// Create normalized tag pair (sorted alphabetically)
		tags := []string{fromTag, toTag}
		sort.Strings(tags)

		// Prefer full URIs if available, fallback to username only
		fromUser := sip.FromUri
		if fromUser == "" {
			fromUser = sip.FromUser
		}
		toUser := sip.ToUri
		if toUser == "" {
			toUser = sip.ToUser
		}

		call = &CorrelatedCall{
			CorrelationID: correlationID,
			TagPair:       [2]string{tags[0], tags[1]},
			FromUser:      fromUser,
			ToUser:        toUser,
			CallLegs:      make(map[string]*CallLeg),
			StartTime:     timestamp,
			LastSeen:      timestamp,
			State:         CallStateTrying,
		}
		cc.calls[correlationID] = call

		// Index by both tags for quick lookup
		cc.callsByTag[tags[0]] = correlationID
		cc.callsByTag[tags[1]] = correlationID

		logger.Info("New correlated call detected",
			"correlation_id", correlationID,
			"tag_pair", tags,
			"from_user", fromUser,
			"to_user", toUser)
	}

	// Find or create call leg
	leg, legExists := call.CallLegs[sip.CallId]
	if !legExists {
		leg = &CallLeg{
			CallID:    sip.CallId,
			HunterID:  hunterID,
			SrcIP:     packet.Metadata.SrcIp,
			DstIP:     packet.Metadata.DstIp,
			StartTime: timestamp,
			LastSeen:  timestamp,
		}
		call.CallLegs[sip.CallId] = leg

		logger.Info("New call leg detected for correlated call",
			"correlation_id", correlationID,
			"call_id", sip.CallId,
			"hunter_id", hunterID,
			"leg_count", len(call.CallLegs))
	}

	// Update leg state
	leg.Method = sip.Method
	leg.ResponseCode = sip.ResponseCode
	leg.PacketCount++
	leg.LastSeen = timestamp

	// Update call state
	call.LastSeen = timestamp
	cc.updateCallState(call, sip.Method, sip.ResponseCode)
}

// ProcessPacketDisplay processes a PacketDisplay (for TUI offline mode)
func (cc *CallCorrelator) ProcessPacketDisplay(pkt *types.PacketDisplay, nodeID string) {
	if pkt.VoIPData == nil {
		return
	}

	voip := pkt.VoIPData

	// Extract tags
	fromTag := voip.FromTag
	toTag := voip.ToTag

	// Handle early dialog: defer correlation until ToTag is available
	if toTag == "" {
		return
	}

	// Generate correlation ID
	correlationID := generateCorrelationID(fromTag, toTag)
	if correlationID == "" {
		return
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Find or create correlated call
	call, exists := cc.calls[correlationID]
	if !exists {
		// Create normalized tag pair (sorted alphabetically)
		tags := []string{fromTag, toTag}
		sort.Strings(tags)

		call = &CorrelatedCall{
			CorrelationID: correlationID,
			TagPair:       [2]string{tags[0], tags[1]},
			FromUser:      voip.From,
			ToUser:        voip.To,
			CallLegs:      make(map[string]*CallLeg),
			StartTime:     pkt.Timestamp,
			LastSeen:      pkt.Timestamp,
			State:         CallStateTrying,
		}
		cc.calls[correlationID] = call

		// Index by both tags
		cc.callsByTag[tags[0]] = correlationID
		cc.callsByTag[tags[1]] = correlationID
	}

	// Find or create call leg
	leg, legExists := call.CallLegs[voip.CallID]
	if !legExists {
		leg = &CallLeg{
			CallID:    voip.CallID,
			HunterID:  nodeID,
			SrcIP:     pkt.SrcIP,
			DstIP:     pkt.DstIP,
			StartTime: pkt.Timestamp,
			LastSeen:  pkt.Timestamp,
		}
		call.CallLegs[voip.CallID] = leg
	}

	// Update leg state
	leg.Method = voip.Method
	if voip.Status >= 0 && voip.Status <= int(^uint32(0)) {
		leg.ResponseCode = uint32(voip.Status)
	}
	leg.PacketCount++
	leg.LastSeen = pkt.Timestamp

	// Update call state
	call.LastSeen = pkt.Timestamp
	cc.updateCallState(call, voip.Method, leg.ResponseCode)
}

// updateCallState updates the call state based on SIP method and response code
func (cc *CallCorrelator) updateCallState(call *CorrelatedCall, method string, responseCode uint32) {
	oldState := call.State

	switch method {
	case "INVITE":
		if call.State == CallStateTrying {
			call.State = CallStateRinging
		}
	case "ACK":
		if call.State == CallStateRinging {
			call.State = CallStateEstablished
		}
	case "BYE", "CANCEL":
		call.State = CallStateEnded
	}

	// Handle responses
	if responseCode >= 180 && responseCode < 200 {
		if call.State == CallStateTrying {
			call.State = CallStateRinging
		}
	} else if responseCode >= 200 && responseCode < 300 {
		if call.State == CallStateRinging {
			call.State = CallStateEstablished
		}
	} else if responseCode >= 400 {
		call.State = CallStateEnded
	}

	// Log state transitions
	if oldState != call.State {
		logger.Info("Correlated call state transition",
			"correlation_id", call.CorrelationID,
			"from_state", oldState.String(),
			"to_state", call.State.String(),
			"method", method,
			"response_code", responseCode,
			"leg_count", len(call.CallLegs))
	}
}

// GetCorrelatedCalls returns all correlated calls
func (cc *CallCorrelator) GetCorrelatedCalls() []*CorrelatedCall {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	calls := make([]*CorrelatedCall, 0, len(cc.calls))
	for _, call := range cc.calls {
		// Create a deep copy to avoid race conditions
		callCopy := cc.copyCall(call)
		calls = append(calls, callCopy)
	}

	return calls
}

// GetCorrelatedCall returns a specific correlated call by ID
func (cc *CallCorrelator) GetCorrelatedCall(correlationID string) (*CorrelatedCall, bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	call, exists := cc.calls[correlationID]
	if !exists {
		return nil, false
	}

	return cc.copyCall(call), true
}

// GetCallCount returns the number of correlated calls
func (cc *CallCorrelator) GetCallCount() int {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return len(cc.calls)
}

// copyCall creates a deep copy of a correlated call
func (cc *CallCorrelator) copyCall(call *CorrelatedCall) *CorrelatedCall {
	callCopy := &CorrelatedCall{
		CorrelationID: call.CorrelationID,
		TagPair:       call.TagPair,
		FromUser:      call.FromUser,
		ToUser:        call.ToUser,
		StartTime:     call.StartTime,
		LastSeen:      call.LastSeen,
		State:         call.State,
		CallLegs:      make(map[string]*CallLeg, len(call.CallLegs)),
	}

	// Deep copy call legs
	for callID, leg := range call.CallLegs {
		legCopy := *leg
		callCopy.CallLegs[callID] = &legCopy
	}

	return callCopy
}

// cleanupLoop periodically removes stale correlated calls
func (cc *CallCorrelator) cleanupLoop() {
	for {
		select {
		case <-cc.cleanupTicker.C:
			cc.cleanupStaleCalls(1 * time.Hour)
		case <-cc.stopCleanup:
			return
		}
	}
}

// cleanupStaleCalls removes calls older than maxAge
func (cc *CallCorrelator) cleanupStaleCalls(maxAge time.Duration) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	now := time.Now()
	removed := 0

	for correlationID, call := range cc.calls {
		if now.Sub(call.LastSeen) > maxAge {
			// Remove from tag index
			for _, tag := range call.TagPair {
				delete(cc.callsByTag, tag)
			}

			delete(cc.calls, correlationID)
			removed++
		}
	}

	if removed > 0 {
		logger.Info("Cleaned up stale correlated calls",
			"removed", removed,
			"remaining", len(cc.calls),
			"max_age", maxAge)
	}
}

// generateCorrelationID generates a correlation ID from two tags
func generateCorrelationID(tag1, tag2 string) string {
	// Handle empty tags
	if tag1 == "" || tag2 == "" {
		return ""
	}

	// Normalize: sort tags alphabetically
	tags := []string{tag1, tag2}
	sort.Strings(tags)

	// Hash normalized pair
	data := fmt.Sprintf("%s:%s", tags[0], tags[1])
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

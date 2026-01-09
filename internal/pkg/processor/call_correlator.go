//go:build processor || tap || all

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
	PhonePairKey  string              // Phone suffix pair key for B2BUA correlation
	FromUser      string              // From user (participant A)
	ToUser        string              // To user (participant B)
	CallLegs      map[string]*CallLeg // Key: CallID, Value: leg details
	StartTime     time.Time
	LastSeen      time.Time
	State         CallState // TRYING, RINGING, ESTABLISHED, ENDED
}

// PhoneCorrelationConfig configures phone number suffix matching
type PhoneCorrelationConfig struct {
	Enabled         bool          // Enable phone suffix correlation (default: true)
	MinSuffixDigits int           // Minimum digits for suffix matching (default: 7)
	TimeWindow      time.Duration // Max time between call legs (default: 30s)
}

// DefaultPhoneCorrelationConfig returns default phone correlation settings
func DefaultPhoneCorrelationConfig() PhoneCorrelationConfig {
	return PhoneCorrelationConfig{
		Enabled:         true,
		MinSuffixDigits: 7,
		TimeWindow:      30 * time.Second,
	}
}

// CallCorrelator correlates call legs based on SIP dialog tags and phone number suffixes
type CallCorrelator struct {
	calls            map[string]*CorrelatedCall // Key: CorrelationID
	callsByTag       map[string]string          // Key: individual tag -> CorrelationID (for quick lookup)
	callsByPhonePair map[string]string          // Key: phone suffix pair -> CorrelationID
	phoneConfig      PhoneCorrelationConfig
	mu               sync.RWMutex
	cleanupTicker    *time.Ticker
	stopCleanup      chan struct{}
}

// NewCallCorrelator creates a new call correlator with default phone correlation config
func NewCallCorrelator() *CallCorrelator {
	return NewCallCorrelatorWithConfig(DefaultPhoneCorrelationConfig())
}

// NewCallCorrelatorWithConfig creates a new call correlator with custom phone correlation config
func NewCallCorrelatorWithConfig(phoneConfig PhoneCorrelationConfig) *CallCorrelator {
	cc := &CallCorrelator{
		calls:            make(map[string]*CorrelatedCall),
		callsByTag:       make(map[string]string),
		callsByPhonePair: make(map[string]string),
		phoneConfig:      phoneConfig,
		stopCleanup:      make(chan struct{}),
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
	tagCorrelationID := generateCorrelationID(fromTag, toTag)
	if tagCorrelationID == "" {
		return
	}

	// Prefer full URIs if available, fallback to username only
	fromUser := sip.FromUri
	if fromUser == "" {
		fromUser = sip.FromUser
	}
	toUser := sip.ToUri
	if toUser == "" {
		toUser = sip.ToUser
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Try to find an existing call by tag correlation ID first
	call, exists := cc.calls[tagCorrelationID]

	// If not found by tag, try phone suffix correlation (for B2BUA scenarios)
	var phonePairKey string
	if !exists && cc.phoneConfig.Enabled {
		phonePairKey = phoneSuffixPairKey(fromUser, toUser, cc.phoneConfig.MinSuffixDigits)
		if phonePairKey != "" {
			if existingCorrelationID, found := cc.callsByPhonePair[phonePairKey]; found {
				if existingCall, callFound := cc.calls[existingCorrelationID]; callFound {
					// Check time window - only correlate if within configured window
					if timestamp.Sub(existingCall.StartTime) <= cc.phoneConfig.TimeWindow {
						call = existingCall
						exists = true
						logger.Info("Correlated call leg via phone suffix",
							"correlation_id", existingCorrelationID,
							"phone_pair_key", phonePairKey,
							"call_id", sip.CallId,
							"from_user", fromUser,
							"to_user", toUser)
					}
				}
			}
		}
	}

	// Ensure phonePairKey is computed if not already (needed for new calls)
	if phonePairKey == "" && cc.phoneConfig.Enabled {
		phonePairKey = phoneSuffixPairKey(fromUser, toUser, cc.phoneConfig.MinSuffixDigits)
	}

	if !exists {
		// Create normalized tag pair (sorted alphabetically)
		tags := []string{fromTag, toTag}
		sort.Strings(tags)

		call = &CorrelatedCall{
			CorrelationID: tagCorrelationID,
			TagPair:       [2]string{tags[0], tags[1]},
			PhonePairKey:  phonePairKey,
			FromUser:      fromUser,
			ToUser:        toUser,
			CallLegs:      make(map[string]*CallLeg),
			StartTime:     timestamp,
			LastSeen:      timestamp,
			State:         CallStateTrying,
		}
		cc.calls[tagCorrelationID] = call

		// Index by both tags for quick lookup
		cc.callsByTag[tags[0]] = tagCorrelationID
		cc.callsByTag[tags[1]] = tagCorrelationID

		// Index by phone pair for B2BUA correlation
		if cc.phoneConfig.Enabled && phonePairKey != "" {
			cc.callsByPhonePair[phonePairKey] = tagCorrelationID
		}

		logger.Info("New correlated call detected",
			"correlation_id", tagCorrelationID,
			"tag_pair", tags,
			"phone_pair_key", phonePairKey,
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
			"correlation_id", call.CorrelationID,
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

	// Generate correlation ID from tags
	tagCorrelationID := generateCorrelationID(fromTag, toTag)
	if tagCorrelationID == "" {
		return
	}

	fromUser := voip.From
	toUser := voip.To

	cc.mu.Lock()
	defer cc.mu.Unlock()

	// Try to find an existing call by tag correlation ID first
	call, exists := cc.calls[tagCorrelationID]

	// If not found by tag, try phone suffix correlation (for B2BUA scenarios)
	var phonePairKey string
	if !exists && cc.phoneConfig.Enabled {
		phonePairKey = phoneSuffixPairKey(fromUser, toUser, cc.phoneConfig.MinSuffixDigits)
		if phonePairKey != "" {
			if existingCorrelationID, found := cc.callsByPhonePair[phonePairKey]; found {
				if existingCall, callFound := cc.calls[existingCorrelationID]; callFound {
					// Check time window - only correlate if within configured window
					if pkt.Timestamp.Sub(existingCall.StartTime) <= cc.phoneConfig.TimeWindow {
						call = existingCall
						exists = true
						logger.Info("Correlated call leg via phone suffix (display)",
							"correlation_id", existingCorrelationID,
							"phone_pair_key", phonePairKey,
							"call_id", voip.CallID,
							"from_user", fromUser,
							"to_user", toUser)
					}
				}
			}
		}
	}

	// Ensure phonePairKey is computed if not already (needed for new calls)
	if phonePairKey == "" && cc.phoneConfig.Enabled {
		phonePairKey = phoneSuffixPairKey(fromUser, toUser, cc.phoneConfig.MinSuffixDigits)
	}

	if !exists {
		// Create normalized tag pair (sorted alphabetically)
		tags := []string{fromTag, toTag}
		sort.Strings(tags)

		call = &CorrelatedCall{
			CorrelationID: tagCorrelationID,
			TagPair:       [2]string{tags[0], tags[1]},
			PhonePairKey:  phonePairKey,
			FromUser:      fromUser,
			ToUser:        toUser,
			CallLegs:      make(map[string]*CallLeg),
			StartTime:     pkt.Timestamp,
			LastSeen:      pkt.Timestamp,
			State:         CallStateTrying,
		}
		cc.calls[tagCorrelationID] = call

		// Index by both tags
		cc.callsByTag[tags[0]] = tagCorrelationID
		cc.callsByTag[tags[1]] = tagCorrelationID

		// Index by phone pair for B2BUA correlation
		if cc.phoneConfig.Enabled && phonePairKey != "" {
			cc.callsByPhonePair[phonePairKey] = tagCorrelationID
		}
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
		PhonePairKey:  call.PhonePairKey,
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

			// Remove from phone pair index
			if call.PhonePairKey != "" {
				delete(cc.callsByPhonePair, call.PhonePairKey)
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

// extractPhoneSuffix extracts the last N digits from a phone number/SIP user.
// It strips prefixes, country codes, and non-digit characters.
// Returns empty string if insufficient digits found.
func extractPhoneSuffix(phoneNumber string, minDigits int) string {
	// Extract only digits
	var digits []byte
	for i := 0; i < len(phoneNumber); i++ {
		c := phoneNumber[i]
		if c >= '0' && c <= '9' {
			digits = append(digits, c)
		}
	}

	// Return the last minDigits (suffix)
	if len(digits) < minDigits {
		return ""
	}
	return string(digits[len(digits)-minDigits:])
}

// generatePhoneCorrelationID generates a correlation ID from phone number suffixes.
// This matches calls with the same participants regardless of prefixes added by B2BUAs.
func generatePhoneCorrelationID(from, to string, minSuffixLen int) string {
	fromSuffix := extractPhoneSuffix(from, minSuffixLen)
	toSuffix := extractPhoneSuffix(to, minSuffixLen)

	if fromSuffix == "" || toSuffix == "" {
		return ""
	}

	// Normalize: sort suffixes alphabetically so A→B and B→A match
	suffixes := []string{fromSuffix, toSuffix}
	sort.Strings(suffixes)

	// Use "phone:" prefix to distinguish from tag-based correlation
	data := fmt.Sprintf("phone:%s:%s", suffixes[0], suffixes[1])
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// phoneSuffixPairKey generates a key for phone pair lookup
func phoneSuffixPairKey(from, to string, minSuffixLen int) string {
	fromSuffix := extractPhoneSuffix(from, minSuffixLen)
	toSuffix := extractPhoneSuffix(to, minSuffixLen)

	if fromSuffix == "" || toSuffix == "" {
		return ""
	}

	// Normalize: sort suffixes
	suffixes := []string{fromSuffix, toSuffix}
	sort.Strings(suffixes)

	return suffixes[0] + ":" + suffixes[1]
}

// Package processor provides a reusable VoIP packet processor that can be used
// by both hunter nodes and tap nodes for SIP/RTP detection and call tracking.
//
// The processor extracts VoIP metadata from packets and associates RTP streams
// with their corresponding SIP calls via SDP port extraction.
package processor

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// VoIPProcessor processes packets for VoIP (SIP/RTP) detection and call tracking.
// It is designed to be reusable across hunter, tap, and processor nodes.
type VoIPProcessor interface {
	// Process analyzes a packet and returns VoIP metadata if applicable.
	// Returns nil if the packet is not a VoIP packet or doesn't match filters.
	Process(packet gopacket.Packet) *ProcessResult

	// ActiveCalls returns information about currently tracked calls.
	ActiveCalls() []CallInfo

	// Close releases any resources held by the processor.
	Close()
}

// ProcessResult contains the result of processing a single packet.
type ProcessResult struct {
	// IsVoIP indicates whether the packet is a VoIP packet (SIP or RTP).
	IsVoIP bool

	// PacketType indicates whether this is a SIP or RTP packet.
	PacketType PacketType

	// CallID is the SIP Call-ID associated with this packet.
	// For SIP packets, this is extracted from headers.
	// For RTP packets, this is looked up from the port-to-call mapping.
	CallID string

	// Metadata contains protobuf metadata for forwarding to processors.
	Metadata *data.PacketMetadata

	// CallMetadata contains extracted SIP header information (for SIP packets only).
	CallMetadata *CallMetadata
}

// PacketType indicates the type of VoIP packet.
type PacketType int

const (
	PacketTypeUnknown PacketType = iota
	PacketTypeSIP
	PacketTypeRTP
)

// CallInfo contains information about an active call.
type CallInfo struct {
	CallID      string
	State       string
	From        string
	To          string
	Created     time.Time
	LastUpdated time.Time
}

// CallMetadata contains extracted SIP header information.
type CallMetadata struct {
	CallID            string
	From              string
	To                string
	FromTag           string
	ToTag             string
	PAssertedIdentity string
	Method            string
	ResponseCode      uint32
	SDPBody           string
}

// ApplicationFilter is an optional filter interface for VoIP call filtering.
// When set, only SIP packets matching the filter will create call tracking entries.
// RTP packets are only tracked for calls that passed the filter.
type ApplicationFilter interface {
	// MatchPacket returns true if the packet matches any active filter.
	MatchPacket(packet gopacket.Packet) bool
}

// Config contains configuration for the VoIPProcessor.
type Config struct {
	// MaxCalls is the maximum number of calls to track concurrently.
	// Older calls are evicted when this limit is reached.
	MaxCalls int

	// CallTimeout is the duration after which inactive calls are expired.
	CallTimeout time.Duration

	// MaxBufferAge is the maximum time to buffer packets before filter decision.
	MaxBufferAge time.Duration

	// MaxBufferSize is the maximum number of packets to buffer per call.
	MaxBufferSize int

	// ApplicationFilter is an optional filter for call selection.
	// When set, only SIP packets matching the filter will be tracked.
	ApplicationFilter ApplicationFilter
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxCalls:      10000,
		CallTimeout:   30 * time.Minute,
		MaxBufferAge:  30 * time.Second,
		MaxBufferSize: 1000,
	}
}

// Processor implements VoIPProcessor for SIP/RTP packet processing.
type Processor struct {
	config Config

	// Call tracking
	calls        map[string]*callState
	portToCallID map[string]string // RTP port -> CallID
	mu           sync.RWMutex

	// Optional application filter for call selection
	appFilter ApplicationFilter

	// Janitor for cleanup
	janitorCtx    chan struct{}
	janitorClosed bool
}

// callState holds internal state for a tracked call.
type callState struct {
	info        CallInfo
	metadata    *CallMetadata
	rtpPorts    []string
	lastUpdated time.Time
}

// New creates a new VoIPProcessor with the given configuration.
func New(cfg Config) *Processor {
	if cfg.MaxCalls == 0 {
		cfg.MaxCalls = 10000
	}
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 30 * time.Minute
	}

	p := &Processor{
		config:       cfg,
		calls:        make(map[string]*callState),
		portToCallID: make(map[string]string),
		appFilter:    cfg.ApplicationFilter,
		janitorCtx:   make(chan struct{}),
	}

	// Start janitor goroutine for cleanup
	go p.janitorLoop()

	return p
}

// Process analyzes a packet and returns VoIP metadata if applicable.
func (p *Processor) Process(packet gopacket.Packet) *ProcessResult {
	// Try UDP first (most common for VoIP)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return p.processUDP(packet, udp)
	}

	// TODO: Add TCP SIP support in future
	return nil
}

// processUDP processes a UDP packet for SIP/RTP content.
func (p *Processor) processUDP(packet gopacket.Packet, udp *layers.UDP) *ProcessResult {
	payload := udp.Payload

	// Try SIP detection first
	if result := p.detectSIP(packet, udp, payload); result != nil {
		return result
	}

	// Try RTP detection (check if port is tracked)
	if result := p.detectRTP(packet, udp); result != nil {
		return result
	}

	return nil
}

// ActiveCalls returns information about currently tracked calls.
func (p *Processor) ActiveCalls() []CallInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	calls := make([]CallInfo, 0, len(p.calls))
	for _, state := range p.calls {
		calls = append(calls, state.info)
	}
	return calls
}

// Close releases resources held by the processor.
func (p *Processor) Close() {
	p.mu.Lock()
	if !p.janitorClosed {
		close(p.janitorCtx)
		p.janitorClosed = true
	}
	p.mu.Unlock()
}

// janitorLoop periodically cleans up expired calls.
func (p *Processor) janitorLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.janitorCtx:
			return
		case <-ticker.C:
			p.cleanupExpiredCalls()
		}
	}
}

// cleanupExpiredCalls removes calls that have exceeded the timeout.
func (p *Processor) cleanupExpiredCalls() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for callID, state := range p.calls {
		if now.Sub(state.lastUpdated) > p.config.CallTimeout {
			// Remove port mappings
			for _, port := range state.rtpPorts {
				delete(p.portToCallID, port)
			}
			delete(p.calls, callID)
		}
	}
}

// getOrCreateCall gets or creates a call state for the given CallID.
func (p *Processor) getOrCreateCall(callID string) *callState {
	p.mu.Lock()
	defer p.mu.Unlock()

	state, exists := p.calls[callID]
	if !exists {
		now := time.Now()
		state = &callState{
			info: CallInfo{
				CallID:      callID,
				State:       "NEW",
				Created:     now,
				LastUpdated: now,
			},
			rtpPorts:    make([]string, 0, 2),
			lastUpdated: now,
		}
		p.calls[callID] = state

		// Evict oldest call if at capacity
		if len(p.calls) > p.config.MaxCalls {
			p.evictOldestCallLocked()
		}
	}
	return state
}

// evictOldestCallLocked removes the oldest call (must hold mu lock).
func (p *Processor) evictOldestCallLocked() {
	var oldestID string
	var oldestTime time.Time

	for id, state := range p.calls {
		if oldestID == "" || state.lastUpdated.Before(oldestTime) {
			oldestID = id
			oldestTime = state.lastUpdated
		}
	}

	if oldestID != "" {
		state := p.calls[oldestID]
		for _, port := range state.rtpPorts {
			delete(p.portToCallID, port)
		}
		delete(p.calls, oldestID)
	}
}

// registerRTPPort associates an RTP port with a call.
func (p *Processor) registerRTPPort(callID, port string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.portToCallID[port] = callID

	if state, exists := p.calls[callID]; exists {
		// Avoid duplicates
		for _, p := range state.rtpPorts {
			if p == port {
				return
			}
		}
		state.rtpPorts = append(state.rtpPorts, port)
	}
}

// getCallIDForPort looks up the CallID for an RTP port.
func (p *Processor) getCallIDForPort(port string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	callID, exists := p.portToCallID[port]
	return callID, exists
}

// CleanupCallPorts removes all port-to-callID mappings for a given callID.
// This should be called when a call ends to prevent port collisions with new calls.
func (p *Processor) CleanupCallPorts(callID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	state, exists := p.calls[callID]
	if !exists {
		return
	}

	// Remove all port mappings for this call
	for _, port := range state.rtpPorts {
		delete(p.portToCallID, port)
	}

	// Clear the ports list but keep the call state for reference
	state.rtpPorts = state.rtpPorts[:0]
}

// updateCallState updates the state and metadata for a call.
func (p *Processor) updateCallState(callID, state string, metadata *CallMetadata) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if callState, exists := p.calls[callID]; exists {
		callState.info.State = state
		callState.info.LastUpdated = time.Now()
		callState.lastUpdated = time.Now()
		if metadata != nil {
			callState.metadata = metadata
			callState.info.From = metadata.From
			callState.info.To = metadata.To
		}
	}
}

// Ensure Processor implements VoIPProcessor.
var _ VoIPProcessor = (*Processor)(nil)

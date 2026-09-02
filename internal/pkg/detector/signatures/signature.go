package signatures

import (
	"context"
	"sync"
	"time"

	"github.com/google/gopacket"
)

// LayerType represents the OSI layer of a protocol
type LayerType int

const (
	LayerLink LayerType = iota
	LayerNetwork
	LayerTransport
	LayerApplication
)

// Signature defines a protocol detection rule
type Signature interface {
	// Name returns the signature name
	Name() string

	// Protocols returns the list of protocols this signature can detect
	Protocols() []string

	// Priority returns the detection priority (higher = checked first)
	Priority() int

	// Layer returns the OSI layer this signature operates on
	Layer() LayerType

	// Detect attempts to detect a protocol from the given context
	// Returns nil if the protocol is not detected
	Detect(ctx *DetectionContext) *DetectionResult
}

// DetectionContext provides packet info and state for detection
type DetectionContext struct {
	// Packet is the full gopacket.Packet
	Packet gopacket.Packet

	// Payload is the application layer payload (if available)
	Payload []byte

	// Transport protocol ("TCP", "UDP", etc.)
	Transport string

	// Network layer information
	SrcIP string
	DstIP string

	// Transport layer information
	SrcPort uint16
	DstPort uint16

	// Flow tracking
	FlowID string
	Flow   *FlowContext

	// Context for cancellation and deadlines
	Context context.Context
}

// CacheStrategy indicates how detection results should be cached
type CacheStrategy int

const (
	CacheNever   CacheStrategy = iota // Never cache (e.g., DNS queries, HTTP GET)
	CacheFlow                         // Cache for multi-packet flows (e.g., SIP→RTP)
	CacheSession                      // Cache for sessions (e.g., TLS connections)
)

// DetectionResult contains the outcome of protocol detection
type DetectionResult struct {
	// Protocol name (e.g., "SIP", "RTP", "DNS")
	Protocol string

	// Confidence score (0.0 - 1.0)
	Confidence float64

	// Metadata contains protocol-specific information
	Metadata map[string]interface{}

	// ShouldCache indicates if this result should be cached
	ShouldCache bool

	// CacheStrategy indicates caching strategy
	CacheStrategy CacheStrategy

	// Priority override (optional, for multi-protocol packets)
	PriorityOverride int
}

// FlowContext tracks state for multi-packet protocol flows.
//
// FlowContext owns synchronization for all mutable fields after the context is
// published by FlowTracker. Callers may initialize fields in a struct literal
// before publication, but must use the methods below for subsequent timestamp,
// protocol, metadata, and state access. FlowTracker separately owns membership
// in its flow map; its lock does not protect a returned FlowContext.
type FlowContext struct {
	// FlowID is the unique flow identifier (5-tuple hash)
	FlowID string

	// Timestamps
	FirstSeen time.Time
	LastSeen  time.Time

	// Detected protocols in this flow
	Protocols []string

	// Generic metadata storage
	Metadata map[string]interface{}

	// Protocol-specific state (type-asserted by signatures)
	State interface{}

	// mu protects all mutable fields after publication.
	mu sync.RWMutex
}

// RecordDetection updates flow activity and records a protocol once.
func (f *FlowContext) RecordDetection(protocol string, seen time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.LastSeen = seen
	for _, existing := range f.Protocols {
		if existing == protocol {
			return
		}
	}
	f.Protocols = append(f.Protocols, protocol)
}

// LastSeenTime returns the last activity timestamp.
func (f *FlowContext) LastSeenTime() time.Time {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.LastSeen
}

// ProtocolsSnapshot returns a copy safe for use after the method returns.
func (f *FlowContext) ProtocolsSnapshot() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return append([]string(nil), f.Protocols...)
}

// UpdateState serializes a read-modify-write transition of protocol state.
// The callback executes while the context is locked and must not call another
// FlowContext method. Its return value becomes the new state.
func (f *FlowContext) UpdateState(update func(interface{}) interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.State = update(f.State)
}

// SetMetadata safely sets a metadata key-value pair
func (f *FlowContext) SetMetadata(key string, value interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Metadata[key] = value
}

// GetMetadata safely retrieves a metadata value
func (f *FlowContext) GetMetadata(key string) (interface{}, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	val, ok := f.Metadata[key]
	return val, ok
}

// DeleteMetadata safely deletes a metadata key
func (f *FlowContext) DeleteMetadata(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.Metadata, key)
}

// SetState safely sets the flow state
func (f *FlowContext) SetState(state interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.State = state
}

// GetState safely retrieves the flow state
func (f *FlowContext) GetState() interface{} {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.State
}

// Confidence level constants for standardized scoring
const (
	ConfidenceDefinite = 1.00 // Cryptographic proof (e.g., TLS cert)
	ConfidenceVeryHigh = 0.95 // Strong indicators (e.g., SIP with valid headers)
	ConfidenceHigh     = 0.85 // Multiple indicators match
	ConfidenceMedium   = 0.70 // Single strong indicator
	ConfidenceLow      = 0.50 // Weak heuristic
	ConfidenceGuess    = 0.30 // Unlikely but possible
)

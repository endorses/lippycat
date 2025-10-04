package signatures

import (
	"context"
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
	CacheNever  CacheStrategy = iota // Never cache (e.g., DNS queries, HTTP GET)
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

// FlowContext tracks state for multi-packet protocol flows
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

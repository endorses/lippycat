// Package analyzer provides a compile-time protocol analysis framework.
//
// This package implements a static protocol module system where protocol analyzers
// are compiled into the binary and registered at initialization time. This approach
// provides cross-platform compatibility, type safety, and high performance without
// the maintenance burden of Go's dynamic plugin system.
//
// # Architecture
//
// Protocol modules implement the Protocol interface and register themselves via
// init() functions. The Registry manages all registered protocols and routes
// packets to appropriate analyzers based on protocol detection.
//
// # Adding New Protocol Modules
//
// To add a new protocol analyzer (e.g., HTTP, DNS, TLS):
//
//  1. Create a new file (e.g., http_protocol.go) implementing the Protocol interface
//  2. Register it in an init() function:
//     func init() {
//     GetRegistry().MustRegister("http", NewHTTPProtocol(), DefaultConfig())
//     }
//  3. The protocol will be automatically available at runtime
//
// # Example Usage
//
//	registry := analyzer.GetRegistry()
//	results, err := registry.ProcessPacket(ctx, packet)
//	for _, result := range results {
//	    log.Printf("Detected %s protocol: %s", result.Protocol, result.CallID)
//	}
package analyzer

import (
	"context"
	"time"

	"github.com/google/gopacket"
)

// Protocol defines the interface that all protocol analyzers must implement.
//
// Protocol modules are stateless and thread-safe. All packet processing is
// context-aware and supports timeouts and cancellation.
type Protocol interface {
	// Name returns the human-readable name of the protocol analyzer
	Name() string

	// Version returns the analyzer version (semver recommended)
	Version() string

	// SupportedProtocols returns a list of protocols this analyzer handles
	// (e.g., ["sip", "sdp"] for VoIP, ["http", "https"] for HTTP)
	SupportedProtocols() []string

	// ProcessPacket analyzes a packet and returns the result.
	// Returns nil result if the packet is not handled by this analyzer.
	// Context timeout should be respected for long-running analysis.
	ProcessPacket(ctx context.Context, packet gopacket.Packet) (*Result, error)

	// Initialize sets up the analyzer with configuration.
	// Called once during registration before any packet processing.
	Initialize(config map[string]interface{}) error

	// Shutdown gracefully shuts down the analyzer.
	// Should complete within the context deadline.
	Shutdown(ctx context.Context) error

	// HealthCheck returns the current health status of the analyzer
	HealthCheck() HealthStatus

	// Metrics returns current analyzer metrics
	Metrics() Metrics
}

// Result contains the result of packet analysis
type Result struct {
	// CallID extracted from the packet (for session-based protocols)
	// For stateless protocols, this may be a flow identifier
	CallID string

	// Protocol detected in the packet (e.g., "sip", "http", "dns")
	Protocol string

	// Action to be taken (e.g., "track", "ignore", "alert")
	Action string

	// Metadata extracted from the packet (protocol-specific)
	Metadata map[string]interface{}

	// Confidence level (0.0 to 1.0) of the detection
	Confidence float64

	// ProcessingTime how long it took to analyze the packet
	ProcessingTime time.Duration

	// ShouldContinue indicates if other analyzers should also process this packet.
	// Set to false if this analyzer has definitively handled the packet.
	ShouldContinue bool
}

// HealthStatus represents the health of a protocol analyzer
type HealthStatus struct {
	Status    HealthLevel
	Message   string
	Timestamp time.Time
	Details   map[string]interface{}
}

// HealthLevel represents different health states
type HealthLevel int

const (
	HealthUnknown HealthLevel = iota
	HealthHealthy
	HealthDegraded
	HealthUnhealthy
	HealthCritical
)

func (h HealthLevel) String() string {
	switch h {
	case HealthHealthy:
		return "healthy"
	case HealthDegraded:
		return "degraded"
	case HealthUnhealthy:
		return "unhealthy"
	case HealthCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Metrics contains metrics collected by a protocol analyzer
type Metrics struct {
	PacketsProcessed int64
	ProcessingTime   time.Duration
	ErrorCount       int64
	LastError        string
	LastErrorTime    time.Time
	MemoryUsage      int64
	GoroutineCount   int
	CustomMetrics    map[string]interface{}
}

// Config contains configuration for a protocol analyzer
type Config struct {
	Enabled   bool                   `yaml:"enabled"`
	Priority  int                    `yaml:"priority"`
	Timeout   time.Duration          `yaml:"timeout"`
	MaxMemory int64                  `yaml:"max_memory"`
	Settings  map[string]interface{} `yaml:"settings"`
}

// DefaultConfig returns a default configuration for protocol analyzers
func DefaultConfig() Config {
	return Config{
		Enabled:   true,
		Priority:  0,
		Timeout:   time.Second,
		MaxMemory: 100 * 1024 * 1024, // 100 MB
		Settings:  make(map[string]interface{}),
	}
}

// Info contains metadata about a protocol analyzer
type Info struct {
	Name        string
	Version     string
	Description string
	Protocols   []string
	Config      Config
	LoadTime    time.Time
}

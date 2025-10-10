package plugins

import (
	"context"
	"time"

	"github.com/google/gopacket"
)

// ProtocolHandler defines the interface that all protocol plugins must implement
type ProtocolHandler interface {
	// Name returns the human-readable name of the plugin
	Name() string

	// Version returns the plugin version
	Version() string

	// SupportedProtocols returns a list of protocols this handler supports
	SupportedProtocols() []string

	// ProcessPacket processes a packet and returns the result
	ProcessPacket(ctx context.Context, packet gopacket.Packet) (*ProcessResult, error)

	// Initialize sets up the plugin with configuration
	Initialize(config map[string]interface{}) error

	// Shutdown gracefully shuts down the plugin
	Shutdown(ctx context.Context) error

	// HealthCheck returns the current health status of the plugin
	HealthCheck() HealthStatus

	// Metrics returns current plugin metrics
	Metrics() PluginMetrics
}

// ProcessResult contains the result of packet processing
type ProcessResult struct {
	// CallID extracted from the packet (if any)
	CallID string

	// Protocol detected in the packet
	Protocol string

	// Action to be taken (e.g., "track", "ignore", "alert")
	Action string

	// Metadata extracted from the packet
	Metadata map[string]interface{}

	// Confidence level (0.0 to 1.0) of the detection
	Confidence float64

	// ProcessingTime how long it took to process
	ProcessingTime time.Duration

	// ShouldContinue indicates if other plugins should also process this packet
	ShouldContinue bool
}

// HealthStatus represents the health of a plugin
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

// PluginMetrics contains metrics collected by a plugin
type PluginMetrics struct {
	PacketsProcessed int64
	ProcessingTime   time.Duration
	ErrorCount       int64
	LastError        string
	LastErrorTime    time.Time
	MemoryUsage      int64
	GoroutineCount   int
	CustomMetrics    map[string]interface{}
}

// PluginInfo contains metadata about a plugin
type PluginInfo struct {
	Name        string
	Version     string
	Author      string
	Description string
	Protocols   []string
	Config      PluginConfig
	LoadTime    time.Time
	FilePath    string
}

// PluginConfig contains configuration for a plugin
type PluginConfig struct {
	Enabled   bool                   `yaml:"enabled"`
	Priority  int                    `yaml:"priority"`
	Timeout   time.Duration          `yaml:"timeout"`
	MaxMemory int64                  `yaml:"max_memory"`
	Settings  map[string]interface{} `yaml:"settings"`
}

// PluginError represents an error from a plugin
type PluginError struct {
	PluginName string
	Operation  string
	Err        error
	Timestamp  time.Time
}

func (e *PluginError) Error() string {
	return e.PluginName + " " + e.Operation + ": " + e.Err.Error()
}

// PacketContext provides context information for packet processing
type PacketContext struct {
	PacketID    string
	Timestamp   time.Time
	Source      string
	Destination string
	Size        int
	LinkType    string
}

// PluginEvent represents events from plugins
type PluginEvent struct {
	Type       EventType
	PluginName string
	Timestamp  time.Time
	Data       interface{}
}

// EventType represents different types of plugin events
type EventType int

const (
	EventUnknown EventType = iota
	EventPluginLoaded
	EventPluginUnloaded
	EventPluginError
	EventPluginHealthChange
	EventProtocolDetected
	EventCallDetected
)

func (e EventType) String() string {
	switch e {
	case EventPluginLoaded:
		return "plugin_loaded"
	case EventPluginUnloaded:
		return "plugin_unloaded"
	case EventPluginError:
		return "plugin_error"
	case EventPluginHealthChange:
		return "plugin_health_change"
	case EventProtocolDetected:
		return "protocol_detected"
	case EventCallDetected:
		return "call_detected"
	default:
		return "unknown"
	}
}

// EventHandler handles plugin events
type EventHandler func(event PluginEvent)

// PluginFactory creates new instances of plugins
type PluginFactory interface {
	CreatePlugin() ProtocolHandler
	PluginInfo() PluginInfo
}

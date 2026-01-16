// Package constants provides shared constants used across lippycat components.
package constants

import "time"

// Shutdown and graceful termination timeouts
const (
	// GracefulShutdownTimeout is the time to wait for graceful component shutdown
	GracefulShutdownTimeout = 2 * time.Second

	// SnifferCleanupTimeout is the time to wait for sniffer cleanup operations
	SnifferCleanupTimeout = 500 * time.Millisecond

	// PollingInterval is the standard interval for polling operations
	PollingInterval = 10 * time.Millisecond

	// IdleLoopDelay is the delay when a loop has no work to do
	IdleLoopDelay = 1 * time.Millisecond
)

// Channel buffer sizes
//
// Buffer Sizing Strategy:
//
// 1. Single-item buffers (size = 1):
//   - Used for signals and errors that should never block the sender
//   - Examples: OS signals, error channels
//   - Rationale: These are infrequent events that must be handled immediately
//
// 2. Small buffers (size = 10):
//   - Used for control plane operations with low frequency
//   - Examples: Filter updates, batch queues
//   - Rationale: Control operations are rare but should not block; small buffer
//     provides cushion without excessive memory overhead
//
// 3. Medium buffers (size = 100):
//   - Used for moderate-throughput data plane operations
//   - Examples: Subscriber channels, general packet processing
//   - Rationale: Balance between latency and memory; suitable for operations
//     processing hundreds to low thousands of items per second
//
// 4. Large buffers (size = 1000):
//   - Used for high-throughput data plane operations
//   - Examples: PCAP writer queue, VoIP analyzer queues
//   - Rationale: High packet rates (10K+ pps) require larger buffers to absorb
//     bursts and prevent drops during GC pauses; memory cost justified by criticality
//
// Note: These are default sizes. Critical buffers can be made configurable via
// Config structs if deployment-specific tuning is needed.
const (
	// SignalChannelBuffer is the buffer size for OS signal channels (strategy: single-item)
	SignalChannelBuffer = 1

	// ErrorChannelBuffer is the buffer size for error reporting channels (strategy: single-item)
	ErrorChannelBuffer = 1

	// FilterUpdateChannelBuffer is the buffer size for filter update channels (strategy: small)
	// Provides cushion for control plane operations without excessive memory
	FilterUpdateChannelBuffer = 10

	// SubscriberChannelBuffer is the buffer size for subscriber packet channels (strategy: medium)
	// Balances latency and memory for moderate packet throughput
	SubscriberChannelBuffer = 100

	// VoIPAnalyzerQueueBuffer is the buffer size for VoIP analyzer queues (strategy: large)
	// Handles high packet rates and absorbs bursts during GC pauses
	VoIPAnalyzerQueueBuffer = 1000

	// PCAPWriteQueueBuffer is the buffer size for PCAP writer queue (strategy: large)
	// Critical path for packet capture; large buffer prevents drops at high rates
	PCAPWriteQueueBuffer = 1000

	// PacketChannelBuffer is the standard buffer for packet processing channels (strategy: medium)
	// General-purpose packet channel for moderate throughput scenarios
	PacketChannelBuffer = 100

	// BatchQueueBuffer is the buffer size for batch processing queues (strategy: small)
	// Batches are larger units than individual packets; smaller buffer sufficient
	BatchQueueBuffer = 10
)

// gRPC configuration
const (
	// MaxGRPCMessageSize is the maximum size for gRPC messages (10MB)
	MaxGRPCMessageSize = 10 * 1024 * 1024
)

// Hierarchy configuration
const (
	// MaxHierarchyDepth is the maximum allowed depth of the processor hierarchy
	// Depth is calculated from the root processor (depth 0) to the registering processor
	// Example: root → intermediate → leaf has depth 2 for the leaf processor
	// Rationale: Deep hierarchies increase operation latency and complexity
	// Recommended: 1-3 levels for optimal performance
	// Maximum: 10 levels to balance flexibility with operational overhead
	MaxHierarchyDepth = 10
)

// Network configuration
const (
	// DefaultGRPCPort is the default port for gRPC communication between hunters and processors
	DefaultGRPCPort = 50051

	// DefaultMaxHunters is the default maximum number of concurrent hunter connections per processor
	DefaultMaxHunters = 100

	// DefaultMaxSubscribers is the default maximum number of concurrent TUI/monitoring subscribers
	DefaultMaxSubscribers = 100
)

// Flow control thresholds
//
// Flow Control Strategy:
//
// Flow control is based on PCAP write queue utilization to prevent packet loss
// during I/O pressure. Thresholds are set to provide smooth transitions between
// flow states while preventing queue overflow.
//
// Threshold Levels:
// - RESUME (<30%): Queue has drained sufficiently, hunters can resume normal rate
// - CONTINUE (30-70%): Normal operation, no action needed
// - SLOW (70-90%): Queue filling up, hunters should reduce packet rate
// - PAUSE (>90%): Queue critically full, hunters should pause packet transmission
//
// Rationale:
// - 30% resume threshold: Provides hysteresis to prevent rapid state oscillation
// - 70% slow threshold: Early warning allows hunters to reduce rate before critical
// - 90% pause threshold: Emergency brake to prevent queue overflow and packet loss
const (
	// FlowControlResumeThreshold is the queue utilization (0-1) below which to resume normal flow
	FlowControlResumeThreshold = 0.30

	// FlowControlSlowThreshold is the queue utilization (0-1) above which to slow down hunters
	FlowControlSlowThreshold = 0.70

	// FlowControlPauseThreshold is the queue utilization (0-1) above which to pause hunters
	FlowControlPauseThreshold = 0.90

	// FlowControlUpstreamBacklogThreshold is the packet backlog above which to trigger slowdown
	// when forwarding to upstream processors
	FlowControlUpstreamBacklogThreshold = 10000
)

// UI/TUI configuration
const (
	// TUITickInterval is the interval for TUI screen refresh
	TUITickInterval = 50 * time.Millisecond

	// TUICleanupInterval is the interval for TUI cleanup operations (stale data removal)
	TUICleanupInterval = 30 * time.Second

	// TUIConnectionTimeout is the timeout for establishing TUI remote connections
	TUIConnectionTimeout = 10 * time.Second

	// TUIReconnectInterval is the initial interval for TUI reconnection attempts
	TUIReconnectInterval = 5 * time.Second

	// TUIMaxReconnectInterval is the maximum interval for TUI reconnection attempts (with backoff)
	TUIMaxReconnectInterval = 60 * time.Second
)

// Hunter/Processor keepalive and monitoring
const (
	// HunterHeartbeatInterval is the interval for hunter heartbeat messages
	HunterHeartbeatInterval = 10 * time.Second

	// HunterStaleCheckInterval is the interval for checking stale hunters
	HunterStaleCheckInterval = 2 * time.Minute

	// HunterStaleGracePeriod is the time since last heartbeat before considering a hunter stale
	HunterStaleGracePeriod = 5 * time.Minute

	// ProcessorBatchTimeoutMs is the default timeout in milliseconds for batching packets before sending
	ProcessorBatchTimeoutMs = 100
)

// PCAP writer configuration
//
// These constants define defaults for PCAP file writing operations.
const (
	// DefaultPCAPMaxFileSize is the default maximum size for PCAP files (100MB)
	// Files are rotated when they reach this size
	DefaultPCAPMaxFileSize = 100 * 1024 * 1024

	// DefaultPCAPBufferSize is the default buffer size for PCAP I/O operations (4KB)
	// This balances memory usage with I/O efficiency
	DefaultPCAPBufferSize = 4096

	// DefaultPCAPSyncInterval is the default interval for syncing PCAP files to disk
	DefaultPCAPSyncInterval = 5 * time.Second

	// DefaultPCAPSnapLen is the snapshot length for PCAP files (64KB - 1)
	// This is the maximum packet data captured per packet
	DefaultPCAPSnapLen = 65536

	// DefaultMaxFilesPerCall is the maximum number of PCAP files per call for rotation
	DefaultMaxFilesPerCall = 10
)

// Forwarding and connection resilience
//
// These constants control retry behavior and failure detection.
const (
	// MaxConsecutiveSendFailures is the threshold for considering a connection dead
	// After this many consecutive failures, the connection is assumed to be lost
	MaxConsecutiveSendFailures = 3

	// DefaultSendTimeout is the timeout for sending a batch via gRPC
	// Used to prevent indefinite blocking on unresponsive connections
	DefaultSendTimeout = 5 * time.Second
)

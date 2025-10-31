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

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
const (
	// SignalChannelBuffer is the buffer size for OS signal channels
	SignalChannelBuffer = 1

	// ErrorChannelBuffer is the buffer size for error reporting channels
	ErrorChannelBuffer = 1

	// FilterUpdateChannelBuffer is the buffer size for filter update channels
	FilterUpdateChannelBuffer = 10

	// SubscriberChannelBuffer is the buffer size for subscriber packet channels
	SubscriberChannelBuffer = 100

	// VoIPAnalyzerQueueBuffer is the buffer size for VoIP analyzer queues
	VoIPAnalyzerQueueBuffer = 1000

	// PCAPWriteQueueBuffer is the buffer size for PCAP writer queue
	PCAPWriteQueueBuffer = 1000

	// PacketChannelBuffer is the standard buffer for packet processing channels
	PacketChannelBuffer = 100

	// BatchQueueBuffer is the buffer size for batch processing queues
	BatchQueueBuffer = 10
)

// gRPC configuration
const (
	// MaxGRPCMessageSize is the maximum size for gRPC messages (10MB)
	MaxGRPCMessageSize = 10 * 1024 * 1024
)

package voip

import (
	"time"
)

// VoIP-related constants

const (
	// Standard SIP ports as defined in RFC 3261
	SIPPort    = 5060 // SIP over UDP/TCP
	SIPPortTLS = 5061 // SIP over TLS (SIPS)

	// PCAP constants
	MaxPcapSnapshotLen = 65535 // Maximum packet capture size

	// Default limits and timeouts
	DefaultGoroutineLimit = 1000 // Default maximum concurrent goroutines for stream processing
	DefaultMaxCalls       = 1000 // Default maximum calls to keep in ring buffer

	// Default timeout configurations (configurable via config file)
	DefaultCallIDDetectionTimeout = 30 * time.Second   // Timeout for Call-ID detection
	DefaultJanitorCleanupInterval = 30 * time.Second   // How often to run cleanup
	DefaultCallExpirationTime     = 3600 * time.Second // How long to keep calls in memory (1 hour)
	DefaultStreamQueueBuffer      = 500                // Default stream queue buffer size

	// TCP-specific defaults
	DefaultTCPCleanupInterval    = 60 * time.Second  // How often to cleanup TCP resources
	DefaultTCPBufferMaxAge       = 300 * time.Second // Maximum age for TCP packet buffers
	DefaultTCPStreamMaxQueueTime = 120 * time.Second // Maximum time a stream can wait in queue
	DefaultMaxTCPBuffers         = 10000             // Maximum number of TCP packet buffers
	DefaultTCPStreamTimeout      = 600 * time.Second // Timeout for TCP stream processing
	DefaultTCPAssemblerMaxPages  = 100               // Maximum pages for TCP assembler

	// TCP Performance defaults
	DefaultTCPPerformanceMode     = "balanced"        // Default performance mode
	DefaultTCPBufferStrategy      = "adaptive"        // Default buffer strategy
	DefaultEnableBackpressure     = true              // Enable backpressure by default
	DefaultMemoryOptimization     = false             // Memory optimization disabled by default
	DefaultTCPBufferPoolSize      = 1000              // Default buffer pool size
	DefaultTCPBatchSize           = 32                // Default batch processing size
	DefaultTCPIOThreads           = 4                 // Default number of I/O threads
	DefaultTCPCompressionLevel    = 1                 // Default compression level (1=fast)
	DefaultTCPMemoryLimit         = 100 * 1024 * 1024 // Default memory limit (100MB)
	DefaultTCPLatencyOptimization = false             // Latency optimization disabled by default
)

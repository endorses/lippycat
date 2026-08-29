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
	DefaultGoroutineLimit = 1000 // Warning threshold for concurrent stream goroutines
	DefaultMaxStreams     = 0    // Hard cap on concurrent TCP SIP streams (0 = unlimited)
	DefaultMaxCalls       = 1000 // Default maximum calls to keep in ring buffer

	// Default timeout configurations (configurable via config file)
	DefaultCallIDDetectionTimeout = 30 * time.Second   // Timeout for Call-ID detection
	DefaultJanitorCleanupInterval = 30 * time.Second   // How often to run cleanup
	DefaultCallExpirationTime     = 3600 * time.Second // How long to keep calls in memory (1 hour)
	DefaultStreamQueueBuffer      = 500                // Default stream queue buffer size
	DefaultMaxFilenameLength      = 100                // Max chars of a sanitized Call-ID used in a per-call PCAP name

	// TCP-specific defaults
	DefaultTCPCleanupInterval    = 60 * time.Second  // How often to cleanup TCP resources
	DefaultTCPBufferMaxAge       = 300 * time.Second // Maximum age for TCP packet buffers
	DefaultTCPStreamMaxQueueTime = 120 * time.Second // Maximum time a stream can wait in queue
	DefaultMaxTCPBuffers         = 10000             // Maximum number of TCP packet buffers
	DefaultTCPStreamTimeout      = 600 * time.Second // Timeout for TCP stream processing
	DefaultTCPAssemblerMaxPages  = 100               // Maximum pages for TCP assembler
	DefaultTCPSIPIdleTimeout     = 120 * time.Second // Idle timeout for SIP TCP connections (RFC 5626)

	// Phase 3: State-based TCP timeout defaults
	// These are used when EnableStateTCPTimeouts is true
	DefaultTCPOpeningTimeout     = 5 * time.Minute  // Timeout for connections that haven't seen SIP data yet
	DefaultTCPEstablishedTimeout = 30 * time.Minute // Timeout for established connections with valid SIP
	DefaultTCPClosingTimeout     = 5 * time.Minute  // Timeout for connections in closing state (FIN/RST seen)

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

// Security validation constants
//
// These limits protect against DoS attacks and malformed input.
const (
	// MaxCallIDLength is the maximum allowed length for SIP Call-ID values
	// Call-IDs exceeding this length are rejected as potential DoS vectors
	// RFC 3261 doesn't specify a max, but 1024 bytes is generous for any valid use
	MaxCallIDLength = 1024

	// MaxContentLengthDigits is the maximum number of digits in Content-Length header
	// A 10-digit number allows up to ~10GB which exceeds any reasonable SIP message
	// Longer strings are rejected to prevent parsing DoS attacks
	MaxContentLengthDigits = 10

	// MaxInt32ForContentLength is used for overflow protection when parsing Content-Length
	// This is math.MaxInt32 (2147483647) used to detect integer overflow during parsing
	MaxInt32ForContentLength = 2147483647
)

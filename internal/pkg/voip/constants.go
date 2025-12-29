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

// Memory pool configuration constants
//
// Buffer Size Classes:
// Memory pools use graduated size classes to efficiently handle objects of varying sizes.
// Each class handles objects up to its size, reducing memory fragmentation.
const (
	// PoolSizeClass128 is the smallest buffer class (128 bytes)
	// Used for small SIP headers, short strings, and minimal packet metadata
	PoolSizeClass128 = 128

	// PoolSizeClass512 is for medium-small buffers (512 bytes)
	// Handles most SIP method lines and typical header values
	PoolSizeClass512 = 512

	// PoolSizeClass2K is for medium buffers (2KB)
	// Suitable for SIP messages with several headers
	PoolSizeClass2K = 2048

	// PoolSizeClass8K is for larger buffers (8KB)
	// Handles most complete SIP messages and moderate RTP payloads
	PoolSizeClass8K = 8192

	// PoolSizeClass32K is for large buffers (32KB)
	// Used for SIP messages with large SDP bodies or multiple participants
	PoolSizeClass32K = 32768

	// PoolSizeClass64K is the maximum pooled buffer size (64KB)
	// Maximum size for pooled objects; larger allocations bypass the pool
	PoolSizeClass64K = 65536

	// PoolDefaultInitialSize is the initial number of objects pre-allocated per pool
	PoolDefaultInitialSize = 128

	// PoolDefaultMaxSize is the maximum number of objects retained in a pool
	// Objects beyond this limit are discarded to prevent memory bloat
	PoolDefaultMaxSize = 10000

	// PoolDefaultMaxObjectSize is the maximum size of objects allowed in the pool
	// Larger objects are allocated directly and not pooled
	PoolDefaultMaxObjectSize = PoolSizeClass64K

	// PoolDefaultGrowthFactor is the multiplier when expanding pool capacity
	PoolDefaultGrowthFactor = 2
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

package voip

import (
	"time"
)

// VoIP-related constants

const (
	// Standard SIP port as defined in RFC 3261
	SIPPort = 5060

	// PCAP constants
	MaxPcapSnapshotLen = 65535 // Maximum packet capture size

	// Default limits and timeouts
	DefaultGoroutineLimit = 1000 // Default maximum concurrent goroutines for stream processing

	// Default timeout configurations (configurable via config file)
	DefaultCallIDDetectionTimeout = 30 * time.Second  // Timeout for Call-ID detection
	DefaultJanitorCleanupInterval = 30 * time.Second  // How often to run cleanup
	DefaultCallExpirationTime     = 90 * time.Second  // How long to keep calls in memory
	DefaultStreamQueueBuffer      = 500               // Default stream queue buffer size
)

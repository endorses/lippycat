package capture

import "time"

// Packet capture constants

const (
	// Default packet buffer size - increased to handle high-speed traffic
	// At 1Gbps, this provides ~1 second of buffering for average packet sizes
	DefaultPacketBufferSize = 100000

	// Default pcap read timeout - allows graceful shutdown while maintaining smooth packet display
	// 200ms = 5 wakeups/second for context cancellation checks
	// Lower values = more responsive shutdown but potentially choppy display
	// Higher values = smoother display but slower shutdown response
	DefaultPcapTimeout = 200 * time.Millisecond
)

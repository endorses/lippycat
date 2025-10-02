package capture

// Packet capture constants

const (
	// Default packet buffer size - increased to handle high-speed traffic
	// At 1Gbps, this provides ~1 second of buffering for average packet sizes
	DefaultPacketBufferSize = 100000
)

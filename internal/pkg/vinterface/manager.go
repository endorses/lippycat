// Package vinterface provides virtual network interface management for packet injection.
// It enables integration with third-party tools (Wireshark, Snort, Suricata, tcpdump)
// by creating TAP/TUN interfaces and injecting captured packets in real-time.
package vinterface

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// Manager manages a virtual network interface for packet injection.
// It provides a platform-agnostic interface for creating, managing, and
// injecting packets into virtual interfaces (TAP/TUN devices).
type Manager interface {
	// Name returns the name of the virtual interface (e.g., "lc0").
	Name() string

	// Start initializes and brings up the virtual interface.
	// Returns error if interface creation fails (e.g., permission denied).
	Start() error

	// InjectPacket injects a single raw packet into the virtual interface.
	// The packet should be a complete Ethernet frame (for TAP) or IP packet (for TUN).
	// Returns error if injection fails.
	InjectPacket(packet []byte) error

	// InjectPacketBatch injects multiple packets from PacketDisplay format.
	// This is the primary method for use by capture loops and processors.
	// Packets are converted to raw frames and injected asynchronously.
	// Returns error if batch processing fails.
	InjectPacketBatch(packets []types.PacketDisplay) error

	// Shutdown cleanly tears down the virtual interface.
	// Closes file descriptors, deletes the interface, and stops injection workers.
	Shutdown() error

	// Stats returns current statistics for the virtual interface.
	Stats() Stats
}

// Stats tracks metrics for virtual interface operations.
type Stats struct {
	// PacketsInjected is the total number of packets successfully injected.
	PacketsInjected uint64

	// PacketsDropped is the number of packets dropped due to queue overflow.
	PacketsDropped uint64

	// InjectionErrors is the number of failed injection attempts.
	InjectionErrors uint64

	// ConversionErrors is the number of packets that failed conversion.
	ConversionErrors uint64

	// QueueUtilization is the current utilization of the injection queue (0.0-1.0).
	QueueUtilization float64

	// BytesInjected is the total number of bytes injected.
	BytesInjected uint64

	// LastInjection is the timestamp of the last successful injection.
	LastInjection time.Time
}

// Config holds configuration for virtual interface creation.
type Config struct {
	// Name is the interface name (e.g., "lc0", "lippycat-voip0").
	// Default: "lc0"
	Name string

	// Type is the interface type ("tap" or "tun").
	// TAP: Layer 2 (Ethernet frames)
	// TUN: Layer 3 (IP packets)
	// Default: "tap"
	Type string

	// BufferSize is the size of the async injection queue.
	// Larger buffers reduce drops but increase memory usage.
	// Default: 4096 packets
	BufferSize int

	// MTU is the Maximum Transmission Unit for the interface.
	// Default: 1500 bytes
	MTU int

	// NetNS is the network namespace name to create the interface in.
	// If empty, the interface is created in the default namespace.
	// Example: "lippycat-isolated"
	// Note: Requires CAP_NET_ADMIN and CAP_SYS_ADMIN capabilities.
	NetNS string

	// DropPrivilegesUser is the username to drop privileges to after interface creation.
	// If empty, privileges are not dropped.
	// Example: "lippycat" or "nobody"
	// Note: Only works when running as root (UID 0). Requires Go 1.16+.
	DropPrivilegesUser string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Name:       "lc0",
		Type:       "tap",
		BufferSize: 4096,
		MTU:        1500,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.Name == "" {
		return ErrInvalidName
	}

	if c.Type != "tap" && c.Type != "tun" {
		return ErrInvalidType
	}

	if c.BufferSize <= 0 {
		return ErrInvalidBufferSize
	}

	if c.MTU <= 0 || c.MTU > 65535 {
		return ErrInvalidMTU
	}

	return nil
}

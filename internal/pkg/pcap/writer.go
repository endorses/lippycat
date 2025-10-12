package pcap

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PcapWriter defines the interface for writing packets to PCAP files
// This interface is used by both TUI (for user-initiated saves) and
// processor (for automated capture to disk)
type PcapWriter interface {
	// WritePacket writes a single packet to the PCAP file
	WritePacket(pkt types.PacketDisplay) error

	// Close closes the writer and flushes data to disk
	Close() error

	// PacketCount returns the number of packets written
	PacketCount() int

	// FilePath returns the path to the PCAP file
	FilePath() string
}

// Config holds common configuration for PCAP writers
type Config struct {
	FilePath     string          // Path to output PCAP file
	LinkType     layers.LinkType // Link layer type (usually Ethernet)
	Snaplen      uint32          // Snapshot length (usually 65536)
	SyncInterval time.Duration   // How often to sync to disk (streaming only, 0 = after each packet)
	BufferSize   int             // Write buffer size (streaming only)
}

// DefaultConfig returns default PCAP writer configuration
func DefaultConfig() Config {
	return Config{
		LinkType:     layers.LinkTypeEthernet,
		Snaplen:      65536,
		SyncInterval: 5 * time.Second,
		BufferSize:   1000,
	}
}

// PacketDisplayToGopacket converts a PacketDisplay to gopacket format
// Returns CaptureInfo and raw packet bytes suitable for PCAP writing
func PacketDisplayToGopacket(pkt types.PacketDisplay) (gopacket.CaptureInfo, []byte, error) {
	if pkt.RawData == nil || len(pkt.RawData) == 0 {
		return gopacket.CaptureInfo{}, nil, fmt.Errorf("packet has no raw data")
	}

	ci := gopacket.CaptureInfo{
		Timestamp:     pkt.Timestamp,
		CaptureLength: len(pkt.RawData),
		Length:        pkt.Length,
	}

	// If Length is 0, use RawData length as fallback
	if ci.Length == 0 {
		ci.Length = len(pkt.RawData)
	}

	return ci, pkt.RawData, nil
}

// Package source defines abstractions for packet origins in the processor.
// This enables the processor to work with different packet sources:
// - GRPCSource: packets received from remote hunters via gRPC
// - LocalSource: packets captured locally (for standalone tap mode)
package source

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
)

// PacketSource abstracts the origin of packets for the processor.
// Implementations include:
// - GRPCSource: receives packets from hunters via gRPC streaming
// - LocalSource: captures packets locally using gopacket
type PacketSource interface {
	// Start begins packet capture/reception. Blocks until ctx is cancelled.
	Start(ctx context.Context) error

	// Batches returns a channel that receives packet batches.
	// The channel is closed when the source stops.
	Batches() <-chan *PacketBatch

	// Stats returns current capture/reception statistics.
	Stats() Stats

	// SourceID returns a unique identifier for this source.
	// For GRPCSource this could be "grpc", for LocalSource the interface name.
	SourceID() string
}

// DNSProcessor provides DNS packet parsing and tunneling detection.
// Implementations parse DNS packets and optionally detect tunneling behavior.
type DNSProcessor interface {
	// ProcessPacket parses a DNS packet and returns proto-ready metadata.
	// Returns nil if the packet is not a DNS packet or parsing fails.
	ProcessPacket(packet gopacket.Packet) *data.DNSMetadata

	// Stop stops the DNS processor and releases resources.
	Stop()
}

// PacketBatch contains a batch of packets from a source.
// This is the internal representation used by the processor, distinct from
// the protobuf data.PacketBatch which is used for gRPC transport.
type PacketBatch struct {
	// SourceID identifies where this batch came from.
	// For hunters, this is the hunter ID.
	// For local capture, this is "local" or the interface name.
	SourceID string

	// Packets in this batch
	Packets []*data.CapturedPacket

	// Sequence number for ordering and loss detection
	Sequence uint64

	// TimestampNs is when the batch was created (Unix nanoseconds)
	TimestampNs int64

	// Stats contains optional statistics about capture at the source
	Stats *data.BatchStats

	// MatchedFilterIDs contains filter IDs that matched this batch.
	// Used for LI (Lawful Interception) correlation to identify which
	// intercept tasks apply to these packets.
	// Populated by hunters (distributed mode) or LocalSource (tap mode).
	MatchedFilterIDs []string
}

// Stats contains packet source statistics.
type Stats struct {
	// PacketsReceived is the total number of packets received/captured
	PacketsReceived uint64

	// PacketsDropped is the number of packets dropped (buffer overflow, etc.)
	PacketsDropped uint64

	// BytesReceived is the total bytes received/captured
	BytesReceived uint64

	// BatchesReceived is the number of batches processed
	BatchesReceived uint64

	// LastPacketTime is when the last packet was received
	LastPacketTime time.Time

	// StartTime is when the source started
	StartTime time.Time
}

// AtomicStats provides thread-safe access to Stats fields.
// Use this for concurrent updates from packet processing goroutines.
type AtomicStats struct {
	packetsReceived atomic.Uint64
	packetsDropped  atomic.Uint64
	bytesReceived   atomic.Uint64
	batchesReceived atomic.Uint64
	lastPacketTime  atomic.Int64 // Unix nano
	startTime       int64        // Set once at start
}

// NewAtomicStats creates a new AtomicStats initialized with the current time.
func NewAtomicStats() *AtomicStats {
	return &AtomicStats{
		startTime: time.Now().UnixNano(),
	}
}

// AddPacket records a received packet.
func (s *AtomicStats) AddPacket(bytes uint64) {
	s.packetsReceived.Add(1)
	s.bytesReceived.Add(bytes)
	s.lastPacketTime.Store(time.Now().UnixNano())
}

// AddDropped records a dropped packet.
func (s *AtomicStats) AddDropped(count uint64) {
	s.packetsDropped.Add(count)
}

// AddBatch records a received batch.
func (s *AtomicStats) AddBatch() {
	s.batchesReceived.Add(1)
}

// Snapshot returns a copy of the current stats.
func (s *AtomicStats) Snapshot() Stats {
	lastNano := s.lastPacketTime.Load()
	var lastTime time.Time
	if lastNano > 0 {
		lastTime = time.Unix(0, lastNano)
	}

	return Stats{
		PacketsReceived: s.packetsReceived.Load(),
		PacketsDropped:  s.packetsDropped.Load(),
		BytesReceived:   s.bytesReceived.Load(),
		BatchesReceived: s.batchesReceived.Load(),
		LastPacketTime:  lastTime,
		StartTime:       time.Unix(0, s.startTime),
	}
}

// FromProtoBatch converts a protobuf PacketBatch to the internal PacketBatch type.
func FromProtoBatch(pb *data.PacketBatch) *PacketBatch {
	if pb == nil {
		return nil
	}
	return &PacketBatch{
		SourceID:    pb.HunterId,
		Packets:     pb.Packets,
		Sequence:    pb.Sequence,
		TimestampNs: pb.TimestampNs,
		Stats:       pb.Stats,
	}
}

// ToProtoBatch converts the internal PacketBatch to a protobuf PacketBatch.
func (b *PacketBatch) ToProtoBatch() *data.PacketBatch {
	if b == nil {
		return nil
	}
	return &data.PacketBatch{
		HunterId:    b.SourceID,
		Packets:     b.Packets,
		Sequence:    b.Sequence,
		TimestampNs: b.TimestampNs,
		Stats:       b.Stats,
	}
}

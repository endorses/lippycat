// Package source defines abstractions for packet origins in the processor.
// This enables the processor to work with different packet sources:
// - GRPCSource: packets received from remote hunters via gRPC
// - LocalSource: packets captured locally (for standalone tap mode)
package source

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/sysmetrics"
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

	// Envelopes is the transport-neutral representation produced at the gRPC
	// boundary. Packets remains temporarily available to unmigrated processor
	// consumers during the pipeline migration.
	Envelopes []*pipeline.PacketEnvelope

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
	// PacketsCaptured is the total number of packets received from the capture buffer
	// (before any application-layer filtering)
	PacketsCaptured uint64

	// PacketsForwarded is the number of packets that passed filtering and were batched
	PacketsForwarded uint64

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

	// CPUPercent is the CPU usage percentage (0-100, -1 if unavailable)
	CPUPercent float64

	// MemoryRSSBytes is the process resident set size in bytes
	MemoryRSSBytes uint64

	// MemoryLimitBytes is the memory limit from cgroup (0 if unavailable)
	MemoryLimitBytes uint64
}

// AtomicStats provides thread-safe access to Stats fields.
// Use this for concurrent updates from packet processing goroutines.
type AtomicStats struct {
	packetsCaptured  atomic.Uint64
	packetsForwarded atomic.Uint64
	packetsDropped   atomic.Uint64
	bytesReceived    atomic.Uint64
	batchesReceived  atomic.Uint64
	lastPacketTime   atomic.Int64 // Unix nano
	startTime        int64        // Set once at start

	// System metrics (CPU/RAM)
	cpuPercent       atomic.Value // stores float64
	memoryRSSBytes   atomic.Uint64
	memoryLimitBytes atomic.Uint64
}

// NewAtomicStats creates a new AtomicStats initialized with the current time.
func NewAtomicStats() *AtomicStats {
	s := &AtomicStats{
		startTime: time.Now().UnixNano(),
	}
	s.cpuPercent.Store(float64(-1)) // Initialize as unavailable
	return s
}

// AddCaptured records a packet received from the capture buffer (before filtering).
func (s *AtomicStats) AddCaptured() {
	s.packetsCaptured.Add(1)
	s.lastPacketTime.Store(time.Now().UnixNano())
}

// AddForwarded records a packet that passed filtering and was batched.
func (s *AtomicStats) AddForwarded(bytes uint64) {
	s.packetsForwarded.Add(1)
	s.bytesReceived.Add(bytes)
}

// AddDropped records a dropped packet.
func (s *AtomicStats) AddDropped(count uint64) {
	s.packetsDropped.Add(count)
}

// AddBatch records a received batch.
func (s *AtomicStats) AddBatch() {
	s.batchesReceived.Add(1)
}

// SetSystemMetrics updates the system metrics (CPU/RAM) from sysmetrics collector.
func (s *AtomicStats) SetSystemMetrics(m sysmetrics.Metrics) {
	s.cpuPercent.Store(m.CPUPercent)
	s.memoryRSSBytes.Store(m.MemoryRSSBytes)
	s.memoryLimitBytes.Store(m.MemoryLimitBytes)
}

// Snapshot returns a copy of the current stats.
func (s *AtomicStats) Snapshot() Stats {
	lastNano := s.lastPacketTime.Load()
	var lastTime time.Time
	if lastNano > 0 {
		lastTime = time.Unix(0, lastNano)
	}

	return Stats{
		PacketsCaptured:  s.packetsCaptured.Load(),
		PacketsForwarded: s.packetsForwarded.Load(),
		PacketsDropped:   s.packetsDropped.Load(),
		BytesReceived:    s.bytesReceived.Load(),
		BatchesReceived:  s.batchesReceived.Load(),
		LastPacketTime:   lastTime,
		StartTime:        time.Unix(0, s.startTime),
		CPUPercent:       s.cpuPercent.Load().(float64),
		MemoryRSSBytes:   s.memoryRSSBytes.Load(),
		MemoryLimitBytes: s.memoryLimitBytes.Load(),
	}
}

// FromProtoBatch converts a protobuf PacketBatch to the internal PacketBatch type.
func FromProtoBatch(pb *data.PacketBatch) *PacketBatch {
	b, err := FromProtoBatchE(pb)
	if err != nil {
		panic(err)
	}
	return b
}

// FromProtoBatchE converts at the gRPC boundary and reports malformed metadata.
func FromProtoBatchE(pb *data.PacketBatch) (*PacketBatch, error) {
	if pb == nil {
		return nil, nil
	}
	normalized, err := grpcadapter.FromPacketBatch(pb)
	if err != nil {
		return nil, fmt.Errorf("normalize gRPC packet batch: %w", err)
	}
	return &PacketBatch{
		SourceID:    pb.HunterId,
		Packets:     pb.Packets,
		Envelopes:   normalized.Packets,
		Sequence:    pb.Sequence,
		TimestampNs: pb.TimestampNs,
		Stats:       pb.Stats,
	}, nil
}

// ToProtoBatch converts the internal PacketBatch to a protobuf PacketBatch.
func (b *PacketBatch) ToProtoBatch() *data.PacketBatch {
	pb, err := b.ToProtoBatchE()
	if err != nil {
		panic(err)
	}
	return pb
}

// ToProtoBatchE performs transport encoding in the gRPC adapter.
func (b *PacketBatch) ToProtoBatchE() (*data.PacketBatch, error) {
	if b == nil {
		return nil, nil
	}
	if b.Envelopes != nil {
		// Unmigrated processor stages still enrich Packets directly. Normalize
		// their current values here so those enrichments survive forwarding.
		normalized, err := grpcadapter.FromPacketBatch(&data.PacketBatch{
			HunterId: b.SourceID, Sequence: b.Sequence, TimestampNs: b.TimestampNs,
			Packets: b.Packets, Stats: b.Stats,
		})
		if err != nil {
			return nil, fmt.Errorf("normalize processed packet batch: %w", err)
		}
		pb, err := grpcadapter.ToPacketBatch(normalized)
		if err != nil {
			return nil, fmt.Errorf("encode gRPC packet batch: %w", err)
		}
		return pb, nil
	}
	return &data.PacketBatch{
		HunterId:    b.SourceID,
		Packets:     b.Packets,
		Sequence:    b.Sequence,
		TimestampNs: b.TimestampNs,
		Stats:       b.Stats,
	}, nil
}

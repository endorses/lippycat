//go:build tui || all

package components

import (
	"sync"
)

// DropStats aggregates drop statistics from multiple sources.
// Tracks kernel drops (pcap), application drops (buffer/queue),
// and distributed mode drops (hunter/network).
type DropStats struct {
	mu sync.RWMutex

	// Kernel level (from pcap stats)
	KernelDrops    int64
	KernelReceived int64 // For calculating drop rate

	// Application level
	BufferDrops        int64 // Compatible aggregate of regular and SIP PacketBuffer overflow
	BufferRegularDrops int64 // Regular-lane PacketBuffer overflow
	BufferSIPDrops     int64 // Protected SIP-lane PacketBuffer overflow
	QueueDrops         int64 // TCP assembler queue full
	FilterDrops        int64 // Filtered out (intentional, not counted in total)

	// Distributed mode
	HunterDrops  int64 // Aggregated from all hunters
	NetworkDrops int64 // gRPC stream drops

	// Local TUI detail-feed loss. These packet-level counters are separate from
	// capture/network loss because exact ingress statistics still include them.
	SampledOutPackets     int64
	BatchQueuePacketDrops int64
	PendingEvictions      int64
	DisplayRetentionRatio int64 // End-to-end valid-ingress retention * 1000
	hasDisplayRetention   bool

	// Total packets for percentage calculations
	TotalPackets int64
}

// NewDropStats creates a new drop statistics aggregator.
func NewDropStats() *DropStats {
	return &DropStats{}
}

// SetKernelStats updates kernel-level drop statistics from pcap.
func (ds *DropStats) SetKernelStats(received, dropped int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.KernelReceived = received
	ds.KernelDrops = dropped
}

// AddBufferDrops adds to the buffer drop counter.
func (ds *DropStats) AddBufferDrops(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.BufferDrops += count
}

// SetBufferDrops sets the buffer drop counter (for absolute values).
func (ds *DropStats) SetBufferDrops(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.BufferDrops = count
}

// SetBufferDropStages sets the named PacketBuffer loss stages and maintains the
// compatible aggregate used by existing health calculations.
func (ds *DropStats) SetBufferDropStages(regular, sip int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.BufferRegularDrops = regular
	ds.BufferSIPDrops = sip
	ds.BufferDrops = regular + sip
}

// AddQueueDrops adds to the queue drop counter.
func (ds *DropStats) AddQueueDrops(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.QueueDrops += count
}

// SetQueueDrops sets the queue drop counter.
func (ds *DropStats) SetQueueDrops(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.QueueDrops = count
}

// SetFilterDrops sets the filter drop counter (intentional drops).
func (ds *DropStats) SetFilterDrops(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.FilterDrops = count
}

// SetHunterDrops sets the aggregated hunter drops.
func (ds *DropStats) SetHunterDrops(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.HunterDrops = count
}

// AddHunterDrops adds to the hunter drop counter.
func (ds *DropStats) AddHunterDrops(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.HunterDrops += count
}

// SetNetworkDrops sets the network (gRPC) drop counter.
func (ds *DropStats) SetNetworkDrops(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.NetworkDrops = count
}

// SetTotalPackets sets the total packets for percentage calculations.
func (ds *DropStats) SetTotalPackets(count int64) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.TotalPackets = count
}

// DropSummary contains computed drop statistics.
type DropSummary struct {
	KernelDrops           int64
	KernelDropRate        float64
	BufferDrops           int64
	BufferRegularDrops    int64
	BufferSIPDrops        int64
	BufferDropRate        float64
	QueueDrops            int64
	QueueDropRate         float64
	HunterDrops           int64
	HunterDropRate        float64
	NetworkDrops          int64
	NetworkDropRate       float64
	SampledOutPackets     int64
	BatchQueuePacketDrops int64
	PendingEvictions      int64
	DisplayDrops          int64
	DisplayRetentionRate  float64
	TotalDrops            int64
	TotalDropRate         float64
	FilterDrops           int64 // Intentional, tracked separately
}

// GetSummary returns a summary of all drop statistics with calculated rates.
func (ds *DropStats) GetSummary() DropSummary {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	// Calculate total (excluding intentional filter drops)
	totalDrops := ds.KernelDrops + ds.BufferDrops + ds.QueueDrops + ds.HunterDrops + ds.NetworkDrops

	// Use total packets for rate calculation
	// If no packets, use kernel received as fallback
	base := ds.TotalPackets
	if base == 0 {
		base = ds.KernelReceived
	}

	summary := DropSummary{
		KernelDrops:           ds.KernelDrops,
		BufferDrops:           ds.BufferDrops,
		BufferRegularDrops:    ds.BufferRegularDrops,
		BufferSIPDrops:        ds.BufferSIPDrops,
		QueueDrops:            ds.QueueDrops,
		HunterDrops:           ds.HunterDrops,
		NetworkDrops:          ds.NetworkDrops,
		SampledOutPackets:     ds.SampledOutPackets,
		BatchQueuePacketDrops: ds.BatchQueuePacketDrops,
		PendingEvictions:      ds.PendingEvictions,
		TotalDrops:            totalDrops,
		FilterDrops:           ds.FilterDrops,
	}
	summary.DisplayDrops = ds.SampledOutPackets + ds.BatchQueuePacketDrops + ds.PendingEvictions
	if ds.hasDisplayRetention {
		summary.DisplayRetentionRate = float64(ds.DisplayRetentionRatio) / 10
	} else if ds.TotalPackets > 0 {
		retained := ds.TotalPackets - summary.DisplayDrops
		if retained < 0 {
			retained = 0
		}
		summary.DisplayRetentionRate = float64(retained) / float64(ds.TotalPackets) * 100
	} else {
		summary.DisplayRetentionRate = 100
	}

	// Calculate rates if we have a valid base
	if base > 0 {
		summary.KernelDropRate = float64(ds.KernelDrops) / float64(base) * 100
		summary.BufferDropRate = float64(ds.BufferDrops) / float64(base) * 100
		summary.QueueDropRate = float64(ds.QueueDrops) / float64(base) * 100
		summary.HunterDropRate = float64(ds.HunterDrops) / float64(base) * 100
		summary.NetworkDropRate = float64(ds.NetworkDrops) / float64(base) * 100
		summary.TotalDropRate = float64(totalDrops) / float64(base) * 100
	}

	return summary
}

// HasDrops returns true if any drops have been recorded.
func (ds *DropStats) HasDrops() bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.KernelDrops > 0 || ds.BufferDrops > 0 || ds.QueueDrops > 0 ||
		ds.HunterDrops > 0 || ds.NetworkDrops > 0 || ds.SampledOutPackets > 0 ||
		ds.BatchQueuePacketDrops > 0 || ds.PendingEvictions > 0
}

// Reset clears all drop statistics.
func (ds *DropStats) Reset() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.KernelDrops = 0
	ds.KernelReceived = 0
	ds.BufferDrops = 0
	ds.BufferRegularDrops = 0
	ds.BufferSIPDrops = 0
	ds.QueueDrops = 0
	ds.FilterDrops = 0
	ds.HunterDrops = 0
	ds.NetworkDrops = 0
	ds.SampledOutPackets = 0
	ds.BatchQueuePacketDrops = 0
	ds.PendingEvictions = 0
	ds.DisplayRetentionRatio = 0
	ds.hasDisplayRetention = false
	ds.TotalPackets = 0
}

// UpdateFromBridgeStats updates TUI queue pressure from BridgeStatistics.
// PacketBuffer drops are supplied by capture telemetry and must not be
// overwritten with an estimate derived from dropped batches.
func (ds *DropStats) UpdateFromBridgeStats(bs *BridgeStatistics) {
	if bs == nil {
		return
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	ds.SampledOutPackets = bs.PacketsSampledOut
	ds.BatchQueuePacketDrops = bs.BatchQueuePacketDrops
	ds.PendingEvictions = bs.PendingPacketEvictions
	ds.DisplayRetentionRatio = bs.DisplayRetentionRatio
	ds.hasDisplayRetention = true

	// Total packets from bridge
	ds.TotalPackets = bs.PacketsReceived
}

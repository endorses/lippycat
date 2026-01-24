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
	BufferDrops int64 // PacketBuffer overflow
	QueueDrops  int64 // TCP assembler queue full
	FilterDrops int64 // Filtered out (intentional, not counted in total)

	// Distributed mode
	HunterDrops  int64 // Aggregated from all hunters
	NetworkDrops int64 // gRPC stream drops

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
	KernelDrops     int64
	KernelDropRate  float64
	BufferDrops     int64
	BufferDropRate  float64
	QueueDrops      int64
	QueueDropRate   float64
	HunterDrops     int64
	HunterDropRate  float64
	NetworkDrops    int64
	NetworkDropRate float64
	TotalDrops      int64
	TotalDropRate   float64
	FilterDrops     int64 // Intentional, tracked separately
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
		KernelDrops:  ds.KernelDrops,
		BufferDrops:  ds.BufferDrops,
		QueueDrops:   ds.QueueDrops,
		HunterDrops:  ds.HunterDrops,
		NetworkDrops: ds.NetworkDrops,
		TotalDrops:   totalDrops,
		FilterDrops:  ds.FilterDrops,
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
		ds.HunterDrops > 0 || ds.NetworkDrops > 0
}

// Reset clears all drop statistics.
func (ds *DropStats) Reset() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.KernelDrops = 0
	ds.KernelReceived = 0
	ds.BufferDrops = 0
	ds.QueueDrops = 0
	ds.FilterDrops = 0
	ds.HunterDrops = 0
	ds.NetworkDrops = 0
	ds.TotalPackets = 0
}

// UpdateFromBridgeStats updates drop stats from BridgeStatistics.
func (ds *DropStats) UpdateFromBridgeStats(bs *BridgeStatistics) {
	if bs == nil {
		return
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Bridge batches dropped represents buffer/queue pressure
	// Convert batch drops to estimated packet drops (assume ~100 packets per batch average)
	ds.BufferDrops = bs.BatchesDropped * 100

	// Total packets from bridge
	ds.TotalPackets = bs.PacketsReceived
}

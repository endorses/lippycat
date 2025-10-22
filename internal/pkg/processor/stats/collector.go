package stats

import (
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
)

// Stats contains processor statistics
type Stats struct {
	TotalHunters          uint32
	HealthyHunters        uint32
	WarningHunters        uint32
	ErrorHunters          uint32
	TotalPacketsReceived  uint64
	TotalPacketsForwarded uint64
	TotalFilters          uint32
}

// cachedStats holds incrementally updated statistics
type cachedStats struct {
	stats      Stats
	lastUpdate int64 // Unix timestamp
}

// Collector collects and caches processor statistics
type Collector struct {
	cache   atomic.Value  // stores *cachedStats
	updates atomic.Uint64 // incremented on every stats change

	packetsReceived  *atomic.Uint64
	packetsForwarded *atomic.Uint64

	processorID       string
	upstreamProcessor string // Upstream processor address (if any)
}

// NewCollector creates a new stats collector
func NewCollector(processorID string, packetsReceived, packetsForwarded *atomic.Uint64) *Collector {
	c := &Collector{
		packetsReceived:  packetsReceived,
		packetsForwarded: packetsForwarded,
		processorID:      processorID,
	}

	// Initialize cache
	c.cache.Store(&cachedStats{
		stats:      Stats{},
		lastUpdate: time.Now().Unix(),
	})

	return c
}

// UpdateHealthStats updates hunter health statistics
// Should be called with pre-calculated health stats from hunter manager
func (c *Collector) UpdateHealthStats(total, healthy, warning, errCount, totalFilters uint32) {
	// Get current cache, update, and store back (copy-on-write)
	oldCache := c.cache.Load().(*cachedStats)
	newStats := oldCache.stats // Copy current stats

	// Update hunter health stats
	newStats.TotalHunters = total
	newStats.HealthyHunters = healthy
	newStats.WarningHunters = warning
	newStats.ErrorHunters = errCount
	newStats.TotalFilters = totalFilters

	// Store updated cache
	c.cache.Store(&cachedStats{
		stats:      newStats,
		lastUpdate: time.Now().Unix(),
	})
	c.updates.Add(1)
}

// Get returns current statistics (lock-free read)
func (c *Collector) Get() Stats {
	// Lock-free read from cache (hunter health stats)
	cached := c.cache.Load().(*cachedStats)
	stats := cached.stats

	// Add atomic packet counters
	if c.packetsReceived != nil {
		stats.TotalPacketsReceived = c.packetsReceived.Load()
	}
	if c.packetsForwarded != nil {
		stats.TotalPacketsForwarded = c.packetsForwarded.Load()
	}

	return stats
}

// SetUpstreamProcessor sets the upstream processor address
func (c *Collector) SetUpstreamProcessor(upstreamAddr string) {
	c.upstreamProcessor = upstreamAddr
}

// GetProto returns statistics as protobuf message
func (c *Collector) GetProto() *management.ProcessorStats {
	stats := c.Get()

	return &management.ProcessorStats{
		TotalHunters:          stats.TotalHunters,
		HealthyHunters:        stats.HealthyHunters,
		WarningHunters:        stats.WarningHunters,
		ErrorHunters:          stats.ErrorHunters,
		TotalPacketsReceived:  stats.TotalPacketsReceived,
		TotalPacketsForwarded: stats.TotalPacketsForwarded,
		TotalFilters:          stats.TotalFilters,
		ProcessorId:           c.processorID,
		UpstreamProcessor:     c.upstreamProcessor,
	}
}

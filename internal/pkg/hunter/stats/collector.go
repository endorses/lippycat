//go:build hunter || all

package stats

import (
	"sync/atomic"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/sysmetrics"
)

// Collector tracks hunter statistics with lock-free atomic operations
type Collector struct {
	packetsCaptured  atomic.Uint64
	packetsMatched   atomic.Uint64
	packetsForwarded atomic.Uint64
	packetsDropped   atomic.Uint64
	bufferBytes      atomic.Uint64

	// System metrics (CPU/RAM)
	cpuPercent       atomic.Value // stores float64
	memoryRSSBytes   atomic.Uint64
	memoryLimitBytes atomic.Uint64
}

// New creates a new statistics collector
func New() *Collector {
	c := &Collector{}
	c.cpuPercent.Store(float64(-1)) // Initialize as unavailable
	return c
}

// IncrementCaptured increments the packets captured counter
func (c *Collector) IncrementCaptured() {
	c.packetsCaptured.Add(1)
}

// IncrementMatched increments the packets matched counter
func (c *Collector) IncrementMatched() {
	c.packetsMatched.Add(1)
}

// IncrementForwarded increments packets by count
func (c *Collector) IncrementForwarded(count uint64) {
	c.packetsForwarded.Add(count)
}

// IncrementDropped increments dropped packets by count
func (c *Collector) IncrementDropped(count uint64) {
	c.packetsDropped.Add(count)
}

// SetBufferBytes sets the current buffer bytes
func (c *Collector) SetBufferBytes(bytes uint64) {
	c.bufferBytes.Store(bytes)
}

// GetCaptured returns packets captured count
func (c *Collector) GetCaptured() uint64 {
	return c.packetsCaptured.Load()
}

// GetMatched returns packets matched count
func (c *Collector) GetMatched() uint64 {
	return c.packetsMatched.Load()
}

// GetForwarded returns packets forwarded count
func (c *Collector) GetForwarded() uint64 {
	return c.packetsForwarded.Load()
}

// GetDropped returns packets dropped count
func (c *Collector) GetDropped() uint64 {
	return c.packetsDropped.Load()
}

// GetBufferBytes returns current buffer bytes
func (c *Collector) GetBufferBytes() uint64 {
	return c.bufferBytes.Load()
}

// SetSystemMetrics updates the system metrics (CPU/RAM) from sysmetrics collector
func (c *Collector) SetSystemMetrics(m sysmetrics.Metrics) {
	c.cpuPercent.Store(m.CPUPercent)
	c.memoryRSSBytes.Store(m.MemoryRSSBytes)
	c.memoryLimitBytes.Store(m.MemoryLimitBytes)
}

// GetSystemMetrics returns the current system metrics
func (c *Collector) GetSystemMetrics() sysmetrics.Metrics {
	return sysmetrics.Metrics{
		CPUPercent:       c.cpuPercent.Load().(float64),
		MemoryRSSBytes:   c.memoryRSSBytes.Load(),
		MemoryLimitBytes: c.memoryLimitBytes.Load(),
	}
}

// GetAll returns all statistics as individual values
func (c *Collector) GetAll() (captured, matched, forwarded, dropped, bufferBytes uint64) {
	return c.packetsCaptured.Load(),
		c.packetsMatched.Load(),
		c.packetsForwarded.Load(),
		c.packetsDropped.Load(),
		c.bufferBytes.Load()
}

// ToProto converts statistics to protobuf HunterStats message
func (c *Collector) ToProto(activeFilters uint32) *management.HunterStats {
	return &management.HunterStats{
		PacketsCaptured:  c.packetsCaptured.Load(),
		PacketsMatched:   c.packetsMatched.Load(),
		PacketsForwarded: c.packetsForwarded.Load(),
		PacketsDropped:   c.packetsDropped.Load(),
		BufferBytes:      c.bufferBytes.Load(),
		ActiveFilters:    activeFilters,
		CpuPercent:       float32(c.cpuPercent.Load().(float64)),
		MemoryRssBytes:   c.memoryRSSBytes.Load(),
		MemoryLimitBytes: c.memoryLimitBytes.Load(),
	}
}

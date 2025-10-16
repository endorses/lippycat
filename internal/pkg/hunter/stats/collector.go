//go:build hunter || all

package stats

import (
	"sync/atomic"

	"github.com/endorses/lippycat/api/gen/management"
)

// Collector tracks hunter statistics with lock-free atomic operations
type Collector struct {
	packetsCaptured  atomic.Uint64
	packetsMatched   atomic.Uint64
	packetsForwarded atomic.Uint64
	packetsDropped   atomic.Uint64
	bufferBytes      atomic.Uint64
}

// New creates a new statistics collector
func New() *Collector {
	return &Collector{}
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
	}
}

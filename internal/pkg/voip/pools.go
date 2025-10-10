package voip

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
)

// PoolMetrics tracks allocation statistics for memory pools
type PoolMetrics struct {
	Allocations   atomic.Int64 // Total allocations requested
	Reuses        atomic.Int64 // Objects reused from pool
	CurrentSize   atomic.Int64 // Current pool size
	PeakSize      atomic.Int64 // Peak pool size
	TotalGets     atomic.Int64 // Total Get() calls
	TotalPuts     atomic.Int64 // Total Put() calls
	Discards      atomic.Int64 // Objects discarded (oversized, etc.)
	LastResetTime atomic.Int64 // Unix timestamp of last reset
}

// Reset resets metrics counters (useful for benchmarking)
func (m *PoolMetrics) Reset() {
	m.Allocations.Store(0)
	m.Reuses.Store(0)
	m.TotalGets.Store(0)
	m.TotalPuts.Store(0)
	m.Discards.Store(0)
	m.LastResetTime.Store(time.Now().Unix())
}

// GetStats returns a snapshot of current metrics
func (m *PoolMetrics) GetStats() PoolStats {
	return PoolStats{
		Allocations: m.Allocations.Load(),
		Reuses:      m.Reuses.Load(),
		CurrentSize: m.CurrentSize.Load(),
		PeakSize:    m.PeakSize.Load(),
		TotalGets:   m.TotalGets.Load(),
		TotalPuts:   m.TotalPuts.Load(),
		Discards:    m.Discards.Load(),
		ReuseRate:   m.calculateReuseRate(),
	}
}

func (m *PoolMetrics) calculateReuseRate() float64 {
	gets := m.TotalGets.Load()
	if gets == 0 {
		return 0.0
	}
	reuses := m.Reuses.Load()
	return float64(reuses) / float64(gets) * 100.0
}

// PoolStats is a snapshot of pool metrics
type PoolStats struct {
	Allocations int64
	Reuses      int64
	CurrentSize int64
	PeakSize    int64
	TotalGets   int64
	TotalPuts   int64
	Discards    int64
	ReuseRate   float64 // Percentage
}

// PoolConfig contains configuration for memory pools
type PoolConfig struct {
	InitialSize     int  // Initial pool size
	MaxSize         int  // Maximum pool size (0 = unlimited)
	MaxObjectSize   int  // Maximum size of pooled objects
	EnableMetrics   bool // Enable metrics tracking
	DrainOnPressure bool // Drain pool under memory pressure
	GrowthFactor    int  // Growth factor when expanding pool
}

var defaultPoolConfig = PoolConfig{
	InitialSize:     128,
	MaxSize:         10000,
	MaxObjectSize:   65536, // 64KB max for individual objects
	EnableMetrics:   true,
	DrainOnPressure: true,
	GrowthFactor:    2,
}

// PacketBuffer represents a reusable packet buffer
type PacketBuffer struct {
	Data     []byte
	packet   gopacket.Packet
	refCount atomic.Int32
}

// Reset clears the buffer for reuse
func (pb *PacketBuffer) Reset() {
	pb.Data = pb.Data[:0]
	pb.packet = nil
	pb.refCount.Store(0)
}

// PacketPool manages packet buffer reuse
type PacketPool struct {
	pool    sync.Pool
	config  PoolConfig
	metrics *PoolMetrics
}

// NewPacketPool creates a new packet buffer pool
func NewPacketPool(config PoolConfig) *PacketPool {
	pp := &PacketPool{
		config:  config,
		metrics: &PoolMetrics{},
	}

	pp.pool = sync.Pool{
		New: func() interface{} {
			pp.metrics.Allocations.Add(1)
			return &PacketBuffer{
				Data: make([]byte, 0, config.InitialSize),
			}
		},
	}

	pp.metrics.LastResetTime.Store(time.Now().Unix())
	return pp
}

// Get retrieves a packet buffer from the pool
func (pp *PacketPool) Get() *PacketBuffer {
	pp.metrics.TotalGets.Add(1)

	pb := pp.pool.Get().(*PacketBuffer)
	pb.Reset()

	pp.metrics.Reuses.Add(1)
	pp.updateCurrentSize(1)

	return pb
}

// Put returns a packet buffer to the pool
func (pp *PacketPool) Put(pb *PacketBuffer) {
	if pb == nil {
		return
	}

	pp.metrics.TotalPuts.Add(1)

	// Discard oversized buffers to prevent memory bloat
	if cap(pb.Data) > pp.config.MaxObjectSize {
		pp.metrics.Discards.Add(1)
		return
	}

	pb.Reset()
	pp.pool.Put(pb)
	pp.updateCurrentSize(-1)
}

func (pp *PacketPool) updateCurrentSize(delta int64) {
	newSize := pp.metrics.CurrentSize.Add(delta)

	// Update peak if necessary
	for {
		peak := pp.metrics.PeakSize.Load()
		if newSize <= peak {
			break
		}
		if pp.metrics.PeakSize.CompareAndSwap(peak, newSize) {
			break
		}
	}
}

// GetMetrics returns pool metrics
func (pp *PacketPool) GetMetrics() PoolStats {
	if !pp.config.EnableMetrics {
		return PoolStats{}
	}
	return pp.metrics.GetStats()
}

// CallInfoPool manages CallInfo struct reuse
type CallInfoPool struct {
	pool    sync.Pool
	config  PoolConfig
	metrics *PoolMetrics
}

// NewCallInfoPool creates a new CallInfo pool
func NewCallInfoPool(config PoolConfig) *CallInfoPool {
	cip := &CallInfoPool{
		config:  config,
		metrics: &PoolMetrics{},
	}

	cip.pool = sync.Pool{
		New: func() interface{} {
			cip.metrics.Allocations.Add(1)
			return &CallInfo{}
		},
	}

	cip.metrics.LastResetTime.Store(time.Now().Unix())
	return cip
}

// Get retrieves a CallInfo from the pool
func (cip *CallInfoPool) Get() *CallInfo {
	cip.metrics.TotalGets.Add(1)
	cip.metrics.Reuses.Add(1)

	ci := cip.pool.Get().(*CallInfo)
	cip.updateCurrentSize(1)

	return ci
}

// Put returns a CallInfo to the pool
func (cip *CallInfoPool) Put(ci *CallInfo) {
	if ci == nil {
		return
	}

	cip.metrics.TotalPuts.Add(1)

	// Clear fields before returning to pool
	ci.CallID = ""
	ci.State = ""
	ci.Created = time.Time{}
	ci.LastUpdated = time.Time{}
	ci.LinkType = 0
	ci.SIPWriter = nil
	ci.RTPWriter = nil
	ci.sipFile = nil
	ci.rtpFile = nil

	cip.pool.Put(ci)
	cip.updateCurrentSize(-1)
}

func (cip *CallInfoPool) updateCurrentSize(delta int64) {
	newSize := cip.metrics.CurrentSize.Add(delta)

	for {
		peak := cip.metrics.PeakSize.Load()
		if newSize <= peak {
			break
		}
		if cip.metrics.PeakSize.CompareAndSwap(peak, newSize) {
			break
		}
	}
}

// GetMetrics returns pool metrics
func (cip *CallInfoPool) GetMetrics() PoolStats {
	if !cip.config.EnableMetrics {
		return PoolStats{}
	}
	return cip.metrics.GetStats()
}

// BufferPool manages general byte slice reuse
type BufferPool struct {
	pools   []*sync.Pool // Multiple pools for different size classes
	config  PoolConfig
	metrics *PoolMetrics
	sizes   []int // Size classes
}

// NewBufferPool creates a new buffer pool with multiple size classes
func NewBufferPool(config PoolConfig) *BufferPool {
	// Size classes: 128B, 512B, 2KB, 8KB, 32KB, 64KB
	sizes := []int{128, 512, 2048, 8192, 32768, 65536}

	bp := &BufferPool{
		pools:   make([]*sync.Pool, len(sizes)),
		config:  config,
		metrics: &PoolMetrics{},
		sizes:   sizes,
	}

	// Create a pool for each size class
	for i, size := range sizes {
		sz := size // Capture for closure
		bp.pools[i] = &sync.Pool{
			New: func() interface{} {
				bp.metrics.Allocations.Add(1)
				return make([]byte, 0, sz)
			},
		}
	}

	bp.metrics.LastResetTime.Store(time.Now().Unix())
	return bp
}

// Get retrieves a buffer of at least the requested size
func (bp *BufferPool) Get(size int) []byte {
	bp.metrics.TotalGets.Add(1)

	// Find appropriate size class
	poolIdx := bp.findSizeClass(size)
	if poolIdx == -1 {
		// Size too large, allocate directly
		bp.metrics.Allocations.Add(1)
		return make([]byte, 0, size)
	}

	bp.metrics.Reuses.Add(1)
	bp.updateCurrentSize(1)

	buf := bp.pools[poolIdx].Get().([]byte)
	return buf[:0] // Reset length but keep capacity
}

// Put returns a buffer to the appropriate pool
func (bp *BufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	bp.metrics.TotalPuts.Add(1)

	capacity := cap(buf)

	// Discard oversized buffers
	if capacity > bp.config.MaxObjectSize {
		bp.metrics.Discards.Add(1)
		return
	}

	poolIdx := bp.findSizeClass(capacity)
	if poolIdx == -1 {
		bp.metrics.Discards.Add(1)
		return
	}

	// Reset buffer before returning to pool
	buf = buf[:0]
	bp.pools[poolIdx].Put(buf)
	bp.updateCurrentSize(-1)
}

func (bp *BufferPool) findSizeClass(size int) int {
	for i, s := range bp.sizes {
		if size <= s {
			return i
		}
	}
	return -1 // Size too large
}

func (bp *BufferPool) updateCurrentSize(delta int64) {
	newSize := bp.metrics.CurrentSize.Add(delta)

	for {
		peak := bp.metrics.PeakSize.Load()
		if newSize <= peak {
			break
		}
		if bp.metrics.PeakSize.CompareAndSwap(peak, newSize) {
			break
		}
	}
}

// GetMetrics returns pool metrics
func (bp *BufferPool) GetMetrics() PoolStats {
	if !bp.config.EnableMetrics {
		return PoolStats{}
	}
	return bp.metrics.GetStats()
}

// Global pool instances
var (
	globalPacketPool   *PacketPool
	globalCallInfoPool *CallInfoPool
	globalBufferPool   *BufferPool
	poolsOnce          sync.Once
)

// InitPools initializes global memory pools
func InitPools(config PoolConfig) {
	poolsOnce.Do(func() {
		globalPacketPool = NewPacketPool(config)
		globalCallInfoPool = NewCallInfoPool(config)
		globalBufferPool = NewBufferPool(config)
	})
}

// GetPacketPool returns the global packet pool
func GetPacketPool() *PacketPool {
	if globalPacketPool == nil {
		InitPools(defaultPoolConfig)
	}
	return globalPacketPool
}

// GetCallInfoPool returns the global CallInfo pool
func GetCallInfoPool() *CallInfoPool {
	if globalCallInfoPool == nil {
		InitPools(defaultPoolConfig)
	}
	return globalCallInfoPool
}

// GetBufferPool returns the global buffer pool
func GetBufferPool() *BufferPool {
	if globalBufferPool == nil {
		InitPools(defaultPoolConfig)
	}
	return globalBufferPool
}

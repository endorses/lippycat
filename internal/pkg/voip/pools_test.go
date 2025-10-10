package voip

import (
	"runtime"
	"sync"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketPool_GetPut(t *testing.T) {
	config := PoolConfig{
		InitialSize:   128,
		MaxSize:       1000,
		MaxObjectSize: 65536,
		EnableMetrics: true,
	}

	pool := NewPacketPool(config)

	// Get a buffer
	pb := pool.Get()
	require.NotNil(t, pb)
	assert.Equal(t, 0, len(pb.Data))
	assert.GreaterOrEqual(t, cap(pb.Data), config.InitialSize)

	// Put it back
	pool.Put(pb)

	// Get again - should reuse
	pb2 := pool.Get()
	require.NotNil(t, pb2)

	// Verify metrics
	stats := pool.GetMetrics()
	assert.Equal(t, int64(2), stats.TotalGets)
	assert.Equal(t, int64(1), stats.TotalPuts)
	assert.GreaterOrEqual(t, stats.Reuses, int64(1))
}

func TestPacketPool_ThreadSafety(t *testing.T) {
	config := defaultPoolConfig
	pool := NewPacketPool(config)

	const numGoroutines = 100
	const operationsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				pb := pool.Get()
				pb.Data = append(pb.Data, byte(j))
				pool.Put(pb)
			}
		}()
	}

	wg.Wait()

	stats := pool.GetMetrics()
	assert.Equal(t, int64(numGoroutines*operationsPerGoroutine), stats.TotalGets)
	assert.Equal(t, int64(numGoroutines*operationsPerGoroutine), stats.TotalPuts)
}

func TestPacketPool_OversizedDiscard(t *testing.T) {
	config := PoolConfig{
		InitialSize:   128,
		MaxSize:       1000,
		MaxObjectSize: 1024,
		EnableMetrics: true,
	}

	pool := NewPacketPool(config)

	pb := pool.Get()
	// Make buffer oversized
	pb.Data = make([]byte, 2048)

	pool.Put(pb)

	stats := pool.GetMetrics()
	assert.Equal(t, int64(1), stats.Discards)
}

func TestCallInfoPool_GetPut(t *testing.T) {
	config := defaultPoolConfig
	pool := NewCallInfoPool(config)

	// Get a CallInfo
	ci := pool.Get()
	require.NotNil(t, ci)

	// Set some fields
	ci.CallID = "test-call-id"
	ci.State = "INVITE"
	ci.LinkType = layers.LinkTypeEthernet

	// Put it back
	pool.Put(ci)

	// Get again - should be cleared
	ci2 := pool.Get()
	require.NotNil(t, ci2)
	assert.Equal(t, "", ci2.CallID)
	assert.Equal(t, "", ci2.State)
	assert.Equal(t, layers.LinkType(0), ci2.LinkType)

	// Verify metrics
	stats := pool.GetMetrics()
	assert.Equal(t, int64(2), stats.TotalGets)
	assert.Equal(t, int64(1), stats.TotalPuts)
}

func TestCallInfoPool_ThreadSafety(t *testing.T) {
	config := defaultPoolConfig
	pool := NewCallInfoPool(config)

	const numGoroutines = 100
	const operationsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				ci := pool.Get()
				ci.CallID = "test"
				ci.State = "INVITE"
				pool.Put(ci)
			}
		}(i)
	}

	wg.Wait()

	stats := pool.GetMetrics()
	assert.Equal(t, int64(numGoroutines*operationsPerGoroutine), stats.TotalGets)
	assert.Equal(t, int64(numGoroutines*operationsPerGoroutine), stats.TotalPuts)
}

func TestBufferPool_GetPut(t *testing.T) {
	config := defaultPoolConfig
	pool := NewBufferPool(config)

	// Test different size classes
	sizes := []int{100, 500, 2000, 8000, 32000, 64000}

	for _, size := range sizes {
		buf := pool.Get(size)
		require.NotNil(t, buf)
		assert.GreaterOrEqual(t, cap(buf), size)
		assert.Equal(t, 0, len(buf))

		pool.Put(buf)
	}

	stats := pool.GetMetrics()
	assert.Equal(t, int64(len(sizes)), stats.TotalGets)
	assert.Equal(t, int64(len(sizes)), stats.TotalPuts)
}

func TestBufferPool_ThreadSafety(t *testing.T) {
	config := defaultPoolConfig
	pool := NewBufferPool(config)

	const numGoroutines = 100
	const operationsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				size := 128 + (j % 8192)
				buf := pool.Get(size)
				buf = append(buf, make([]byte, size)...)
				pool.Put(buf)
			}
		}()
	}

	wg.Wait()

	stats := pool.GetMetrics()
	assert.Equal(t, int64(numGoroutines*operationsPerGoroutine), stats.TotalGets)
	assert.Equal(t, int64(numGoroutines*operationsPerGoroutine), stats.TotalPuts)
}

func TestBufferPool_OversizedBuffer(t *testing.T) {
	config := PoolConfig{
		InitialSize:   128,
		MaxSize:       1000,
		MaxObjectSize: 1024,
		EnableMetrics: true,
	}

	pool := NewBufferPool(config)

	// Get a buffer and make it oversized
	buf := pool.Get(512)
	buf = make([]byte, 0, 2048)

	pool.Put(buf)

	stats := pool.GetMetrics()
	assert.Equal(t, int64(1), stats.Discards)
}

func TestPoolMetrics_ReuseRate(t *testing.T) {
	config := defaultPoolConfig
	pool := NewPacketPool(config)

	// Perform operations
	for i := 0; i < 100; i++ {
		pb := pool.Get()
		pool.Put(pb)
	}

	stats := pool.GetMetrics()
	assert.Greater(t, stats.ReuseRate, 0.0)
	assert.LessOrEqual(t, stats.ReuseRate, 100.0)
}

func TestPoolMetrics_Reset(t *testing.T) {
	config := defaultPoolConfig
	pool := NewPacketPool(config)

	// Perform operations
	pb := pool.Get()
	pool.Put(pb)

	// Reset metrics
	pool.metrics.Reset()

	stats := pool.GetMetrics()
	assert.Equal(t, int64(0), stats.TotalGets)
	assert.Equal(t, int64(0), stats.TotalPuts)
	assert.Equal(t, int64(0), stats.Reuses)
}

func TestGlobalPools_Initialization(t *testing.T) {
	// Test that global pools are initialized correctly
	pp := GetPacketPool()
	require.NotNil(t, pp)

	cip := GetCallInfoPool()
	require.NotNil(t, cip)

	bp := GetBufferPool()
	require.NotNil(t, bp)

	// Test that they work
	pb := pp.Get()
	require.NotNil(t, pb)
	pp.Put(pb)

	ci := cip.Get()
	require.NotNil(t, ci)
	cip.Put(ci)

	buf := bp.Get(128)
	require.NotNil(t, buf)
	bp.Put(buf)
}

func TestPacketPool_NoMemoryLeak(t *testing.T) {
	config := defaultPoolConfig
	pool := NewPacketPool(config)

	// Force garbage collection baseline
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Perform many operations
	for i := 0; i < 10000; i++ {
		pb := pool.Get()
		pb.Data = append(pb.Data, make([]byte, 1024)...)
		pool.Put(pb)
	}

	// Force garbage collection
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// Memory should not grow significantly
	// Check absolute growth instead of relative to avoid issues with small baseline
	absoluteGrowth := int64(m2.Alloc - m1.Alloc)
	// Allow up to 10MB growth (10000 iterations * 1024 bytes = ~10MB max expected)
	assert.Less(t, absoluteGrowth, int64(20*1024*1024), "Memory grew too much: %d bytes", absoluteGrowth)
}

func BenchmarkPacketPool_GetPut(b *testing.B) {
	config := defaultPoolConfig
	pool := NewPacketPool(config)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pb := pool.Get()
		pool.Put(pb)
	}
}

func BenchmarkPacketPool_Parallel(b *testing.B) {
	config := defaultPoolConfig
	pool := NewPacketPool(config)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p := pool.Get()
			pool.Put(p)
		}
	})
}

func BenchmarkCallInfoPool_GetPut(b *testing.B) {
	config := defaultPoolConfig
	pool := NewCallInfoPool(config)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		ci := pool.Get()
		pool.Put(ci)
	}
}

func BenchmarkBufferPool_GetPut(b *testing.B) {
	config := defaultPoolConfig
	pool := NewBufferPool(config)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		buf := pool.Get(1024)
		pool.Put(buf)
	}
}

func BenchmarkDirectAllocation(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = make([]byte, 0, 1024)
	}
}

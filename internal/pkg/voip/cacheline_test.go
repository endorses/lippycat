package voip

import (
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestCacheLineSizeConstant(t *testing.T) {
	assert.Equal(t, 64, CacheLineSize)
}

func TestPaddedAtomic(t *testing.T) {
	pa := NewPaddedAtomic(100)

	// Test Load
	assert.Equal(t, uint64(100), pa.Load())

	// Test Store
	pa.Store(200)
	assert.Equal(t, uint64(200), pa.Load())

	// Test Add
	result := pa.Add(50)
	assert.Equal(t, uint64(250), result)
	assert.Equal(t, uint64(250), pa.Load())

	// Test CompareAndSwap
	swapped := pa.CompareAndSwap(250, 300)
	assert.True(t, swapped)
	assert.Equal(t, uint64(300), pa.Load())

	swapped = pa.CompareAndSwap(250, 400)
	assert.False(t, swapped)
	assert.Equal(t, uint64(300), pa.Load())
}

func TestPaddedCounter(t *testing.T) {
	pc := NewPaddedCounter()

	// Initial value
	assert.Equal(t, uint64(0), pc.Get())

	// Inc
	pc.Inc()
	assert.Equal(t, uint64(1), pc.Get())

	// Add
	pc.Add(10)
	assert.Equal(t, uint64(11), pc.Get())

	// Reset
	pc.Reset()
	assert.Equal(t, uint64(0), pc.Get())
}

func TestPaddedBool(t *testing.T) {
	pb := NewPaddedBool(false)

	assert.False(t, pb.Load())

	pb.Store(true)
	assert.True(t, pb.Load())

	// CompareAndSwap
	swapped := pb.CompareAndSwap(true, false)
	assert.True(t, swapped)
	assert.False(t, pb.Load())

	swapped = pb.CompareAndSwap(true, false)
	assert.False(t, swapped)
}

func TestPaddedPointer(t *testing.T) {
	value1 := 42
	value2 := 100

	pp := NewPaddedPointer(&value1)

	// Test Load
	loaded := pp.Load()
	assert.NotNil(t, loaded)
	assert.Equal(t, 42, *loaded)

	// Test Store
	pp.Store(&value2)
	loaded = pp.Load()
	assert.Equal(t, 100, *loaded)

	// Test CompareAndSwap
	swapped := pp.CompareAndSwap(&value2, &value1)
	assert.True(t, swapped)
	loaded = pp.Load()
	assert.Equal(t, 42, *loaded)
}

func TestAlignedAlloc(t *testing.T) {
	sizes := []int{64, 128, 256, 1024, 4096}

	for _, size := range sizes {
		buf := AlignedAlloc(size)

		assert.Equal(t, size, len(buf))

		// Check alignment
		ptr := unsafe.Pointer(&buf[0])
		assert.True(t, IsAligned(ptr),
			"Buffer of size %d should be aligned", size)
	}
}

func TestIsAligned(t *testing.T) {
	// Allocate aligned buffer
	aligned := AlignedAlloc(256)
	ptr := unsafe.Pointer(&aligned[0])
	assert.True(t, IsAligned(ptr))

	// Regular slice (may or may not be aligned)
	regular := make([]byte, 256)
	regularPtr := unsafe.Pointer(&regular[0])
	_ = IsAligned(regularPtr) // Just checking it doesn't crash
}

func TestPaddedSizes(t *testing.T) {
	// Verify padded types are properly sized
	pa := &PaddedAtomic{}
	assert.GreaterOrEqual(t, int(unsafe.Sizeof(*pa)), CacheLineSize*2)

	pc := &PaddedCounter{}
	assert.GreaterOrEqual(t, int(unsafe.Sizeof(*pc)), CacheLineSize*2)

	pb := &PaddedBool{}
	assert.GreaterOrEqual(t, int(unsafe.Sizeof(*pb)), CacheLineSize*2)
}

// Benchmarks

func BenchmarkPaddedCounterInc(b *testing.B) {
	pc := NewPaddedCounter()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pc.Inc()
	}
}

func BenchmarkPaddedCounterIncParallel(b *testing.B) {
	pc := NewPaddedCounter()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pc.Inc()
		}
	})
}

func BenchmarkPaddedAtomicAdd(b *testing.B) {
	pa := NewPaddedAtomic(0)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pa.Add(1)
	}
}

func BenchmarkPaddedAtomicAddParallel(b *testing.B) {
	pa := NewPaddedAtomic(0)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pa.Add(1)
		}
	})
}

// Benchmark to demonstrate false sharing vs padding
func BenchmarkFalseSharingComparison(b *testing.B) {
	b.Run("WithoutPadding", func(b *testing.B) {
		// Simulate false sharing with adjacent counters
		type UnpaddedCounters struct {
			counter1 uint64
			counter2 uint64
		}

		counters := &UnpaddedCounters{}

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// Different goroutines access adjacent memory
				atomic.AddUint64(&counters.counter1, 1)
			}
		})
	})

	b.Run("WithPadding", func(b *testing.B) {
		counter1 := NewPaddedCounter()
		counter2 := NewPaddedCounter()

		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				counter1.Inc()
			}
		})

		_ = counter2 // Use counter2 to prevent optimization
	})
}

package sysmetrics

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned nil")
	}
}

func TestCollector_GetReturnsInitialState(t *testing.T) {
	c := New()
	m := c.Get()

	// Before Start(), CPU should be -1 (unavailable)
	if m.CPUPercent != -1 {
		t.Errorf("expected initial CPUPercent = -1, got %f", m.CPUPercent)
	}
	if m.SampleTimeNS != 0 || m.CPUCapacityCores != 0 {
		t.Fatalf("expected unknown capacity and no initial sample, got %+v", m)
	}
}

func TestCollector_SampleTimestampBelongsToCollection(t *testing.T) {
	c := New().(*collector)
	c.initPlatform()
	before := time.Now().UnixNano()
	c.collect()
	first := c.Get()
	if first.SampleTimeNS < before || first.SampleTimeNS > time.Now().UnixNano() {
		t.Fatalf("sample timestamp is not from collection: %d", first.SampleTimeNS)
	}
	if again := c.Get(); again != first {
		t.Fatal("reading the snapshot changed the metrics or sample timestamp")
	}
	c.collect()
	if second := c.Get(); second.SampleTimeNS <= first.SampleTimeNS {
		t.Fatal("new collection did not advance the sample timestamp")
	}
}

func TestCollector_StartStop(t *testing.T) {
	c := New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// Wait a bit for collection
	time.Sleep(100 * time.Millisecond)

	c.Stop()

	// Should not panic
}

func TestCollector_CollectsMemory(t *testing.T) {
	c := New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// Wait for at least one collection cycle
	time.Sleep(150 * time.Millisecond)

	m := c.Get()
	c.Stop()

	// Memory RSS should be non-zero after collection
	if m.MemoryRSSBytes == 0 {
		t.Error("expected non-zero MemoryRSSBytes after collection")
	}
}

func TestCollector_CollectsCPU_Linux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("CPU collection only available on Linux")
	}

	c := New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)

	// Need at least 2 samples to calculate CPU delta
	time.Sleep(1100 * time.Millisecond)

	m := c.Get()
	c.Stop()

	// After enough time, CPU should be >= 0
	if m.CPUPercent < 0 {
		t.Errorf("expected CPUPercent >= 0 after 2 samples, got %f", m.CPUPercent)
	}
}

func TestCollector_ConcurrentGet(t *testing.T) {
	c := New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.Start(ctx)
	defer c.Stop()

	// Concurrent Get() calls should not race
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_ = c.Get()
			}
			done <- struct{}{}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

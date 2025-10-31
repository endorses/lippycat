package proxy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
)

// TestBatching_ReducedUpdateFrequency verifies that batching reduces the number
// of flush operations when many updates are published in quick succession
func TestBatching_ReducedUpdateFrequency(t *testing.T) {
	var flushCount int32
	var totalUpdates int32

	flushFunc := func(updates []*pb.TopologyUpdate) {
		atomic.AddInt32(&flushCount, 1)
		atomic.AddInt32(&totalUpdates, int32(len(updates)))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	defer batcher.Stop()

	// Publish 50 updates rapidly (much faster than the 100ms batch delay)
	startTime := time.Now()
	for i := 0; i < 50; i++ {
		batcher.Add(&pb.TopologyUpdate{
			UpdateType:  pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
			TimestampNs: time.Now().UnixNano(),
		})
		time.Sleep(2 * time.Millisecond) // Simulate small delay between updates
	}
	duration := time.Since(startTime)

	// Wait for final batch to flush
	time.Sleep(150 * time.Millisecond)

	flushes := atomic.LoadInt32(&flushCount)
	total := atomic.LoadInt32(&totalUpdates)

	t.Logf("Published 50 updates over %v", duration)
	t.Logf("Number of flush operations: %d", flushes)
	t.Logf("Total updates flushed: %d", total)

	// Verify all updates were flushed
	assert.Equal(t, int32(50), total, "all updates should be flushed")

	// Verify batching reduced the number of flush operations
	// Without batching: 50 flushes
	// With batching (max 10): 5 flushes
	// With time-based batching: even fewer (depends on timing)
	assert.LessOrEqual(t, flushes, int32(10),
		"batching should reduce flush operations to at most 10")

	// Calculate efficiency: updates per flush
	avgBatchSize := float64(total) / float64(flushes)
	t.Logf("Average batch size: %.2f updates/flush", avgBatchSize)

	// Verify average batch size is greater than 1 (batching is working)
	assert.Greater(t, avgBatchSize, 1.0,
		"average batch size should be > 1 (batching is effective)")
}

// TestBatching_TimeBasedFlushing verifies that batching flushes based on time
// even when max batch size is not reached
func TestBatching_TimeBasedFlushing(t *testing.T) {
	var flushTimes []time.Time
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushTimes = append(flushTimes, time.Now())
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	defer batcher.Stop()

	// Add 3 updates, wait for flush, repeat
	// This should trigger at least 1 time-based flush per batch
	for batch := 0; batch < 3; batch++ {
		for i := 0; i < 3; i++ {
			batcher.Add(&pb.TopologyUpdate{
				UpdateType:  pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
				TimestampNs: time.Now().UnixNano(),
			})
		}
		time.Sleep(120 * time.Millisecond) // Wait longer than batch delay (100ms)
	}

	// Wait for any final batch to flush
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	t.Logf("Number of time-based flushes: %d", len(flushTimes))

	// Verify we got at least 1 flush (batching by time is working)
	assert.GreaterOrEqual(t, len(flushTimes), 1,
		"should have at least one time-based flush")

	// If we have multiple flushes, log the timing
	for i := 1; i < len(flushTimes); i++ {
		delay := flushTimes[i].Sub(flushTimes[i-1])
		t.Logf("Flush %d to %d delay: %v", i-1, i, delay)
	}
}

// TestBatching_NetworkBandwidthReduction simulates a high-frequency update scenario
// and verifies that batching reduces network overhead
func TestBatching_NetworkBandwidthReduction(t *testing.T) {
	var unbatchedFlushCount int32
	var batchedFlushCount int32

	// Test without batching (simulate by flushing every update)
	unbatchedFlushFunc := func(updates []*pb.TopologyUpdate) {
		atomic.AddInt32(&unbatchedFlushCount, 1)
	}

	// Test with batching
	batchedFlushFunc := func(updates []*pb.TopologyUpdate) {
		atomic.AddInt32(&batchedFlushCount, 1)
	}

	// Scenario: 100 hunters connecting over 200ms
	const updateCount = 100
	const durationMs = 200

	// Without batching (each update triggers immediate flush)
	for i := 0; i < updateCount; i++ {
		unbatchedFlushFunc([]*pb.TopologyUpdate{{
			UpdateType:  pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
			TimestampNs: time.Now().UnixNano(),
		}})
		time.Sleep(time.Duration(durationMs/updateCount) * time.Millisecond)
	}

	// With batching
	batcher := NewTopologyUpdateBatcher(batchedFlushFunc)
	batcher.Start()

	for i := 0; i < updateCount; i++ {
		batcher.Add(&pb.TopologyUpdate{
			UpdateType:  pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
			TimestampNs: time.Now().UnixNano(),
		})
		time.Sleep(time.Duration(durationMs/updateCount) * time.Millisecond)
	}

	// Wait for final batch
	time.Sleep(150 * time.Millisecond)
	batcher.Stop()

	unbatched := atomic.LoadInt32(&unbatchedFlushCount)
	batched := atomic.LoadInt32(&batchedFlushCount)

	t.Logf("Unbatched flush operations: %d", unbatched)
	t.Logf("Batched flush operations: %d", batched)

	reduction := float64(unbatched-batched) / float64(unbatched) * 100
	t.Logf("Reduction in flush operations: %.1f%%", reduction)

	// Verify significant reduction (at least 80%)
	assert.Less(t, batched, unbatched/5,
		"batching should reduce flush operations by at least 80%")
}

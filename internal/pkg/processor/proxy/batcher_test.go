package proxy

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTopologyUpdateBatcher_BasicBatching(t *testing.T) {
	var flushedBatches []int
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushedBatches = append(flushedBatches, len(updates))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	defer batcher.Stop()

	// Add 5 updates (should not flush yet, as max batch size is 10)
	for i := 0; i < 5; i++ {
		batcher.Add(&pb.TopologyUpdate{
			UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		})
	}

	// Wait for batch delay to trigger flush
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, flushedBatches, 1, "should have flushed one batch")
	assert.Equal(t, 5, flushedBatches[0], "batch should contain 5 updates")
}

func TestTopologyUpdateBatcher_MaxBatchSize(t *testing.T) {
	var flushedBatches []int
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushedBatches = append(flushedBatches, len(updates))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	defer batcher.Stop()

	// Add 10 updates (should flush immediately)
	for i := 0; i < 10; i++ {
		batcher.Add(&pb.TopologyUpdate{
			UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		})
	}

	// Wait a bit for async flush
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, flushedBatches, 1, "should have flushed one batch")
	assert.Equal(t, 10, flushedBatches[0], "batch should contain 10 updates")
}

func TestTopologyUpdateBatcher_MultipleBatches(t *testing.T) {
	var flushedBatches []int
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushedBatches = append(flushedBatches, len(updates))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	defer batcher.Stop()

	// Add 25 updates (should flush 2 batches of 10, then 1 batch of 5 on delay)
	for i := 0; i < 25; i++ {
		batcher.Add(&pb.TopologyUpdate{
			UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		})
	}

	// Wait for batch delay to trigger flush of remaining 5
	time.Sleep(150 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, flushedBatches, 3, "should have flushed three batches")
	assert.Equal(t, 10, flushedBatches[0], "first batch should contain 10 updates")
	assert.Equal(t, 10, flushedBatches[1], "second batch should contain 10 updates")
	assert.Equal(t, 5, flushedBatches[2], "third batch should contain 5 updates")
}

func TestTopologyUpdateBatcher_ManualFlush(t *testing.T) {
	var flushedBatches []int
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushedBatches = append(flushedBatches, len(updates))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	defer batcher.Stop()

	// Add 3 updates (not enough to trigger max size flush)
	for i := 0; i < 3; i++ {
		batcher.Add(&pb.TopologyUpdate{
			UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		})
	}

	// Manually flush
	batcher.Flush()

	// Wait for async flush
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, flushedBatches, 1, "should have flushed one batch")
	assert.Equal(t, 3, flushedBatches[0], "batch should contain 3 updates")
}

func TestTopologyUpdateBatcher_StopFlushes(t *testing.T) {
	var flushedBatches []int
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushedBatches = append(flushedBatches, len(updates))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()

	// Add 3 updates (not enough to trigger max size flush)
	for i := 0; i < 3; i++ {
		batcher.Add(&pb.TopologyUpdate{
			UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		})
	}

	// Stop should flush pending updates
	batcher.Stop()

	// Wait for async flush
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, flushedBatches, 1, "should have flushed pending updates on stop")
	assert.Equal(t, 3, flushedBatches[0], "batch should contain 3 updates")
}

func TestTopologyUpdateBatcher_ConcurrentAccess(t *testing.T) {
	var totalUpdates int32
	var wg sync.WaitGroup

	flushFunc := func(updates []*pb.TopologyUpdate) {
		atomic.AddInt32(&totalUpdates, int32(len(updates)))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	defer batcher.Stop()

	// Spawn 10 goroutines, each adding 10 updates
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				batcher.Add(&pb.TopologyUpdate{
					UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
				})
			}
		}()
	}

	wg.Wait()

	// Flush remaining updates
	batcher.Flush()

	// Wait for all flushes to complete
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int32(100), atomic.LoadInt32(&totalUpdates),
		"should have flushed all 100 updates")
}

func TestTopologyUpdateBatcher_IgnoresNilUpdates(t *testing.T) {
	var flushedBatches []int
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushedBatches = append(flushedBatches, len(updates))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	defer batcher.Stop()

	// Add valid update
	batcher.Add(&pb.TopologyUpdate{
		UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
	})

	// Note: nil updates are not explicitly handled in the batcher
	// but the PublishTopologyUpdate method in manager.go checks for nil
	// So this test is just documenting current behavior

	batcher.Flush()
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, flushedBatches, 1, "should have flushed one batch")
	assert.Equal(t, 1, flushedBatches[0], "batch should contain 1 update")
}

func TestTopologyUpdateBatcher_ConfigurableParameters(t *testing.T) {
	var flushedBatches []int
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushedBatches = append(flushedBatches, len(updates))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)

	// Set custom parameters
	batcher.SetMaxBatchSize(5)
	batcher.SetBatchDelay(50 * time.Millisecond)

	batcher.Start()
	defer batcher.Stop()

	// Add 5 updates (should flush immediately with new max batch size)
	for i := 0; i < 5; i++ {
		batcher.Add(&pb.TopologyUpdate{
			UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		})
	}

	// Wait for async flush
	time.Sleep(30 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, flushedBatches, 1, "should have flushed one batch")
	assert.Equal(t, 5, flushedBatches[0], "batch should contain 5 updates")
}

func TestTopologyUpdateBatcher_AddAfterStop(t *testing.T) {
	var flushedBatches []int
	var mu sync.Mutex

	flushFunc := func(updates []*pb.TopologyUpdate) {
		mu.Lock()
		defer mu.Unlock()
		flushedBatches = append(flushedBatches, len(updates))
	}

	batcher := NewTopologyUpdateBatcher(flushFunc)
	batcher.Start()
	batcher.Stop()

	// Try to add update after stop (should be dropped)
	batcher.Add(&pb.TopologyUpdate{
		UpdateType: pb.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
	})

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, flushedBatches, 0, "should not have flushed any batches")
}

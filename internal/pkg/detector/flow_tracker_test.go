package detector

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlowTrackerEvictsOldestBatch(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Hour, 20)
	t.Cleanup(tracker.Close)

	now := time.Now()
	for i := 0; i < 20; i++ {
		flow := tracker.GetOrCreate(fmt.Sprintf("flow-%02d", i))
		flow.Touch(now.Add(time.Duration(i+1) * time.Second))
	}

	tracker.GetOrCreate("new")

	assert.Equal(t, 19, tracker.Size(), "10%% batch eviction must make room before insertion")
	assert.Nil(t, tracker.Get("flow-00"))
	assert.Nil(t, tracker.Get("flow-01"))
	assert.NotNil(t, tracker.Get("flow-02"))
	assert.NotNil(t, tracker.Get("new"))
}

func TestFlowTrackerBatchEvictionMinimumAndHardCap(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Hour, 5)
	t.Cleanup(tracker.Close)

	for i := 0; i < 100; i++ {
		tracker.GetOrCreate(fmt.Sprintf("flow-%03d", i))
		require.LessOrEqual(t, tracker.Size(), 5)
	}
	assert.Equal(t, 5, tracker.Size(), "capacities below ten must evict at least one entry")
}

func TestFlowTrackerBatchEvictionRecoversFromOversizedMap(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Hour, 10)
	t.Cleanup(tracker.Close)

	now := time.Now()
	tracker.mu.Lock()
	for i := 0; i < 15; i++ {
		flowID := fmt.Sprintf("flow-%02d", i)
		tracker.flows[flowID] = &signatures.FlowContext{
			FlowID:   flowID,
			LastSeen: now.Add(time.Duration(i) * time.Second),
		}
		tracker.cleanupElements[flowID] = tracker.cleanupOrder.PushBack(flowID)
	}
	tracker.mu.Unlock()

	tracker.GetOrCreate("new")

	assert.Equal(t, 10, tracker.Size())
	for i := 0; i < 6; i++ {
		assert.Nil(t, tracker.Get(fmt.Sprintf("flow-%02d", i)))
	}
	assert.NotNil(t, tracker.Get("flow-06"))
	assert.NotNil(t, tracker.Get("new"))
}

func TestFlowTrackerCapWarningEligibilityIsRateLimited(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Hour, 10)
	t.Cleanup(tracker.Close)

	now := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	require.True(t, tracker.capWarningEligibleLocked(now), "the initial warning must be immediate")
	tracker.lastCapWarning = now
	assert.False(t, tracker.capWarningEligibleLocked(now.Add(flowCapWarningInterval-time.Nanosecond)))
	assert.True(t, tracker.capWarningEligibleLocked(now.Add(flowCapWarningInterval)))
}

func TestFlowTrackerEvictionScratchDoesNotRetainFlowIDs(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Hour, 10)
	t.Cleanup(tracker.Close)

	for i := 0; i < 10; i++ {
		tracker.GetOrCreate(fmt.Sprintf("flow-%02d", i))
	}
	tracker.GetOrCreate("pressure")

	assert.Empty(t, tracker.evictionScratch)
	for _, candidate := range tracker.evictionScratch[:cap(tracker.evictionScratch)] {
		assert.Empty(t, candidate.flowID)
		assert.True(t, candidate.lastSeen.IsZero())
	}
}

func TestFlowContextConcurrentDetectionUpdatesAndSnapshots(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Hour, 0)
	t.Cleanup(tracker.Close)
	flow := tracker.GetOrCreate("shared")

	const workers = 12
	const iterations = 200
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				metadataKey := fmt.Sprintf("worker-%d", worker)
				flow.RecordDetection(
					fmt.Sprintf("protocol-%d", worker%3),
					time.Unix(int64(worker*iterations+iteration+1), 0),
				)
				_ = flow.LastSeenTime()
				_ = flow.ProtocolsSnapshot()
				flow.SetMetadata(metadataKey, iteration)
				_, _ = flow.GetMetadata(metadataKey)
				if iteration%7 == 0 {
					flow.DeleteMetadata(metadataKey)
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	protocols := flow.ProtocolsSnapshot()
	assert.ElementsMatch(t, []string{"protocol-0", "protocol-1", "protocol-2"}, protocols)
	assert.False(t, flow.LastSeenTime().IsZero())

	// A snapshot belongs to the caller and must not mutate tracker-owned state.
	protocols[0] = "mutated"
	assert.NotContains(t, flow.ProtocolsSnapshot(), "mutated")
}

func TestFlowContextRecordDetectionKeepsLastSeenMonotonic(t *testing.T) {
	newer := time.Unix(200, 0)
	older := time.Unix(100, 0)
	flow := &signatures.FlowContext{LastSeen: newer}

	flow.RecordDetection("new", older)

	assert.Equal(t, newer, flow.LastSeenTime())
	assert.Equal(t, []string{"new"}, flow.ProtocolsSnapshot())
}

func TestFlowContextUpdateStateSerializesReadModifyWrite(t *testing.T) {
	flow := &signatures.FlowContext{}

	const workers = 16
	const increments = 250
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range increments {
				flow.UpdateState(func(state interface{}) interface{} {
					if state == nil {
						return 1
					}
					return state.(int) + 1
				})
				_ = flow.GetState()
			}
		}()
	}
	close(start)
	wg.Wait()

	assert.Equal(t, workers*increments, flow.GetState())
}

func TestFlowTrackerConcurrentLookupUpdateEvictionDeleteAndClear(t *testing.T) {
	const capacity = 32
	tracker := NewFlowTrackerWithMaxEntries(time.Hour, capacity)
	t.Cleanup(tracker.Close)

	const workers = 8
	const iterations = 250
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				flowID := fmt.Sprintf("flow-%d", (worker*iterations+iteration)%64)
				flow := tracker.GetOrCreate(flowID)
				flow.RecordDetection("test", time.Now())
				if current := tracker.Get(flowID); current != nil {
					_ = current.LastSeenTime()
					_ = current.ProtocolsSnapshot()
				}
				if iteration%11 == 0 {
					tracker.Delete(flowID)
				}
				if iteration%13 == 0 {
					tracker.cleanupExpired(time.Now().Add(2*time.Hour), 3)
				}
				if iteration%79 == 0 {
					tracker.Clear()
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	require.LessOrEqual(t, tracker.Size(), capacity)
}

func TestFlowTrackerCleanupExpirationIsBounded(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Minute, 0)
	t.Cleanup(tracker.Close)

	now := time.Now()
	for i := 0; i < 5; i++ {
		tracker.GetOrCreate(fmt.Sprintf("expired-%d", i)).RecordDetection("test", now)
	}
	cleanupTime := now.Add(2 * time.Minute)
	tracker.GetOrCreate("live").RecordDetection("test", cleanupTime)

	assert.Equal(t, 2, tracker.cleanupExpired(cleanupTime, 2))
	assert.Equal(t, 4, tracker.Size(), "one cleanup pass must inspect at most its limit")
	assert.NotNil(t, tracker.Get("live"))

	assert.Equal(t, 3, tracker.cleanupExpired(cleanupTime, 16))
	assert.Equal(t, 1, tracker.Size())
	assert.NotNil(t, tracker.Get("live"))
}

func TestFlowTrackerGetOrCreateRefreshesActivityBeforeCleanup(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Minute, 0)
	t.Cleanup(tracker.Close)
	flow := tracker.GetOrCreate("active")
	initial := flow.LastSeenTime()

	flow.RecordDetection("test", initial.Add(-time.Minute))
	refreshed := tracker.GetOrCreate("active")

	assert.Same(t, flow, refreshed)
	assert.True(t, refreshed.LastSeenTime().After(initial))
	assert.Zero(t, tracker.cleanupExpired(initial.Add(time.Minute), 1))
	assert.Same(t, flow, tracker.Get("active"))
}

func TestFlowTrackerCloseIsConcurrentAndIdempotent(t *testing.T) {
	tracker := NewFlowTrackerWithMaxEntries(time.Hour, 16)

	const callers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			tracker.Close()
		}()
	}
	close(start)
	wg.Wait()

	select {
	case <-tracker.cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("flow cleanup goroutine survived Close")
	}
}

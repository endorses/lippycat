package detector

import (
	"fmt"
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
		flow.LastSeen = now.Add(time.Duration(i) * time.Second)
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
	for i := 0; i < 15; i++ {
		flowID := fmt.Sprintf("flow-%02d", i)
		tracker.flows[flowID] = &signatures.FlowContext{
			FlowID:   flowID,
			LastSeen: now.Add(time.Duration(i) * time.Second),
		}
	}

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

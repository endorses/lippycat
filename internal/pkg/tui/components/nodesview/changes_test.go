//go:build tui || all

package nodesview

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func trackerFixture() ([]ProcessorInfo, NodeKey) {
	return []ProcessorInfo{{Address: "processor:5555", ConnectionState: ProcessorConnectionStateConnected, Hunters: []types.HunterInfo{{ID: "hunter", Hostname: "edge", CPUPercent: 12.1, MemoryRSSBytes: 1000000, ActiveFilters: 5, PacketsCaptured: 10, PacketsForwarded: 8}}}}, NodeKey{ProcessorAddr: "processor:5555", HunterID: "hunter"}
}

func TestCounterAccentsAdvanceAndExpireIndependently(t *testing.T) {
	now := time.Unix(100, 0)
	p, key := trackerFixture()
	var tracker ChangeTracker
	tracker.Observe(p, now)
	p[0].Hunters[0].PacketsCaptured++
	tracker.Observe(p, now)
	assert.Equal(t, NodeChanges{CapturedChanged: true, Activity: true}, tracker.Snapshot()[key])
	p[0].Hunters[0].PacketsForwarded++
	tracker.Observe(p, now.Add(500*time.Millisecond))
	assert.Equal(t, NodeChanges{CapturedChanged: true, ForwardedChanged: true, Activity: true}, tracker.Snapshot()[key])
	tracker.Observe(p, now.Add(900*time.Millisecond))
	tracker.Advance(now.Add(time.Second))
	assert.Equal(t, NodeChanges{ForwardedChanged: true, Activity: true}, tracker.Snapshot()[key])
	tracker.Advance(now.Add(1500 * time.Millisecond))
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
	p[0].Hunters[0].PacketsCaptured++
	p[0].Hunters[0].PacketsForwarded++
	tracker.Observe(p, now.Add(2*time.Second))
	p[0].Hunters[0].PacketsForwarded = 0
	tracker.Observe(p, now.Add(2100*time.Millisecond))
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key], "counter reset clears both accents")
}

func TestCounterAccentsOnlyFollowDisplayedChanges(t *testing.T) {
	for _, scale := range []uint64{1000, 1000000, 1000000000} {
		t.Run(FormatPacketNumber(scale), func(t *testing.T) {
			now := time.Unix(100, 0)
			p, key := trackerFixture()
			hunter := &p[0].Hunters[0]
			hunter.PacketsCaptured, hunter.PacketsForwarded = scale, scale
			var tracker ChangeTracker
			tracker.Observe(p, now)
			hunter.PacketsCaptured++
			hunter.PacketsForwarded++
			tracker.Observe(p, now)
			assert.Equal(t, NodeChanges{Activity: true}, tracker.Snapshot()[key], "raw traffic alone must not highlight unchanged rounded totals")
			hunter.PacketsCaptured, hunter.PacketsForwarded = scale+scale/10, scale+scale/10
			tracker.Observe(p, now.Add(100*time.Millisecond))
			assert.Equal(t, NodeChanges{Activity: true, CapturedChanged: true, ForwardedChanged: true}, tracker.Snapshot()[key])
			hunter.PacketsCaptured++
			hunter.PacketsForwarded++
			tracker.Observe(p, now.Add(900*time.Millisecond))
			tracker.Advance(now.Add(1100 * time.Millisecond))
			assert.Equal(t, NodeChanges{Activity: true}, tracker.Snapshot()[key], "sub-rounding increments must not extend cell highlights")
			tracker.Advance(now.Add(1900 * time.Millisecond))
			assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
			// A decrease can stay in the same rounded bucket, but still resets
			// the raw baseline and clears activity.
			hunter.PacketsCaptured++
			tracker.Observe(p, now.Add(2*time.Second))
			hunter.PacketsCaptured--
			tracker.Observe(p, now.Add(2100*time.Millisecond))
			assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
		})
	}
}

func TestChangesMetricBaselinesAndDisplayedValues(t *testing.T) {
	now := time.Unix(100, 0)
	p, key := trackerFixture()
	var tracker ChangeTracker
	tracker.Observe(p, now)
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
	p[0].Hunters[0].CPUPercent = 12.2
	p[0].Hunters[0].MemoryRSSBytes = 1000001
	tracker.Observe(p, now)
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key], "invisible changes remain quiet")
	p[0].Hunters[0].CPUPercent = 13
	p[0].Hunters[0].MemoryRSSBytes = 900000
	tracker.Observe(p, now)
	assert.Equal(t, MetricChange{Direction: 1, Changed: true}, tracker.Snapshot()[key].CPU)
	assert.Equal(t, MetricChange{Direction: -1, Changed: true}, tracker.Snapshot()[key].Memory)
	tracker.Observe(p, now.Add(900*time.Millisecond))
	assert.True(t, tracker.Advance(now.Add(time.Second)))
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key], "identical reports do not prolong highlights")
	assert.False(t, tracker.Advance(now.Add(2*time.Second)))
}

func TestChangesUnknownTelemetryAndAvailability(t *testing.T) {
	now := time.Unix(100, 0)
	p, key := trackerFixture()
	p[0].Hunters[0].CPUPercent = -1
	p[0].Hunters[0].MemoryRSSBytes = 0
	var tracker ChangeTracker
	tracker.Observe(p, now)
	p[0].Hunters[0].CPUPercent = 0 // Known zero is different from unavailable.
	p[0].Hunters[0].MemoryRSSBytes = 100000
	tracker.Observe(p, now)
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
	p[0].Hunters[0].PacketsCaptured++
	p[0].Hunters[0].CPUPercent = 2
	tracker.Observe(p, now)
	assert.True(t, tracker.Snapshot()[key].Activity)
	assert.True(t, tracker.Snapshot()[key].CPU.Changed)
	p[0].Hunters[0].StatsUnavailable = true
	tracker.Observe(p, now)
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
	p[0].Hunters[0].StatsUnavailable = false
	p[0].Hunters[0].CPUPercent = 90
	p[0].Hunters[0].ActiveFilters = 100
	p[0].Hunters[0].PacketsCaptured = 1000
	tracker.Observe(p, now)
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key], "first real telemetry is a baseline")
}

func TestChangesFiltersCountersAndImmutableSnapshots(t *testing.T) {
	now := time.Unix(100, 0)
	p, key := trackerFixture()
	var tracker ChangeTracker
	tracker.Observe(p, now)
	p[0].Hunters[0].ActiveFilters = 3
	p[0].Hunters[0].PacketsForwarded++
	tracker.Observe(p, now)
	snapshot := tracker.Snapshot()
	assert.EqualValues(t, -2, snapshot[key].FilterDelta)
	assert.True(t, snapshot[key].FiltersChanged)
	assert.True(t, snapshot[key].Activity)
	delete(snapshot, key)
	assert.True(t, tracker.Snapshot()[key].Activity)
	p[0].Hunters[0].PacketsCaptured = 0
	tracker.Observe(p, now)
	assert.False(t, tracker.Snapshot()[key].Activity, "reset does not imply traffic")
	p[0].Hunters[0].PacketsCaptured = 1
	p[0].Hunters[0].ActiveFilters = 4
	tracker.Observe(p, now.Add(500*time.Millisecond))
	assert.EqualValues(t, 1, tracker.Snapshot()[key].FilterDelta)
	tracker.Advance(now.Add(time.Second))
	assert.True(t, tracker.Snapshot()[key].FiltersChanged, "new real change replaces expiry")
	tracker.Advance(now.Add(1500 * time.Millisecond))
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[key])
}

func TestChangesLifecycleAndHealth(t *testing.T) {
	now := time.Unix(100, 0)
	p, key := trackerFixture()
	processorKey := NodeKey{ProcessorAddr: p[0].Address}
	var tracker ChangeTracker
	p[0].ConnectionState = ProcessorConnectionStateConnecting
	tracker.Baseline(key, "edge")
	tracker.Observe(p, now)
	p[0].ConnectionState = ProcessorConnectionStateConnected
	tracker.Observe(p, now)
	assert.Empty(t, tracker.RecentText(now), "initial connection is not recovery")
	tracker.Joined(key, "edge", now)
	assert.Empty(t, tracker.RecentText(now), "duplicate join after initial topology baseline is quiet")
	p[0].Hunters[0].Status = management.HunterStatus_STATUS_WARNING
	tracker.Observe(p, now)
	assert.True(t, tracker.Snapshot()[key].StatusChanged)
	assert.Contains(t, tracker.RecentText(now), "edge warning")
	tracker.Observe(p, now)
	assert.Len(t, tracker.events, 1)
	p[0].Hunters[0].Status = management.HunterStatus_STATUS_HEALTHY
	tracker.Observe(p, now)
	assert.Equal(t, "RECOVERED", tracker.Snapshot()[key].Label)
	p[0].ConnectionState = ProcessorConnectionStateFailed
	p[0].Hunters[0].PacketsCaptured++
	tracker.Observe(p, now)
	assert.Equal(t, "DISCONNECTED", tracker.Snapshot()[processorKey].Label)
	assert.False(t, tracker.Snapshot()[key].Activity)
	assert.Len(t, tracker.events, 3, "parent loss produces one event")
	p[0].ConnectionState = ProcessorConnectionStateConnecting
	tracker.Observe(p, now)
	assert.Len(t, tracker.events, 3)
	p[0].ConnectionState = ProcessorConnectionStateConnected
	tracker.Observe(p, now)
	assert.Equal(t, "RECOVERED", tracker.Snapshot()[processorKey].Label)
	assert.Len(t, tracker.events, 4)
	tracker.Advance(now.Add(5 * time.Second))
	assert.Empty(t, tracker.Snapshot()[processorKey].Label)
}

func TestChangesJoinedAcceptsEitherPollingOrderOnce(t *testing.T) {
	for _, pollFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("pollFirst=%v", pollFirst), func(t *testing.T) {
			now := time.Unix(100, 0)
			p, key := trackerFixture()
			var tracker ChangeTracker
			if pollFirst {
				tracker.Observe(p, now)
			}
			tracker.Joined(key, "edge", now)
			tracker.Observe(p, now)
			assert.Equal(t, "NEW", tracker.Snapshot()[key].Label)
			assert.Len(t, tracker.events, 1)
			// Duplicate streamed events after polling neither append events nor
			// prolong the original lifecycle marker.
			tracker.Joined(key, "edge", now.Add(4*time.Second))
			assert.Len(t, tracker.events, 1)
			tracker.Advance(now.Add(5 * time.Second))
			assert.Empty(t, tracker.Snapshot()[key].Label)
		})
	}
}

func TestChangesTopologyBaselinePreservesMetricsAndSuppressesJoins(t *testing.T) {
	now := time.Unix(100, 0)
	p, key := trackerFixture()
	var tracker ChangeTracker
	tracker.Baseline(key, "edge")
	tracker.Observe(p, now)
	tracker.Joined(key, "edge", now)
	assert.Empty(t, tracker.events)
	p[0].Hunters[0].CPUPercent = 50
	tracker.Observe(p, now)
	before := tracker.Snapshot()[key]
	tracker.Baseline(key, "edge") // Reconnect snapshot does not reset metrics.
	assert.Equal(t, before, tracker.Snapshot()[key])
	tracker.Joined(key, "edge", now.Add(time.Second))
	assert.Empty(t, tracker.events)
	tracker.Advance(now.Add(time.Second))
	assert.False(t, tracker.Snapshot()[key].CPU.Changed)
	// Removing a subscription/node also discards lifecycle bookkeeping.
	tracker.Observe(nil, now)
	assert.Empty(t, tracker.nodes)
	tracker.Joined(key, "edge", now)
	assert.Equal(t, "NEW", tracker.Snapshot()[key].Label)
}

func TestChangesInitialDisconnectedConfigurationIsNotRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	p, _ := trackerFixture()
	var tracker ChangeTracker
	for _, state := range []ProcessorConnectionState{ProcessorConnectionStateDisconnected, ProcessorConnectionStateDisconnected, ProcessorConnectionStateConnecting, ProcessorConnectionStateConnected} {
		p[0].ConnectionState = state
		tracker.Observe(p, now)
	}
	assert.Empty(t, tracker.events)
	p[0].ConnectionState = ProcessorConnectionStateFailed
	tracker.Observe(p, now)
	p[0].ConnectionState = ProcessorConnectionStateConnected
	tracker.Observe(p, now)
	assert.Equal(t, "RECOVERED", tracker.Snapshot()[NodeKey{ProcessorAddr: p[0].Address}].Label)
}

func TestChangesAncestorVisibilityAndIndirectProcessorRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	p, _ := trackerFixture()
	p = append(p, ProcessorInfo{Address: "middle", UpstreamAddr: p[0].Address}, ProcessorInfo{Address: "leaf", UpstreamAddr: "middle", Hunters: p[0].Hunters})
	var tracker ChangeTracker
	tracker.Observe(p, now)
	p[2].Status = management.ProcessorStatus_PROCESSOR_WARNING
	tracker.Observe(p, now)
	p[2].Status = management.ProcessorStatus_PROCESSOR_HEALTHY
	tracker.Observe(p, now)
	assert.Equal(t, "RECOVERED", tracker.Snapshot()[NodeKey{ProcessorAddr: "leaf"}].Label)
	tracker.Advance(now.Add(30 * time.Second))
	// Indirect processors stay in their existing unknown connection state when
	// the root fails. Cascading health values do not represent independent loss.
	p[0].ConnectionState = ProcessorConnectionStateFailed
	p[1].Status = management.ProcessorStatus_PROCESSOR_ERROR
	p[2].Status = management.ProcessorStatus_PROCESSOR_ERROR
	p[2].Hunters = append([]types.HunterInfo(nil), p[2].Hunters...)
	p[2].Hunters[0].Status = management.HunterStatus_STATUS_ERROR
	p[2].Hunters[0].PacketsCaptured++
	tracker.Observe(p, now.Add(30*time.Second))
	assert.Len(t, tracker.events, 1)
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[NodeKey{ProcessorAddr: "leaf", HunterID: "hunter"}])
	assert.Equal(t, NodeChanges{}, tracker.Snapshot()[NodeKey{ProcessorAddr: "leaf"}])
}

func TestChangesRecentEventAgingIsDirtyOnlyWhenTextChanges(t *testing.T) {
	now := time.Unix(100, 0)
	var tracker ChangeTracker
	tracker.Joined(NodeKey{ProcessorAddr: "edge"}, "edge", now)
	assert.False(t, tracker.Advance(now.Add(100*time.Millisecond)))
	assert.True(t, tracker.Advance(now.Add(time.Second)))
	assert.False(t, tracker.Advance(now.Add(1100*time.Millisecond)))
	assert.True(t, tracker.Advance(now.Add(30*time.Second)))
	assert.False(t, tracker.Advance(now.Add(31*time.Second)))
}

func TestChangesJoinsRemovalsPruningAndEventBounds(t *testing.T) {
	now := time.Unix(100, 0)
	var tracker ChangeTracker
	p, key := trackerFixture()
	tracker.Observe(p, now)
	other := NodeKey{ProcessorAddr: "other:5555", HunterID: key.HunterID}
	tracker.Joined(other, "other-edge", now)
	tracker.Joined(other, "other-edge", now.Add(time.Second))
	require.Len(t, tracker.events, 1)
	assert.Equal(t, "NEW", tracker.Snapshot()[other].Label)
	assert.Empty(t, tracker.Snapshot()[key].Label, "same hunter ID on another processor is distinct")
	tracker.Removed(other, "other-edge", now)
	tracker.Removed(other, "other-edge", now)
	assert.NotContains(t, tracker.Snapshot(), other)
	assert.Len(t, tracker.events, 2)
	tracker.Observe(nil, now) // A subscription change is not a disconnect.
	assert.Empty(t, tracker.Snapshot())
	assert.Len(t, tracker.events, 2)
	assert.Contains(t, tracker.RecentText(now), "other-edge disconnected (+1 more)")
	for i := 0; i < 30; i++ {
		key := NodeKey{ProcessorAddr: fmt.Sprintf("processor-%d", i)}
		tracker.Joined(key, key.ProcessorAddr, now)
		tracker.Removed(key, key.ProcessorAddr, now)
	}
	assert.Len(t, tracker.events, 20)
	assert.Empty(t, tracker.nodes)
	assert.Contains(t, tracker.RecentText(now.Add(time.Second)), "1s ago")
	assert.Contains(t, tracker.RecentText(now), "+19 more")
	assert.True(t, tracker.Advance(now.Add(30*time.Second)))
	assert.Empty(t, tracker.RecentText(now.Add(30*time.Second)))
	assert.Empty(t, tracker.events)
	tracker.Reset()
	assert.Empty(t, tracker.Snapshot())
}

//go:build tui || all

package tui

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCallTrackerInsertionAvoidsSnapshotsAndCleansEvictedState(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(2)
	spy := installRTPLookupRegistrySpy(t, tracker)
	tracker.RegisterCallPartyInfo("first", "alice", "bob")
	tracker.RegisterMediaPorts("first", "10.0.0.1", []uint16{1000}, false)
	tracker.lastRTPTouch.Store("first", time.Now().UnixNano())
	tracker.RegisterCallPartyInfo("second", "carol", "dave")
	tracker.RegisterCallPartyInfo("third", "erin", "frank")
	require.Zero(t, spy.activeCallsCalls)
	from, to := tracker.GetCallPartyInfo("first")
	require.Empty(t, from)
	require.Empty(t, to)
	_, found := tracker.lastRTPTouch.Load("first")
	require.False(t, found)
	require.Empty(t, tracker.GetEndpointsForCall("first"))
	from, to = tracker.GetCallPartyInfo("second")
	require.Equal(t, "carol", from)
	require.Equal(t, "dave", to)
	from, to = tracker.GetCallPartyInfo("third")
	require.Equal(t, "erin", from)
	require.Equal(t, "frank", to)
	require.Equal(t, 2, tracker.GetTrackedCallCount())
}

func TestCallTrackerInsertionPreservesExistingPartyInfoAndRecency(t *testing.T) {
	tracker := NewCallTrackerWithCapacity(2)
	tracker.RegisterCallPartyInfo("first", "alice", "")
	tracker.RegisterCallPartyInfo("second", "bob", "carol")
	tracker.RegisterCallPartyInfo("first", "replacement", "dave")
	tracker.RegisterCallPartyInfo("third", "erin", "frank")
	from, to := tracker.GetCallPartyInfo("first")
	require.Equal(t, "alice", from)
	require.Equal(t, "dave", to)
	require.False(t, tracker.IsCallActive("second"))
}

func BenchmarkCallTrackerNewCallAtCapacity(b *testing.B) {
	for _, capacity := range []int{100, 5000} {
		b.Run(fmt.Sprint(capacity), func(b *testing.B) {
			tracker := NewCallTrackerWithCapacity(capacity)
			ids := make([]string, capacity+1)
			for i := range ids {
				ids[i] = fmt.Sprint(i)
			}
			for _, id := range ids[:capacity] {
				tracker.RegisterCallPartyInfo(id, "alice", "bob")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tracker.RegisterCallPartyInfo(ids[(i+capacity)%len(ids)], "alice", "bob")
			}
		})
	}
}

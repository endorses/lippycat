package callregistry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpsertWithEvictionReportsOnlyRemovedCall(t *testing.T) {
	observer := &recordingObserver{}
	core := New(Config{MaxCalls: 2, MaxEndpointsPerCall: 2, Observers: []LifecycleObserver{observer}})
	for _, id := range []string{"first", "second"} {
		ok, evicted := core.UpsertWithEviction(Call{CallID: id})
		require.True(t, ok)
		require.Empty(t, evicted)
	}
	require.True(t, core.TryAssociateEndpoint("first", "host:1000"))
	ok, evicted := core.UpsertWithEviction(Call{CallID: "second", From: "updated"})
	require.True(t, ok)
	require.Empty(t, evicted)
	ok, evicted = core.UpsertWithEviction(Call{CallID: "third"})
	require.True(t, ok)
	require.Equal(t, "first", evicted)
	require.Empty(t, core.CallIDsForEndpoint("host:1000"))
	require.Equal(t, []string{"first:evicted"}, observer.ends)
	require.Equal(t, []string{"first", "second", "third"}, observer.starts)
}

func TestUpsertWithEvictionRejectedMutationsAndPinnedLRU(t *testing.T) {
	core := New(Config{MaxCalls: 2})
	require.True(t, core.Upsert(Call{CallID: "old"}))
	require.True(t, core.Upsert(Call{CallID: "recent"}))
	core.Pin("old")
	ok, evicted := core.UpsertWithEviction(Call{CallID: "new"})
	require.True(t, ok)
	require.Equal(t, "recent", evicted)
	core.Pin("new")
	for _, id := range []string{"", "rejected"} {
		ok, evicted = core.UpsertWithEviction(Call{CallID: id})
		require.False(t, ok)
		require.Empty(t, evicted)
	}
	core.Close()
	ok, evicted = core.UpsertWithEviction(Call{CallID: "closed"})
	require.False(t, ok)
	require.Empty(t, evicted)
}

func TestUpsertWithEvictionRetainsPriorityAndLRUTieBreak(t *testing.T) {
	core := New(Config{MaxCalls: 3, EvictionPriority: func(c Call) int {
		if c.State == "ended" {
			return 2
		}
		return -1
	}})
	require.True(t, core.Upsert(Call{CallID: "old-active"}))
	require.True(t, core.Upsert(Call{CallID: "first-ended", State: "ended"}))
	require.True(t, core.Upsert(Call{CallID: "second-ended", State: "ended"}))
	ok, evicted := core.UpsertWithEviction(Call{CallID: "new"})
	require.True(t, ok)
	require.Equal(t, "first-ended", evicted)
}

package callregistry

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type recordingObserver struct {
	mu     sync.Mutex
	starts []string
	ends   []string
}

func (o *recordingObserver) OnCallStarted(call Call) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.starts = append(o.starts, call.CallID)
}

func (o *recordingObserver) OnCallEnded(call Call, reason EndReason) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ends = append(o.ends, call.CallID+":"+string(reason))
}

func TestCoreMultiValuedAssociationsAndCleanup(t *testing.T) {
	observer := &recordingObserver{}
	core := New(Config{MaxCalls: 2, MaxEndpointsPerCall: 2, MaxEndpointAssociations: 3, Observers: []LifecycleObserver{observer}})
	require.True(t, core.Upsert(Call{CallID: "one"}))
	require.True(t, core.Upsert(Call{CallID: "two"}))
	require.True(t, core.TryAssociateEndpoint("one", "10.0.0.1:8000"))
	require.True(t, core.TryAssociateEndpoint("two", "10.0.0.1:8000"))
	require.Equal(t, 2, core.ActiveCallCount())
	require.Equal(t, 2, core.EndpointAssociationCount())
	require.Equal(t, []string{"one", "two"}, core.CallIDsForEndpoint("10.0.0.1:8000"))

	require.True(t, core.Remove("two", EndCompleted))
	require.Equal(t, []string{"one"}, core.CallIDsForEndpoint("10.0.0.1:8000"))
	require.Empty(t, core.EndpointsForCall("two"))
	require.Equal(t, 1, core.ActiveCallCount())
	require.Equal(t, 1, core.EndpointAssociationCount())
	require.Equal(t, []string{"two:completed"}, observer.ends)
}

func TestCoreMostRecentEndpointOwnerChangesOnTouch(t *testing.T) {
	core := New(Config{MaxCalls: 3, MaxEndpointsPerCall: 1})
	require.True(t, core.Upsert(Call{CallID: "one"}))
	require.True(t, core.Upsert(Call{CallID: "two"}))
	require.True(t, core.TryAssociateEndpoint("two", "10.0.0.1:8000"))
	// Association order must not change the global call-recency preference.
	require.True(t, core.TryAssociateEndpoint("one", "10.0.0.1:8000"))

	winner, ok := core.MostRecentCallIDForEndpoint("10.0.0.1:8000")
	require.True(t, ok)
	require.Equal(t, "two", winner)

	require.True(t, core.Touch("one", time.Unix(1, 0)))
	winner, ok = core.MostRecentCallIDForEndpoint("10.0.0.1:8000")
	require.True(t, ok)
	require.Equal(t, "one", winner)
}

func TestCoreEndpointWinnerCleanupOnRemovalAndEviction(t *testing.T) {
	core := New(Config{
		MaxCalls:            2,
		MaxEndpointsPerCall: 1,
		EvictionPriority: func(call Call) int {
			if call.State == "evict-first" {
				return 1
			}
			return 0
		},
	})
	require.True(t, core.Upsert(Call{CallID: "one"}))
	require.True(t, core.Upsert(Call{CallID: "two", State: "evict-first"}))
	require.True(t, core.TryAssociateEndpoint("one", "shared"))
	require.True(t, core.TryAssociateEndpoint("two", "shared"))

	winner, ok := core.MostRecentCallIDForEndpoint("shared")
	require.True(t, ok)
	require.Equal(t, "two", winner)

	require.True(t, core.Upsert(Call{CallID: "three"}))
	winner, ok = core.MostRecentCallIDForEndpoint("shared")
	require.True(t, ok)
	require.Equal(t, "one", winner)

	require.True(t, core.Remove("one", EndCompleted))
	_, ok = core.MostRecentCallIDForEndpoint("shared")
	require.False(t, ok)
}

func TestCoreCountsAreSafeDuringConcurrentMutation(t *testing.T) {
	core := New(Config{MaxCalls: 100, MaxEndpointsPerCall: 1})

	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := 0; index < 100; index++ {
				callID := fmt.Sprintf("%d-%d", worker, index)
				core.Upsert(Call{CallID: callID})
				core.TryAssociateEndpoint(callID, callID)
				_ = core.ActiveCallCount()
				_ = core.EndpointAssociationCount()
				core.Remove(callID, EndCompleted)
			}
		}()
	}
	wg.Wait()

	require.Zero(t, core.ActiveCallCount())
	require.Zero(t, core.EndpointAssociationCount())
}

func TestCoreEvictionIsDeterministicAndCleansAssociations(t *testing.T) {
	observer := &recordingObserver{}
	core := New(Config{MaxCalls: 2, MaxEndpointsPerCall: 2, Observers: []LifecycleObserver{observer}})
	require.True(t, core.Upsert(Call{CallID: "old"}))
	require.True(t, core.Upsert(Call{CallID: "recent"}))
	require.True(t, core.TryAssociateEndpoint("old", "8000"))
	require.True(t, core.Touch("old", time.Unix(1, 0)))
	require.True(t, core.Upsert(Call{CallID: "new"}))

	_, recentExists := core.Call("recent")
	require.False(t, recentExists)
	require.Equal(t, []string{"old"}, core.CallIDsForEndpoint("8000"))
	require.Equal(t, []string{"recent:evicted"}, observer.ends)
	_, oldExists := core.Call("old")
	require.True(t, oldExists)
}

func TestCoreCloseIsIdempotentAndRejectsFurtherMutation(t *testing.T) {
	observer := &recordingObserver{}
	core := New(Config{MaxCalls: 1, MaxEndpointsPerCall: 1, Observers: []LifecycleObserver{observer}})
	require.True(t, core.Upsert(Call{CallID: "one"}))
	require.True(t, core.TryAssociateEndpoint("one", "8000"))
	core.Close()
	core.Close()
	require.False(t, core.Upsert(Call{CallID: "two"}))
	require.False(t, core.TryAssociateEndpoint("one", "8002"))
	require.Equal(t, []string{"one:shutdown"}, observer.ends)
}

func TestCorePinnedCallsAndEvictionPriority(t *testing.T) {
	core := New(Config{
		MaxCalls: 2, MaxEndpointsPerCall: 1,
		EvictionPriority: func(call Call) int {
			if call.State == "ended" {
				return 1
			}
			return 0
		},
	})
	require.True(t, core.Upsert(Call{CallID: "active"}))
	require.True(t, core.Upsert(Call{CallID: "ended", State: "ended"}))
	core.Pin("active")
	require.True(t, core.Upsert(Call{CallID: "new"}))
	_, active := core.Call("active")
	_, ended := core.Call("ended")
	require.True(t, active)
	require.False(t, ended)
	core.Pin("new")
	require.False(t, core.Upsert(Call{CallID: "rejected"}))
	core.Unpin("active")
	require.True(t, core.Upsert(Call{CallID: "admitted"}))
}

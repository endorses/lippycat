package callregistry

import (
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
	require.Equal(t, []string{"one", "two"}, core.CallIDsForEndpoint("10.0.0.1:8000"))

	require.True(t, core.Remove("two", EndCompleted))
	require.Equal(t, []string{"one"}, core.CallIDsForEndpoint("10.0.0.1:8000"))
	require.Empty(t, core.EndpointsForCall("two"))
	require.Equal(t, []string{"two:completed"}, observer.ends)
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

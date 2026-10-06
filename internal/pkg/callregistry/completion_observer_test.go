package callregistry

import (
	"github.com/stretchr/testify/require"
	"testing"
)

type completionObserver struct {
	registry *Core
	calls    []Call
	reenter  func(Call)
}

func (*completionObserver) OnCallStarted(Call)          {}
func (*completionObserver) OnCallEnded(Call, EndReason) {}
func (o *completionObserver) OnCallCompleting(call Call) {
	current, ok := o.registry.Call(call.CallID)
	if ok && current.Lifetime == call.Lifetime {
		o.calls = append(o.calls, call)
	}
	if o.reenter != nil {
		o.reenter(call)
	}
}

func TestCompletionObserverExactLifetimeAndReentry(t *testing.T) {
	registry := New(Config{MaxCalls: 2})
	observer := &completionObserver{registry: registry}
	registry.AddObserver(observer)
	require.True(t, registry.Upsert(Call{CallID: "synthetic"}))
	original, _ := registry.Call("synthetic")
	require.True(t, registry.NotifyCallCompleting(original.CallID, original.Lifetime))
	require.Equal(t, []Call{original}, observer.calls)
	// Beginning grace is distinct from final lifetime removal.
	current, ok := registry.Call(original.CallID)
	require.True(t, ok)
	require.Equal(t, original.Lifetime, current.Lifetime)
	require.True(t, registry.Remove(original.CallID, EndCompleted))
	require.True(t, registry.Upsert(Call{CallID: original.CallID}))
	replacement, _ := registry.Call(original.CallID)
	require.False(t, registry.NotifyCallCompleting(original.CallID, original.Lifetime))
	require.Len(t, observer.calls, 1)
	observer.reenter = func(call Call) { require.True(t, registry.Remove(call.CallID, EndCompleted)) }
	require.True(t, registry.NotifyCallCompleting(replacement.CallID, replacement.Lifetime))
	require.Len(t, observer.calls, 2)
	require.False(t, registry.NotifyCallCompleting(replacement.CallID, replacement.Lifetime))
}

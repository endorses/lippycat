package processor

import (
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/stretchr/testify/require"
)

type lifecycleEvent struct {
	callID string
	reason callregistry.EndReason
}

type recordingLifecycleObserver struct {
	mu     sync.Mutex
	events []lifecycleEvent
}

func (o *recordingLifecycleObserver) OnCallStarted(call callregistry.Call) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, lifecycleEvent{callID: call.CallID})
}

func (o *recordingLifecycleObserver) OnCallEnded(call callregistry.Call, reason callregistry.EndReason) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events = append(o.events, lifecycleEvent{callID: call.CallID, reason: reason})
}

func (o *recordingLifecycleObserver) snapshot() []lifecycleEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]lifecycleEvent(nil), o.events...)
}

func TestCallRegistryCapacityAndLifecycleOrdering(t *testing.T) {
	observer := &recordingLifecycleObserver{}
	p := New(Config{MaxCalls: 2, CallTimeout: time.Hour, LifecycleObservers: []callregistry.LifecycleObserver{observer}})
	p.AssociateEndpoint("one", "192.0.2.1:10000")
	time.Sleep(time.Millisecond)
	p.AssociateEndpoint("two", "192.0.2.2:10002")
	time.Sleep(time.Millisecond)
	p.AssociateEndpoint("three", "192.0.2.3:10004")

	require.Len(t, p.ActiveCalls(), 2)
	_, exists := p.Call("one")
	require.False(t, exists)
	require.Equal(t, []lifecycleEvent{
		{callID: "one"},
		{callID: "two"},
		{callID: "one", reason: callregistry.EndEvicted},
		{callID: "three"},
	}, observer.snapshot())
	p.Close()
}

func TestCallRegistryB2BUAAssociationsAreCopied(t *testing.T) {
	p := New(Config{MaxCalls: 10, CallTimeout: time.Hour})
	t.Cleanup(p.Close)
	p.AssociateEndpoint("leg-a", "192.0.2.1:10000")
	p.AssociateEndpoint("leg-b", "192.0.2.1:10000")

	got := p.CallIDsForEndpoint("192.0.2.1:10000")
	require.Equal(t, []string{"leg-a", "leg-b"}, got)
	got[0] = "corrupted"
	require.Equal(t, []string{"leg-a", "leg-b"}, p.CallIDsForEndpoint("192.0.2.1:10000"))

	p.CompleteCall("leg-a")
	require.Equal(t, []string{"leg-b"}, p.CallIDsForEndpoint("192.0.2.1:10000"))
}

func TestCallRegistryCompletionAndTimeoutNotifications(t *testing.T) {
	observer := &recordingLifecycleObserver{}
	p := New(Config{MaxCalls: 10, CallTimeout: time.Millisecond, LifecycleObservers: []callregistry.LifecycleObserver{observer}})
	t.Cleanup(p.Close)
	p.AssociateEndpoint("completed", "192.0.2.1:10000")
	p.CompleteCall("completed")
	p.AssociateEndpoint("expired", "192.0.2.2:10002")
	p.mu.Lock()
	p.calls["expired"].lastUpdated = time.Now().Add(-time.Second)
	p.mu.Unlock()
	p.cleanupExpiredCalls()

	require.Equal(t, []lifecycleEvent{
		{callID: "completed"},
		{callID: "completed", reason: callregistry.EndCompleted},
		{callID: "expired"},
		{callID: "expired", reason: callregistry.EndTimeout},
	}, observer.snapshot())
}

func TestCallRegistryConcurrentCloseIsIdempotent(t *testing.T) {
	observer := &recordingLifecycleObserver{}
	p := New(Config{MaxCalls: 10, CallTimeout: time.Hour, LifecycleObservers: []callregistry.LifecycleObserver{observer}})
	p.AssociateEndpoint("b", "192.0.2.2:10002")
	p.AssociateEndpoint("a", "192.0.2.1:10000")

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Close()
		}()
	}
	wg.Wait()

	require.Equal(t, []lifecycleEvent{
		{callID: "b"},
		{callID: "a"},
		{callID: "a", reason: callregistry.EndShutdown},
		{callID: "b", reason: callregistry.EndShutdown},
	}, observer.snapshot())
	require.Empty(t, p.ActiveCalls())
}

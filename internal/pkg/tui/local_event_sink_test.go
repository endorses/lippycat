//go:build tui || all

package tui

import (
	"context"
	"sync"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestLocalEventSinkLivePressureIsBoundedAndReported(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var batches []types.EventBatch
	sink := newLocalEventSink(1, false, func(batch types.EventBatch) {
		mu.Lock()
		first := len(batches) == 0
		batches = append(batches, batch)
		mu.Unlock()
		if first {
			close(entered)
			<-release
		}
	})

	require.NoError(t, sink.HandleEvent(context.Background(), localSinkTestEvent("one", 1)))
	<-entered
	require.NoError(t, sink.HandleEvent(context.Background(), localSinkTestEvent("two", 2)))
	require.NoError(t, sink.HandleEvent(context.Background(), localSinkTestEvent("dropped", 3)))
	close(release)
	require.NoError(t, sink.Close(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, batches, 2)
	require.Equal(t, "one", batches[0].Events[0].Envelope().EventID)
	require.Equal(t, "two", batches[1].Events[0].Envelope().EventID)
	require.Len(t, batches[1].Losses, 1)
	require.Equal(t, uint64(1), batches[1].Losses[0].Count)
}

func TestLocalEventSinkOfflineWaitsAndFlushesInOrder(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	var mu sync.Mutex
	var ids []string
	sink := newLocalEventSink(1, true, func(batch types.EventBatch) {
		mu.Lock()
		first := len(ids) == 0
		ids = append(ids, batch.Events[0].Envelope().EventID)
		mu.Unlock()
		if first {
			close(entered)
			<-release
		}
	})
	require.NoError(t, sink.HandleEvent(context.Background(), localSinkTestEvent("one", 1)))
	<-entered
	require.NoError(t, sink.HandleEvent(context.Background(), localSinkTestEvent("two", 2)))

	thirdDone := make(chan error, 1)
	go func() { thirdDone <- sink.HandleEvent(context.Background(), localSinkTestEvent("three", 3)) }()
	select {
	case <-thirdDone:
		t.Fatal("offline delivery bypassed bounded backpressure")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-thirdDone)
	require.NoError(t, sink.Flush(context.Background()))
	require.NoError(t, sink.Close(context.Background()))

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"one", "two", "three"}, ids)
}

func TestPendingLocalEventsAreBoundedOrderedAndReportPressure(t *testing.T) {
	pendingLocalEvents.clear()
	t.Cleanup(pendingLocalEvents.clear)

	for i := 0; i < maxPendingLocalEventBatches; i++ {
		pendingLocalEvents.addBatch(types.EventBatch{Events: []events.Event{
			localSinkTestEvent("event", uint64(i+1)),
		}})
	}
	pendingLocalEvents.addBatch(types.EventBatch{Events: []events.Event{
		localSinkTestEvent("dropped", maxPendingLocalEventBatches+1),
	}})

	batches := drainPendingLocalEvents(true)
	require.Len(t, batches, maxPendingLocalEventBatches+1)
	require.Equal(t, uint64(1), batches[0].Events[0].Envelope().EventSequence)
	require.Equal(t, uint64(maxPendingLocalEventBatches), batches[maxPendingLocalEventBatches-1].Events[0].Envelope().EventSequence)
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_BUFFER, batches[maxPendingLocalEventBatches].Losses[0].Kind)
	require.Equal(t, uint64(1), batches[maxPendingLocalEventBatches].Losses[0].Count)
}

func localSinkTestEvent(id string, sequence uint64) events.Event {
	return events.NewDNSEvent(testEventEnvelope(id, sequence))
}

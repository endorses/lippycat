//go:build tui || all

package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestPendingEventsRetainDeliveryBoundaries(t *testing.T) {
	pending := &pendingLocalEventBuffer{}
	batches := []types.EventBatch{
		{Events: []events.Event{localSinkTestEvent("first", 1)}, StreamID: "stream-a", DeliverySequence: 3},
		{Losses: []types.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_BUFFER, SourceNodeID: "node-a", ProducerSessionID: "session-a", SequenceRanges: []types.EventSequenceRange{{First: 2, Last: 4}}}}, StreamID: "stream-a", DeliverySequence: 4},
		{Events: []events.Event{localSinkTestEvent("second", 5)}, CompatibilityOmissions: 2, StreamID: "stream-b", DeliverySequence: 1},
	}
	for _, batch := range batches {
		pending.addBatch(batch)
	}
	msg := EventBatchMsg{Batches: pending.drain(50), Local: true}
	require.Equal(t, batches, msg.Batches)
	require.Empty(t, pending.drain(50))
}

func TestPendingEventsPressureStaysAtOriginalBoundary(t *testing.T) {
	pending := &pendingLocalEventBuffer{}
	for i := 0; i < maxPendingLocalEventBatches; i++ {
		pending.addBatch(types.EventBatch{Events: []events.Event{localSinkTestEvent("before-loss", uint64(i+1))}})
	}
	pending.addBatch(types.EventBatch{Events: []events.Event{localSinkTestEvent("dropped", 5000)}, CompatibilityOmissions: 2, Losses: []types.EventLoss{{Count: 3}}})
	first := pending.drain(50)
	require.Len(t, first, 50)
	for _, batch := range first {
		require.Empty(t, batch.Losses)
	}
	pending.addBatch(types.EventBatch{Events: []events.Event{localSinkTestEvent("after-loss", 5001)}})
	rest := pending.drain(0)
	require.Len(t, rest, maxPendingLocalEventBatches-50+2)
	for _, batch := range rest[:len(rest)-2] {
		require.Empty(t, batch.Losses)
	}
	require.Equal(t, uint64(6), rest[len(rest)-2].Losses[0].Count)
	require.Equal(t, uint64(5001), rest[len(rest)-1].Events[0].Envelope().EventSequence)
	require.Empty(t, pending.drain(0))
}

func TestRemoteEventsDoNotSendPerArrival(t *testing.T) {
	// Sending to an unstarted program blocks. Delivery must complete solely by
	// enqueueing, independently of whether Bubble Tea can render or receive.
	program := tea.NewProgram(NewModel(100, 100, "", "", nil, false, true, "", false))
	handler := NewTUIEventHandler(program)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			handler.OnEventBatch(types.EventBatch{Events: []events.Event{localSinkTestEvent("remote", uint64(i+1))}})
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		program.Kill()
		t.Fatal("event delivery waited for Bubble Tea")
	}
	for offset := 0; offset < 100; offset += 50 {
		batches := handler.DrainEventBatches()
		require.Len(t, batches, 50)
		for i, batch := range batches {
			require.Equal(t, uint64(offset+i+1), batch.Events[0].Envelope().EventSequence)
		}
	}
	require.Empty(t, handler.DrainEventBatches())
}

func TestPendingEventsConcurrentProducerAndDrain(t *testing.T) {
	pending := &pendingLocalEventBuffer{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i <= 1000; i++ {
			pending.addBatch(types.EventBatch{Events: []events.Event{localSinkTestEvent("concurrent", uint64(i))}})
		}
	}()
	var received []types.EventBatch
	for {
		received = append(received, pending.drain(50)...)
		select {
		case <-done:
			received = append(received, pending.drain(0)...)
			require.Len(t, received, 1000)
			for i, batch := range received {
				require.Empty(t, batch.Losses)
				require.Equal(t, uint64(i+1), batch.Events[0].Envelope().EventSequence)
			}
			return
		default:
		}
	}
}

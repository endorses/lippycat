package eventforwarding

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
)

func TestSinkPendingLossesPreserveReverseOrderCoverage(t *testing.T) {
	sink := &Sink{}
	for _, sequence := range []uint64{10, 5, 7, 6, 9, 8} {
		sink.appendPendingLossLocked(&eventsv1.EventLoss{
			Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1,
			SourceNodeId: "node", ProducerSessionId: "session",
			EventSequenceRanges: []*eventsv1.SequenceRange{{First: sequence, Last: sequence}},
		})
		if sequence == 5 {
			require.Len(t, sink.pendingLosses, 2, "disjoint earlier coverage must not be swallowed")
		}
	}
	require.Len(t, sink.pendingLosses, 1)
	require.Equal(t, uint64(6), sink.pendingLosses[0].GetCount())
	require.Equal(t, uint64(5), sink.pendingLosses[0].GetEventSequenceRanges()[0].GetFirst())
	require.Equal(t, uint64(10), sink.pendingLosses[0].GetEventSequenceRanges()[0].GetLast())
}

func TestSinkUnsupportedEventRetainsEarlierQueueLoss(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spool.Close()) })
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "node", ProducerSessionID: producer.SessionID()}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	first := producer.Assign(events.NewFileContentEvent(events.Envelope{Timestamp: time.Unix(1, 0)}))
	second := producer.Assign(events.NewFileContentEvent(events.Envelope{Timestamp: time.Unix(2, 0)}))
	sink.HandleDroppedEventLocked(first, time.Time{})
	require.NoError(t, sink.HandleEvent(context.Background(), second))
	require.Empty(t, sink.pendingLosses)
	require.NoError(t, sink.Flush(context.Background()))
	batches := spool.Batches()
	require.Len(t, batches, 1)
	var count uint64
	for _, loss := range batches[0].GetStats().GetLosses() {
		count += loss.GetCount()
	}
	require.Equal(t, uint64(2), count)
}

func TestSinkCarrierKeepsLocalLossesAndRecoveryBarrier(t *testing.T) {
	pending := []*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1,
		SourceNodeId: "node", ProducerSessionId: "session",
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: 1, Last: 1}}}}
	for _, barrier := range []error{eventspool.ErrDurabilityUncertain, eventspool.ErrCheckpointRequired} {
		t.Run(barrier.Error(), func(t *testing.T) {
			sink := &Sink{nextBatchSequence: 1, pendingLosses: cloneLosses(pending)}
			joined := errors.Join(barrier, &eventspool.CleanupError{Operation: "remove", Path: "record", Err: errors.New("injected")})
			err := sink.applyCarrierResult(eventspool.EnqueueResult{Stored: true}, joined)
			require.ErrorIs(t, err, barrier)
			require.Equal(t, uint64(2), sink.nextBatchSequence)
			require.Equal(t, pending, sink.pendingLosses)
			require.ErrorIs(t, handledRejectionError(errors.Join(joined, eventspool.ErrRecordTooLarge)), barrier)
		})
	}
}

func TestSinkFragmentedLocalLossesDoNotRejectValidEvent(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spool.Close()) })
	producer, err := events.NewLiveProducer("node")
	require.NoError(t, err)
	producer, err = events.ResumeLiveProducer("node", producer.SessionID(), 4097)
	require.NoError(t, err)
	var newLosses uint64
	client, err := New(Config{SourceNodeID: "node", ProducerSessionID: producer.SessionID(),
		OnLoss: func(_ eventsv1.LossKind, count uint64) { newLosses += count }}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	for sequence := uint64(1); sequence <= 4097; sequence++ {
		kind := eventsv1.LossKind_LOSS_KIND_TRANSPORT
		if sequence%2 == 0 {
			kind = eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT
		}
		sink.pendingLosses = append(sink.pendingLosses, &eventsv1.EventLoss{
			Kind: kind, Count: 1, SourceNodeId: "node", ProducerSessionId: producer.SessionID(),
			EventSequenceRanges: []*eventsv1.SequenceRange{{First: sequence, Last: sequence}},
		})
	}
	event := producer.Assign(events.NewDNSEvent(events.Envelope{Timestamp: time.Unix(1, 0), CaptureScope: events.CaptureScopeFiltered, Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53}}))
	_, err = protoadapter.ToProtoBatch("node", producer.SessionID(), 1, []events.Event{event}, nil, 1)
	require.NoError(t, err)
	require.NoError(t, sink.HandleEvent(context.Background(), event))
	batches := spool.Batches()
	require.Equal(t, 2, len(batches))
	for _, batch := range batches {
		require.NoError(t, protoadapter.ValidateBatch(batch))
	}
	require.Len(t, batches[1].GetEvents(), 1)
	require.Equal(t, uint64(4098), batches[1].GetEvents()[0].GetEventSequence())
	require.Zero(t, newLosses, "existing omission coverage must not cause a new valid-event loss")
	require.Empty(t, sink.pendingLosses)
}

package eventforwarding

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestEventTransportSchemaHasNoRawPacketBytes(t *testing.T) {
	visited := make(map[protoreflect.FullName]bool)
	var checkMessage func(protoreflect.MessageDescriptor)
	checkMessage = func(message protoreflect.MessageDescriptor) {
		if visited[message.FullName()] {
			return
		}
		visited[message.FullName()] = true
		fields := message.Fields()
		for i := 0; i < fields.Len(); i++ {
			field := fields.Get(i)
			require.NotEqualf(t, protoreflect.BytesKind, field.Kind(),
				"event transport field %s must not carry raw packet bytes", field.FullName())
			if field.Kind() == protoreflect.MessageKind {
				checkMessage(field.Message())
			}
		}
	}

	checkMessage((&eventsv1.ProtocolEventBatch{}).ProtoReflect().Descriptor())
}

func TestSinkReportsUnsupportedContentAndCarriesExactGap(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	producer, err := events.NewLiveProducer("hunter-a")
	require.NoError(t, err)
	var unsupported uint64
	client, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: producer.SessionID(), EventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_DNS}, OnLoss: func(kind eventsv1.LossKind, count uint64) {
		if kind == eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT {
			unsupported += count
		}
	}}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)

	content := producer.Assign(events.NewFileContentEvent(events.Envelope{Timestamp: time.Unix(1, 0), NodeID: "hunter-a"}))
	require.NoError(t, sink.HandleEvent(context.Background(), content))
	require.Equal(t, uint64(1), unsupported)
	require.Empty(t, spool.Batches())

	envelope := events.Envelope{Timestamp: time.Unix(2, 0), NodeID: "hunter-a", CaptureScope: events.CaptureScopeFiltered, Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53}}
	dns := producer.Assign(events.NewDNSEvent(envelope))
	require.NoError(t, sink.HandleEvent(context.Background(), dns))
	batches := spool.Batches()
	require.Len(t, batches, 1)
	losses := batches[0].GetStats().GetLosses()
	require.Len(t, losses, 1)
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, losses[0].GetKind())
	require.Equal(t, uint64(1), losses[0].GetEventSequenceRanges()[0].GetFirst())
	require.Equal(t, uint64(1), losses[0].GetEventSequenceRanges()[0].GetLast())
}

func TestSinkFlushPersistsTerminalUnsupportedLoss(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	producer, err := events.NewLiveProducer("hunter-a")
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: producer.SessionID()}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	require.NoError(t, sink.HandleEvent(context.Background(), producer.Assign(events.NewFileContentEvent(events.Envelope{Timestamp: time.Unix(1, 0), NodeID: "hunter-a"}))))
	require.NoError(t, sink.Flush(context.Background()))
	batches := spool.Batches()
	require.Len(t, batches, 1)
	require.Empty(t, batches[0].GetEvents())
	require.Equal(t, uint64(1), batches[0].GetStats().GetLosses()[0].GetEventSequenceRanges()[0].GetLast())
}

func TestSinkUnsupportedLossSurvivesRestartBeforeFlush(t *testing.T) {
	dir := t.TempDir()
	producer, err := events.NewLiveProducer("hunter-a")
	require.NoError(t, err)
	spool, err := eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: producer.SessionID()}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	unsupported := producer.Assign(events.NewFileContentEvent(events.Envelope{Timestamp: time.Unix(1, 0), NodeID: "hunter-a"}))
	require.NoError(t, sink.HandleEvent(context.Background(), unsupported))
	require.True(t, spool.HasPendingLosses())
	require.NoError(t, spool.Close())

	recovered, err := eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recovered.Close()) })
	recoveredClient, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: producer.SessionID()}, recovered)
	require.NoError(t, err)
	recoveredSink, err := NewSink(recoveredClient, 1, 1)
	require.NoError(t, err)
	require.NoError(t, recoveredSink.Flush(context.Background()))
	batches, err := recovered.BatchesAfter("hunter-a", producer.SessionID(), 0, 2)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Empty(t, batches[0].GetEvents())
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, batches[0].GetStats().GetLosses()[0].GetKind())
	require.Equal(t, uint64(1), batches[0].GetStats().GetLosses()[0].GetEventSequenceRanges()[0].GetFirst())
}

func TestSinkOversizedEventRetainsLossAndReusesSequenceForValidEvent(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir(), MaxRecordBytes: 1024})
	require.NoError(t, err)
	producer, err := events.NewLiveProducer("hunter-a")
	require.NoError(t, err)
	var transportLoss uint64
	client, err := New(Config{
		SourceNodeID: "hunter-a", ProducerSessionID: producer.SessionID(),
		OnLoss: func(kind eventsv1.LossKind, count uint64) {
			if kind == eventsv1.LossKind_LOSS_KIND_TRANSPORT {
				transportLoss += count
			}
		},
	}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)

	envelope := events.Envelope{
		Timestamp: time.Unix(1, 0), NodeID: "hunter-a", CaptureScope: events.CaptureScopeFiltered,
		Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53},
	}
	oversized := events.NewDNSEvent(envelope)
	oversized.Query = strings.Repeat("x", 2048)
	require.NoError(t, sink.HandleEvent(context.Background(), producer.Assign(oversized)))
	require.Equal(t, uint64(1), transportLoss)
	require.Equal(t, uint64(1), sink.nextBatchSequence)

	valid := events.NewDNSEvent(envelope)
	valid.Query = "example.test"
	require.NoError(t, sink.HandleEvent(context.Background(), producer.Assign(valid)))
	require.Equal(t, uint64(2), sink.nextBatchSequence)
	batches, err := spool.BatchesAfter("hunter-a", producer.SessionID(), 0, 2)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Equal(t, uint64(1), batches[0].GetBatchSequence())
	require.Len(t, batches[0].GetEvents(), 1)
	require.Equal(t, uint64(2), batches[0].GetEvents()[0].GetEventSequence())
	require.Len(t, batches[0].GetStats().GetLosses(), 1)
	require.Equal(t, uint64(1), batches[0].GetStats().GetLosses()[0].GetCount())
	require.Equal(t, uint64(1), batches[0].GetStats().GetLosses()[0].GetEventSequenceRanges()[0].GetFirst())
}

func TestSinkFlushesRecoveredOversizedLossAsLossOnlyBatch(t *testing.T) {
	dir := t.TempDir()
	producer, err := events.NewLiveProducer("hunter-a")
	require.NoError(t, err)
	spool, err := eventspool.Open(eventspool.Config{Directory: dir, MaxRecordBytes: 1024})
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: producer.SessionID()}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	envelope := events.Envelope{
		Timestamp: time.Unix(1, 0), NodeID: "hunter-a", CaptureScope: events.CaptureScopeFiltered,
		Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53},
	}
	oversized := events.NewDNSEvent(envelope)
	oversized.Query = strings.Repeat("x", 2048)
	require.NoError(t, sink.HandleEvent(context.Background(), producer.Assign(oversized)))
	require.True(t, spool.HasPendingLosses())
	require.NoError(t, spool.Close())

	recovered, err := eventspool.Open(eventspool.Config{Directory: dir, MaxRecordBytes: 1024})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recovered.Close()) })
	recoveredClient, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: producer.SessionID()}, recovered)
	require.NoError(t, err)
	recoveredSink, err := NewSink(recoveredClient, 1, 1)
	require.NoError(t, err)
	require.NoError(t, recoveredSink.Flush(context.Background()))

	batches, err := recovered.BatchesAfter("hunter-a", producer.SessionID(), 0, 2)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Empty(t, batches[0].GetEvents())
	require.Equal(t, uint64(1), batches[0].GetBatchSequence())
	require.Equal(t, uint64(1), batches[0].GetStats().GetLosses()[0].GetCount())
	require.False(t, recovered.HasPendingLosses())
}

func TestSinkCommittedRejectionClearsVolatileLossAndStopsOnUncertainty(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spool.Close()) })
	client, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: "session-a"}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 7, 1)
	require.NoError(t, err)
	sink.pendingLosses = []*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1}}

	err = sink.applyEnqueueResult(eventspool.EnqueueResult{Rejection: eventspool.RejectionRecordTooLarge}, eventspool.ErrDurabilityUncertain)
	require.ErrorIs(t, err, eventspool.ErrDurabilityUncertain)
	require.Empty(t, sink.pendingLosses, "durably adopted coverage must not be retried by the sink")
	require.Equal(t, uint64(7), sink.nextBatchSequence, "a rejection does not consume a batch sequence")
}

func TestDispatcherStopsForwardingAfterFatalSpoolErrorAndRetainsQueuedRanges(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	producer, err := events.NewLiveProducer("hunter-a")
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: producer.SessionID()}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 8, SinkQueueSize: 8})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Register(sink))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, dispatcher.Start(ctx))
	require.NoError(t, spool.Close())

	envelope := events.Envelope{
		Timestamp: time.Unix(1, 0), NodeID: "hunter-a", CaptureScope: events.CaptureScopeFiltered,
		Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53},
	}
	first := producer.Assign(events.NewDNSEvent(envelope))
	second := producer.Assign(events.NewDNSEvent(envelope))
	third := producer.Assign(events.NewDNSEvent(envelope))
	require.True(t, dispatcher.Enqueue(first))
	require.True(t, dispatcher.Enqueue(second))
	require.Eventually(t, func() bool { return dispatcher.Stats().SinkErrors == 1 }, time.Second, time.Millisecond)
	require.False(t, dispatcher.Enqueue(third), "terminal forwarding failure must stop new dispatcher admission")
	require.ErrorIs(t, dispatcher.Stop(context.Background()), eventspool.ErrClosed)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.ErrorIs(t, sink.failed, eventspool.ErrClosed)
	require.Len(t, sink.pendingLosses, 1)
	require.Equal(t, uint64(3), sink.pendingLosses[0].GetCount())
	require.Equal(t, uint64(1), sink.pendingLosses[0].GetEventSequenceRanges()[0].GetFirst())
	require.Equal(t, uint64(3), sink.pendingLosses[0].GetEventSequenceRanges()[0].GetLast())
}

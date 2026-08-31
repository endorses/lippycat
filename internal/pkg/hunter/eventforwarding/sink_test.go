package eventforwarding

import (
	"context"
	"net/netip"
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

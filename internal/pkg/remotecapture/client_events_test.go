package remotecapture

import (
	"context"
	"io"
	"net/netip"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
)

type fakeEventStream struct {
	eventsv1.EventService_SubscribeEventsClient
	messages []*eventsv1.EventSubscriptionMessage
}

func (s *fakeEventStream) Recv() (*eventsv1.EventSubscriptionMessage, error) {
	if len(s.messages) == 0 {
		return nil, io.EOF
	}
	message := s.messages[0]
	s.messages = s.messages[1:]
	return message, nil
}

func TestReceiveEventsDecodesBatchesAndSurfacesLosses(t *testing.T) {
	handler := &MockEventHandler{}
	client := &Client{ctx: context.Background(), handler: handler}
	envelope := events.Envelope{
		Timestamp: time.Unix(10, 0), ProducerSessionID: "session", EventSequence: 1,
		NodeID: "node", CaptureScope: events.CaptureScopeFull, Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"), SourcePort: 53000, DestinationPort: 53},
	}
	envelope.EventID = events.DeliveryEventID(envelope.NodeID, envelope.ProducerSessionID, envelope.EventSequence)
	event := events.NewDNSEvent(envelope)
	wire, err := protoadapter.ToProtoBatch("node", "session", 1, []events.Event{event}, nil, 1)
	require.NoError(t, err)

	stream := &fakeEventStream{messages: []*eventsv1.EventSubscriptionMessage{
		{DeliverySequence: 1, Message: &eventsv1.EventSubscriptionMessage_Control{Control: &eventsv1.EventSubscriptionControl{Kind: eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED, StreamId: "stream", DeliverySequence: 1, SupportedEventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_DNS}}}},
		{DeliverySequence: 2, Message: &eventsv1.EventSubscriptionMessage_Batch{Batch: wire}},
		{DeliverySequence: 3, Message: &eventsv1.EventSubscriptionMessage_Control{Control: &eventsv1.EventSubscriptionControl{Kind: eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_GAP, StreamId: "stream", DeliverySequence: 3, Losses: []*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_SUBSCRIBER, Count: 2, SourceNodeId: "node", ProducerSessionId: "session"}}}}},
	}}
	client.receiveEvents(context.Background(), stream)

	require.Len(t, handler.EventBatches, 3)
	require.Equal(t, uint64(4), handler.EventBatches[0].CompatibilityOmissions)
	require.Len(t, handler.EventBatches[1].Events, 1)
	require.Equal(t, events.KindDNS, handler.EventBatches[1].Events[0].Kind())
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_SUBSCRIBER, handler.EventBatches[2].Losses[0].Kind)
	require.Equal(t, "stream", client.eventStreamID)
	require.Equal(t, uint64(3), client.eventDeliverySequence)
}

func TestReceiveEventsRejectsNonMonotonicDelivery(t *testing.T) {
	handler := &MockEventHandler{}
	client := &Client{ctx: context.Background(), handler: handler}
	client.receiveEvents(context.Background(), &fakeEventStream{messages: []*eventsv1.EventSubscriptionMessage{{DeliverySequence: 2}}})

	require.Len(t, handler.EventBatches, 1)
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_TRANSPORT, handler.EventBatches[0].Losses[0].Kind)
	require.Empty(t, handler.Disconnects)
}

func TestConvertEventLossesPreservesIdentityAndRanges(t *testing.T) {
	losses := convertEventLosses([]*eventsv1.EventLoss{{Kind: eventsv1.LossKind_LOSS_KIND_RECONNECT, Count: 3, SourceNodeId: "node", ProducerSessionId: "session", EventSequenceRanges: []*eventsv1.SequenceRange{{First: 4, Last: 6}}}})
	require.Equal(t, "node", losses[0].SourceNodeID)
	require.Equal(t, "session", losses[0].ProducerSessionID)
	require.Equal(t, uint64(4), losses[0].SequenceRanges[0].First)
	require.Equal(t, uint64(6), losses[0].SequenceRanges[0].Last)
}

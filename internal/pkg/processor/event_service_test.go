//go:build processor || tap || all

package processor

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type eventSubscriptionTestStream struct {
	eventsv1.EventService_SubscribeEventsServer
	ctx        context.Context
	mu         sync.Mutex
	messages   []*eventsv1.EventSubscriptionMessage
	notify     chan struct{}
	blockBatch <-chan struct{}
}

func (s *eventSubscriptionTestStream) Context() context.Context { return s.ctx }
func (s *eventSubscriptionTestStream) Send(message *eventsv1.EventSubscriptionMessage) error {
	s.mu.Lock()
	s.messages = append(s.messages, message)
	s.mu.Unlock()
	if message.GetBatch() != nil && s.blockBatch != nil {
		<-s.blockBatch
	}
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return nil
}
func (s *eventSubscriptionTestStream) SetHeader(metadata.MD) error  { return nil }
func (s *eventSubscriptionTestStream) SendHeader(metadata.MD) error { return nil }
func (s *eventSubscriptionTestStream) SetTrailer(metadata.MD)       {}
func (s *eventSubscriptionTestStream) SendMsg(any) error            { return nil }
func (s *eventSubscriptionTestStream) RecvMsg(any) error            { return nil }

func (s *eventSubscriptionTestStream) snapshot() []*eventsv1.EventSubscriptionMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*eventsv1.EventSubscriptionMessage(nil), s.messages...)
}

func TestEventServiceStreamsLiveFilteredProjectedEvents(t *testing.T) {
	b := broadcast.New()
	service, err := NewEventService(b, EventSubscriptionPolicy{ProcessorNodeID: "processor-a", AllowFileMetadata: true})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 8)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{
			SubscriptionVersion: 1,
			EventKinds:          []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_HTTP},
			NodeIds:             []string{"node-a"},
		}, stream)
	}()
	waitEventMessage(t, stream.notify)

	filtered := events.NewDNSEvent(testEventEnvelope("node-a", 1))
	require.NoError(t, b.HandleEvent(context.Background(), filtered))
	httpEvent := events.NewHTTPEvent(testEventEnvelope("node-a", 2))
	httpEvent.Method, httpEvent.Host, httpEvent.URI = "GET", "example.test", "/private"
	httpEvent.Username = "alice"
	httpEvent.Headers = map[string][]string{"Authorization": {"secret"}}
	require.NoError(t, b.HandleEvent(context.Background(), httpEvent))
	waitEventMessage(t, stream.notify)
	cancel()
	require.NoError(t, <-done)

	messages := stream.snapshot()
	require.Len(t, messages, 2)
	assert.Equal(t, uint64(1), messages[0].DeliverySequence)
	assert.NotEmpty(t, messages[0].GetControl().StreamId)
	assert.NotNil(t, messages[0].GetControl().LiveBoundary)
	assert.Equal(t, uint64(2), messages[1].DeliverySequence)
	require.Len(t, messages[1].GetBatch().Events, 1)
	wireHTTP := messages[1].GetBatch().Events[0].GetHttp()
	assert.Equal(t, "GET", wireHTTP.Method)
	assert.Empty(t, wireHTTP.Uri)
	assert.Empty(t, wireHTTP.Username)
	assert.Empty(t, wireHTTP.Headers)
	decoded, omission, err := protoadapter.FromProto(messages[1].GetBatch().Events[0])
	require.NoError(t, err)
	assert.Nil(t, omission)
	assert.Equal(t, httpEvent.Envelope(), decoded.Envelope())
	assert.Equal(t, "/private", httpEvent.URI)
	assert.Equal(t, "alice", httpEvent.Username)
	assert.Equal(t, 0, b.Stats().Subscribers)
}

func TestEventServiceSeparatesFilteredSequenceGapsIntoValidBatches(t *testing.T) {
	b := broadcast.New()
	service, err := NewEventService(b, EventSubscriptionPolicy{})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 8)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{
			SubscriptionVersion: 1,
			EventKinds:          []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_HTTP},
		}, stream)
	}()
	waitEventMessage(t, stream.notify)
	require.NoError(t, b.HandleEvent(context.Background(), events.NewHTTPEvent(testEventEnvelope("node-a", 1))))
	require.NoError(t, b.HandleEvent(context.Background(), events.NewDNSEvent(testEventEnvelope("node-a", 2))))
	require.NoError(t, b.HandleEvent(context.Background(), events.NewHTTPEvent(testEventEnvelope("node-a", 3))))
	waitEventMessage(t, stream.notify)
	waitEventMessage(t, stream.notify)
	cancel()
	require.NoError(t, <-done)
	messages := stream.snapshot()
	require.Len(t, messages, 3)
	assert.Equal(t, uint64(1), messages[1].GetBatch().FirstEventSequence)
	assert.Equal(t, uint64(3), messages[2].GetBatch().FirstEventSequence)
}

func TestEventServiceReportsOverflowWithoutLaterEvent(t *testing.T) {
	b := broadcast.New()
	service, err := NewEventService(b, EventSubscriptionPolicy{ProcessorNodeID: "processor-a", QueueSize: 1, MaxBatchEvents: 1})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 8), blockBatch: release}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1}, stream)
	}()
	waitEventMessage(t, stream.notify)
	require.NoError(t, b.HandleEvent(context.Background(), events.NewDNSEvent(testEventEnvelope("node-a", 1))))
	for sequence := uint64(2); sequence <= 4; sequence++ {
		require.NoError(t, b.HandleEvent(context.Background(), events.NewDNSEvent(testEventEnvelope("node-a", sequence))))
	}
	close(release)
	waitEventMessage(t, stream.notify)
	waitEventMessage(t, stream.notify)
	waitEventMessage(t, stream.notify)
	cancel()
	require.NoError(t, <-done)
	var subscriberLoss uint64
	for _, message := range stream.snapshot() {
		for _, loss := range message.GetControl().GetLosses() {
			if loss.Kind == eventsv1.LossKind_LOSS_KIND_SUBSCRIBER {
				subscriberLoss += loss.Count
			}
		}
	}
	assert.GreaterOrEqual(t, subscriberLoss, uint64(1))
}

func TestEventServiceEnforcesEncodedMessageSize(t *testing.T) {
	b := broadcast.New()
	service, err := NewEventService(b, EventSubscriptionPolicy{MaxMessageBytes: 4096, AllowSensitiveFields: true})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 4)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, MaxMessageBytes: 1024, IncludeSensitiveFields: true}, stream)
	}()
	waitEventMessage(t, stream.notify)
	event := events.NewHTTPEvent(testEventEnvelope("node-a", 1))
	event.URI = "/" + string(make([]byte, 2000))
	require.NoError(t, b.HandleEvent(context.Background(), event))
	waitEventMessage(t, stream.notify)
	cancel()
	require.NoError(t, <-done)
	messages := stream.snapshot()
	require.Len(t, messages, 2)
	assert.Nil(t, messages[1].GetBatch())
	assert.Equal(t, eventsv1.LossKind_LOSS_KIND_POLICY_OMISSION, messages[1].GetControl().Losses[0].Kind)
	assert.Equal(t, "session-a", messages[1].GetControl().Losses[0].ProducerSessionId)
	assert.Equal(t, uint64(2), messages[1].DeliverySequence)
}

func TestEventServiceBoundsOversizedEventGap(t *testing.T) {
	b := broadcast.New()
	service, err := NewEventService(b, EventSubscriptionPolicy{MaxMessageBytes: 4096, AllowSensitiveFields: true})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 4)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, MaxMessageBytes: 1024, IncludeSensitiveFields: true}, stream)
	}()
	waitEventMessage(t, stream.notify)
	event := events.NewHTTPEvent(testEventEnvelope(strings.Repeat("n", 2000), 1))
	event.URI = "/" + strings.Repeat("x", 2000)
	require.NoError(t, b.HandleEvent(context.Background(), event))
	waitEventMessage(t, stream.notify)
	cancel()
	require.NoError(t, <-done)
	messages := stream.snapshot()
	require.Len(t, messages, 2)
	assert.LessOrEqual(t, proto.Size(messages[1]), 1024)
	require.Len(t, messages[1].GetControl().Losses, 1)
	assert.Equal(t, eventsv1.LossKind_LOSS_KIND_POLICY_OMISSION, messages[1].GetControl().Losses[0].Kind)
	assert.Equal(t, uint64(1), messages[1].GetControl().Losses[0].Count)
}

func TestEventServiceReportsReconnectGap(t *testing.T) {
	b := broadcast.New()
	service, err := NewEventService(b, EventSubscriptionPolicy{ProcessorNodeID: "processor-a"})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 4)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, PreviousStreamId: "old", PreviousDeliverySequence: 42}, stream)
	}()
	waitEventMessage(t, stream.notify)
	waitEventMessage(t, stream.notify)
	cancel()
	require.NoError(t, <-done)
	messages := stream.snapshot()
	require.Len(t, messages, 2)
	assert.Equal(t, eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_GAP, messages[1].GetControl().Kind)
	require.Len(t, messages[1].GetControl().Losses, 1)
	assert.Equal(t, eventsv1.LossKind_LOSS_KIND_RECONNECT, messages[1].GetControl().Losses[0].Kind)
	assert.Equal(t, "old", messages[1].GetControl().PreviousStreamId)
	assert.Equal(t, uint64(42), messages[1].GetControl().PreviousDeliverySequence)
	assert.Equal(t, uint64(2), messages[1].DeliverySequence)
}

func TestEventServiceBoundsReconnectGapToNegotiatedMessageSize(t *testing.T) {
	b := broadcast.New()
	service, err := NewEventService(b, EventSubscriptionPolicy{ProcessorNodeID: strings.Repeat("p", 2048)})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 4)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{
			SubscriptionVersion:      1,
			PreviousStreamId:         strings.Repeat("s", 2048),
			PreviousDeliverySequence: 42,
			MaxMessageBytes:          1024,
		}, stream)
	}()
	waitEventMessage(t, stream.notify)
	waitEventMessage(t, stream.notify)
	cancel()
	require.NoError(t, <-done)

	messages := stream.snapshot()
	require.Len(t, messages, 2)
	assert.LessOrEqual(t, proto.Size(messages[1]), 1024)
	control := messages[1].GetControl()
	require.NotNil(t, control)
	assert.Equal(t, eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_GAP, control.Kind)
	require.Len(t, control.Losses, 1)
	assert.Equal(t, eventsv1.LossKind_LOSS_KIND_RECONNECT, control.Losses[0].Kind)
	assert.Empty(t, control.Losses[0].SourceNodeId)
	assert.Empty(t, control.PreviousStreamId)
	assert.Equal(t, uint64(42), control.PreviousDeliverySequence)
}

func TestEventServiceSharesSubscriberLimit(t *testing.T) {
	b := broadcast.New()
	limit := newSubscriptionLimiter(1)
	service, err := NewEventService(b, EventSubscriptionPolicy{subscriptionLimit: limit})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 2)}
	done := make(chan error, 1)
	go func() {
		done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1}, stream)
	}()
	waitEventMessage(t, stream.notify)

	second := &eventSubscriptionTestStream{ctx: context.Background(), notify: make(chan struct{}, 1)}
	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1}, second)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))

	cancel()
	require.NoError(t, <-done)
	assert.True(t, limit.acquire())
	limit.release()
}

func TestSubscriberLossesDistinguishDispatcherOverflow(t *testing.T) {
	wire := subscriberLosses([]broadcast.Loss{{
		SourceNodeID: "node-a", ProducerSessionID: "session-a",
		Cause: broadcast.LossCauseDispatcherOverflow, Count: 1,
		Ranges: []broadcast.SequenceRange{{First: 7, Last: 7}},
	}})
	require.Len(t, wire, 1)
	assert.Equal(t, eventsv1.LossKind_LOSS_KIND_DISPATCH, wire[0].Kind)
	assert.Equal(t, uint64(1), wire[0].Count)
	assert.Equal(t, "session-a", wire[0].ProducerSessionId)
}

func TestSendLossGapsHonorsMessageLimit(t *testing.T) {
	stream := &eventSubscriptionTestStream{ctx: context.Background(), notify: make(chan struct{}, 32)}
	losses := make([]*eventsv1.EventLoss, 17)
	for index := range losses {
		loss := &eventsv1.EventLoss{
			Kind:              eventsv1.LossKind_LOSS_KIND_SUBSCRIBER,
			Count:             64,
			SourceNodeId:      strings.Repeat("n", 64),
			ProducerSessionId: strings.Repeat("s", 64),
		}
		for sequence := uint64(1); sequence <= 64; sequence++ {
			loss.EventSequenceRanges = append(loss.EventSequenceRanges, &eventsv1.SequenceRange{First: sequence * 2, Last: sequence * 2})
		}
		losses[index] = loss
	}

	deliverySequence, err := sendLossGaps(stream, "stream", 1, losses, 1024)
	require.NoError(t, err)
	messages := stream.snapshot()
	assert.Greater(t, len(messages), 1)
	assert.Equal(t, uint64(len(messages)+1), deliverySequence)
	var lossCount uint64
	for index, message := range messages {
		assert.LessOrEqual(t, proto.Size(message), 1024)
		assert.Equal(t, uint64(index+2), message.DeliverySequence)
		for _, loss := range message.GetControl().Losses {
			lossCount += loss.Count
		}
	}
	assert.Equal(t, uint64(17*64), lossCount)
}

func TestSendLossGapsSummarizesOversizedDetail(t *testing.T) {
	stream := &eventSubscriptionTestStream{ctx: context.Background(), notify: make(chan struct{}, 1)}
	loss := &eventsv1.EventLoss{
		Kind:              eventsv1.LossKind_LOSS_KIND_DISPATCH,
		Count:             7,
		SourceNodeId:      strings.Repeat("n", 2048),
		ProducerSessionId: strings.Repeat("s", 2048),
		EventSequenceRanges: []*eventsv1.SequenceRange{
			{First: 1, Last: 7},
		},
	}

	deliverySequence, err := sendLossGaps(stream, "stream", 4, []*eventsv1.EventLoss{loss}, 1024)
	require.NoError(t, err)
	assert.Equal(t, uint64(5), deliverySequence)
	messages := stream.snapshot()
	require.Len(t, messages, 1)
	assert.LessOrEqual(t, proto.Size(messages[0]), 1024)
	require.Len(t, messages[0].GetControl().Losses, 1)
	summary := messages[0].GetControl().Losses[0]
	assert.Equal(t, eventsv1.LossKind_LOSS_KIND_DISPATCH, summary.Kind)
	assert.Equal(t, uint64(7), summary.Count)
	assert.Empty(t, summary.SourceNodeId)
	assert.Empty(t, summary.ProducerSessionId)
	assert.Empty(t, summary.EventSequenceRanges)
}

func TestEventServiceRejectsUnauthorizedAndInvalidRequests(t *testing.T) {
	service, err := NewEventService(broadcast.New(), EventSubscriptionPolicy{})
	require.NoError(t, err)
	stream := &eventSubscriptionTestStream{ctx: context.Background(), notify: make(chan struct{}, 1)}

	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 2}, stream)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, IncludeSensitiveFields: true}, stream)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, IncludeFileMetadata: true}, stream)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, MaxMessageBytes: 100}, stream)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, NodeIds: []string{""}}, stream)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, NodeIds: []string{strings.Repeat("x", protoadapter.MaxStringBytes+1)}}, stream)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, ProcessorNodeIds: make([]string, protoadapter.MaxCollectionEntries+1)}, stream)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	err = service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, PreviousStreamId: strings.Repeat("x", protoadapter.MaxStringBytes+1)}, stream)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Empty(t, stream.snapshot())
}

func testEventEnvelope(nodeID string, sequence uint64) events.Envelope {
	return events.Envelope{
		Timestamp: time.Now().UTC(), EventID: events.DeliveryEventID(nodeID, "session-a", sequence),
		ProducerSessionID: "session-a", EventSequence: sequence, UID: "uid", CommunityID: "1:test", NodeID: nodeID,
		Flow:         events.FlowTuple{Protocol: 6, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 1234, DestinationPort: 80},
		CaptureScope: events.CaptureScopeFull, Provenance: events.SourceProvenance{CaptureSource: "test", ProcessorNodeIDs: []string{"processor-a"}},
	}
}

func waitEventMessage(t *testing.T, notify <-chan struct{}) {
	t.Helper()
	select {
	case <-notify:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event subscription message")
	}
}

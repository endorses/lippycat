//go:build processor || tap || all

package processor

import (
	"context"
	"net/netip"
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
	assert.Equal(t, uint64(2), messages[1].DeliverySequence)
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

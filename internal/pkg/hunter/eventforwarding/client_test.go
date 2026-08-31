package eventforwarding

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
)

type fakeStream struct {
	mu       sync.Mutex
	sent     []*eventsv1.EventIngressMessage
	controls chan *eventsv1.EventIngressControl
}

func (s *fakeStream) Send(message *eventsv1.EventIngressMessage) error {
	s.mu.Lock()
	s.sent = append(s.sent, message)
	s.mu.Unlock()
	return nil
}

func (s *fakeStream) Recv() (*eventsv1.EventIngressControl, error) {
	control, ok := <-s.controls
	if !ok {
		return nil, io.EOF
	}
	return control, nil
}

func (s *fakeStream) messages() []*eventsv1.EventIngressMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*eventsv1.EventIngressMessage(nil), s.sent...)
}

func newTestClient(t *testing.T) (*Client, *eventspool.Spool) {
	t.Helper()
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "hunter", ProducerSessionID: "session", Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}, spool)
	require.NoError(t, err)
	return client, spool
}

func ingressBatch(sequence uint64) *eventsv1.ProtocolEventBatch {
	return &eventsv1.ProtocolEventBatch{SourceNodeId: "hunter", ProducerSessionId: "session", BatchSequence: sequence, FirstEventSequence: sequence, LastEventSequence: sequence}
}

func TestServeRetriesPersistedIdentityAndDeletesOnlyAfterAck(t *testing.T) {
	client, spool := newTestClient(t)
	_, err := client.Enqueue(ingressBatch(1))
	require.NoError(t, err)

	first := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 4)}
	first.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, first) }()
	require.Eventually(t, func() bool { return len(first.messages()) == 2 }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.Len(t, spool.Batches(), 1, "send without ACK must remain crash recoverable")

	second := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 4)}
	second.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { done <- client.Serve(ctx, second) }()
	require.Eventually(t, func() bool { return len(second.messages()) == 2 }, time.Second, time.Millisecond)
	require.Equal(t, first.messages()[1].GetBatch().ProducerSessionId, second.messages()[1].GetBatch().ProducerSessionId)
	require.Equal(t, first.messages()[1].GetBatch().BatchSequence, second.messages()[1].GetBatch().BatchSequence)
	second.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: 1}
	require.Eventually(t, func() bool { return len(spool.Batches()) == 0 }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeNackResendsRequestedBatch(t *testing.T) {
	client, _ := newTestClient(t)
	_, err := client.Enqueue(ingressBatch(1))
	require.NoError(t, err)
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 4)}
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, stream) }()
	require.Eventually(t, func() bool { return len(stream.messages()) == 2 }, time.Second, time.Millisecond)
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK, NackBatchRanges: []*eventsv1.SequenceRange{{First: 1, Last: 1}}}
	require.Eventually(t, func() bool { return len(stream.messages()) == 3 }, time.Second, time.Millisecond)
	require.Equal(t, uint64(1), stream.messages()[2].GetBatch().BatchSequence)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeRejectsProfileDowngrade(t *testing.T) {
	client, _ := newTestClient(t)
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 1)}
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY}
	err := client.Serve(context.Background(), stream)
	require.ErrorContains(t, err, "accepted profile")
}

func TestEnqueueRejectsProducerSessionMutation(t *testing.T) {
	client, spool := newTestClient(t)
	b := ingressBatch(1)
	b.ProducerSessionId = "changed"
	_, err := client.Enqueue(b)
	require.ErrorContains(t, err, "fixed session")
	require.Empty(t, spool.Batches())
}

func TestACKCarriesFlowControl(t *testing.T) {
	client, _ := newTestClient(t)
	paused, _, err := client.handleControl(context.Background(), controlResult{control: &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, FlowControl: int32(data.FlowControl_FLOW_PAUSE)}}, false, 1)
	require.NoError(t, err)
	require.True(t, paused)
	paused, _, err = client.handleControl(context.Background(), controlResult{control: &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, FlowControl: int32(data.FlowControl_FLOW_RESUME)}}, true, 1)
	require.NoError(t, err)
	require.False(t, paused)
}

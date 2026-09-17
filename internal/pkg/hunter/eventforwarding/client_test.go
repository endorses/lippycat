package eventforwarding

import (
	"context"
	"fmt"
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
	onSend   func(*eventsv1.EventIngressMessage)
}

func (s *fakeStream) Send(message *eventsv1.EventIngressMessage) error {
	s.mu.Lock()
	s.sent = append(s.sent, message)
	s.mu.Unlock()
	if s.onSend != nil {
		s.onSend(message)
	}
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
	return &eventsv1.ProtocolEventBatch{
		SourceNodeId: "hunter", ProducerSessionId: "session", BatchSequence: sequence, SemanticProfileRevision: 1,
		Stats: &eventsv1.EventBatchStats{Losses: []*eventsv1.EventLoss{{
			Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1, SourceNodeId: "hunter", ProducerSessionId: "session",
			EventSequenceRanges: []*eventsv1.SequenceRange{{First: sequence, Last: sequence}},
		}}},
	}
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

func TestServeFetchesFixedBacklogInBoundedChunks(t *testing.T) {
	client, spool := newTestClient(t)
	const batchCount = 300
	for sequence := uint64(1); sequence <= batchCount; sequence++ {
		result, err := client.Enqueue(ingressBatch(sequence))
		require.NoError(t, err)
		require.True(t, result.Stored)
	}

	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 1)}
	stream.controls <- &eventsv1.EventIngressControl{
		Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, stream) }()
	require.Eventually(t, func() bool { return len(stream.messages()) == batchCount+1 }, 5*time.Second, time.Millisecond)
	// Three bounded non-empty fetches cover the fixed backlog. One final empty
	// fetch is permitted before Serve waits for a wake or control message.
	require.LessOrEqual(t, client.batchFetches.Load(), uint64(4))
	metrics := spool.SnapshotMetrics()
	require.Equal(t, uint64(batchCount), metrics.RetrievalClones)
	require.LessOrEqual(t, metrics.RetrievalCalls, uint64(4))
	messages := stream.messages()
	for i := 1; i < len(messages); i++ {
		require.Equal(t, uint64(i), messages[i].GetBatch().GetBatchSequence())
	}
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeOrdersBacklogsIncludingSequenceHoles(t *testing.T) {
	tests := []struct {
		name      string
		sequences []uint64
	}{
		{name: "contiguous", sequences: []uint64{1, 2, 3, 4}},
		{name: "sequence holes", sequences: []uint64{1, 3, 7, 8}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := newTestClient(t)
			for _, sequence := range tt.sequences {
				result, err := client.Enqueue(ingressBatch(sequence))
				require.NoError(t, err)
				require.True(t, result.Stored)
			}
			stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 1)}
			stream.controls <- &eventsv1.EventIngressControl{
				Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- client.Serve(ctx, stream) }()
			require.Eventually(t, func() bool { return len(stream.messages()) == len(tt.sequences)+1 }, time.Second, time.Millisecond)
			var got []uint64
			for _, message := range stream.messages()[1:] {
				got = append(got, message.GetBatch().GetBatchSequence())
			}
			require.Equal(t, tt.sequences, got)
			cancel()
			require.ErrorIs(t, <-done, context.Canceled)
		})
	}
}

func TestServePauseEvictResumeSkipsRemovedCachedBatch(t *testing.T) {
	client, spool := newTestClient(t)
	for sequence := uint64(1); sequence <= 3; sequence++ {
		_, err := client.Enqueue(ingressBatch(sequence))
		require.NoError(t, err)
	}
	selected := make(chan struct{})
	release := make(chan struct{})
	controlQueued := make(chan struct{}, 2)
	client.controlReceived = func() { controlQueued <- struct{}{} }
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 2)}
	stream.onSend = func(message *eventsv1.EventIngressMessage) {
		if message.GetBatch().GetBatchSequence() == 1 {
			close(selected)
			<-release
		}
	}
	stream.controls <- &eventsv1.EventIngressControl{
		Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, stream) }()
	select {
	case <-selected:
	case <-time.After(time.Second):
		t.Fatal("first batch was not selected")
	}
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_FLOW, FlowControl: int32(data.FlowControl_FLOW_PAUSE)}
	select {
	case <-controlQueued:
	case <-time.After(time.Second):
		t.Fatal("pause was not queued for Serve")
	}
	close(release)
	require.Eventually(t, func() bool { return len(stream.messages()) == 2 }, time.Second, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	require.Len(t, stream.messages(), 2, "pause may overshoot by only the already selected batch")

	require.NoError(t, spool.Ack("hunter", "session", 2))
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_FLOW, FlowControl: int32(data.FlowControl_FLOW_RESUME)}
	select {
	case <-controlQueued:
	case <-time.After(time.Second):
		t.Fatal("resume was not queued for Serve")
	}
	require.Eventually(t, func() bool { return len(stream.messages()) == 3 }, time.Second, time.Millisecond)
	require.Equal(t, uint64(3), stream.messages()[2].GetBatch().GetBatchSequence())
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeSeesSustainedEnqueueWakesDuringDrain(t *testing.T) {
	client, spool := newTestClient(t)
	_, err := client.Enqueue(ingressBatch(1))
	require.NoError(t, err)
	selected := make(chan struct{})
	release := make(chan struct{})
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 1)}
	stream.onSend = func(message *eventsv1.EventIngressMessage) {
		if message.GetBatch().GetBatchSequence() == 1 {
			close(selected)
			<-release
		}
	}
	stream.controls <- &eventsv1.EventIngressControl{
		Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, stream) }()
	select {
	case <-selected:
	case <-time.After(time.Second):
		t.Fatal("initial batch was not selected")
	}
	for sequence := uint64(2); sequence <= 100; sequence++ {
		result, enqueueErr := client.Enqueue(ingressBatch(sequence))
		require.NoError(t, enqueueErr)
		require.True(t, result.Stored)
	}
	close(release)
	require.Eventually(t, func() bool { return len(stream.messages()) == 101 }, 3*time.Second, time.Millisecond)
	for i, message := range stream.messages()[1:] {
		require.Equal(t, uint64(i+1), message.GetBatch().GetBatchSequence())
	}
	metrics := spool.SnapshotMetrics()
	require.Equal(t, uint64(100), metrics.RetrievalClones)
	require.LessOrEqual(t, metrics.RetrievalCalls, uint64(4))
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeSkipsCachedBatchRemovedDuringDrain(t *testing.T) {
	client, spool := newTestClient(t)
	for sequence := uint64(1); sequence <= 3; sequence++ {
		_, err := client.Enqueue(ingressBatch(sequence))
		require.NoError(t, err)
	}
	firstSelected := make(chan struct{})
	releaseFirst := make(chan struct{})
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 4)}
	stream.onSend = func(message *eventsv1.EventIngressMessage) {
		if message.GetBatch().GetBatchSequence() == 1 {
			close(firstSelected)
			<-releaseFirst
		}
	}
	stream.controls <- &eventsv1.EventIngressControl{
		Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, stream) }()
	select {
	case <-firstSelected:
	case <-time.After(time.Second):
		t.Fatal("first batch was not selected")
	}

	// The cache already contains all three clones, but cumulative removal makes
	// the second ineligible after the in-flight first send completes.
	require.NoError(t, spool.Ack("hunter", "session", 2))
	close(releaseFirst)
	require.Eventually(t, func() bool {
		for _, message := range stream.messages()[1:] {
			if message.GetBatch().GetBatchSequence() == 3 {
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	sequences := make([]uint64, 0, 2)
	for _, message := range stream.messages()[1:] {
		sequences = append(sequences, message.GetBatch().GetBatchSequence())
	}
	require.Equal(t, []uint64{1, 3}, sequences)
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

func TestHasPendingTracksDurableAcknowledgement(t *testing.T) {
	client, spool := newTestClient(t)
	require.False(t, client.HasPending())

	_, err := client.Enqueue(ingressBatch(1))
	require.NoError(t, err)
	require.True(t, client.HasPending())
	require.NoError(t, spool.Ack("hunter", "session", 1))
	require.False(t, client.HasPending())
}

func TestACKCarriesFlowControl(t *testing.T) {
	client, _ := newTestClient(t)
	paused, _, _, err := client.handleControl(context.Background(), controlResult{control: &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, FlowControl: int32(data.FlowControl_FLOW_PAUSE)}}, false, 1)
	require.NoError(t, err)
	require.True(t, paused)
	paused, _, _, err = client.handleControl(context.Background(), controlResult{control: &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, FlowControl: int32(data.FlowControl_FLOW_RESUME)}}, true, 1)
	require.NoError(t, err)
	require.False(t, paused)
}

func BenchmarkServeBacklogDrain(b *testing.B) {
	for _, batchCount := range []int{1_000, 10_000} {
		b.Run(fmt.Sprintf("batches_%d", batchCount), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				spool, err := eventspool.Open(eventspool.Config{Directory: b.TempDir(), CheckpointEvery: 256})
				require.NoError(b, err)
				client, err := New(Config{SourceNodeID: "hunter", ProducerSessionID: "session", Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}, spool)
				require.NoError(b, err)
				for sequence := uint64(1); sequence <= uint64(batchCount); sequence++ {
					result, enqueueErr := client.Enqueue(ingressBatch(sequence))
					require.NoError(b, enqueueErr)
					require.True(b, result.Stored)
				}
				stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, batchCount+1)}
				stream.controls <- &eventsv1.EventIngressControl{
					Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
				}
				stream.onSend = func(message *eventsv1.EventIngressMessage) {
					if sequence := message.GetBatch().GetBatchSequence(); sequence != 0 {
						stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: sequence}
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				b.StartTimer()
				go func() { done <- client.Serve(ctx, stream) }()
				require.Eventually(b, func() bool { return len(stream.messages()) == batchCount+1 && !spool.HasPending() }, 30*time.Second, time.Millisecond)
				b.StopTimer()
				metrics := spool.SnapshotMetrics()
				expectedMaxCalls := uint64((batchCount+batchFetchLimit-1)/batchFetchLimit + 1)
				require.Equal(b, uint64(batchCount), metrics.RetrievalClones)
				require.LessOrEqual(b, metrics.RetrievalCalls, expectedMaxCalls)
				b.ReportMetric(float64(metrics.RetrievalCalls), "retrieval_calls/op")
				b.ReportMetric(float64(metrics.RetrievalClones), "retrieval_clones/op")
				b.ReportMetric(float64(metrics.ACKRemovalVisits), "ack_visits/op")
				b.ReportMetric(float64(metrics.MetadataBytes), "metadata_bytes/op")
				cancel()
				require.ErrorIs(b, <-done, context.Canceled)
				require.NoError(b, spool.Close())
			}
		})
	}
}

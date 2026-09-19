package eventforwarding

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
)

type fakeStream struct {
	mu       sync.Mutex
	sent     []*eventsv1.EventIngressMessage
	controls chan *eventsv1.EventIngressControl
	onSend   func(*eventsv1.EventIngressMessage)
}

type blockedControlStream struct {
	mu           sync.Mutex
	sendCount    int
	recvCount    int
	recvBlocked  chan struct{}
	canceled     chan struct{}
	batchSendErr error
}

func (s *blockedControlStream) Send(message *eventsv1.EventIngressMessage) error {
	s.mu.Lock()
	s.sendCount++
	sendCount := s.sendCount
	s.mu.Unlock()
	if sendCount == 1 {
		return nil
	}
	<-s.recvBlocked
	return s.batchSendErr
}

func (s *blockedControlStream) Recv() (*eventsv1.EventIngressControl, error) {
	s.mu.Lock()
	s.recvCount++
	recvCount := s.recvCount
	s.mu.Unlock()
	switch recvCount {
	case 1:
		return &eventsv1.EventIngressControl{
			Kind:            eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED,
			AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
		}, nil
	case 2:
		close(s.recvBlocked)
		<-s.canceled
		return nil, context.Canceled
	default:
		return nil, io.EOF
	}
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

func fakeStreamCancel(stream *fakeStream) context.CancelFunc {
	var once sync.Once
	return func() {
		once.Do(func() { close(stream.controls) })
	}
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
	go func() { done <- client.Serve(ctx, first, fakeStreamCancel(first)) }()
	require.Eventually(t, func() bool { return len(first.messages()) == 2 }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.Len(t, spool.Batches(), 1, "send without ACK must remain crash recoverable")

	second := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 4)}
	second.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { done <- client.Serve(ctx, second, fakeStreamCancel(second)) }()
	require.Eventually(t, func() bool { return len(second.messages()) == 2 }, time.Second, time.Millisecond)
	require.Equal(t, first.messages()[1].GetBatch().ProducerSessionId, second.messages()[1].GetBatch().ProducerSessionId)
	require.Equal(t, first.messages()[1].GetBatch().BatchSequence, second.messages()[1].GetBatch().BatchSequence)
	second.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: 1}
	require.Eventually(t, func() bool { return len(spool.Batches()) == 0 }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeSendFailureCancelsBlockedControlDelivery(t *testing.T) {
	client, _ := newTestClient(t)
	_, err := client.Enqueue(ingressBatch(1))
	require.NoError(t, err)

	receiverExited := make(chan struct{})
	client.controlReceiverExited = func() { close(receiverExited) }
	stream := &blockedControlStream{
		recvBlocked:  make(chan struct{}),
		canceled:     make(chan struct{}),
		batchSendErr: errors.New("send failed"),
	}

	err = client.Serve(context.Background(), stream, func() { close(stream.canceled) })
	require.ErrorContains(t, err, "serve event forwarding: send batch 1: send failed")
	select {
	case <-receiverExited:
	case <-time.After(time.Second):
		t.Fatal("control receiver did not exit after Serve returned")
	}
}

func TestServeRejectsLateBatchBelowSentHighWater(t *testing.T) {
	client, spool := newTestClient(t)
	result, err := client.Enqueue(ingressBatch(2))
	require.NoError(t, err)
	require.True(t, result.Stored)

	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 1)}
	stream.controls <- &eventsv1.EventIngressControl{
		Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
	require.Eventually(t, func() bool { return len(stream.messages()) == 2 }, time.Second, time.Millisecond)
	require.Equal(t, uint64(2), stream.messages()[1].GetBatch().GetBatchSequence())

	result, err = client.Enqueue(ingressBatch(1))
	require.ErrorContains(t, err, "does not advance committed high-water mark 2")
	require.False(t, result.Stored)
	require.Len(t, spool.Batches(), 1)
	require.Never(t, func() bool { return len(stream.messages()) > 2 }, 25*time.Millisecond, time.Millisecond)

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
	go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
	require.Eventually(t, func() bool { return len(stream.messages()) == 2 }, time.Second, time.Millisecond)
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK, NackBatchRanges: []*eventsv1.SequenceRange{{First: 1, Last: 1}}}
	require.Eventually(t, func() bool { return len(stream.messages()) == 3 }, time.Second, time.Millisecond)
	require.Equal(t, uint64(1), stream.messages()[2].GetBatch().BatchSequence)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestHandleControlAcceptsCumulativeAckFromPreviousStream(t *testing.T) {
	client, spool := newTestClient(t)
	for sequence := uint64(1); sequence <= 3; sequence++ {
		result, err := client.Enqueue(ingressBatch(sequence))
		require.NoError(t, err)
		require.True(t, result.Stored)
	}

	// On reconnect, the receiver can deduplicate the first retransmission and
	// cumulatively ACK later batches that it durably admitted on the old stream.
	_, highest, rewind, err := client.handleControl(context.Background(), controlResult{control: &eventsv1.EventIngressControl{
		Kind:                  eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK,
		CumulativeAckSequence: 3,
	}}, false, 1)
	require.NoError(t, err)
	require.Equal(t, uint64(1), highest)
	require.False(t, rewind)
	require.Empty(t, spool.Batches())
}

func TestHandleControlRejectsMalformedNackRanges(t *testing.T) {
	client, _ := newTestClient(t)
	tests := []struct {
		name   string
		ranges []*eventsv1.SequenceRange
	}{
		{name: "nil", ranges: []*eventsv1.SequenceRange{nil}},
		{name: "zero", ranges: []*eventsv1.SequenceRange{{First: 0, Last: 1}}},
		{name: "inverted", ranges: []*eventsv1.SequenceRange{{First: 3, Last: 2}}},
		{name: "unsent", ranges: []*eventsv1.SequenceRange{{First: 4, Last: 4}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, highest, rewind, err := client.handleControl(context.Background(), controlResult{control: &eventsv1.EventIngressControl{
				Kind:            eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK,
				NackBatchRanges: tt.ranges,
			}}, false, 3)
			require.ErrorContains(t, err, "invalid NACK batch ranges")
			require.Equal(t, uint64(3), highest)
			require.False(t, rewind)
		})
	}
}

func TestHandleControlAcceptsUnorderedOverlappingNackRanges(t *testing.T) {
	client, _ := newTestClient(t)
	_, highest, rewind, err := client.handleControl(context.Background(), controlResult{control: &eventsv1.EventIngressControl{
		Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_NACK,
		NackBatchRanges: []*eventsv1.SequenceRange{
			{First: 3, Last: 3},
			{First: 1, Last: 2},
			{First: 2, Last: 3},
		},
	}}, false, 3)
	require.NoError(t, err)
	require.Equal(t, uint64(0), highest)
	require.True(t, rewind)
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
	go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
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
			go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
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
	go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
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

func TestServePauseDropOldestEvictResumeSkipsCachedVictimWithLossCoverage(t *testing.T) {
	calibration, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	for sequence := uint64(1); sequence <= 3; sequence++ {
		result, enqueueErr := calibration.Enqueue(ingressBatch(sequence))
		require.NoError(t, enqueueErr)
		require.True(t, result.Stored)
	}
	maxBytes := calibration.Bytes()
	require.NoError(t, calibration.Close())

	spool, err := eventspool.Open(eventspool.Config{
		Directory: t.TempDir(),
		MaxBytes:  maxBytes,
		Policy:    eventspool.DropOldest,
	})
	require.NoError(t, err)
	client, err := New(Config{
		SourceNodeID:      "hunter",
		ProducerSessionID: "session",
		Profile:           eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	}, spool)
	require.NoError(t, err)
	for sequence := uint64(1); sequence <= 3; sequence++ {
		result, enqueueErr := client.Enqueue(ingressBatch(sequence))
		require.NoError(t, enqueueErr)
		require.True(t, result.Stored)
	}

	firstSelected := make(chan struct{})
	releaseFirst := make(chan struct{})
	controlQueued := make(chan struct{}, 2)
	client.controlReceived = func() { controlQueued <- struct{}{} }
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 2)}
	stream.onSend = func(message *eventsv1.EventIngressMessage) {
		if message.GetBatch().GetBatchSequence() == 1 {
			close(firstSelected)
			<-releaseFirst
		}
	}
	stream.controls <- &eventsv1.EventIngressControl{
		Kind:            eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED,
		AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
	select {
	case <-firstSelected:
	case <-time.After(time.Second):
		t.Fatal("first batch was not selected")
	}
	stream.controls <- &eventsv1.EventIngressControl{
		Kind:        eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_FLOW,
		FlowControl: int32(data.FlowControl_FLOW_PAUSE),
	}
	select {
	case <-controlQueued:
	case <-time.After(time.Second):
		t.Fatal("pause was not queued for Serve")
	}
	close(releaseFirst)
	require.Eventually(t, func() bool { return len(stream.messages()) == 2 }, time.Second, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	require.Len(t, stream.messages(), 2, "pause may overshoot by only the selected batch")

	// Force actual drop-oldest replacement while batches 2 and 3 are cached.
	// Continue only until cached batch 2 is a committed victim.
	for sequence := uint64(4); spool.IsActive("hunter", "session", 2); sequence++ {
		result, enqueueErr := client.Enqueue(ingressBatch(sequence))
		require.NoError(t, enqueueErr)
		require.True(t, result.Stored)
		require.Less(t, sequence, uint64(10), "bounded spool should evict cached batch 2 promptly")
	}
	require.False(t, spool.IsActive("hunter", "session", 2))

	active := spool.Batches()
	expected := make([]uint64, 0, len(active))
	coveredVictim := false
	for _, activeBatch := range active {
		require.NoError(t, protoadapter.ValidateBatch(activeBatch))
		if activeBatch.GetBatchSequence() > 1 {
			expected = append(expected, activeBatch.GetBatchSequence())
		}
		for _, loss := range activeBatch.GetStats().GetLosses() {
			for _, eventRange := range loss.GetEventSequenceRanges() {
				if eventRange.GetFirst() <= 2 && eventRange.GetLast() >= 2 {
					coveredVictim = true
				}
			}
		}
	}
	require.True(t, coveredVictim, "a surviving replacement must report the evicted cached batch's coverage")

	stream.controls <- &eventsv1.EventIngressControl{
		Kind:        eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_FLOW,
		FlowControl: int32(data.FlowControl_FLOW_RESUME),
	}
	select {
	case <-controlQueued:
	case <-time.After(time.Second):
		t.Fatal("resume was not queued for Serve")
	}
	require.Eventually(t, func() bool { return len(stream.messages()) == len(expected)+2 }, time.Second, time.Millisecond)
	got := make([]uint64, 0, len(expected))
	for _, message := range stream.messages()[2:] {
		batch := message.GetBatch()
		require.NoError(t, protoadapter.ValidateBatch(batch))
		got = append(got, batch.GetBatchSequence())
	}
	require.Equal(t, expected, got)
	require.NotContains(t, got, uint64(2))
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
	go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
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
	go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
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

func TestServeRefillsAfterEntireCachedSuffixRemoved(t *testing.T) {
	client, spool := newTestClient(t)
	for sequence := uint64(1); sequence <= batchFetchLimit+1; sequence++ {
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
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
	select {
	case <-firstSelected:
	case <-time.After(time.Second):
		t.Fatal("first batch was not selected")
	}

	// Retire the entire cached window while the first send is in flight. The
	// next window remains pending and must not require another enqueue wake.
	require.NoError(t, spool.Ack("hunter", "session", batchFetchLimit))
	close(releaseFirst)
	require.Eventually(t, func() bool {
		for _, message := range stream.messages()[1:] {
			if message.GetBatch().GetBatchSequence() == batchFetchLimit+1 {
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	sequences := make([]uint64, 0, 2)
	for _, message := range stream.messages()[1:] {
		sequences = append(sequences, message.GetBatch().GetBatchSequence())
	}
	require.Equal(t, []uint64{1, batchFetchLimit + 1}, sequences)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeRejectsProfileDowngrade(t *testing.T) {
	client, _ := newTestClient(t)
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 1)}
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY}
	err := client.Serve(context.Background(), stream, fakeStreamCancel(stream))
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

func TestServeDrainsRecoveredFinalBatchSequence(t *testing.T) {
	dir := t.TempDir()
	spool, err := eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "hunter", ProducerSessionID: "session", Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}, spool)
	require.NoError(t, err)
	result, err := client.Enqueue(ingressBatch(^uint64(0)))
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.NoError(t, spool.Close())

	recovered, err := eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recovered.Close()) })
	recoveredClient, err := New(Config{SourceNodeID: "hunter", ProducerSessionID: "session", Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}, recovered)
	require.NoError(t, err)
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 2)}
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}
	stream.onSend = func(message *eventsv1.EventIngressMessage) {
		if message.GetBatch().GetBatchSequence() == ^uint64(0) {
			stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, CumulativeAckSequence: ^uint64(0)}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- recoveredClient.Serve(ctx, stream, fakeStreamCancel(stream)) }()
	require.Eventually(t, func() bool { return !recovered.HasPending() }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
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
			var syncs, checkpoints, rotations float64
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
				go func() { done <- client.Serve(ctx, stream, fakeStreamCancel(stream)) }()
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
				syncs += float64(metrics.Syncs)
				checkpoints += float64(metrics.Checkpoints)
				rotations += float64(metrics.Rotations)
				cancel()
				require.ErrorIs(b, <-done, context.Canceled)
				require.NoError(b, spool.Close())
			}
			b.ReportMetric(syncs/float64(b.N), "syncs/op")
			b.ReportMetric(checkpoints/float64(b.N), "checkpoints/op")
			b.ReportMetric(rotations/float64(b.N), "rotations/op")
		})
	}
}

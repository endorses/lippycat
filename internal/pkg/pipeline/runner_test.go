package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type recordingPacketSink struct {
	mu         sync.Mutex
	name       string
	order      *[]string
	sequences  []uint64
	result     Result
	closeErr   error
	closeCount int
}

func (s *recordingPacketSink) HandlePacket(_ context.Context, envelope *PacketEnvelope) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequences = append(s.sequences, envelope.Source.BatchSequence)
	if s.order != nil {
		*s.order = append(*s.order, s.name)
	}
	return s.result
}

func (s *recordingPacketSink) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeCount++
	if s.order != nil {
		*s.order = append(*s.order, "close:"+s.name)
	}
	return s.closeErr
}

func TestPacketFanoutPreservesRegistrationOrderAndOutcomes(t *testing.T) {
	order := make([]string, 0, 2)
	first := &recordingPacketSink{name: "first", order: &order, result: Result{Outcome: OutcomeAccepted}}
	second := &recordingPacketSink{name: "second", order: &order, result: Result{Outcome: OutcomeDropped, DropReason: DropQueueFull}}
	fanout, err := NewPacketFanout(
		SinkRegistration{Name: "cli", Sink: first},
		SinkRegistration{Name: "pcap", Sink: second},
	)
	require.NoError(t, err)

	results := fanout.Dispatch(context.Background(), &PacketEnvelope{})
	require.Equal(t, []string{"first", "second"}, order)
	require.Equal(t, []SinkResult{
		{Name: "cli", Result: Result{Outcome: OutcomeAccepted}},
		{Name: "pcap", Result: Result{Outcome: OutcomeDropped, DropReason: DropQueueFull}},
	}, results)
}

func TestPacketFanoutAttributesOutcomeAndDropMetricsBySink(t *testing.T) {
	accepted := &recordingPacketSink{result: Result{Outcome: OutcomeAccepted}}
	dropped := &recordingPacketSink{result: Result{Outcome: OutcomeDropped, DropReason: DropQueueFull}}
	consumer, err := NewPacketFanout(
		SinkRegistration{Name: "cli", Sink: accepted},
		SinkRegistration{Name: "virtual-interface", Sink: dropped},
	)
	require.NoError(t, err)

	consumer.Dispatch(context.Background(), &PacketEnvelope{})
	consumer.Dispatch(context.Background(), &PacketEnvelope{})

	metrics := consumer.Metrics()
	require.Equal(t, uint64(2), metrics["cli"].Outcomes[OutcomeAccepted])
	require.Empty(t, metrics["cli"].Drops)
	require.Equal(t, uint64(2), metrics["virtual-interface"].Outcomes[OutcomeDropped])
	require.Equal(t, uint64(2), metrics["virtual-interface"].Drops[DropQueueFull])
}

func TestPacketFanoutAttributesCancellationBySink(t *testing.T) {
	sink := &recordingPacketSink{}
	consumer, err := NewPacketFanout(SinkRegistration{Name: "writer", Sink: sink})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	consumer.Dispatch(ctx, &PacketEnvelope{})

	metrics := consumer.Metrics()["writer"]
	require.Equal(t, uint64(1), metrics.Outcomes[OutcomeShutdown])
	require.Equal(t, uint64(1), metrics.Drops[DropShutdown])
}

func TestEnvelopeRunnerPreservesPacketOrderAndReportsErrors(t *testing.T) {
	deliveryErr := errors.New("writer unavailable")
	sink := &recordingPacketSink{result: Result{Outcome: OutcomeRetryableFailure, Err: deliveryErr}}
	fanout, err := NewPacketFanout(SinkRegistration{Name: "writer", Sink: sink})
	require.NoError(t, err)
	input := make(chan *PacketEnvelope, 3)
	for i := uint64(1); i <= 3; i++ {
		input <- &PacketEnvelope{Source: SourceProvenance{BatchSequence: i}}
	}
	close(input)

	var observed []uint64
	runner := EnvelopeRunner{Fanout: fanout, Outcome: func(envelope *PacketEnvelope, _ []SinkResult) {
		observed = append(observed, envelope.Source.BatchSequence)
	}}
	runErr := runner.Run(context.Background(), input)
	require.ErrorIs(t, runErr, deliveryErr)
	require.Equal(t, []uint64{1, 2, 3}, sink.sequences)
	require.Equal(t, []uint64{1, 2, 3}, observed)
}

func TestPacketFanoutCloseIsIdempotentAndReverseOrdered(t *testing.T) {
	order := make([]string, 0, 2)
	closeErr := errors.New("close failed")
	first := &recordingPacketSink{name: "first", order: &order}
	second := &recordingPacketSink{name: "second", order: &order, closeErr: closeErr}
	fanout, err := NewPacketFanout(
		SinkRegistration{Name: "first", Sink: first},
		SinkRegistration{Name: "second", Sink: second},
	)
	require.NoError(t, err)

	require.ErrorIs(t, fanout.Close(context.Background()), closeErr)
	require.ErrorIs(t, fanout.Close(context.Background()), closeErr)
	require.Equal(t, []string{"close:second", "close:first"}, order)
	require.Equal(t, 1, first.closeCount)
	require.Equal(t, 1, second.closeCount)
	require.Equal(t, OutcomeShutdown, fanout.Dispatch(context.Background(), &PacketEnvelope{})[0].Result.Outcome)
}

func TestEnvelopeRunnerStopsOnCancellation(t *testing.T) {
	fanout, err := NewPacketFanout()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = (EnvelopeRunner{Fanout: fanout}).Run(ctx, make(chan *PacketEnvelope))
	require.ErrorIs(t, err, context.Canceled)
}

func TestNewPacketFanoutRejectsInvalidRegistrations(t *testing.T) {
	sink := &recordingPacketSink{}
	_, err := NewPacketFanout(SinkRegistration{Sink: sink})
	require.Error(t, err)
	_, err = NewPacketFanout(SinkRegistration{Name: "sink"})
	require.Error(t, err)
	_, err = NewPacketFanout(
		SinkRegistration{Name: "sink", Sink: sink},
		SinkRegistration{Name: "sink", Sink: sink},
	)
	require.Error(t, err)
}

func TestEnvelopeRunnerEmptyInputReturnsPromptly(t *testing.T) {
	fanout, err := NewPacketFanout()
	require.NoError(t, err)
	input := make(chan *PacketEnvelope)
	close(input)
	done := make(chan error, 1)
	go func() { done <- (EnvelopeRunner{Fanout: fanout}).Run(context.Background(), input) }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("runner did not return after input closed")
	}
}

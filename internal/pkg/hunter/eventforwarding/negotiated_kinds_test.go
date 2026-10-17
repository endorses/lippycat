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

func negotiatedNTP(producer *events.Producer) events.Event {
	env := events.Envelope{Timestamp: time.Unix(1000, 0), NodeID: "sensor", CaptureScope: events.CaptureScopeFull, Flow: events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 1234, DestinationPort: 123}}
	e := events.NewNTPEvent(env)
	e.Version = 4
	e.Mode = 3
	e.Association = events.AssociationRequest
	return producer.Assign(e)
}

func TestNegotiatedOptionalOmissionSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	spool, err := eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	producer, err := events.NewLiveProducer("sensor")
	require.NoError(t, err)
	config := Config{SourceNodeID: "sensor", ProducerSessionID: producer.SessionID(), EventKinds: protoadapter.SupportedKinds(false)}
	client, err := New(config, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	require.NoError(t, client.SetAcceptedKinds([]eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}))
	omitted := negotiatedNTP(producer)
	require.NoError(t, sink.HandleEvent(context.Background(), omitted))
	require.True(t, spool.HasPendingLosses())
	require.Empty(t, spool.Batches())
	require.NoError(t, spool.Close())
	spool, err = eventspool.Open(eventspool.Config{Directory: dir})
	require.NoError(t, err)
	defer func() { require.NoError(t, spool.Close()) }()
	client, err = New(config, spool)
	require.NoError(t, err)
	require.NoError(t, client.SetAcceptedKinds([]eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}))
	sink, err = NewSink(client, 1, 1)
	require.NoError(t, err)
	env := omitted.Envelope()
	env.EventID = ""
	env.EventSequence = 0
	env.ProducerSessionID = ""
	dns := producer.Assign(events.NewDNSEvent(env))
	require.NoError(t, sink.HandleEvent(context.Background(), dns))
	batches := spool.Batches()
	require.Len(t, batches, 1)
	require.Len(t, batches[0].Events, 1)
	require.NotNil(t, batches[0].Events[0].GetDns())
	losses := batches[0].Stats.Losses
	require.Len(t, losses, 1)
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, losses[0].Kind)
	require.Equal(t, uint64(1), losses[0].Count)
	require.Equal(t, omitted.Envelope().EventSequence, losses[0].EventSequenceRanges[0].First)
	require.Equal(t, omitted.Envelope().EventSequence, losses[0].EventSequenceRanges[0].Last)
	require.NoError(t, protoadapter.ValidateBatch(batches[0]))
}

func TestNegotiatedDowngradePreservesUnacknowledgedIdentity(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	defer func() { require.NoError(t, spool.Close()) }()
	producer, err := events.NewLiveProducer("sensor")
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "sensor", ProducerSessionID: producer.SessionID(), EventKinds: protoadapter.SupportedKinds(false)}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	e := negotiatedNTP(producer)
	_, encodeErr := protoadapter.ToProto(e)
	require.NoError(t, encodeErr)
	require.NoError(t, sink.HandleEvent(context.Background(), e))
	before := spool.Batches()
	require.ErrorContains(t, client.SetAcceptedKinds([]eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}), "unacknowledged event kind")
	require.Equal(t, before, spool.Batches())
	require.NoError(t, client.SetAcceptedKinds(protoadapter.SupportedKinds(false)))
	require.NoError(t, spool.Ack("sensor", producer.SessionID(), before[0].BatchSequence))
	require.NoError(t, client.SetAcceptedKinds([]eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}))
}

func TestRejectedCandidateDoesNotChangeProducerKinds(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	defer func() { require.NoError(t, spool.Close()) }()
	producer, err := events.NewLiveProducer("sensor")
	require.NoError(t, err)
	client, err := New(Config{SourceNodeID: "sensor", ProducerSessionID: producer.SessionID(), EventKinds: protoadapter.SupportedKinds(false)}, spool)
	require.NoError(t, err)
	candidateKinds := []eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 1)}
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}
	rejected := errors.New("candidate policy setup failed")
	require.ErrorIs(t, client.ServeNegotiated(context.Background(), stream, fakeStreamCancel(stream), candidateKinds, func() error { return rejected }), rejected)
	require.Len(t, stream.messages(), 1, "tentative peer must receive only its open, no captured data")
	require.Equal(t, candidateKinds, stream.messages()[0].GetOpen().GetEventKinds())
	require.False(t, client.negotiated)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	require.NoError(t, sink.HandleEvent(context.Background(), negotiatedNTP(producer)))
	require.Len(t, spool.Batches(), 1)
	require.NotNil(t, spool.Batches()[0].Events[0].GetNtp(), "failed peer must not cause optional events to become omissions")
	before := spool.Batches()
	require.ErrorContains(t, client.ValidateAcceptedKinds(candidateKinds), "unacknowledged event kind")
	require.Equal(t, before, spool.Batches(), "validation must not rewrite or retire pending identities")
}

func TestNegotiatedCandidateWaitsForOwnerCommitBeforeReplay(t *testing.T) {
	client, spool := newTestClient(t)
	defer func() { require.NoError(t, spool.Close()) }()
	_, err := client.Enqueue(ingressBatch(1))
	require.NoError(t, err)
	stream := &fakeStream{controls: make(chan *eventsv1.EventIngressControl, 1)}
	stream.controls <- &eventsv1.EventIngressControl{Kind: eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED, AcceptedProfile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}
	candidateKinds := []eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}
	ready, commit := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.ServeNegotiated(ctx, stream, fakeStreamCancel(stream), candidateKinds, func() error {
			close(ready)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-commit:
			}
			return client.SetAcceptedKinds(candidateKinds)
		})
	}()
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("acceptance callback not reached")
	}
	require.Len(t, stream.messages(), 1)
	require.Len(t, spool.Batches(), 1)
	require.False(t, client.negotiated)
	close(commit)
	require.Eventually(t, func() bool { return len(stream.messages()) == 2 }, time.Second, time.Millisecond)
	require.Equal(t, "session", stream.messages()[1].GetBatch().ProducerSessionId)
	require.Equal(t, uint64(1), stream.messages()[1].GetBatch().BatchSequence)
	require.Len(t, spool.Batches(), 1, "transport send is not an acknowledgement")
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeNegotiatedRequiresCancellationAndCommit(t *testing.T) {
	client, spool := newTestClient(t)
	defer func() { require.NoError(t, spool.Close()) }()
	require.ErrorContains(t, client.ServeNegotiated(context.Background(), nil, nil, nil, nil), "stream cancel")
	canceled := false
	require.ErrorContains(t, client.ServeNegotiated(context.Background(), nil, func() { canceled = true }, nil, nil), "acceptance callback")
	require.True(t, canceled)
}

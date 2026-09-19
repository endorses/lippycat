//go:build processor || tap || all

package processor

import (
	"context"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
)

func carrierRegressionIngress(t *testing.T) *eventIngress {
	t.Helper()
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 16})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, dispatcher.Close(context.Background())) })
	ingress, err := newEventIngress(EventIngressPolicy{Dispatcher: dispatcher, Profile: "memory_only"})
	require.NoError(t, err)
	return ingress
}

func admitCarrierRegressionBatch(t *testing.T, ingress *eventIngress, spool *eventspool.Spool, batch *eventsv1.ProtocolEventBatch) {
	t.Helper()
	open := &eventsv1.EventIngressOpen{SourceNodeId: batch.SourceNodeId, ProducerSessionId: batch.ProducerSessionId, SemanticProfileRevision: 1}
	control, err := ingress.admit(context.Background(), ingressKey(batch.SourceNodeId, batch.ProducerSessionId), open, nil, batch)
	require.NoError(t, err)
	require.Equal(t, eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, control.GetKind())
	require.Equal(t, batch.BatchSequence, control.GetCumulativeAckSequence())
	require.NoError(t, spool.Ack(batch.SourceNodeId, batch.ProducerSessionId, control.GetCumulativeAckSequence()))
}

func TestEventSpoolMixedKindCarriersAdmittedAcrossFlushes(t *testing.T) {
	ingress := carrierRegressionIngress(t)
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spool.Close()) })
	first := ingressBatch(t, 1, 1)
	result, err := spool.Enqueue(first)
	require.NoError(t, err)
	require.True(t, result.Stored)
	admitCarrierRegressionBatch(t, ingress, spool, first)

	// Each kind has disjoint ranges interleaved with the other kind. The
	// combined 4,200 ranges exceed the carrier's collection budget.
	losses := []*eventsv1.EventLoss{
		{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, SourceNodeId: first.SourceNodeId, ProducerSessionId: first.ProducerSessionId},
		{Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, SourceNodeId: first.SourceNodeId, ProducerSessionId: first.ProducerSessionId},
	}
	for sequence := uint64(2); sequence <= 4201; sequence++ {
		loss := losses[sequence%2]
		loss.Count++
		loss.EventSequenceRanges = append(loss.EventSequenceRanges, &eventsv1.SequenceRange{First: sequence, Last: sequence})
	}
	_, err = spool.RetainLosses(losses)
	require.NoError(t, err)
	flushes := 0
	for spool.HasPendingLosses() {
		require.Less(t, flushes, 10, "loss flushing must make bounded progress")
		result, err = spool.FlushPendingLosses(first.SourceNodeId, first.ProducerSessionId, uint64(flushes+2), 1)
		require.NoError(t, err)
		require.True(t, result.Stored)
		batches := spool.Batches()
		require.Len(t, batches, 1)
		admitCarrierRegressionBatch(t, ingress, spool, batches[0])
		flushes++
	}
	require.Greater(t, flushes, 1)
	require.Equal(t, uint64(4201), ingress.sessions[ingressKey(first.SourceNodeId, first.ProducerSessionId)].event)
	require.False(t, spool.HasPending())
}

func TestEventSpoolDropOldestCarrierPreservesEarlierEventCoverage(t *testing.T) {
	ingress := carrierRegressionIngress(t)
	now := time.Unix(100, 0)
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir(), Policy: eventspool.DropOldest, MaxAge: time.Second, Clock: func() time.Time { return now }})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spool.Close()) })
	first := ingressBatch(t, 1, 1)
	result, err := spool.Enqueue(first)
	require.NoError(t, err)
	require.True(t, result.Stored)
	admitCarrierRegressionBatch(t, ingress, spool, first)
	second := ingressBatch(t, 2, 2)
	result, err = spool.Enqueue(second)
	require.NoError(t, err)
	require.True(t, result.Stored)
	_, err = spool.RetainLosses([]*eventsv1.EventLoss{
		{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1, SourceNodeId: first.SourceNodeId, ProducerSessionId: first.ProducerSessionId, EventSequenceRanges: []*eventsv1.SequenceRange{{First: 3, Last: 3}}},
		{Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, Count: 1, SourceNodeId: first.SourceNodeId, ProducerSessionId: first.ProducerSessionId, EventSequenceRanges: []*eventsv1.SequenceRange{{First: 4, Last: 4}}},
	})
	require.NoError(t, err)
	now = now.Add(2 * time.Second)
	result, err = spool.FlushPendingLosses(first.SourceNodeId, first.ProducerSessionId, 3, 1)
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.False(t, spool.Contains(first.SourceNodeId, first.ProducerSessionId, 2))
	for _, batch := range spool.Batches() {
		admitCarrierRegressionBatch(t, ingress, spool, batch)
	}
	require.Equal(t, uint64(4), ingress.sessions[ingressKey(first.SourceNodeId, first.ProducerSessionId)].event)
	require.False(t, spool.HasPending(), "evicted event coverage must travel in the carrier that advances ingress")
}

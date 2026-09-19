package eventforwarding

import (
	"context"
	"testing"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
)

func TestSinkFlushPreservesLocalLossWhenDurableCoverageNeedsCarrier(t *testing.T) {
	spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spool.Close()) })
	client, err := New(Config{SourceNodeID: "hunter-a", ProducerSessionID: "session-a"}, spool)
	require.NoError(t, err)
	sink, err := NewSink(client, 1, 1)
	require.NoError(t, err)
	losses := []*eventsv1.EventLoss{
		{Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, SourceNodeId: "hunter-a", ProducerSessionId: "session-a"},
		{Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, SourceNodeId: "hunter-a", ProducerSessionId: "session-a"},
	}
	for sequence := uint64(1); sequence <= protoadapter.MaxCollectionEntries; sequence++ {
		loss := losses[(sequence+1)%2]
		loss.Count++
		loss.EventSequenceRanges = append(loss.EventSequenceRanges, &eventsv1.SequenceRange{First: sequence, Last: sequence})
	}
	retention, err := spool.RetainLosses(losses)
	require.NoError(t, err)
	require.True(t, retention.Committed)
	const localSequence = uint64(protoadapter.MaxCollectionEntries + 1)
	sink.pendingLosses = []*eventsv1.EventLoss{{
		Kind: eventsv1.LossKind_LOSS_KIND_TRANSPORT, Count: 1,
		SourceNodeId: "hunter-a", ProducerSessionId: "session-a",
		EventSequenceRanges: []*eventsv1.SequenceRange{{First: localSequence, Last: localSequence}},
	}}
	require.NoError(t, sink.Flush(context.Background()))
	covered := make(map[uint64]bool)
	for _, batch := range spool.Batches() {
		require.NoError(t, protoadapter.ValidateBatch(batch))
		for _, loss := range batch.GetStats().GetLosses() {
			for _, r := range loss.GetEventSequenceRanges() {
				for sequence := r.First; sequence <= r.Last; sequence++ {
					require.False(t, covered[sequence], "duplicate sequence %d", sequence)
					covered[sequence] = true
				}
			}
		}
	}
	require.True(t, covered[localSequence], "local loss must survive durable carrier overflow")
	require.Len(t, covered, int(localSequence))
	require.Empty(t, sink.pendingLosses)
	require.False(t, spool.HasPendingLosses())
}

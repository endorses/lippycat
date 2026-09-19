//go:build processor || tap || all

package processor

import (
	"context"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventforwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
)

func TestEventIngressAcceptsQueuedEventsBeforeObservedLaterDrop(t *testing.T) {
	for _, profile := range []string{"memory_only", "reliable"} {
		t.Run(profile, func(t *testing.T) {
			ctx := context.Background()
			dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 8, SinkQueueSize: 8})
			require.NoError(t, err)
			broadcaster := broadcast.New()
			require.NoError(t, dispatcher.Register(broadcaster))
			require.NoError(t, dispatcher.Start(ctx))
			t.Cleanup(func() { require.NoError(t, dispatcher.Close(ctx)) })
			ingress, err := newEventIngress(EventIngressPolicy{Dispatcher: dispatcher, Profile: profile, WALDirectory: t.TempDir()})
			require.NoError(t, err)
			if ingress.wal != nil {
				t.Cleanup(func() { require.NoError(t, ingress.wal.close()) })
			}
			spool, err := eventspool.Open(eventspool.Config{Directory: t.TempDir()})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, spool.Close()) })
			var assigned []events.Event
			for sequence := uint64(1); sequence <= 3; sequence++ {
				decoded, _, err := protoadapter.DecodeBatch(ingressBatch(t, sequence, sequence))
				require.NoError(t, err)
				assigned = append(assigned, decoded[0])
			}
			envelope := assigned[0].Envelope()
			client, err := eventforwarding.New(eventforwarding.Config{SourceNodeID: envelope.NodeID, ProducerSessionID: envelope.ProducerSessionID}, spool)
			require.NoError(t, err)
			sink, err := eventforwarding.NewSink(client, 1, 1)
			require.NoError(t, err)
			// Queue overflow can notify the observer before the sink worker
			// handles earlier items already buffered in its queue.
			sink.LockDropBoundary()
			sink.HandleDroppedEventLocked(assigned[2], time.Now())
			sink.UnlockDropBoundary()
			require.NoError(t, sink.HandleEvent(ctx, assigned[0]))
			require.NoError(t, sink.HandleEvent(ctx, assigned[1]))
			require.NoError(t, sink.Flush(ctx))
			open := &eventsv1.EventIngressOpen{SourceNodeId: envelope.NodeID, ProducerSessionId: envelope.ProducerSessionID, SemanticProfileRevision: 1}
			key := ingressKey(open.SourceNodeId, open.ProducerSessionId)
			for _, batch := range spool.Batches() {
				control, err := ingress.admit(ctx, key, open, nil, batch)
				require.NoError(t, err)
				require.Equal(t, eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, control.Kind)
				require.NoError(t, spool.Ack(open.SourceNodeId, open.ProducerSessionId, control.CumulativeAckSequence))
			}
			require.False(t, spool.HasPending())
			require.Equal(t, uint64(3), ingress.sessions[key].event)
			require.Eventually(t, func() bool { return broadcaster.Stats().Published == 2 }, time.Second, time.Millisecond)
		})
	}
}

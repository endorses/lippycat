//go:build processor || tap || all

package processor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/endorses/lippycat/internal/pkg/processor/upstream"
	"github.com/stretchr/testify/require"
)

func TestEventIngressAcceptsUpstreamQueueLossBeforeRouteCreation(t *testing.T) {
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

			var assigned []events.Event
			for sequence := uint64(1); sequence <= 4; sequence++ {
				decoded, _, err := protoadapter.DecodeBatch(ingressBatch(t, sequence, sequence))
				require.NoError(t, err)
				assigned = append(assigned, decoded[0])
			}
			dir := t.TempDir()
			manager := upstream.NewManager(upstream.Config{ForwardMode: "events"}, nil)
			t.Cleanup(manager.Disconnect)
			router, err := upstream.NewEventRouter(manager, upstream.EventRouterConfig{SpoolDirectory: dir})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, router.Close(ctx)) })
			observer, ok := any(router).(interface {
				LockDropBoundary()
				HandleDroppedEventLocked(events.Event, time.Time)
				UnlockDropBoundary()
			})
			require.True(t, ok, "upstream router must observe dispatcher queue drops")
			// An overflow notification may precede handling of every older
			// buffered event, including the event that creates this route.
			observer.LockDropBoundary()
			observer.HandleDroppedEventLocked(assigned[2], time.Now())
			observer.UnlockDropBoundary()
			for _, index := range []int{0, 1, 3} {
				require.NoError(t, router.HandleEvent(ctx, assigned[index]))
			}
			require.NoError(t, router.Flush(ctx))
			require.Equal(t, uint64(1), router.Losses().Transport)
			require.NoError(t, router.Close(ctx))

			// Reopen the real route spool to verify that exact coverage survives
			// shutdown and remains admissible by either receiver profile.
			routeDirs, err := filepath.Glob(filepath.Join(dir, "*", "*"))
			require.NoError(t, err)
			require.Len(t, routeDirs, 1)
			spool, err := eventspool.Open(eventspool.Config{Directory: routeDirs[0]})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, spool.Close()) })
			envelope := assigned[0].Envelope()
			open := &eventsv1.EventIngressOpen{SourceNodeId: envelope.NodeID, ProducerSessionId: envelope.ProducerSessionID, SemanticProfileRevision: 1}
			key := ingressKey(open.SourceNodeId, open.ProducerSessionId)
			var received []uint64
			var losses []*eventsv1.SequenceRange
			for _, batch := range spool.Batches() {
				for _, event := range batch.Events {
					received = append(received, event.EventSequence)
				}
				for _, loss := range batch.GetStats().GetLosses() {
					require.Equal(t, eventsv1.LossKind_LOSS_KIND_TRANSPORT, loss.Kind)
					losses = append(losses, loss.EventSequenceRanges...)
				}
				control, err := ingress.admit(ctx, key, open, nil, batch)
				require.NoError(t, err)
				require.Equal(t, eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, control.Kind)
				require.Equal(t, batch.BatchSequence, control.CumulativeAckSequence)
				require.NoError(t, spool.Ack(open.SourceNodeId, open.ProducerSessionId, control.CumulativeAckSequence))
			}
			require.Equal(t, []uint64{1, 2, 4}, received)
			require.Len(t, losses, 1)
			require.Equal(t, uint64(3), losses[0].First)
			require.Equal(t, uint64(3), losses[0].Last)
			require.False(t, spool.HasPending())
			require.Equal(t, uint64(4), ingress.sessions[key].event)
			require.Eventually(t, func() bool { return broadcaster.Stats().Published == 3 }, time.Second, time.Millisecond)
		})
	}
}

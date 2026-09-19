package upstream

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
)

type routerDropObserver interface {
	LockDropBoundary()
	HandleDroppedEventLocked(events.Event, time.Time)
	UnlockDropBoundary()
}

func TestEventRouterPreservesDispatcherDropsBeforeOlderEvents(t *testing.T) {
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: t.TempDir(), Policy: eventspool.DropOldest})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })
	observer, ok := any(router).(routerDropObserver)
	require.True(t, ok, "the registered router must observe dispatcher queue losses")
	const node, session = "tap-node", "30313233343536373839616263646566"
	observer.LockDropBoundary()
	observer.HandleDroppedEventLocked(routedDNS(node, session, 4), time.Now())
	observer.HandleDroppedEventLocked(routedDNS(node, session, 3), time.Now())
	observer.UnlockDropBoundary()
	require.Empty(t, router.routes, "drop callbacks must not open spools")
	require.True(t, router.HasPendingDurableBatches(), "packet fallback must not strand buffered loss reports")
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS(node, session, 1)))
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS(node, session, 2)))
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS(node, session, 5)))
	batches := router.routes[eventRouteKey{node, session}].spool.Batches()
	require.Len(t, batches, 3)
	require.Empty(t, batches[0].GetStats().GetLosses())
	require.Empty(t, batches[1].GetStats().GetLosses())
	losses := batches[2].GetStats().GetLosses()
	require.Len(t, losses, 1)
	require.Equal(t, uint64(2), losses[0].Count)
	require.Equal(t, uint64(3), losses[0].EventSequenceRanges[0].First)
	require.Equal(t, uint64(4), losses[0].EventSequenceRanges[0].Last)
	require.Equal(t, uint64(2), router.Losses().Transport)
}

func TestEventRouterFlushPersistsDropsWithoutAnExistingRoute(t *testing.T) {
	router, err := NewEventRouter(NewManager(Config{ForwardMode: "events"}, nil), EventRouterConfig{SpoolDirectory: t.TempDir(), Policy: eventspool.DropOldest})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })
	failed, ok := any(router).(interface{ HandleFailedEvent(events.Event) })
	require.True(t, ok, "accepted events behind a terminal failure must retain exact loss coverage")
	const node, session = "tap-node", "30313233343536373839616263646566"
	failed.HandleFailedEvent(routedDNS(node, session, 1))
	require.NoError(t, router.Flush(context.Background()))
	batches := router.routes[eventRouteKey{node, session}].spool.Batches()
	require.Len(t, batches, 1)
	require.Empty(t, batches[0].Events)
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_TRANSPORT, batches[0].Stats.Losses[0].Kind)
	require.Equal(t, uint64(1), batches[0].Stats.Losses[0].Count)
}

func TestEventRouterRouteFailureRetainsAssignedEvents(t *testing.T) {
	base := filepath.Join(t.TempDir(), "spool")
	router, err := NewEventRouter(NewManager(Config{ForwardMode: "events"}, nil), EventRouterConfig{SpoolDirectory: base, Policy: eventspool.DropOldest})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })
	require.NoError(t, os.WriteFile(base, []byte("block spool creation"), 0600))
	const node, session = "tap-node", "30313233343536373839616263646566"
	err = router.HandleEvent(context.Background(), routedDNS(node, session, 1))
	var terminal interface{ TerminalSinkError() bool }
	require.ErrorAs(t, err, &terminal)
	require.True(t, terminal.TerminalSinkError())
	router.HandleFailedEvent(routedDNS(node, session, 2))
	require.NoError(t, os.Remove(base))
	require.NoError(t, router.Flush(context.Background()))
	batches := router.routes[eventRouteKey{node, session}].spool.Batches()
	require.Len(t, batches, 1)
	require.Equal(t, uint64(2), batches[0].Stats.Losses[0].Count)
	require.Equal(t, uint64(2), router.Losses().Transport)
}

func TestEventRouterRetiresDropOnlySession(t *testing.T) {
	router, err := NewEventRouter(NewManager(Config{ForwardMode: "events"}, nil), EventRouterConfig{SpoolDirectory: t.TempDir(), Policy: eventspool.DropOldest})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })
	const node, session = "tap-node", "30313233343536373839616263646566"
	router.HandleFailedEvent(routedDNS(node, session, 1))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, router.DrainAndRetire(ctx, node, session), context.DeadlineExceeded)
	route := router.routes[eventRouteKey{node, session}]
	require.NotNil(t, route)
	require.Len(t, route.spool.Batches(), 1)
	require.NoError(t, route.spool.Ack(node, session, 1))
	require.NoError(t, router.DrainAndRetire(context.Background(), node, session))
	require.Empty(t, router.routes)
}

func TestEventRouterFlushCannotReopenRoutesAfterFailedClose(t *testing.T) {
	base := filepath.Join(t.TempDir(), "spool")
	router, err := NewEventRouter(NewManager(Config{ForwardMode: "events"}, nil), EventRouterConfig{SpoolDirectory: base, Policy: eventspool.DropOldest})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(base, []byte("block spool creation"), 0600))
	router.HandleFailedEvent(routedDNS("tap-node", "30313233343536373839616263646566", 1))
	require.Error(t, router.Close(context.Background()))
	require.NoError(t, os.Remove(base))
	require.ErrorContains(t, router.Flush(context.Background()), "router is closed")
	require.Empty(t, router.routes)
	_, err = os.Stat(base)
	require.True(t, os.IsNotExist(err))
}

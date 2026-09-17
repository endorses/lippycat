package upstream

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/stretchr/testify/require"
)

func routedDNS(node, session string, sequence uint64) events.Event {
	env := events.Envelope{
		Timestamp: time.Unix(1, 0), EventID: events.DeliveryEventID(node, session, sequence),
		ProducerSessionID: session, EventSequence: sequence, NodeID: node,
		Flow:         events.FlowTuple{Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.2"), SourcePort: 1234, DestinationPort: 53},
		CaptureScope: events.CaptureScopeFull,
	}
	return events.NewDNSEvent(env)
}

func TestEventRouterPersistsIndependentProducerSessions(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)

	require.NoError(t, router.HandleEvent(context.Background(), routedDNS("tap-node", "30313233343536373839616263646566", 1)))
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS("other-node", "31313233343536373839616263646566", 1)))

	first, err := filepath.Glob(filepath.Join(dir, identityPathPart("tap-node"), identityPathPart("30313233343536373839616263646566"), "*.eventbatch"))
	require.NoError(t, err)
	second, err := filepath.Glob(filepath.Join(dir, identityPathPart("other-node"), identityPathPart("31313233343536373839616263646566"), "*.eventbatch"))
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Len(t, second, 1)
	info, err := os.Stat(first[0])
	require.NoError(t, err)
	require.Positive(t, info.Size())
	require.NoError(t, router.Close(context.Background()))

	recovered, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recovered.Close(context.Background())) })
	require.Len(t, recovered.routes, 2, "startup must resume every unacknowledged producer route")
	require.True(t, recovered.HasPendingDurableBatches())
}

func TestEventRouterRejectsRecoveredSessionPolicyMismatch(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	reliable := EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE}
	router, err := NewEventRouter(manager, reliable)
	require.NoError(t, err)
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS("tap-node", "30313233343536373839616263646566", 1)))
	require.NoError(t, router.Close(context.Background()))

	memoryOnly := reliable
	memoryOnly.Profile = eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY
	_, err = NewEventRouter(manager, memoryOnly)
	require.ErrorContains(t, err, "pending records use policy")
}

func TestEventRouterKeepsSanitizedIdentityCollisionsIndependent(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)

	session := "30313233343536373839616263646566"
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS("tap/a", session, 1)))
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS("tap_a", session, 1)))
	require.Len(t, router.routes, 2)
	require.NotEqual(t, identityPathPart("tap/a"), identityPathPart("tap_a"))
	require.NoError(t, router.Close(context.Background()))

	recovered, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recovered.Close(context.Background())) })
	require.Contains(t, recovered.routes, eventRouteKey{nodeID: "tap/a", sessionID: session})
	require.Contains(t, recovered.routes, eventRouteKey{nodeID: "tap_a", sessionID: session})
}

func TestEventRouterFlushPersistsTerminalUnsupportedLoss(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })

	node := "tap-node"
	session := "30313233343536373839616263646566"
	envelope := events.Envelope{
		Timestamp: time.Unix(1, 0), EventID: events.DeliveryEventID(node, session, 1),
		ProducerSessionID: session, EventSequence: 1, NodeID: node,
	}
	require.NoError(t, router.HandleEvent(context.Background(), events.NewFileContentEvent(envelope)))
	require.NoError(t, router.Flush(context.Background()))

	router.mu.Lock()
	route := router.routes[eventRouteKey{nodeID: node, sessionID: session}]
	router.mu.Unlock()
	require.NotNil(t, route)
	batches, err := route.spool.BatchesAfter(node, session, 0, 2)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Empty(t, batches[0].GetEvents())
	losses := batches[0].GetStats().GetLosses()
	require.Len(t, losses, 1)
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, losses[0].GetKind())
	require.Equal(t, uint64(1), losses[0].GetEventSequenceRanges()[0].GetFirst())
	require.Equal(t, uint64(1), losses[0].GetEventSequenceRanges()[0].GetLast())
}

func TestEventRouterSeparatesLossCounters(t *testing.T) {
	router := &EventRouter{}
	router.recordLoss(eventsv1.LossKind_LOSS_KIND_CAPTURE, 1)
	router.recordLoss(eventsv1.LossKind_LOSS_KIND_ANALYSIS, 2)
	router.recordLoss(eventsv1.LossKind_LOSS_KIND_BUFFER, 3)
	router.recordLoss(eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, 4)
	router.recordLoss(eventsv1.LossKind_LOSS_KIND_TRANSPORT, 5)

	require.Equal(t, LossSnapshot{Capture: 1, Analysis: 2, Queue: 3, UnsupportedKind: 4, Transport: 5}, router.Losses())
}

func TestEventRouterDrainAndRetireWaitsForAcknowledgment(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })

	node := "tap-node"
	session := "30313233343536373839616263646566"
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS(node, session, 1)))

	drained := make(chan error, 1)
	go func() { drained <- router.DrainAndRetire(context.Background(), node, session) }()
	require.Eventually(t, func() bool {
		router.mu.Lock()
		defer router.mu.Unlock()
		return router.routes[eventRouteKey{nodeID: node, sessionID: session}].retiring
	}, time.Second, time.Millisecond)
	require.ErrorContains(t, router.HandleEvent(context.Background(), routedDNS(node, session, 2)), "retiring")
	select {
	case err := <-drained:
		t.Fatalf("route retired before ACK: %v", err)
	default:
	}

	router.mu.Lock()
	route := router.routes[eventRouteKey{nodeID: node, sessionID: session}]
	router.mu.Unlock()
	require.NoError(t, route.spool.Ack(node, session, 1))
	require.NoError(t, <-drained)
	router.mu.Lock()
	_, exists := router.routes[eventRouteKey{nodeID: node, sessionID: session}]
	router.mu.Unlock()
	require.False(t, exists)
}

func TestEventRouterDrainAndRetireHonorsContext(t *testing.T) {
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: t.TempDir(), Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })
	node, session := "tap-node", "30313233343536373839616263646566"
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS(node, session, 1)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, router.DrainAndRetire(ctx, node, session), context.Canceled)
}

func TestEventRouterCloseReleasesSpoolOwnership(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)
	node, session := "tap-node", "30313233343536373839616263646566"
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS(node, session, 1)))
	spoolDir := filepath.Join(dir, identityPathPart(node), identityPathPart(session))

	_, err = eventspool.Open(eventspool.Config{Directory: spoolDir})
	require.Error(t, err, "an active route must retain exclusive spool ownership")
	closeCtx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, router.Close(closeCtx))

	reopened, err := eventspool.Open(eventspool.Config{Directory: spoolDir})
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}

func TestEventRouterOversizedThenValidBatchAdvancesThroughAck(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{
		SpoolDirectory: dir, MaxRecordBytes: 1024, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })
	node, session := "tap-node", "30313233343536373839616263646566"

	oversized := routedDNS(node, session, 1).(events.DNSEvent)
	oversized.Query = strings.Repeat("x", 2048)
	require.NoError(t, router.HandleEvent(context.Background(), oversized))
	require.Equal(t, uint64(1), router.Losses().Transport)

	valid := routedDNS(node, session, 2)
	require.NoError(t, router.HandleEvent(context.Background(), valid))
	router.mu.Lock()
	route := router.routes[eventRouteKey{nodeID: node, sessionID: session}]
	router.mu.Unlock()
	require.NotNil(t, route)
	batches, err := route.spool.BatchesAfter(node, session, 0, 2)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Equal(t, uint64(1), batches[0].GetBatchSequence())
	require.Equal(t, uint64(2), batches[0].GetEvents()[0].GetEventSequence())
	require.Equal(t, uint64(1), batches[0].GetStats().GetLosses()[0].GetEventSequenceRanges()[0].GetFirst())

	require.NoError(t, route.spool.Ack(node, session, 1))
	require.False(t, router.HasPendingDurableBatches())
}

func TestDrainAndRetireWaitsForAdmittedHandleBeforeFinalFlush(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })
	node, session := "tap-node", "30313233343536373839616263646566"
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS(node, session, 1)))
	key := eventRouteKey{nodeID: node, sessionID: session}
	router.mu.Lock()
	route := router.routes[key]
	router.mu.Unlock()
	require.NoError(t, route.spool.Ack(node, session, 1))

	admitted := make(chan struct{})
	release := make(chan struct{})
	route.beforeHandle = func() {
		close(admitted)
		<-release
	}
	handled := make(chan error, 1)
	go func() { handled <- router.HandleEvent(context.Background(), routedDNS(node, session, 2)) }()
	select {
	case <-admitted:
	case <-time.After(time.Second):
		t.Fatal("event was not admitted")
	}
	drained := make(chan error, 1)
	go func() { drained <- router.DrainAndRetire(context.Background(), node, session) }()
	require.Eventually(t, func() bool {
		route.admissionMu.Lock()
		defer route.admissionMu.Unlock()
		return !route.accepting
	}, time.Second, time.Millisecond)
	require.ErrorContains(t, router.HandleEvent(context.Background(), routedDNS(node, session, 3)), "retiring")
	select {
	case err := <-drained:
		t.Fatalf("retirement completed while an admitted handler was active: %v", err)
	default:
	}
	close(release)
	require.NoError(t, <-handled)
	require.Eventually(t, func() bool { return route.spool.Contains(node, session, 2) }, time.Second, time.Millisecond)
	require.NoError(t, route.spool.Ack(node, session, 2))
	require.NoError(t, <-drained)
}

func TestEventRouterCloseWaitsForAdmittedHandleAndReleasesOwnership(t *testing.T) {
	dir := t.TempDir()
	manager := NewManager(Config{ForwardMode: "events"}, nil)
	router, err := NewEventRouter(manager, EventRouterConfig{SpoolDirectory: dir, Policy: eventspool.DropOldest, Profile: eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE})
	require.NoError(t, err)
	node, session := "tap-node", "30313233343536373839616263646566"
	require.NoError(t, router.HandleEvent(context.Background(), routedDNS(node, session, 1)))
	key := eventRouteKey{nodeID: node, sessionID: session}
	router.mu.Lock()
	route := router.routes[key]
	router.mu.Unlock()

	admitted := make(chan struct{})
	release := make(chan struct{})
	route.beforeHandle = func() {
		close(admitted)
		<-release
	}
	handled := make(chan error, 1)
	go func() { handled <- router.HandleEvent(context.Background(), routedDNS(node, session, 2)) }()
	select {
	case <-admitted:
	case <-time.After(time.Second):
		t.Fatal("event was not admitted")
	}
	closed := make(chan error, 1)
	go func() { closed <- router.Close(context.Background()) }()
	require.Eventually(t, func() bool {
		router.mu.Lock()
		defer router.mu.Unlock()
		return router.closed
	}, time.Second, time.Millisecond)
	select {
	case err := <-closed:
		t.Fatalf("close completed while an admitted handler was active: %v", err)
	default:
	}
	close(release)
	require.NoError(t, <-handled)
	require.NoError(t, <-closed)

	spoolDir := filepath.Join(dir, identityPathPart(node), identityPathPart(session))
	reopened, err := eventspool.Open(eventspool.Config{Directory: spoolDir})
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}

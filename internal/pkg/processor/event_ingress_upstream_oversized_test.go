//go:build processor || tap || all

package processor

import (
	"context"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventforwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/endorses/lippycat/internal/pkg/processor/upstream"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type upstreamIngressTestStream struct {
	ctx      context.Context
	ingress  *eventIngress
	controls chan *eventsv1.EventIngressControl

	mu      sync.Mutex
	open    *eventsv1.EventIngressOpen
	batches []*eventsv1.ProtocolEventBatch
}

func (s *upstreamIngressTestStream) Send(message *eventsv1.EventIngressMessage) error {
	if open := message.GetOpen(); open != nil {
		s.mu.Lock()
		s.open = proto.Clone(open).(*eventsv1.EventIngressOpen)
		s.mu.Unlock()
		s.controls <- &eventsv1.EventIngressControl{
			Kind:            eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACCEPTED,
			AcceptedProfile: open.GetProfile(),
		}
		return nil
	}
	batch := message.GetBatch()
	if batch == nil {
		return nil
	}
	s.mu.Lock()
	open := proto.Clone(s.open).(*eventsv1.EventIngressOpen)
	s.batches = append(s.batches, proto.Clone(batch).(*eventsv1.ProtocolEventBatch))
	s.mu.Unlock()
	control, err := s.ingress.admit(s.ctx, ingressKey(open.GetSourceNodeId(), open.GetProducerSessionId()), open, map[events.Kind]struct{}{events.KindDNS: {}}, batch)
	if err != nil {
		return err
	}
	s.controls <- control
	return nil
}

func (s *upstreamIngressTestStream) Recv() (*eventsv1.EventIngressControl, error) {
	select {
	case control := <-s.controls:
		return control, nil
	case <-s.ctx.Done():
		return nil, io.EOF
	}
}

func TestUpstreamOversizedThenValidEventReachesIngressAndACKs(t *testing.T) {
	ctx := context.Background()
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 4, SinkQueueSize: 4})
	require.NoError(t, err)
	broadcaster := broadcast.New()
	require.NoError(t, dispatcher.Register(broadcaster))
	require.NoError(t, dispatcher.Start(ctx))
	t.Cleanup(func() { require.NoError(t, dispatcher.Close(ctx)) })
	ingress, err := newEventIngress(EventIngressPolicy{Dispatcher: dispatcher, Profile: "reliable", WALDirectory: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() {
		ingress.stopRetry()
		require.NoError(t, ingress.wal.close())
	})

	const (
		node    = "upstream-node"
		session = "30313233343536373839616263646566"
	)
	spoolRoot := t.TempDir()
	manager := upstream.NewManager(upstream.Config{ForwardMode: "events", ProcessorID: "relay-a"}, nil)
	t.Cleanup(manager.Disconnect)
	router, err := upstream.NewEventRouter(manager, upstream.EventRouterConfig{
		SpoolDirectory: spoolRoot,
		MaxRecordBytes: 1024,
		Policy:         eventspool.DropOldest,
		Profile:        eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
	})
	require.NoError(t, err)

	oversized := routedIngressDNS(node, session, 1)
	oversized.Query = strings.Repeat("x", 2048)
	require.NoError(t, router.HandleEvent(ctx, oversized))
	require.NoError(t, router.HandleEvent(ctx, routedIngressDNS(node, session, 2)))
	require.Equal(t, uint64(1), router.Losses().Transport)
	require.NoError(t, router.Close(ctx))

	routeDirs, err := filepath.Glob(filepath.Join(spoolRoot, "*", "*"))
	require.NoError(t, err)
	require.Len(t, routeDirs, 1)
	spool, err := eventspool.Open(eventspool.Config{Directory: routeDirs[0], MaxRecordBytes: 1024})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spool.Close()) })
	client, err := eventforwarding.New(eventforwarding.Config{
		SourceNodeID: node, ProducerSessionID: session,
		SemanticProfileRevision: 1,
		EventKinds:              []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_DNS},
		Profile:                 eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE,
		RelayNodeID:             "relay-a",
	}, spool)
	require.NoError(t, err)

	serveCtx, cancel := context.WithCancel(ctx)
	stream := &upstreamIngressTestStream{ctx: serveCtx, ingress: ingress, controls: make(chan *eventsv1.EventIngressControl, 2)}
	served := make(chan error, 1)
	go func() { served <- client.Serve(serveCtx, stream, cancel) }()
	require.Eventually(t, func() bool { return !spool.HasPending() }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-served, context.Canceled)

	stream.mu.Lock()
	require.Len(t, stream.batches, 1)
	batch := stream.batches[0]
	stream.mu.Unlock()
	require.Equal(t, uint64(1), batch.GetBatchSequence())
	require.Equal(t, uint64(2), batch.GetEvents()[0].GetEventSequence())
	require.Equal(t, []*eventsv1.SequenceRange{{First: 1, Last: 1}}, batch.GetStats().GetLosses()[0].GetEventSequenceRanges())
	require.Equal(t, uint64(2), ingress.sessions[ingressKey(node, session)].event)
	require.Eventually(t, func() bool { return broadcaster.Stats().Published == 1 }, time.Second, time.Millisecond)
}

func routedIngressDNS(node, session string, sequence uint64) events.DNSEvent {
	envelope := events.Envelope{
		Timestamp: time.Unix(1, 0), EventID: events.DeliveryEventID(node, session, sequence),
		ProducerSessionID: session, EventSequence: sequence, NodeID: node,
		Flow: events.FlowTuple{
			Protocol: 17, SourceAddress: netip.MustParseAddr("192.0.2.1"), DestinationAddress: netip.MustParseAddr("192.0.2.53"),
			SourcePort: 53000, DestinationPort: 53,
		},
		CaptureScope: events.CaptureScopeFull,
	}
	return events.NewDNSEvent(envelope)
}

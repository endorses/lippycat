//go:build processor || tap || all

package processor

import (
	"context"
	"net"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/endorses/lippycat/internal/pkg/processor/upstream"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

func networkGRPCProcessor(t *testing.T, id, profile string) (*Processor, string) {
	t.Helper()
	p, err := newTestProcessor(t, Config{ListenAddr: "127.0.0.1:0", ProcessorID: id, EventIngressProfile: profile, EventIngressWALDirectory: t.TempDir(), EventAllowSensitiveFields: true})
	require.NoError(t, err)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	p.registerGRPCServices(server)
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); require.NoError(t, <-done) })
	return p, listener.Addr().String()
}
func networkGRPCRouter(t *testing.T, node, address string, profile eventsv1.IngressProfile) *upstream.EventRouter {
	t.Helper()
	manager := upstream.NewManager(upstream.Config{Address: address, ProcessorID: node, ListenAddress: "127.0.0.1:1", ForwardMode: "events"}, nil)
	require.NoError(t, manager.Start())
	t.Cleanup(manager.Disconnect)
	require.Eventually(t, func() bool { return manager.GetUpstreamProcessorID() != "" }, 5*time.Second, time.Millisecond)
	router, err := upstream.NewEventRouter(manager, upstream.EventRouterConfig{SpoolDirectory: t.TempDir(), Policy: eventspool.DropOldest, Profile: profile})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, router.Close(context.Background())) })
	return router
}

func TestNetworkGRPCHierarchyAndSubscription(t *testing.T) {
	input := networkProcessorEvents(t, "network-origin")
	for _, profile := range []string{"memory_only", "reliable"} {
		t.Run(profile, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			wireProfile := eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY
			if profile == "reliable" {
				wireProfile = eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE
			}
			central, centralAddress := networkGRPCProcessor(t, "network-central", profile)
			require.NoError(t, central.eventDispatcher.Start(context.Background()))
			middle, middleAddress := networkGRPCProcessor(t, "network-middle", profile)
			middleRouter := networkGRPCRouter(t, "network-middle", centralAddress, wireProfile)
			require.NoError(t, middle.eventDispatcher.Register(middleRouter))
			require.NoError(t, middle.eventDispatcher.Start(context.Background()))
			edgeRouter := networkGRPCRouter(t, "network-edge", middleAddress, wireProfile)
			conn, err := grpc.NewClient(centralAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
			require.NoError(t, err)
			defer func() { require.NoError(t, conn.Close()) }()
			stream, err := eventsv1.NewEventServiceClient(conn).SubscribeEvents(ctx, &eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, EventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_DHCP, eventsv1.EventKind_EVENT_KIND_NTP}, IncludeSensitiveFields: true})
			require.NoError(t, err)
			started, err := stream.Recv()
			require.NoError(t, err)
			require.Equal(t, eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED, started.GetControl().Kind)
			for _, e := range input {
				require.NoError(t, edgeRouter.HandleEvent(ctx, e))
			}
			var observed []events.Event
			for len(observed) < len(input) {
				message, err := stream.Recv()
				require.NoError(t, err)
				for _, wire := range message.GetBatch().GetEvents() {
					e, omission, err := protoadapter.FromProto(wire)
					require.NoError(t, err)
					require.Nil(t, omission)
					observed = append(observed, e)
				}
			}
			eventfixture.AssertNetworkMessages(t, observed)
			for i, e := range observed {
				before, err := protoadapter.ToProto(input[i])
				require.NoError(t, err)
				after, err := protoadapter.ToProto(e)
				require.NoError(t, err)
				require.Equal(t, before.EventId, after.EventId)
				require.Equal(t, before.Envelope.Uid, after.Envelope.Uid)
				require.Equal(t, before.Envelope.NodeId, after.Envelope.NodeId)
				require.True(t, proto.Equal(before.GetDhcp(), after.GetDhcp()))
				require.True(t, proto.Equal(before.GetNtp(), after.GetNtp()))
			}
			require.Eventually(t, func() bool { return !edgeRouter.HasPendingDurableBatches() && !middleRouter.HasPendingDurableBatches() }, 5*time.Second, time.Millisecond, "both forwarding hops receive ACKs")
		})
	}
}

//go:build processor || tap || all

package processor

import (
	"context"
	"net/netip"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/broadcast"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/stretchr/testify/require"
)

func privacyDHCP() events.DHCPEvent {
	env := testEventEnvelope("sensor", 1)
	env.Flow.Protocol = 17
	env.Flow.SourcePort = 68
	env.Flow.DestinationPort = 67
	e := events.NewDHCPEvent(env)
	e.Operation = 1
	e.MessageType = 1
	e.HardwareType = 1
	e.TransactionID = 42
	e.Association = events.AssociationRequest
	e.AssociationID = "exchange"
	e.HardwareAddress = []byte{1, 2, 3, 4, 5, 6}
	e.ClientIdentifier = []byte{0, 255, 0, 1}
	e.Hostname = "private-host"
	e.Domain = "private-domain"
	zero := netip.MustParseAddr("0.0.0.0")
	e.ClientAddress = zero
	e.OfferedAddress = zero
	e.NextServerAddress = zero
	e.RelayAddress = zero
	return e
}

func TestNetworkDHCPProjectionImmutable(t *testing.T) {
	e := privacyDHCP()
	for _, input := range []events.Event{e, &e} {
		projected, keep, err := safeEventProjector(false, false)(input)
		require.NoError(t, err)
		require.True(t, keep)
		got := projected.(events.DHCPEvent)
		require.Empty(t, got.HardwareAddress)
		require.Empty(t, got.ClientIdentifier)
		require.Empty(t, got.Hostname)
		require.Empty(t, got.Domain)
		require.Equal(t, e.Envelope(), got.Envelope())
		require.Equal(t, e.AssociationID, got.AssociationID)
		require.Equal(t, e.TransactionID, got.TransactionID)
		require.NotEmpty(t, e.Hostname)
		require.NotEmpty(t, e.HardwareAddress)
		sensitive, keep, err := safeEventProjector(true, false)(input)
		require.NoError(t, err)
		require.True(t, keep)
		require.Equal(t, input, sensitive)
	}
}

func TestNetworkSubscriptionPrivacyDirectAndRelay(t *testing.T) {
	for _, relay := range []bool{false, true} {
		for _, sensitive := range []bool{false, true} {
			name := "direct"
			if relay {
				name = "relay"
			}
			if sensitive {
				name += "/sensitive"
			} else {
				name += "/projected"
			}
			t.Run(name, func(t *testing.T) {
				b := broadcast.New()
				service, err := NewEventService(b, EventSubscriptionPolicy{AllowSensitiveFields: true})
				require.NoError(t, err)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				stream := &eventSubscriptionTestStream{ctx: ctx, notify: make(chan struct{}, 16)}
				done := make(chan error, 1)
				go func() {
					done <- service.SubscribeEvents(&eventsv1.EventSubscribeRequest{SubscriptionVersion: 1, IncludeSensitiveFields: sensitive, EventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_DHCP, eventsv1.EventKind_EVENT_KIND_KNOWN_HOST, eventsv1.EventKind_EVENT_KIND_KNOWN_SERVICE}}, stream)
				}()
				waitEventMessage(t, stream.notify)
				dhcp := privacyDHCP()
				host := events.NewKnownHostEvent(testEventEnvelope("sensor", 2))
				host.Host = netip.MustParseAddr("192.0.2.2")
				host.Evidence = events.EvidenceTCPHandshake
				svc := events.NewKnownServiceEvent(testEventEnvelope("sensor", 3))
				svc.Host = host.Host
				svc.Port = 80
				svc.Transport = 6
				svc.Protocol = "http"
				svc.Evidence = events.EvidenceTCPHandshake
				var input = []events.Event{dhcp, host, svc}
				if relay {
					wire, err := protoadapter.ToProtoBatch("sensor", "session-a", 1, input, nil, 1)
					require.NoError(t, err)
					d, err := events.NewDispatcher(events.Config{QueueSize: 16, SinkQueueSize: 16})
					require.NoError(t, err)
					require.NoError(t, d.Register(b))
					require.NoError(t, d.Start(ctx))
					ingress, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: "memory_only"})
					require.NoError(t, err)
					open := &eventsv1.EventIngressOpen{SourceNodeId: "sensor", ProducerSessionId: "session-a", SemanticProfileRevision: 1}
					_, err = ingress.admit(ctx, ingressKey("sensor", "session-a"), open, map[events.Kind]struct{}{events.KindDHCP: {}, events.KindKnownHost: {}, events.KindKnownService: {}}, wire)
					require.NoError(t, err)
					require.NoError(t, d.Close(ctx))
				} else {
					for _, e := range input {
						require.NoError(t, b.HandleEvent(ctx, e))
					}
				}
				require.Eventually(t, func() bool {
					count := 0
					loss := uint64(0)
					for _, m := range stream.snapshot() {
						count += len(m.GetBatch().GetEvents())
						for _, l := range m.GetControl().GetLosses() {
							if l.Kind == eventsv1.LossKind_LOSS_KIND_POLICY_OMISSION {
								loss += l.Count
							}
						}
					}
					if sensitive {
						return count == 3
					}
					return count == 1 && loss == 2
				}, time.Second, 5*time.Millisecond)
				cancel()
				require.NoError(t, <-done)
				for _, m := range stream.snapshot() {
					for _, wire := range m.GetBatch().GetEvents() {
						decoded, omission, err := protoadapter.FromProto(wire)
						require.NoError(t, err)
						require.Nil(t, omission)
						if got, ok := decoded.(events.DHCPEvent); ok {
							require.Equal(t, dhcp.Envelope(), got.Envelope())
							if sensitive {
								require.Equal(t, dhcp.ClientIdentifier, got.ClientIdentifier)
							} else {
								require.Empty(t, got.ClientIdentifier)
								require.Empty(t, got.Hostname)
							}
						}
					}
				}
				require.NotEmpty(t, dhcp.ClientIdentifier)
				require.NotEmpty(t, dhcp.Hostname)
			})
		}
	}
}

func TestNetworkPolicyOmissionRetainsIdentityOnDispatchOverflow(t *testing.T) {
	b := broadcast.New()
	sub, err := b.Subscribe(broadcast.Options{QueueSize: 1, Kinds: []events.Kind{events.KindKnownHost}, Project: safeEventProjector(false, false)})
	require.NoError(t, err)
	defer sub.Close()
	host := events.NewKnownHostEvent(testEventEnvelope("sensor", 7))
	host.Host = netip.MustParseAddr("192.0.2.2")
	host.Evidence = events.EvidenceTCPHandshake
	b.LockDropBoundary()
	b.HandleDroppedEventLocked(host, time.Time{})
	b.UnlockDropBoundary()
	losses := subscriberLosses(sub.ConsumeLosses())
	require.Len(t, losses, 1)
	require.Equal(t, eventsv1.LossKind_LOSS_KIND_POLICY_OMISSION, losses[0].Kind)
	require.Equal(t, "sensor", losses[0].SourceNodeId)
	require.Equal(t, uint64(7), losses[0].EventSequenceRanges[0].First)
}

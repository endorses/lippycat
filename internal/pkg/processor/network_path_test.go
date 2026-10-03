//go:build processor || tap || all

package processor

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func networkProcessorEvents(t *testing.T, source string) []events.Event {
	got := processorFixtureEvents(t, source, nil, eventfixture.NetworkMessages)
	return eventfixture.AssertNetworkMessages(t, got)
}
func inventoryProcessorEvents(t *testing.T, source string) []events.Event {
	got := processorFixtureEvents(t, source, eventfixture.InventoryPolicy(), eventfixture.InventoryMessages)
	eventfixture.AssertInventory(t, got)
	return got
}
func processorFixtureEvents(t *testing.T, source string, policy *eventconfig.Config, fixture func() ([]capture.PacketInfo, error)) []events.Event {
	t.Helper()
	p, err := newTestProcessor(t, Config{EventAnalysis: policy, ListenAddr: ":0", ProcessorID: "network-processor", EventQueueSize: 64})
	require.NoError(t, err)
	sink := &collectingSink{}
	require.NoError(t, p.RegisterEventSink(sink))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	packets, err := fixture()
	require.NoError(t, err)
	for _, info := range packets {
		ci := info.Packet.Metadata().CaptureInfo
		p.emitProtocolEvents(source, []*data.CapturedPacket{{Metadata: protocolmeta.Enrich(info.Packet, nil, false), Data: info.Packet.Data(), TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), LinkType: uint32(info.LinkType), InterfaceName: info.Interface}})
	}
	p.eventRuntime.EOF()
	p.eventRuntime.Close()
	require.NoError(t, p.eventDispatcher.Close(context.Background()))
	return sink.events
}
func TestNetworkProcessorPacketAndTapSourceWithoutLogs(t *testing.T) {
	for _, source := range []string{"hunter", "network-processor-local"} {
		t.Run(source, func(t *testing.T) {
			got := networkProcessorEvents(t, source)
			want := source
			if source == "network-processor-local" {
				want = "network-processor"
			}
			for _, e := range got {
				require.Equal(t, want, e.Envelope().NodeID)
				require.Equal(t, source, e.Envelope().Provenance.CaptureSource)
			}
		})
	}
}
func TestNetworkIngressTwoHopsRetryProfiles(t *testing.T) {
	input := networkProcessorEvents(t, "hunter")
	assertIngressTwoHops(t, input, eventfixture.AssertNetworkMessages)
}

func TestInventoryIngressTwoHopsRetryProfiles(t *testing.T) {
	input := inventoryProcessorEvents(t, "hunter")
	assertIngressTwoHops(t, input, eventfixture.AssertInventory)
}

func assertIngressTwoHops(t *testing.T, input []events.Event, assertFixture func(testing.TB, []events.Event) []events.Event) {
	allowed := make(map[events.Kind]struct{})
	for _, event := range input {
		allowed[event.Kind()] = struct{}{}
	}
	for _, profile := range []string{"memory_only", "reliable"} {
		t.Run(profile, func(t *testing.T) {
			batch, err := protoadapter.ToProtoBatch("hunter", input[0].Envelope().ProducerSessionID, 1, input, nil, 1)
			require.NoError(t, err)
			for hop := 0; hop < 2; hop++ {
				d, err := events.NewDispatcher(events.Config{QueueSize: 64, SinkQueueSize: 64})
				require.NoError(t, err)
				sink := &collectingSink{}
				require.NoError(t, d.Register(sink))
				require.NoError(t, d.Start(context.Background()))
				i, err := newEventIngress(EventIngressPolicy{Dispatcher: d, Profile: profile, WALDirectory: t.TempDir()})
				require.NoError(t, err)
				open := &eventsv1.EventIngressOpen{SourceNodeId: batch.SourceNodeId, ProducerSessionId: batch.ProducerSessionId, SemanticProfileRevision: 1}
				key := ingressKey(open.SourceNodeId, open.ProducerSessionId)
				for retry := 0; retry < 2; retry++ {
					ctrl, err := i.admit(context.Background(), key, open, allowed, batch)
					require.NoError(t, err)
					require.Equal(t, eventsv1.EventIngressControlKind_EVENT_INGRESS_CONTROL_KIND_ACK, ctrl.Kind)
					require.Equal(t, uint64(1), ctrl.CumulativeAckSequence)
				}
				i.stopRetry()
				require.NoError(t, d.Close(context.Background()))
				if i.wal != nil {
					require.NoError(t, i.wal.close())
				}
				assertFixture(t, sink.events)
				got := sink.events
				require.Len(t, got, len(input), "event ingress does not derive inventory from source conn events")
				for n := range input {
					before, err := protoadapter.ToProto(input[n])
					require.NoError(t, err)
					after, err := protoadapter.ToProto(got[n])
					require.NoError(t, err)
					require.True(t, proto.Equal(before, after), "relay preserves semantic timestamp, identity and protocol context")
				}
				batch, err = protoadapter.ToProtoBatch(batch.SourceNodeId, batch.ProducerSessionId, 1, got, nil, 1)
				require.NoError(t, err)
			}
		})
	}
}

func TestInventoryProcessorPacketAndTapSourceWithoutLogs(t *testing.T) {
	for _, source := range []string{"hunter", "network-processor-local"} {
		t.Run(source, func(t *testing.T) {
			got := inventoryProcessorEvents(t, source)
			want := source
			if source == "network-processor-local" {
				want = "network-processor"
			}
			for _, event := range eventfixture.AssertInventory(t, got) {
				require.Equal(t, want, event.Envelope().NodeID)
				require.Equal(t, source, event.Envelope().Provenance.CaptureSource)
			}
		})
	}
}

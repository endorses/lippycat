package remotecapture

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNetworkMonitoringFallbackAndRemoteSubscription(t *testing.T) {
	assertMonitoringFixture(t, nil, eventfixture.NetworkMessages, eventfixture.AssertNetworkMessages)
}
func TestInventoryMonitoringFallbackAndRemoteSubscription(t *testing.T) {
	assertMonitoringFixture(t, eventfixture.InventoryPolicy(), eventfixture.InventoryMessages, eventfixture.AssertInventory)
}
func assertMonitoringFixture(t *testing.T, policy *eventconfig.Config, fixture func() ([]capture.PacketInfo, error), assertFixture func(testing.TB, []events.Event) []events.Event) {
	a, handler := newMonitoringAnalysis(t)
	a.client.eventAnalysis = policy
	packets, err := fixture()
	require.NoError(t, err)
	for _, info := range packets {
		ci := info.Packet.Metadata().CaptureInfo
		require.NoError(t, a.observe(&data.PacketBatch{HunterId: "network-hunter", MonitorEventAnalysis: data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_CLIENT_REQUIRED, Packets: []*data.CapturedPacket{{Data: info.Packet.Data(), TimestampNs: ci.Timestamp.UnixNano(), LinkType: uint32(info.LinkType), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), InterfaceName: info.Interface}}}))
	}
	a.runtime.EOF()
	flushMonitoringAnalysis(t, a)
	var observed []events.Event
	for _, batch := range handler.EventBatches {
		observed = append(observed, batch.Events...)
	}
	got := assertFixture(t, observed)
	for _, e := range got {
		require.True(t, e.Envelope().Partial)
		require.Equal(t, events.CaptureScopeFiltered, e.Envelope().CaptureScope)
		require.Equal(t, "network-hunter", e.Envelope().NodeID)
	}
	batch, err := protoadapter.ToProtoBatch("network-hunter", got[0].Envelope().ProducerSessionID, 1, got, nil, 1)
	require.NoError(t, err)
	remoteHandler := &MockEventHandler{}
	client := &Client{ctx: context.Background(), handler: remoteHandler}
	client.receiveEvents(context.Background(), &fakeEventStream{messages: []*eventsv1.EventSubscriptionMessage{{DeliverySequence: 1, Message: &eventsv1.EventSubscriptionMessage_Control{Control: &eventsv1.EventSubscriptionControl{Kind: eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED, StreamId: "network-stream", DeliverySequence: 1, SupportedEventKinds: protoadapter.SupportedKinds(true)}}}, {DeliverySequence: 2, Message: &eventsv1.EventSubscriptionMessage_Batch{Batch: batch}}}})
	var remote []events.Event
	for _, batch := range remoteHandler.EventBatches {
		remote = append(remote, batch.Events...)
		require.Zero(t, batch.CompatibilityOmissions)
	}
	assertFixture(t, remote)
	for i := range got {
		before, err := protoadapter.ToProto(got[i])
		require.NoError(t, err)
		after, err := protoadapter.ToProto(remote[i])
		require.NoError(t, err)
		require.True(t, proto.Equal(before, after), "subscription preserves semantic timestamps, source fields and IDs")
	}
}

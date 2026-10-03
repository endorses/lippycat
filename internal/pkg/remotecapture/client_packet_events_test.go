package remotecapture

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func monitoringDNSPacket(t *testing.T) *data.CapturedPacket {
	t.Helper()
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{5, 4, 3, 2, 1, 0}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.53"), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	dns := &layers.DNS{ID: 7, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, dns))
	return &data.CapturedPacket{Data: buffer.Bytes(), LinkType: uint32(layers.LinkTypeEthernet), TimestampNs: time.Now().UnixNano(), CaptureLength: uint32(len(buffer.Bytes())), OriginalLength: uint32(len(buffer.Bytes())), InterfaceName: "eth0", InterfaceIndex: 2}
}

func newMonitoringAnalysis(t *testing.T) (*packetEventAnalysis, *MockEventHandler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	handler := &MockEventHandler{}
	client := &Client{ctx: ctx, handler: handler, nodeID: "processor", eventStreamGeneration: 1}
	analysis := &packetEventAnalysis{client: client, ctx: ctx, generation: 1}
	t.Cleanup(func() { cancel(); analysis.close() })
	return analysis, handler
}

func flushMonitoringAnalysis(t *testing.T, a *packetEventAnalysis) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, a.dispatcher.Flush(ctx))
}

func TestPacketEventAnalysisDerivesRawDNSWithPartialProvenance(t *testing.T) {
	for _, withMetadata := range []bool{false, true} {
		t.Run(map[bool]string{false: "raw", true: "flow-metadata-only"}[withMetadata], func(t *testing.T) {
			a, handler := newMonitoringAnalysis(t)
			packet := monitoringDNSPacket(t)
			if withMetadata {
				packet.Metadata = &data.PacketMetadata{SrcIp: "192.0.2.1", DstIp: "192.0.2.53", Transport: "udp", SrcPort: 53000, DstPort: 53}
			}
			require.NoError(t, a.observe(&data.PacketBatch{HunterId: "packet-hunter", Packets: []*data.CapturedPacket{packet}, MonitorEventAnalysis: data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_CLIENT_REQUIRED}))
			flushMonitoringAnalysis(t, a)
			var dns *events.DNSEvent
			for _, batch := range handler.EventBatches {
				for _, event := range batch.Events {
					if observed, ok := event.(events.DNSEvent); ok {
						require.Nil(t, dns, "one DNS query must produce one DNS event")
						dns = &observed
					}
				}
			}
			require.NotNil(t, dns)
			require.Equal(t, "example.com", dns.Query)
			envelope := dns.Envelope()
			require.Equal(t, "packet-hunter", envelope.NodeID)
			require.Equal(t, events.CaptureScopeFiltered, envelope.CaptureScope)
			require.True(t, envelope.Partial)
			require.Equal(t, []string{"processor"}, envelope.Provenance.ProcessorNodeIDs)
			require.Equal(t, "eth0", envelope.Provenance.InterfaceName)
			require.Equal(t, uint32(2), envelope.Provenance.InterfaceIndex)
			require.NotEmpty(t, envelope.ProducerSessionID)
			require.NotEmpty(t, envelope.EventID)
			if withMetadata {
				require.Nil(t, packet.Metadata.Dns, "client analysis must not modify received packets")
			}
		})
	}
}

func TestEventSubscriptionNodesMapsTapCaptureID(t *testing.T) {
	client := &Client{nodeID: "tap"}
	ids := []string{"tap-local", "remote-hunter"}
	require.Equal(t, []string{"tap", "remote-hunter"}, client.eventSubscriptionNodes(ids))
	require.Equal(t, []string{"tap-local", "remote-hunter"}, ids)
	require.Nil(t, client.eventSubscriptionNodes(nil))
	require.Equal(t, []string{}, client.eventSubscriptionNodes([]string{}))
}

func TestPacketEventSinkSurfacesDroppedEventsAtFlush(t *testing.T) {
	a, handler := newMonitoringAnalysis(t)
	sink := &packetEventSink{analysis: a}
	sink.LockDropBoundary()
	sink.HandleDroppedEventLocked(nil, time.Now())
	sink.HandleDroppedEventLocked(nil, time.Now())
	sink.UnlockDropBoundary()
	require.NoError(t, sink.Flush(context.Background()))
	require.Len(t, handler.EventBatches, 1)
	require.Equal(t, uint64(2), handler.EventBatches[0].Losses[0].Count)
	require.NoError(t, sink.Flush(context.Background()))
	require.Len(t, handler.EventBatches, 1)
}

func TestPacketEventAnalysisSkipsAuthoritativeAndLegacyBatches(t *testing.T) {
	a, handler := newMonitoringAnalysis(t)
	for _, mode := range []data.MonitorEventAnalysis{data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_UNSPECIFIED, data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_SERVER_PROVIDED} {
		require.NoError(t, a.observe(&data.PacketBatch{Packets: []*data.CapturedPacket{monitoringDNSPacket(t)}, MonitorEventAnalysis: mode}))
	}
	require.Nil(t, a.runtime)
	require.Nil(t, a.dispatcher)
	require.Empty(t, handler.EventBatches)
}

func TestPacketEventAnalysisMixedSourcesAndAuthority(t *testing.T) {
	a, handler := newMonitoringAnalysis(t)
	for _, node := range []string{"packet-a", "event-node", "packet-b"} {
		mode := data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_CLIENT_REQUIRED
		if node == "event-node" {
			mode = data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_SERVER_PROVIDED
		}
		require.NoError(t, a.observe(&data.PacketBatch{HunterId: node, Packets: []*data.CapturedPacket{monitoringDNSPacket(t)}, MonitorEventAnalysis: mode}))
	}
	flushMonitoringAnalysis(t, a)
	sessions := map[string]string{}
	for _, batch := range handler.EventBatches {
		for _, event := range batch.Events {
			require.NotEqual(t, "event-node", event.Envelope().NodeID)
			sessions[event.Envelope().NodeID] = event.Envelope().ProducerSessionID
		}
	}
	require.Len(t, sessions, 2)
	require.NotEqual(t, sessions["packet-a"], sessions["packet-b"])
}

func TestPacketEventAnalysisStopsOnCancelOrNewSubscription(t *testing.T) {
	for _, cancelStream := range []bool{false, true} {
		t.Run(map[bool]string{false: "subscription-replaced", true: "cancelled"}[cancelStream], func(t *testing.T) {
			a, handler := newMonitoringAnalysis(t)
			ctx, cancel := context.WithCancel(a.ctx)
			defer cancel()
			a.ctx = ctx
			batch := &data.PacketBatch{HunterId: "source", Packets: []*data.CapturedPacket{monitoringDNSPacket(t)}, MonitorEventAnalysis: data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_CLIENT_REQUIRED}
			require.NoError(t, a.observe(batch))
			flushMonitoringAnalysis(t, a)
			before := len(handler.EventBatches)
			if cancelStream {
				cancel()
			} else {
				a.client.eventCursorMu.Lock()
				a.client.eventStreamGeneration++
				a.client.eventCursorMu.Unlock()
			}
			require.NoError(t, a.observe(batch))
			a.close()
			require.Len(t, handler.EventBatches, before, "closed streams must not deliver final conn events into the next subscription")
		})
	}
}

func TestPacketEventAnalysisSkipsNonIPFrames(t *testing.T) {
	a, handler := newMonitoringAnalysis(t)
	// An unknown, non-IP EtherType is legitimate captured network traffic.
	packet := &data.CapturedPacket{Data: []byte{0, 1, 2, 3, 4, 5, 5, 4, 3, 2, 1, 0, 0x88, 0xb5, 1}, LinkType: uint32(layers.LinkTypeEthernet), TimestampNs: time.Now().UnixNano()}
	require.NoError(t, a.observe(&data.PacketBatch{HunterId: "source", Packets: []*data.CapturedPacket{packet}, MonitorEventAnalysis: data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_CLIENT_REQUIRED}))
	flushMonitoringAnalysis(t, a)
	require.Empty(t, handler.EventBatches)
	require.Zero(t, a.runtime.Stats().Invalid)
}

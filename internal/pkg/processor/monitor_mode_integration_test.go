//go:build processor || tap || all

package processor

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type monitorModeHandler struct {
	types.NoopEventHandler
	packets chan []types.PacketDisplay
	events  chan types.EventBatch
}

func (h *monitorModeHandler) OnPacketBatch(packets []types.PacketDisplay) {
	h.packets <- packets
}

func (h *monitorModeHandler) OnEventBatch(batch types.EventBatch) {
	h.events <- batch
}

// monitorModeServerStream observes the actual wire batches without introducing
// another subscription that could change the processor's output demand.
type monitorModeServerStream struct {
	grpc.ServerStream
	packets chan *data.PacketBatch
	started chan struct{}
}

func (s *monitorModeServerStream) SendMsg(message any) error {
	if err := s.ServerStream.SendMsg(message); err != nil {
		return err
	}
	switch value := message.(type) {
	case *data.PacketBatch:
		s.packets <- proto.Clone(value).(*data.PacketBatch)
	case *eventsv1.EventSubscriptionMessage:
		if control := value.GetControl(); control != nil && control.Kind == eventsv1.SubscriptionControlKind_SUBSCRIPTION_CONTROL_KIND_STARTED {
			s.started <- struct{}{}
		}
	}
	return nil
}

func TestRemoteMonitorAnalysisFollowsServingMode(t *testing.T) {
	for _, mode := range []string{"packets", "events"} {
		t.Run(mode, func(t *testing.T) {
			p, err := newTestProcessor(t, Config{ListenAddr: ":0", ProcessorID: "monitor-test", EventQueueSize: 16, UpstreamForwardMode: mode})
			require.NoError(t, err)
			require.False(t, monitorModeRuntimePresent(p), "an idle processor must not allocate analysis state")
			require.NoError(t, p.eventDispatcher.Start(context.Background()))

			wirePackets := make(chan *data.PacketBatch, 8)
			eventStarted := make(chan struct{}, 8)
			server := grpc.NewServer(grpc.StreamInterceptor(func(service any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
				return handler(service, &monitorModeServerStream{ServerStream: stream, packets: wirePackets, started: eventStarted})
			}))
			p.registerGRPCServices(server)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			serveDone := make(chan error, 1)
			go func() { serveDone <- server.Serve(listener) }()
			t.Cleanup(func() {
				server.Stop()
				require.NoError(t, <-serveDone)
			})

			handler := &monitorModeHandler{packets: make(chan []types.PacketDisplay, 16), events: make(chan types.EventBatch, 16)}
			client, err := remotecapture.NewClientWithConfig(&remotecapture.ClientConfig{Address: listener.Addr().String()}, handler)
			require.NoError(t, err)
			closeClient := sync.OnceFunc(client.Close)
			t.Cleanup(closeClient)
			require.Equal(t, remotecapture.NodeTypeProcessor, client.GetNodeType())
			require.NoError(t, client.StreamPacketsWithFilter([]string{"monitor-test-local"}))
			select {
			case <-eventStarted:
			case <-time.After(5 * time.Second):
				t.Fatal("remote event subscription did not start")
			}
			if mode == "packets" {
				require.Eventually(t, func() bool { return p.subscriberManager.Count() == 1 }, 5*time.Second, time.Millisecond)
				require.False(t, monitorModeRuntimePresent(p), "a packet monitor must derive events at the client")
			} else {
				require.True(t, p.wantsEventAnalysis())
				require.True(t, monitorModeRuntimePresent(p), "an event monitor must enable server analysis")
			}

			p.processBatch(monitorModeDNSBatch(t))
			monitorModeAwaitDNS(t, handler.events)
			if mode == "packets" {
				select {
				case batch := <-wirePackets:
					require.Equal(t, data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_CLIENT_REQUIRED, batch.MonitorEventAnalysis)
					require.Len(t, batch.Packets, 1)
					require.NotEmpty(t, batch.Packets[0].Data)
				case <-time.After(5 * time.Second):
					t.Fatal("processor did not forward a monitor packet batch")
				}
				select {
				case packets := <-handler.packets:
					require.Len(t, packets, 1)
				case <-time.After(5 * time.Second):
					t.Fatal("remote client did not deliver packet display output")
				}
				require.False(t, monitorModeRuntimePresent(p), "client analysis must not allocate a server runtime")
			} else {
				require.Never(t, func() bool {
					return len(wirePackets) != 0 || len(handler.packets) != 0
				}, 100*time.Millisecond, time.Millisecond, "event mode must not send raw packets or packet display output")
			}
			closeClient()
			require.Eventually(t, func() bool { return !monitorModeRuntimePresent(p) && !p.wantsEventAnalysis() }, 5*time.Second, time.Millisecond,
				"disconnecting the last monitor must release optional server analysis")
		})
	}
}

func monitorModeRuntimePresent(p *Processor) bool {
	p.eventAnalysisMu.RLock()
	defer p.eventAnalysisMu.RUnlock()
	return p.eventRuntime != nil
}

func monitorModeAwaitDNS(t *testing.T, batches <-chan types.EventBatch) {
	t.Helper()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case batch := <-batches:
			for _, event := range batch.Events {
				if dns, ok := event.(events.DNSEvent); ok {
					require.Equal(t, "monitor.example.test", dns.Query)
					return
				}
			}
		case <-timeout.C:
			t.Fatal("remote monitor did not receive normalized DNS event")
		}
	}
}

func monitorModeDNSBatch(t *testing.T) *source.PacketBatch {
	t.Helper()
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.10"), DstIP: net.ParseIP("192.0.2.53"), Protocol: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: 53000, DstPort: 53}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	dns := &layers.DNS{ID: 7, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("monitor.example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, udp, dns))
	timestamp := time.Now().UnixNano()
	packet := &data.CapturedPacket{Data: buffer.Bytes(), TimestampNs: timestamp, LinkType: uint32(layers.LinkTypeEthernet), CaptureLength: uint32(len(buffer.Bytes())), OriginalLength: uint32(len(buffer.Bytes())),
		Metadata: &data.PacketMetadata{SrcIp: "192.0.2.10", DstIp: "192.0.2.53", SrcPort: 53000, DstPort: 53, Transport: "udp", Protocol: "DNS",
			Dns: &data.DNSMetadata{TransactionId: 7, QueryName: "monitor.example.test", QueryType: "A", QueryClass: "IN"}}}
	batch, err := source.FromProtoBatchE(&data.PacketBatch{HunterId: "monitor-test-local", Sequence: 1, TimestampNs: timestamp, Packets: []*data.CapturedPacket{packet}})
	require.NoError(t, err)
	return batch
}

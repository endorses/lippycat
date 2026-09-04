//go:build tui || all

package tui

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// BenchmarkModelEventDNSReplay replays generated Ethernet/IPv4/UDP DNS queries
// through packet decoding, the production event analyzer and bounded local sink,
// tick delivery, and a fixed 160x40 Events viewport. This is a controlled DNS
// capture workload, not a mixed-protocol production capture or a terminal driver
// benchmark. Rotating through 10,001 flows with 10,000 retained packets exercises
// full related-packet scans as the newest events arrive before their packets.
func BenchmarkModelEventDNSReplay(b *testing.B) {
	const retained, batchSize = 10_000, 50
	ctx := context.Background()
	pendingLocalEvents.clear()
	DrainPendingPackets(true)
	b.Cleanup(func() {
		pendingLocalEvents.clear()
		DrainPendingPackets(true)
	})

	producer, err := events.NewOfflineProducer("Local", events.OfflineSession{
		InputIdentity: "generated-dns-udp-10001-flows-v1", AnalysisProfile: "watch-eventanalysis-v1",
	})
	require.NoError(b, err)
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 128, SinkQueueSize: 128, Producer: producer})
	require.NoError(b, err)
	handler := newLocalTUIEventHandler(nil, true)
	handler.localEventSink = pendingLocalEvents.addBatch
	sink := newLocalEventSink(128, true, handler.OnEventBatch)
	require.NoError(b, dispatcher.Register(sink))
	runtime, err := eventanalysis.New(eventanalysis.Config{Dispatcher: dispatcher, LosslessDelivery: true})
	require.NoError(b, err)
	require.NoError(b, dispatcher.Start(ctx))
	b.Cleanup(func() {
		runtime.Close()
		require.NoError(b, dispatcher.Close(ctx))
	})

	frames := make([][]byte, retained+1)
	for i := range frames {
		frames[i] = benchmarkDNSReplayFrame(b, uint16(10_000+i))
	}
	m := NewModel(retained, 8, "", "", []string{"generated-dns.pcap"}, false, false, "", false)
	m.uiState.Capturing = true
	m.uiState.Tabs.SetActive(0)
	m.uiState.Width, m.uiState.Height = 160, 40
	m.uiState.EventShowDetails = true
	source := eventanalysis.Source{NodeID: "Local", CaptureSource: "pcap", InputFile: "generated-dns.pcap"}
	sequence := 0
	refreshTime := time.Now().Add(time.Hour)
	replayBatch := func() {
		packets := make([]types.PacketDisplay, 0, batchSize)
		for range batchSize {
			raw := frames[sequence%len(frames)]
			sequence++
			packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
			packet.Metadata().Timestamp = time.Unix(1, 0)
			packet.Metadata().CaptureLength, packet.Metadata().Length = len(raw), len(raw)
			if err := runtime.ObservePacket(source, capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, SourcePath: source.InputFile}); err != nil {
				b.Fatal(err)
			}
			fields := capture.ExtractPacketFields(packet)
			packets = append(packets, types.PacketDisplay{
				Timestamp: packet.Metadata().Timestamp, SrcIP: fields.SrcIP, DstIP: fields.DstIP,
				SrcPort: fields.SrcPort, DstPort: fields.DstPort, Protocol: "DNS",
				Length: len(raw), NodeID: "Local",
			})
		}
		if err := dispatcher.Flush(ctx); err != nil {
			b.Fatal(err)
		}
		handler.OnPacketBatch(packets)
		refreshTime = refreshTime.Add(constants.TUITickInterval)
		m, _ = m.handleTickMsg(TickMsg{Time: refreshTime})
	}
	// Seed through the same analysis/delivery path with presentation inactive.
	for range retained / batchSize {
		replayBatch()
	}
	require.Equal(b, uint64(retained), m.eventStore.Stats().Retained)
	require.Equal(b, retained, m.packetStore.Count())
	m.setCaptureView("events")
	_ = m.View()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		replayBatch()
		if output := m.View(); output == "" {
			b.Fatal("empty Events viewport")
		}
	}
	b.StopTimer()
	stats := m.eventStore.Stats()
	require.Equal(b, uint64(sequence), stats.Arrived)
	require.Equal(b, uint64(sequence-retained), stats.Evicted)
	require.Zero(b, stats.TransportLost)
	require.Zero(b, runtime.Stats().Dropped)
	selected, ok := m.eventStore.Selected()
	require.True(b, ok)
	require.Equal(b, uint64(sequence), selected.ArrivalSequence)
	b.ReportMetric(batchSize, "packets/op")
}

func benchmarkDNSReplayFrame(b *testing.B, sourcePort uint16) []byte {
	b.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 53)}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sourcePort), DstPort: 53}
	require.NoError(b, udp.SetNetworkLayerForChecksum(ip))
	dns := &layers.DNS{ID: sourcePort, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(b, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, dns))
	return buffer.Bytes()
}

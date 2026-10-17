//go:build processor || tap || all

package processor

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	packetpcap "github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestLocalOutputsContinueDuringUpstreamSetupOutage(t *testing.T) {
	// Accept TCP but never answer the gRPC handshake. The upstream attempt is
	// demonstrably pending while the local tap processing path delivers output.
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	require.NoError(t, err)
	defer func() { require.NoError(t, listener.Close()) }()
	output := filepath.Join(t.TempDir(), "local.pcap")
	cfg := Config{ProcessorID: "tap", ListenAddr: "127.0.0.1:0", WriteFile: output, UpstreamProcessors: []failover.Endpoint{{Address: listener.Addr().String()}, {Address: "127.0.0.1:1"}}, UpstreamFailover: failover.Config{AttemptTimeout: time.Hour, ReconnectAttempts: 1, RetryInitial: time.Second, RetryMax: time.Minute}}
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	p.pcapWriter, err = packetpcap.NewWriter(output)
	require.NoError(t, err)
	p.pcapWriter.Start(context.Background())
	require.NoError(t, p.upstreamManager.Start())
	require.NoError(t, listener.SetDeadline(time.Now().Add(3*time.Second)))
	pending, err := listener.Accept()
	require.NoError(t, err)
	defer func() { require.NoError(t, pending.Close()) }()
	require.False(t, p.upstreamManager.IsConnected())
	require.Len(t, p.config.UpstreamProcessors, 2)
	local := p.subscriberManager.Add("local-monitor")
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 23456}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload("local capture survives upstream outage")))
	raw := buffer.Bytes()
	packet := &data.CapturedPacket{Data: raw, TimestampNs: time.Now().Truncate(time.Microsecond).UnixNano(), CaptureLength: uint32(len(raw)), OriginalLength: uint32(len(raw)), LinkType: uint32(layers.LinkTypeEthernet), InterfaceName: "local0"}
	batch, err := source.FromProtoBatchE(&data.PacketBatch{HunterId: "tap-local", Sequence: 1, Packets: []*data.CapturedPacket{packet}})
	require.NoError(t, err)
	batch.Envelopes[0].Source.Kind = pipeline.SourceLiveCapture
	processed := make(chan struct{})
	go func() { p.processBatch(batch); close(processed) }()
	select {
	case <-processed:
	case <-time.After(3 * time.Second):
		t.Fatal("local processing waited for unavailable upstream")
	}
	select {
	case delivered := <-local:
		require.Len(t, delivered.Packets, 1)
		require.Equal(t, raw, delivered.Packets[0].Data)
	case <-time.After(time.Second):
		t.Fatal("local subscriber did not receive captured data")
	}
	require.False(t, p.upstreamManager.IsConnected())
	require.NoError(t, p.Shutdown())
	file, err := os.Open(output)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	got, info, err := reader.ReadPacketData()
	require.NoError(t, err)
	require.Equal(t, raw, got)
	require.Equal(t, packet.TimestampNs, info.Timestamp.UnixNano())
}

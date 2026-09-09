//go:build processor || tap || all

package processor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	packetpcap "github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/endorses/lippycat/internal/pkg/testutil/radiusfixture"
)

func radiusOutputFixtures(t *testing.T) []*data.CapturedPacket {
	t.Helper()
	f, err := os.Open(filepath.Join(radiusfixture.Write(t), "acceptance.pcap"))
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	var packets []*data.CapturedPacket
	for range 2 {
		b, ci, err := r.ReadPacketData()
		require.NoError(t, err)
		packets = append(packets, &data.CapturedPacket{Data: b, TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), LinkType: uint32(r.LinkType()), InterfaceName: "eth0", InterfaceIndex: 1})
	}
	return packets
}

func TestRADIUSOrdinaryOutputsPreserveRequestAndResponse(t *testing.T) {
	for _, enablePCAP := range []bool{false, true} {
		t.Run(map[bool]string{false: "broadcast_only", true: "packet_sinks"}[enablePCAP], func(t *testing.T) {
			dir := t.TempDir()
			cfg := Config{ProcessorID: "radius-test", ListenAddr: "127.0.0.1:0", MaxHunters: 2}
			if enablePCAP {
				cfg.WriteFile = filepath.Join(dir, "unified.pcap")
				cfg.AutoRotateConfig = &AutoRotateConfig{Enabled: true, OutputDir: filepath.Join(dir, "rotate"), FilePattern: "{timestamp}.pcap", MaxFileSize: 1 << 20, MaxDuration: time.Hour, MaxIdleTime: time.Hour, BufferSize: 4096, SyncInterval: time.Hour}
				cfg.PcapWriterConfig = &PcapWriterConfig{Enabled: true, OutputDir: filepath.Join(dir, "calls"), FilePattern: "{callid}.pcap", SyncInterval: time.Hour}
			}
			p, err := New(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
			if enablePCAP {
				p.pcapWriter, err = packetpcap.NewWriter(cfg.WriteFile)
				require.NoError(t, err)
			}
			if p.pcapWriter != nil {
				p.pcapWriter.Start(context.Background())
			}
			out := p.subscriberManager.Add("fast")
			packets := radiusOutputFixtures(t)
			// Hostile unrelated protocol metadata must not select a per-call writer or
			// bypass future RADIUS-specific authorization.
			packets[0].Metadata = &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "wrong-call"}, Dns: &data.DNSMetadata{QueryName: "credential"}}
			packets[0].MatchedFilterIds = []string{"untrusted"}
			batch := source.FromProtoBatch(&data.PacketBatch{HunterId: "hunter-a", Packets: packets})
			p.processBatch(batch)
			delivered := <-out
			require.Len(t, delivered.Packets, 2)
			for i, packet := range delivered.Packets {
				require.Equal(t, packets[i].Data, packet.Data)
				require.Equal(t, packets[i].LinkType, packet.LinkType)
				require.Equal(t, packets[i].TimestampNs, packet.TimestampNs)
				require.Equal(t, "RADIUS", packet.Metadata.Protocol)
				require.Nil(t, packet.Metadata.Sip)
				require.Nil(t, packet.Metadata.Dns)
				require.Empty(t, packet.MatchedFilterIds)
				_, err := grpcadapter.RADIUSFromProto(packet)
				require.NoError(t, err)
			}
			require.Equal(t, "request", delivered.Packets[0].Radius.AssociationStatus)
			require.Equal(t, "unique", delivered.Packets[1].Radius.AssociationStatus)
			require.True(t, proto.Equal(delivered.Packets[0].Radius.RequestInstanceId, delivered.Packets[1].Radius.RequestInstanceId))
			require.NoError(t, p.Shutdown())
			if enablePCAP {
				files, err := filepath.Glob(filepath.Join(dir, "rotate", "*.pcap"))
				require.NoError(t, err)
				require.Len(t, files, 1)
				for _, path := range append(files, cfg.WriteFile) {
					f, err := os.Open(path)
					require.NoError(t, err)
					r, err := pcapgo.NewReader(f)
					require.NoError(t, err)
					for _, want := range packets {
						got, ci, err := r.ReadPacketData()
						require.NoError(t, err)
						require.Equal(t, want.Data, got)
						require.Equal(t, want.TimestampNs, ci.Timestamp.UnixNano())
					}
					require.NoError(t, f.Close())
				}
				calls, err := filepath.Glob(filepath.Join(dir, "calls", "*.pcap"))
				require.NoError(t, err)
				require.Empty(t, calls)
			}
		})
	}
}

func TestRADIUSLegacySourceIsolation(t *testing.T) {
	p := &Processor{}
	packets := radiusOutputFixtures(t)
	p.normalizeRADIUS("hunter-a", packets[:1])
	p.normalizeRADIUS("hunter-b", packets[1:])
	require.Equal(t, "missing", packets[1].Radius.AssociationStatus)
	p.radiusCapture.Close()
}

func TestRADIUSSlowSubscriberDoesNotThrottleHunters(t *testing.T) {
	p, err := New(Config{ProcessorID: "radius-test", ListenAddr: "127.0.0.1:0"})
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Shutdown()) }()
	slow := p.subscriberManager.Add("slow")
	fast := p.subscriberManager.Add("fast")
	batch := source.FromProtoBatch(&data.PacketBatch{HunterId: "hunter-a", Packets: radiusOutputFixtures(t)})
	p.processBatch(batch)
	got := <-fast
	require.NotNil(t, got.Packets[1].Radius)
	for range cap(slow) + 2 {
		p.subscriberManager.Broadcast(got)
		require.Len(t, (<-fast).Packets, 2)
	}
	_, drops := p.subscriberManager.GetBackpressureStats()
	require.Greater(t, drops, uint64(0))
	require.Len(t, slow, cap(slow))
	require.Equal(t, data.FlowControl_FLOW_CONTINUE, p.flowController.Determine())
}

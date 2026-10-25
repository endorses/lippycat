//go:build tap || all

package tap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/protocolcatalog"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

type dnsNoticeTapSink struct{ notices chan events.NoticeEvent }

func (s *dnsNoticeTapSink) HandleEvent(ctx context.Context, event events.Event) error {
	select {
	case s.notices <- event.(events.NoticeEvent):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (*dnsNoticeTapSink) Flush(context.Context) error { return nil }
func (*dnsNoticeTapSink) Close(context.Context) error { return nil }

func TestDNSNoticeActualTapRuntimeWritesNoticeLogWithoutCommand(t *testing.T) {
	flag := TapCmd.PersistentFlags().Lookup("no-filter-policy")
	previousPolicy, changed := flag.Value.String(), flag.Changed
	require.NoError(t, TapCmd.PersistentFlags().Set("no-filter-policy", "allow"))
	t.Cleanup(func() { require.NoError(t, flag.Value.Set(previousPolicy)); flag.Changed = changed })
	policy := eventconfig.Default()
	dns := policy.EffectiveDNS()
	dns.DetectTunneling, dns.Threshold, dns.Debounce = true, 0.01, time.Minute
	policy.DNS = &dns
	directory := t.TempDir()
	// libpcap opens this generated PCAP stream as an offline handle. Keeping its
	// writer open lets the actual local-source lifetime remain caller-controlled.
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reader.Close()) })
	closeWriter := sync.OnceFunc(func() { require.NoError(t, writer.Close()) })
	t.Cleanup(closeWriter)
	fixture := &mixedTapInterface{reader: reader}
	frames := pcapgo.NewWriterNanos(writer)
	require.NoError(t, frames.WriteFileHeader(65535, layers.LinkTypeEthernet))
	runtime, err := newTapRuntime(processor.Config{ProcessorID: "tap-notice", ListenAddr: "127.0.0.1:0", FilterFile: filepath.Join(t.TempDir(), "managed", "filters.yaml"), EventAnalysis: &policy, EventQueueSize: 32, GracefulShutdownTimeout: 100 * time.Millisecond,
		LogConfig: &processor.StructuredLogConfig{Enabled: true, Directory: directory, Format: "json", Streams: []string{"notice"}, QueueSize: 16}}, "udp port 53", protocolcatalog.MustLookup("dns"), tapRuntimeHooks{ConfigureSourceConfig: func(config *source.LocalSourceConfig) {
		config.Interfaces, config.BatchSize, config.BatchTimeout, config.BufferSize = []string{"capture0"}, 1, time.Millisecond, 16
		config.CaptureInterfaces = func() []pcaptypes.PcapInterface { return []pcaptypes.PcapInterface{fixture} }
	}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, runtime.processor.Shutdown()) })
	t.Cleanup(runtime.appFilter.Close)
	sink := &dnsNoticeTapSink{notices: make(chan events.NoticeEvent, 4)}
	require.NoError(t, runtime.processor.RegisterEventSink(sink, events.KindNotice))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.processor.Start(ctx) }()
	stop := sync.OnceFunc(func() {
		cancel()
		closeWriter()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("DNS notice tap did not join its local source and processor")
		}
	})
	t.Cleanup(stop)
	require.Eventually(t, runtime.localSource.IsStarted, 5*time.Second, time.Millisecond)
	message := &layers.DNS{ID: 42, RD: true, Questions: []layers.DNSQuestion{{Name: []byte("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.tunnel.example"), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN}}}
	encoded := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(encoded, gopacket.SerializeOptions{FixLengths: true}, message))
	packet, err := eventfixture.NetworkDatagram("192.0.2.10", "192.0.2.53", 42000, 53, encoded.Bytes(), eventfixture.BaseTime)
	require.NoError(t, err)
	require.True(t, runtime.appFilter.MatchPacket(packet.Packet), "the configured capture filter must admit the DNS fixture")
	require.NoError(t, frames.WritePacket(packet.Packet.Metadata().CaptureInfo, packet.Packet.Data()))
	var notice events.NoticeEvent
	select {
	case notice = <-sink.notices:
	case <-time.After(10 * time.Second):
		t.Fatalf("actual tap capture/local source did not emit a canonical DNS notice: source=%+v processor=%+v notices=%+v", runtime.localSource.Stats(), runtime.processor.GetStats(), runtime.processor.GetNoticeStats())
	}
	require.True(t, events.HasValidDeliveryIdentity(notice.Envelope()))
	require.Equal(t, "tap-notice", notice.Envelope().NodeID)
	require.Equal(t, "tap-notice-local", notice.Envelope().Provenance.CaptureSource)
	require.Equal(t, "tap-notice", notice.DetectorNodeID)
	require.NotEmpty(t, notice.DetectorGeneration)
	require.Equal(t, packet.Packet.Metadata().Timestamp.UnixNano(), notice.Envelope().Timestamp.UnixNano())
	require.Equal(t, "tunnel.example", notice.DNS.Domain)
	require.EqualValues(t, 1, runtime.processor.GetNoticeStats().Emitted)
	require.Zero(t, runtime.processor.GetNoticeStats().Commands.Completed)
	// The production processor shutdown drains the configured notice log sink.
	stop()
	content, err := os.ReadFile(filepath.Join(directory, "notice.log"))
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	require.Len(t, lines, 1)
	var record map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &record))
	require.Equal(t, notice.Envelope().EventID, record["event_id"])
	require.Equal(t, "tap-notice", record["node_id"])
	require.Equal(t, "tap-notice", record["detector_node_id"])
	require.Equal(t, "tunnel.example", record["domain"])
	require.Equal(t, events.NoticeDetectorDNSTunneling, record["detector"])
	require.Empty(t, sink.notices)
}

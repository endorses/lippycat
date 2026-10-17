//go:build processor || tap || all

package processor

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/packetdedup"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	processorpcap "github.com/endorses/lippycat/internal/pkg/processor/pcap"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func duplicateTestProcessor(t *testing.T, enabled bool) *Processor {
	t.Helper()
	p, err := newTestProcessor(t, Config{ProcessorID: "overlap", ListenAddr: "127.0.0.1:0", PacketDedup: packetdedup.Settings{Enabled: enabled, Window: time.Minute}, MediaRules: MediaRulesConfig{Sources: []MediaSourceMapping{{HunterID: "*", Interface: "mirror", Domain: mediaadmission.DomainID(1)}}}})
	require.NoError(t, err)
	return p
}
func duplicateTestPacket(t *testing.T) []byte {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, Id: 42, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	udp := &layers.UDP{SrcPort: 4000, DstPort: 5000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, udp, gopacket.Payload([]byte{0x80, 96, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 9})))
	return buffer.Bytes()
}
func duplicateTestBatch(t *testing.T, node string, raw []byte) *source.PacketBatch {
	t.Helper()
	batch, err := source.FromProtoBatchE(&data.PacketBatch{HunterId: node, Packets: []*data.CapturedPacket{{TimestampNs: time.Now().UnixNano(), Data: raw, CaptureLength: uint32(len(raw)), OriginalLength: uint32(len(raw)), LinkType: uint32(layers.LinkTypeRaw), InterfaceName: "mirror", Metadata: &data.PacketMetadata{Protocol: "UDP", Transport: "udp", SrcIp: "192.0.2.1", DstIp: "192.0.2.2", SrcPort: 4000, DstPort: 5000}}}})
	require.NoError(t, err)
	batch.MediaSourceTrusted = true
	return batch
}
func TestPacketDuplicateMonitoringIsIndependentAndQueueRejectionReleases(t *testing.T) {
	p := duplicateTestProcessor(t, true)
	fast := p.subscriberManager.Add("fast")
	full := p.subscriberManager.Add("full")
	for range cap(full) {
		full <- &data.PacketBatch{}
	}
	raw := duplicateTestPacket(t)
	p.processBatch(duplicateTestBatch(t, "a", raw))
	require.Len(t, fast, 1)
	for len(full) > 0 {
		<-full
	}
	p.processBatch(duplicateTestBatch(t, "b", raw))
	require.Len(t, fast, 1, "accepted monitor copy may suppress cross-source overlap")
	require.Len(t, full, 1, "a different monitor's failed first admission must not suppress its eligible alternate")
	require.EqualValues(t, 2, p.packetsReceived.Load(), "ingress counters remain raw observations")
	stats := p.packetDuplicates.Stats()
	require.EqualValues(t, 1, stats.Duplicates)
	require.EqualValues(t, 1, stats.Aborts)
}
func TestPacketDuplicateMonitorEligibilityPrecedesSuppression(t *testing.T) {
	p := duplicateTestProcessor(t, true)
	filtered := p.subscriberManager.Add("selected")
	p.subscriberManager.SetFilter("selected", []string{"b"})
	p.subscriberManager.SetPacketEligibility("selected", func(packet *data.CapturedPacket) bool {
		return packet.Metadata != nil && packet.Metadata.Protocol == "eligible"
	})
	raw := duplicateTestPacket(t)
	a := duplicateTestBatch(t, "a", raw)
	var err error
	a.Envelopes[0].Metadata, err = grpcadapter.MetadataFromProto(&data.PacketMetadata{Protocol: "ineligible"})
	require.NoError(t, err)
	p.processBatch(a)
	require.Empty(t, filtered)
	b := duplicateTestBatch(t, "b", raw)
	b.Envelopes[0].Metadata, err = grpcadapter.MetadataFromProto(&data.PacketMetadata{Protocol: "eligible"})
	require.NoError(t, err)
	p.processBatch(b)
	require.Len(t, filtered, 1)
	require.EqualValues(t, 0, p.packetDuplicates.Stats().Duplicates)
}
func TestPacketDuplicateRequiresVerifiedSourceAndMappedDomain(t *testing.T) {
	for _, mode := range []string{"disabled", "untrusted", "unmapped", "distinct-domain"} {
		t.Run(mode, func(t *testing.T) {
			p := duplicateTestProcessor(t, mode != "disabled")
			out := p.subscriberManager.Add("observer")
			raw := duplicateTestPacket(t)
			a, b := duplicateTestBatch(t, "a", raw), duplicateTestBatch(t, "b", raw)
			switch mode {
			case "untrusted":
				a.MediaSourceTrusted = false
				b.MediaSourceTrusted = false
			case "unmapped":
				a.Envelopes[0].Source.InterfaceName = "elsewhere"
				b.Envelopes[0].Source.InterfaceName = "elsewhere"
			case "distinct-domain":
				p.config.MediaRules.Sources = []MediaSourceMapping{{HunterID: "a", Interface: "mirror", Domain: 1}, {HunterID: "b", Interface: "mirror", Domain: 2}}
			}
			p.processBatch(a)
			p.processBatch(b)
			require.Len(t, out, 2)
			require.EqualValues(t, 2, p.packetsReceived.Load())
		})
	}
}
func TestPacketDuplicateUnifiedPCAPClaimsOnlyAcceptedQueue(t *testing.T) {
	p := duplicateTestProcessor(t, true)
	file := filepath.Join(t.TempDir(), "capture.pcap")
	writer, err := processorpcap.NewWriter(file)
	require.NoError(t, err)
	p.pcapWriter = writer
	raw := duplicateTestPacket(t)
	p.processBatch(duplicateTestBatch(t, "a", raw)) // Not started: queue rejects.
	writer.Start(context.Background())
	p.processBatch(duplicateTestBatch(t, "b", raw))
	p.processBatch(duplicateTestBatch(t, "c", raw))
	require.NoError(t, p.Shutdown())
	input, err := os.Open(file)
	require.NoError(t, err)
	defer func() { require.NoError(t, input.Close()) }()
	reader, err := pcapgo.NewReader(input)
	require.NoError(t, err)
	_, _, err = reader.ReadPacketData()
	require.NoError(t, err)
	_, _, err = reader.ReadPacketData()
	require.ErrorIs(t, err, io.EOF)
	stats := p.packetDuplicates.Stats()
	require.EqualValues(t, 1, stats.Aborts)
	require.EqualValues(t, 1, stats.Duplicates)
}

type duplicateVirtualInterface struct {
	fail    bool
	packets [][]byte
}

func (*duplicateVirtualInterface) Name() string { return "fake" }
func (*duplicateVirtualInterface) Start() error { return nil }
func (v *duplicateVirtualInterface) InjectPacket(packet []byte) error {
	if v.fail {
		return vinterface.ErrQueueFull
	}
	v.packets = append(v.packets, append([]byte(nil), packet...))
	return nil
}
func (*duplicateVirtualInterface) InjectPacketBatch([]types.PacketDisplay) error {
	return errors.New("dedup must use truthful per-packet conversion and admission")
}
func (*duplicateVirtualInterface) Shutdown() error         { return nil }
func (*duplicateVirtualInterface) Stats() vinterface.Stats { return vinterface.Stats{} }
func TestPacketDuplicateVIFRejectionAllowsAlternateAndIndependentMonitor(t *testing.T) {
	p := duplicateTestProcessor(t, true)
	p.config.VirtualInterfaceType = "tun"
	vif := &duplicateVirtualInterface{fail: true}
	p.vifManager = vif
	observer := p.subscriberManager.Add("observer")
	raw := duplicateTestPacket(t)
	p.processBatch(duplicateTestBatch(t, "a", raw))
	vif.fail = false
	p.processBatch(duplicateTestBatch(t, "b", raw))
	require.Len(t, vif.packets, 1)
	require.Len(t, observer, 1, "monitor owns a separate accepted copy")
	require.EqualValues(t, 1, p.vifInjectionErrors.Load())
}

func TestPacketDuplicateEventRuntimeRejectionDoesNotBorrowMonitorAcceptance(t *testing.T) {
	p := duplicateTestProcessor(t, true)
	require.NoError(t, p.RegisterEventSink(&collectingSink{}, events.KindConn))
	require.NoError(t, p.eventDispatcher.Start(context.Background()))
	observer := p.subscriberManager.Add("observer")
	require.NotNil(t, p.eventRuntime)
	p.eventRuntime.Close()
	raw := duplicateTestPacket(t)
	p.processBatch(duplicateTestBatch(t, "a", raw))
	require.Len(t, observer, 1)
	p.eventAnalysisMu.Lock()
	p.eventRuntime = nil
	require.NoError(t, p.initializeEventAnalysisLocked())
	p.eventAnalysisMu.Unlock()
	p.processBatch(duplicateTestBatch(t, "b", raw))
	require.EqualValues(t, 1, p.eventRuntime.Stats().Observed)
	require.Len(t, observer, 1)
	require.EqualValues(t, 1, p.packetDuplicates.Stats().Aborts)
	require.EqualValues(t, 1, p.packetDuplicates.Stats().Duplicates)
}

func TestPacketDuplicateSessionUsesIndependentCallIncarnations(t *testing.T) {
	config := Config{ProcessorID: "session-overlap", ListenAddr: "127.0.0.1:0", PacketDedup: packetdedup.Settings{Enabled: true, Window: time.Minute}, MediaRules: MediaRulesConfig{Sources: []MediaSourceMapping{{HunterID: "*", Interface: "mirror", Domain: 1}}}, PcapWriterConfig: &PcapWriterConfig{Enabled: true, OutputDir: t.TempDir(), FilePattern: "{callid}.pcap", SyncInterval: time.Hour}}
	p, err := newTestProcessor(t, config)
	require.NoError(t, err)
	raw := duplicateTestPacket(t)
	write := func(node string, admission *CallAdmission) {
		t.Helper()
		batch := duplicateTestBatch(t, node, raw)
		projected, err := batch.ToProtoBatchE()
		require.NoError(t, err)
		projected.Packets[0].Metadata = &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "reused-call"}, Rtp: &data.RTPMetadata{Ssrc: 0x01020304, Sequence: 1}}
		require.NoError(t, p.writeConsumerSessionPacket(batch, 0, projected.Packets[0], admission))
	}
	original, err := p.callLifecycle.Admit("reused-call")
	require.NoError(t, err)
	incarnation := original.Incarnation()
	write("a", original)
	original.Release()
	result := p.callLifecycle.Finalize("reused-call", CallFinalizationManual)
	require.True(t, result.Finalized)
	restarted, err := p.callLifecycle.RestartInvite("reused-call")
	require.NoError(t, err)
	require.NotEqual(t, incarnation, restarted.Incarnation())
	write("b", restarted)
	restarted.Release()
	require.EqualValues(t, 2, p.packetDuplicates.Stats().Commits)
	require.Zero(t, p.packetDuplicates.Stats().Duplicates)
}

func TestPacketDuplicatePendingOwnerRetainsAlternateUntilAcceptance(t *testing.T) {
	p := duplicateTestProcessor(t, true)
	raw := duplicateTestPacket(t)
	a, b, c := duplicateTestBatch(t, "a", raw), duplicateTestBatch(t, "b", raw), duplicateTestBatch(t, "c", raw)
	claim, include := p.beginPacketConsumer(a, 0, "test-sink")
	require.True(t, include)
	require.NotNil(t, claim)
	alternate, include := p.beginPacketConsumer(b, 0, "test-sink")
	require.True(t, include, "unaccepted concurrent ownership is never sufficient to suppress")
	require.Nil(t, alternate)
	require.True(t, claim.Abort())
	next, include := p.beginPacketConsumer(c, 0, "test-sink")
	require.True(t, include)
	require.NotNil(t, next)
	require.True(t, next.Commit())
	require.EqualValues(t, 1, p.packetDuplicates.Stats().InFlight)
}

func TestPacketDuplicateCallStateSuppressionPreservesFinalizationVeto(t *testing.T) {
	p := duplicateTestProcessor(t, true)
	batch := duplicateTestBatch(t, "a", duplicateTestPacket(t))
	projected, err := batch.ToProtoBatchE()
	require.NoError(t, err)
	packet := projected.Packets[0]
	packet.Metadata.Sip = &data.SIPMetadata{CallId: "completed"}
	packet.Metadata.Rtp = &data.RTPMetadata{Sequence: 1, Ssrc: 0x01020304}
	admission, err := p.callLifecycle.Admit("completed")
	require.NoError(t, err)
	admission.Release()
	claim, include := p.beginPacketConsumer(batch, 0, "analysis/calls/completed")
	require.True(t, include)
	require.True(t, claim.Commit())
	require.True(t, p.callLifecycle.Finalize("completed", CallFinalizationManual).Finalized)
	other := duplicateTestBatch(t, "b", batch.Envelopes[0].Data)
	_, include = p.beginPacketConsumer(other, 0, "analysis/calls/completed")
	require.False(t, include)
	require.False(t, p.duplicateCallPacketAllowed(packet), "deduplication cannot turn a finalized call into authorized output")
}

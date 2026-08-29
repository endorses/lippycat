//go:build cli || all

package sniff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/vinterface"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestCLIEnvelopeSinkPreservesDisplayContract(t *testing.T) {
	env := testEnvelope(t)
	var output bytes.Buffer
	sink := newCLIEnvelopeSink(&output, "json", false)

	result := sink.HandlePacket(context.Background(), env)
	require.Equal(t, pipeline.OutcomeAccepted, result.Outcome)
	require.NoError(t, result.Err)

	var display types.PacketDisplay
	require.NoError(t, json.Unmarshal(output.Bytes(), &display))
	require.Equal(t, env.CaptureTime, display.Timestamp)
	require.Equal(t, "pcap0", display.Interface)
	require.Equal(t, uint32(env.LinkType), uint32(display.LinkType))
	require.Equal(t, "192.0.2.1", display.SrcIP)
	require.Equal(t, "198.51.100.2", display.DstIP)
}

func TestCLIEnvelopeSinkQuietIsIntentionalFilter(t *testing.T) {
	var output bytes.Buffer
	result := newCLIEnvelopeSink(&output, "json", true).HandlePacket(context.Background(), testEnvelope(t))
	require.Equal(t, pipeline.OutcomeFiltered, result.Outcome)
	require.Empty(t, output.String())
}

func TestPCAPEnvelopeSinkPreservesHeaderAndCaptureInfo(t *testing.T) {
	env := testEnvelope(t)
	path := filepath.Join(t.TempDir(), "output.pcap")
	sink, err := newPCAPEnvelopeSink(path)
	require.NoError(t, err)
	require.Equal(t, pipeline.OutcomeAccepted, sink.HandlePacket(context.Background(), env).Outcome)
	require.NoError(t, sink.Close(context.Background()))
	require.NoError(t, sink.Close(context.Background()), "close must be idempotent")

	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	reader, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	require.Equal(t, env.LinkType, reader.LinkType())
	data, ci, err := reader.ReadPacketData()
	require.NoError(t, err)
	require.Equal(t, env.Data, data)
	require.Equal(t, env.CaptureTime, ci.Timestamp)
	require.Equal(t, env.CaptureLength, ci.CaptureLength)
	require.Equal(t, env.OriginalLength, ci.Length)
}

func TestVirtualInterfaceEnvelopeSinkReportsQueueFullAsDrop(t *testing.T) {
	sink := &virtualInterfaceEnvelopeSink{manager: &stubVIFManager{injectErr: vinterface.ErrQueueFull}}

	result := sink.HandlePacket(context.Background(), testEnvelope(t))

	require.Equal(t, pipeline.OutcomeDropped, result.Outcome)
	require.Equal(t, pipeline.DropQueueFull, result.DropReason)
	require.NoError(t, result.Err)
}

func TestVirtualInterfaceEnvelopeSinkReportsOtherErrorsAsRetryable(t *testing.T) {
	injectErr := errors.New("write failed")
	sink := &virtualInterfaceEnvelopeSink{manager: &stubVIFManager{injectErr: injectErr}}

	result := sink.HandlePacket(context.Background(), testEnvelope(t))

	require.Equal(t, pipeline.OutcomeRetryableFailure, result.Outcome)
	require.ErrorIs(t, result.Err, injectErr)
}

type stubVIFManager struct {
	injectErr error
}

func (*stubVIFManager) Name() string                                    { return "test0" }
func (*stubVIFManager) Start() error                                    { return nil }
func (*stubVIFManager) InjectPacket([]byte) error                       { return nil }
func (m *stubVIFManager) InjectPacketBatch([]types.PacketDisplay) error { return m.injectErr }
func (*stubVIFManager) Shutdown() error                                 { return nil }
func (*stubVIFManager) Stats() vinterface.Stats                         { return vinterface.Stats{} }

func testEnvelope(t *testing.T) *pipeline.PacketEnvelope {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{198, 51, 100, 2}}
	udp := &layers.UDP{SrcPort: 12345, DstPort: 53}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload([]byte("payload"))))
	ts := time.Date(2026, 8, 29, 12, 34, 56, 789000, time.UTC)
	return &pipeline.PacketEnvelope{Data: buf.Bytes(), LinkType: layers.LinkTypeEthernet, CaptureTime: ts, CaptureLength: len(buf.Bytes()), OriginalLength: len(buf.Bytes()), Source: pipeline.SourceProvenance{Kind: pipeline.SourcePCAPReplay, InterfaceName: "pcap0"}}
}

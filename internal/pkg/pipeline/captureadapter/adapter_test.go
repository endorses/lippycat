package captureadapter

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestFromPacketInfoPreservesCaptureRecord(t *testing.T) {
	ts := time.Unix(123, 456)
	p := gopacket.NewPacket([]byte{0, 1, 2, 3}, layers.LinkTypeRaw, gopacket.Default)
	p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: ts, CaptureLength: 4, Length: 40}
	e := FromPacketInfo(capture.PacketInfo{Packet: p, LinkType: layers.LinkTypeRaw, Interface: "any0"})
	require.Equal(t, []byte{0, 1, 2, 3}, e.Data)
	require.Equal(t, ts, e.CaptureTime)
	require.Equal(t, 4, e.CaptureLength)
	require.Equal(t, 40, e.OriginalLength)
	require.Equal(t, "any0", e.Source.InterfaceName)
	require.Equal(t, layers.LinkTypeRaw, e.LinkType)
}

func TestEnvelopePacketRestoresCaptureMetadata(t *testing.T) {
	ts := time.Unix(987, 654)
	envelope := &pipeline.PacketEnvelope{
		Data: []byte{0x45, 0, 0, 20}, LinkType: layers.LinkTypeRaw,
		CaptureTime: ts, CaptureLength: 4, OriginalLength: 20,
	}

	packet := envelope.Packet()
	require.Equal(t, gopacket.CaptureInfo{Timestamp: ts, CaptureLength: 4, Length: 20}, packet.Metadata().CaptureInfo)
	require.True(t, envelope.Stages.Has(pipeline.StageDecoded))
}

func TestFromPacketInfoInfersMissingLinkType(t *testing.T) {
	data := make([]byte, 14)
	data[12], data[13] = 0x08, 0x00
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	envelope := FromPacketInfo(capture.PacketInfo{Packet: packet})
	require.Equal(t, layers.LinkTypeEthernet, envelope.LinkType)
}

func TestPacketInfoRoundTripPreservesCaptureRecordAndReplayProvenance(t *testing.T) {
	ts := time.Unix(1712345678, 123456789)
	original := gopacket.NewPacket([]byte{0x45, 0, 0, 20}, layers.LinkTypeRaw, gopacket.Default)
	original.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: ts, CaptureLength: 4, Length: 20}
	in := capture.PacketInfo{Packet: original, LinkType: layers.LinkTypeRaw, Interface: "pcap0"}

	envelope := FromPacketInfo(in, pipeline.SourcePCAPReplay)
	require.Equal(t, pipeline.SourcePCAPReplay, envelope.Source.Kind)
	out := ToPacketInfo(envelope)

	require.Equal(t, in.Interface, out.Interface)
	require.Equal(t, in.LinkType, out.LinkType)
	require.Equal(t, in.Packet.Data(), out.Packet.Data())
	require.Equal(t, in.Packet.Metadata().CaptureInfo, out.Packet.Metadata().CaptureInfo)
}

func TestForEachPreservesOrderAndReplayProvenance(t *testing.T) {
	first := gopacket.NewPacket([]byte{0x45, 0, 0, 20}, layers.LayerTypeIPv4, gopacket.Default)
	second := gopacket.NewPacket([]byte{0x45, 0, 0, 21}, layers.LayerTypeIPv4, gopacket.Default)
	first.Metadata().Timestamp = time.Unix(1, 0)
	second.Metadata().Timestamp = time.Unix(2, 0)
	in := make(chan capture.PacketInfo, 2)
	in <- capture.PacketInfo{Packet: first, LinkType: layers.LinkTypeRaw, Interface: "one.pcap"}
	in <- capture.PacketInfo{Packet: second, LinkType: layers.LinkTypeRaw, Interface: "two.pcap"}
	close(in)

	var got []*pipeline.PacketEnvelope
	ForEach(in, pipeline.SourcePCAPReplay, func(env *pipeline.PacketEnvelope) { got = append(got, env) })

	require.Len(t, got, 2)
	require.Equal(t, time.Unix(1, 0), got[0].CaptureTime)
	require.Equal(t, time.Unix(2, 0), got[1].CaptureTime)
	require.Equal(t, "one.pcap", got[0].Source.InterfaceName)
	require.Equal(t, "two.pcap", got[1].Source.InterfaceName)
	require.Equal(t, pipeline.SourcePCAPReplay, got[0].Source.Kind)
}

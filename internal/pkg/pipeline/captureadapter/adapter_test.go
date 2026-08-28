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

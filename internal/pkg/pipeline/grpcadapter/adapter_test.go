package grpcadapter

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPacketBatchRoundTrip(t *testing.T) {
	in := &data.PacketBatch{HunterId: "hunter-a", Sequence: 42, TimestampNs: 1712345678123456789, Stats: &data.BatchStats{TotalCaptured: 99, FilteredMatched: 7, Dropped: 6, BufferUsage: 31, CaptureBufferRegularDrops: 2, CaptureBufferSipDrops: 1, BatchChannelDrops: 3}, Packets: []*data.CapturedPacket{{Data: []byte{1, 2, 3, 4}, TimestampNs: 1712345678000000001, CaptureLength: 4, OriginalLength: 64, InterfaceIndex: 3, InterfaceName: "eth9", LinkType: 1, MatchedFilterIds: []string{"filter-b", "filter-a"}, Metadata: &data.PacketMetadata{Protocol: "SIP", SrcIp: "192.0.2.1", DstIp: "198.51.100.2", SrcPort: 5060, DstPort: 5061, Transport: "UDP", Info: "INVITE", Details: map[string]string{"call": "abc"}, Sip: &data.SIPMetadata{Method: "INVITE", CallId: "call-1", CseqMethod: "INVITE", FromUri: "sip:a@example.test", ToUri: "sip:b@example.test"}}, TlsKeys: &data.TLSSessionKeys{ClientRandom: []byte{9, 8}, TlsVersion: 0x0304, CipherSuite: 0x1301, SrcIp: "192.0.2.1", SrcPort: 5060, DstIp: "198.51.100.2", DstPort: 5061}}}}
	domain, err := FromPacketBatch(in)
	require.NoError(t, err)
	require.Equal(t, "hunter-a", domain.Packets[0].Source.NodeID)
	require.Equal(t, in.Packets[0].TimestampNs, domain.Packets[0].CaptureTime.UnixNano())
	require.True(t, domain.Packets[0].Stages.Has(pipeline.StageDetected))
	out, err := ToPacketBatch(domain)
	require.NoError(t, err)
	require.True(t, proto.Equal(in, out), "protobuf batch changed after domain round trip")
}

func TestFromCapturedPacketDoesNotInferAnalysisFromMetadata(t *testing.T) {
	in := &data.CapturedPacket{Metadata: &data.PacketMetadata{Protocol: "HTTP"}}

	envelope, err := FromCapturedPacket(in, pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture})
	require.NoError(t, err)
	require.False(t, envelope.Stages.Has(pipeline.StageDetected))
	require.False(t, envelope.Stages.Has(pipeline.StageAnalyzed))
}

func TestEnvelopeGRPCRoundTripPreservesTransportFields(t *testing.T) {
	metadata := &data.PacketMetadata{
		Protocol: "SIP", SrcIp: "192.0.2.1", DstIp: "198.51.100.2",
		SrcPort: 5060, DstPort: 5061, Transport: "UDP", Info: "INVITE",
		Details: map[string]string{"call": "abc"},
	}
	payload, err := proto.Marshal(metadata)
	require.NoError(t, err)
	capturedAt := time.Unix(1712345678, 123456789)
	createdAt := time.Unix(1712345680, 987654321)
	in := &pipeline.PacketBatch{
		Source:   pipeline.SourceProvenance{Kind: pipeline.SourceGRPC, NodeID: "hunter-a"},
		Sequence: 42, CreatedAt: createdAt,
		Packets: []*pipeline.PacketEnvelope{{
			Data: []byte{1, 2, 3, 4}, LinkType: layers.LinkTypeEthernet,
			CaptureTime: capturedAt, CaptureLength: 4, OriginalLength: 64,
			Source:                    pipeline.SourceProvenance{Kind: pipeline.SourceGRPC, NodeID: "hunter-a", InterfaceName: "eth9", InterfaceIndex: 3},
			MatchedFilterIDs:          []string{"filter-b", "filter-a"},
			DirectMatchedFilterIDs:    []string{"filter-b"},
			InheritedMatchedFilterIDs: []string{"filter-a"},
			Metadata:                  &pipeline.Metadata{Encoding: pipeline.MetadataProtobuf, Payload: payload},
		}},
	}

	wire, err := ToPacketBatch(in)
	require.NoError(t, err)
	out, err := FromPacketBatch(wire)
	require.NoError(t, err)
	require.Equal(t, in.Source.NodeID, out.Source.NodeID)
	require.Equal(t, in.Sequence, out.Sequence)
	require.Equal(t, in.CreatedAt, out.CreatedAt)
	require.Equal(t, in.Packets[0].Data, out.Packets[0].Data)
	require.Equal(t, in.Packets[0].LinkType, out.Packets[0].LinkType)
	require.Equal(t, in.Packets[0].CaptureTime, out.Packets[0].CaptureTime)
	require.Equal(t, in.Packets[0].CaptureLength, out.Packets[0].CaptureLength)
	require.Equal(t, in.Packets[0].OriginalLength, out.Packets[0].OriginalLength)
	require.Equal(t, in.Packets[0].Source.InterfaceName, out.Packets[0].Source.InterfaceName)
	require.Equal(t, in.Packets[0].Source.InterfaceIndex, out.Packets[0].Source.InterfaceIndex)
	require.Equal(t, in.Packets[0].MatchedFilterIDs, out.Packets[0].MatchedFilterIDs)
	require.Equal(t, in.Packets[0].DirectMatchedFilterIDs, out.Packets[0].DirectMatchedFilterIDs)
	require.Equal(t, in.Packets[0].InheritedMatchedFilterIDs, out.Packets[0].InheritedMatchedFilterIDs)
	require.True(t, proto.Equal(metadata, wire.Packets[0].Metadata))
	require.Equal(t, payload, out.Packets[0].Metadata.Payload)
}

func TestPacketBatchRoundTripPreservesAbsentOptionalValues(t *testing.T) {
	in := &data.PacketBatch{HunterId: "hunter-empty", Packets: []*data.CapturedPacket{{}}}
	domain, err := FromPacketBatch(in)
	require.NoError(t, err)
	out, err := ToPacketBatch(domain)
	require.NoError(t, err)
	require.True(t, proto.Equal(in, out))
}

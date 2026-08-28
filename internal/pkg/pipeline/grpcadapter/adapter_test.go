package grpcadapter

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPacketBatchRoundTrip(t *testing.T) {
	in := &data.PacketBatch{HunterId: "hunter-a", Sequence: 42, TimestampNs: 1712345678123456789, Stats: &data.BatchStats{TotalCaptured: 99, FilteredMatched: 7, Dropped: 2, BufferUsage: 31}, Packets: []*data.CapturedPacket{{Data: []byte{1, 2, 3, 4}, TimestampNs: 1712345678000000001, CaptureLength: 4, OriginalLength: 64, InterfaceIndex: 3, InterfaceName: "eth9", LinkType: 1, MatchedFilterIds: []string{"filter-b", "filter-a"}, Metadata: &data.PacketMetadata{Protocol: "SIP", SrcIp: "192.0.2.1", DstIp: "198.51.100.2", SrcPort: 5060, DstPort: 5061, Transport: "UDP", Info: "INVITE", Details: map[string]string{"call": "abc"}, Sip: &data.SIPMetadata{Method: "INVITE", CallId: "call-1", CseqMethod: "INVITE", FromUri: "sip:a@example.test", ToUri: "sip:b@example.test"}}, TlsKeys: &data.TLSSessionKeys{ClientRandom: []byte{9, 8}, TlsVersion: 0x0304, CipherSuite: 0x1301, SrcIp: "192.0.2.1", SrcPort: 5060, DstIp: "198.51.100.2", DstPort: 5061}}}}
	domain, err := FromPacketBatch(in)
	require.NoError(t, err)
	require.Equal(t, "hunter-a", domain.Packets[0].Source.NodeID)
	require.Equal(t, in.Packets[0].TimestampNs, domain.Packets[0].CaptureTime.UnixNano())
	require.True(t, domain.Packets[0].Stages.Has(pipeline.StageDetected))
	out, err := ToPacketBatch(domain)
	require.NoError(t, err)
	require.True(t, proto.Equal(in, out), "protobuf batch changed after domain round trip")
}

func TestPacketBatchRoundTripPreservesAbsentOptionalValues(t *testing.T) {
	in := &data.PacketBatch{HunterId: "hunter-empty", Packets: []*data.CapturedPacket{{}}}
	domain, err := FromPacketBatch(in)
	require.NoError(t, err)
	out, err := ToPacketBatch(domain)
	require.NoError(t, err)
	require.True(t, proto.Equal(in, out))
}

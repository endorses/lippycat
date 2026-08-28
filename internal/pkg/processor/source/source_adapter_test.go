//go:build all || processor || tap

package source

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestProtoBatchBoundaryNormalizationRoundTrip(t *testing.T) {
	in := &data.PacketBatch{
		HunterId: "hunter-a", Sequence: 7, TimestampNs: 1234,
		Packets: []*data.CapturedPacket{{
			Data: []byte{1, 2, 3}, TimestampNs: 1200, CaptureLength: 3,
			OriginalLength: 9, InterfaceName: "eth0", LinkType: 1,
			MatchedFilterIds: []string{"filter-a"},
			Metadata:         &data.PacketMetadata{Protocol: "DNS"},
		}},
	}

	batch, err := FromProtoBatchE(in)
	require.NoError(t, err)
	require.Len(t, batch.Envelopes, 1)
	require.Equal(t, pipeline.SourceGRPC, batch.Envelopes[0].Source.Kind)
	require.True(t, batch.Envelopes[0].Stages.Has(pipeline.StageFiltered))

	out, err := batch.ToProtoBatchE()
	require.NoError(t, err)
	require.True(t, proto.Equal(in, out))
}

func TestProtoBatchBoundaryPreservesProcessorEnrichment(t *testing.T) {
	in := &data.PacketBatch{HunterId: "hunter-a", Packets: []*data.CapturedPacket{{Data: []byte{1}}}}
	batch, err := FromProtoBatchE(in)
	require.NoError(t, err)
	batch.Packets[0].Metadata = &data.PacketMetadata{Protocol: "HTTP", Info: "GET /"}

	out, err := batch.ToProtoBatchE()
	require.NoError(t, err)
	require.Equal(t, "HTTP", out.Packets[0].Metadata.Protocol)
	require.Equal(t, "GET /", out.Packets[0].Metadata.Info)
}

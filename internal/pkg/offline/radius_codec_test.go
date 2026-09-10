package offline

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func radiusMetadataFixture() *types.RADIUSMetadata {
	return &types.RADIUSMetadata{Code: 2, CodeName: "Access-Accept", Identifier: 42,
		MessageLength: 64, Association: "matched", ObservationID: "epoch:2", RequestID: "epoch:1",
		Attributes: []string{"Framed-IP-Address=192.0.2.1"}}
}

func TestCodecRADIUSRoundTripAndOldVersionRejection(t *testing.T) {
	original := Detail{ID: 7, Packet: types.PacketDisplay{Protocol: "RADIUS", RADIUSData: radiusMetadataFixture()}}
	var encoded bytes.Buffer
	_, err := writeRecord(&encoded, recordKindDetail, original.ID, original, 1<<20)
	require.NoError(t, err)
	var decoded Detail
	_, err = readRecordAt(bytes.NewReader(encoded.Bytes()), 0, recordKindDetail, original.ID, 1<<20, &decoded)
	require.NoError(t, err)
	require.Equal(t, original, decoded)
	old := bytes.Clone(encoded.Bytes())
	binary.LittleEndian.PutUint16(old[4:6], 1)
	untouched := Detail{ID: 99}
	_, err = readRecordAt(bytes.NewReader(old), 0, recordKindDetail, original.ID, 1<<20, &untouched)
	require.ErrorContains(t, err, "version")
	require.Equal(t, Detail{ID: 99}, untouched)
	encoded.Reset()
	_, err = writeStreamHeader(&encoded, recordKindDetail)
	require.NoError(t, err)
	binary.LittleEndian.PutUint16(encoded.Bytes()[8:10], 1)
	require.ErrorContains(t, readStreamHeader(bytes.NewReader(encoded.Bytes()), recordKindDetail), "version")
}

func TestCompactRADIUSMetadataRoundTripAndOwnership(t *testing.T) {
	s, builder, detail, provenance := compactReviewBuilder(t)
	detail.Packet.Protocol = "RADIUS"
	detail.Packet.RADIUSData = radiusMetadataFixture()
	want := cloneCompactDetail(detail, detail.Packet.RawData)
	require.NoError(t, builder.AppendCompact(context.Background(), want, provenance))
	// The clone used by asynchronous ingestion must own the attribute slice.
	detail.Packet.RADIUSData.Attributes[0] = "changed"
	require.Equal(t, radiusMetadataFixture(), want.Packet.RADIUSData)
	dataset, err := builder.Finish(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dataset.Close()) })
	got, err := dataset.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.NoError(t, err)
	require.Equal(t, want.Packet.RADIUSData, got.Packet.RADIUSData)
	require.Equal(t, "RADIUS", got.Packet.Protocol)
	s.discardDatasetCache(dataset.(*diskDataset))
	got.Packet.RADIUSData.Attributes[0] = "caller mutation"
	again, err := dataset.Detail(context.Background(), Token{Dataset: 17}, 0)
	require.NoError(t, err)
	require.Equal(t, want.Packet.RADIUSData, again.Packet.RADIUSData)
	// A finalized absent value must also override a decoder's provisional value.
	cleared := metadataDifference(compactMetadata{}, metadataOf(want.Packet))
	cleared.apply(&got.Packet)
	require.Nil(t, got.Packet.RADIUSData)
}

package offline

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestTLSObservationMetadataPersistsInBothOfflineFormats(t *testing.T) {
	for _, metadata := range []types.TLSMetadata{{}, {ClientHelloObserved: true}, {ClientHelloObserved: true, ECHOffered: true}} {
		original := Detail{ID: 1, Packet: types.PacketDisplay{TLSData: &metadata}}
		var output bytes.Buffer
		_, err := writeRecord(&output, recordKindDetail, original.ID, original, 1<<20)
		require.NoError(t, err)
		var decoded Detail
		_, err = readRecordAt(bytes.NewReader(output.Bytes()), 0, recordKindDetail, original.ID, 1<<20, &decoded)
		require.NoError(t, err)
		require.Equal(t, &metadata, decoded.Packet.TLSData)
		// The older declaration-order format must be rejected rather than decoded
		// with the changed TLS payload layout.
		previous := bytes.Clone(output.Bytes())
		binary.LittleEndian.PutUint16(previous[4:6], 6)
		_, err = readRecordAt(bytes.NewReader(previous), 0, recordKindDetail, original.ID, 1<<20, &decoded)
		require.Error(t, err)
		compact := compactMetadata{TLS: &metadata}
		wire, err := encodeCompactValue(compact, 1<<20)
		require.NoError(t, err)
		var read compactMetadata
		require.NoError(t, decodeCompactValue(wire, &read, 1<<20))
		require.Equal(t, compact, read)
	}
}

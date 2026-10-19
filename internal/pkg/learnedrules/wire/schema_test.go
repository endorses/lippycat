package wire

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	evidence "github.com/endorses/lippycat/api/gen/learnedevidence"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Independent vectors freeze field 16's existing raw MediaRule bytes and field
// 17's tagged evidence envelope. Neither vector is produced by our codecs.
func TestPacketEvidenceFieldNumbersAndSharedSchemaDependencies(t *testing.T) {
	legacy := &data.CapturedPacket{}
	require.NoError(t, proto.Unmarshal([]byte{0x82, 0x01, 0x03, 0x0a, 0x01, 'x'}, legacy))
	require.Equal(t, []byte{0x0a, 0x01, 'x'}, legacy.CaptureSelectionProof)
	require.Nil(t, legacy.LearnedCaptureEvidence)
	encoded, err := proto.Marshal(legacy)
	require.NoError(t, err)
	require.Equal(t, []byte{0x82, 0x01, 0x03, 0x0a, 0x01, 'x'}, encoded)
	current := &data.CapturedPacket{}
	require.NoError(t, proto.Unmarshal([]byte{0x8a, 0x01, 0x04, 0x08, 0x01, 0x18, 0x01}, current))
	require.Empty(t, current.CaptureSelectionProof)
	require.Equal(t, &evidence.LearnedCaptureEvidence{Version: 1, Overflow: true}, current.LearnedCaptureEvidence)
	require.Equal(t, 0, evidence.File_learned_evidence_proto.Imports().Len(), "shared evidence must not import data or management/control schemas")
}

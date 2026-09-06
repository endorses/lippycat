package offline

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCompactMetadataEndsMatchGenericBytesAndBudgets(t *testing.T) {
	var compressed, uncompressed bool
	values := []compactOverrides{
		{},
		{Mask: 31, Metadata: compactMetadata{VoIP: &types.VoIPMetadata{}, DNS: &types.DNSMetadata{Answers: []types.DNSAnswer{}}, Email: &types.EmailMetadata{RcptTo: []string{}}, TLS: &types.TLSMetadata{}, HTTP: &types.HTTPMetadata{Headers: map[string]string{}}}},
		{Mask: 1, Metadata: compactMetadata{VoIP: &types.VoIPMetadata{CallID: "call", RawSIP: []byte(strings.Repeat("INVITE sip:user@example.test\r\n", 200)), Headers: map[string]string{"Via": "SIP/2.0/UDP host.test", "To": "user@example.test"}}}},
		{Mask: 31, Metadata: compactMetadata{DNS: &types.DNSMetadata{Answers: []types.DNSAnswer{{Name: "example.test", Data: "192.0.2.1"}}}, Email: &types.EmailMetadata{RcptTo: []string{"a@test", "b@test"}}, HTTP: &types.HTTPMetadata{Headers: map[string]string{"Content-Type": "text/plain"}}}},
	}
	for _, cache := range []uint64{128 << 10, 64 << 20} {
		s, b, _, _ := compactReviewBuilder(t)
		s.limits.CacheBytes = cache
		for _, value := range values {
			for _, max := range []uint64{32, 128, 512, 1024, 2048, 4096, 8192} {
				s.limits.MaxRecordBytes = max
				encoded, oldErr := encodeCompactValue(value, max)
				var oldOff, oldSize uint64
				if oldErr == nil {
					oldOff, oldSize, oldErr = b.writeCompactBlock(b.d.details, 4, 0, [][]byte{encoded})
				}
				off, size, err := b.writeCompactMetadata(0, value)
				require.Equal(t, oldErr == nil, err == nil, "cache=%d max=%d", cache, max)
				if oldErr != nil {
					require.EqualError(t, err, oldErr.Error())
					continue
				}
				require.Equal(t, oldSize, size)
				oldBytes, newBytes := make([]byte, oldSize), make([]byte, size)
				_, err = b.d.details.ReadAt(oldBytes, int64(oldOff))
				require.NoError(t, err)
				_, err = b.d.details.ReadAt(newBytes, int64(off))
				require.NoError(t, err)
				require.Equal(t, oldBytes, newBytes)
				if binary.LittleEndian.Uint16(newBytes[22:]) == 1 {
					compressed = true
				} else {
					uncompressed = true
				}
			}
		}
		require.NoError(t, b.Close())
		require.Zero(t, s.Resources().InFlightBytes)
	}
	require.True(t, compressed, "matrix must exercise compressed metadata blocks")
	require.True(t, uncompressed, "matrix must exercise uncompressed metadata blocks")
}

func TestCompactGenericMetadataStillRejectsMalformedRows(t *testing.T) {
	_, b, _, _ := compactReviewBuilder(t)
	value := compactOverrides{Mask: 1, Metadata: compactMetadata{VoIP: &types.VoIPMetadata{CallID: "call"}}}
	encoded, err := encodeCompactValue(value, b.d.storage.limits.MaxRecordBytes)
	require.NoError(t, err)
	for end := 0; end < len(encoded); end++ {
		_, _, err = b.writeCompactBlock(b.d.details, 4, 0, [][]byte{encoded[:end]})
		require.Error(t, err)
	}
	_, _, err = b.writeCompactBlock(b.d.details, 4, 0, [][]byte{append(encoded, 0)})
	require.Error(t, err)
	require.NoError(t, b.Close())
}

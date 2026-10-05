package mediaadmission

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShadowSamplingFixedByteOrderAndBounds(t *testing.T) {
	sequence := make([]byte, 256)
	for i := range sequence {
		sequence[i] = byte(i)
	}
	for _, tc := range []struct {
		domain DomainID
		frame  []byte
		want   uint32
	}{
		{0, []byte{0}, 0x2c3e4a97},
		{1, []byte{0}, 0xe5240731},
		{0, sequence, 0x242305a4},
		{0x12345678, []byte{1, 2, 3}, 0x24796794},
	} {
		require.Equal(t, tc.want, ShadowSamplingHash(tc.domain, uint32(len(tc.frame)), tc.frame))
		require.True(t, ShadowFrameEligible(tc.domain, tc.frame, 1))
		require.False(t, ShadowFrameEligible(tc.domain, tc.frame, 0))
		for _, interval := range []uint32{2, 7, 256} {
			want := tc.want%interval == 0
			require.Equal(t, want, ShadowFrameEligible(tc.domain, tc.frame, interval))
			require.Equal(t, want, ShadowFrameEligible(tc.domain, append([]byte(nil), tc.frame...), interval), "identical duplicates share eligibility")
		}
	}
	for _, size := range []int{0, 257, 4096} {
		require.False(t, ShadowFrameEligible(0, make([]byte, size), 1))
	}
	for _, size := range []int{1, 255, 256} {
		require.True(t, ShadowFrameEligible(0, make([]byte, size), 1))
	}
	require.NotEqual(t, ShadowSamplingHash(0, 255, sequence[:255]), ShadowSamplingHash(0, 256, sequence))
}

func TestShadowSamplingUsesMediaPayloadVariation(t *testing.T) {
	frame := make([]byte, 256)
	selected := 0
	for i := uint32(0); i < 4096; i++ {
		// Endpoint headers and the first 252 bytes stay identical. Variation at
		// the complete-frame boundary still changes sampling eligibility.
		binary.LittleEndian.PutUint32(frame[252:], i)
		if ShadowFrameEligible(2, frame, 8) {
			selected++
		}
	}
	require.InDelta(t, 512, selected, 80, "sample identities across payload variation rather than whole streams")
}

package offline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompactColumnEndsReuseAndAdmission(t *testing.T) {
	s, b, _, _ := compactReviewBuilder(t)
	before := s.Resources().InFlightBytes
	first, err := b.compactColumnEnds(128)
	require.NoError(t, err)
	first[0] = 123
	require.Equal(t, before+128*4, s.Resources().InFlightBytes)
	again, err := b.compactColumnEnds(64)
	require.NoError(t, err)
	require.Same(t, &first[0], &again[0])
	require.EqualValues(t, 123, again[0])
	require.Equal(t, before+128*4, s.Resources().InFlightBytes)

	// Growing a retained table must admit the new allocation before releasing
	// the old one; failure preserves both the existing table and its charge.
	held := s.limits.CacheBytes - s.Resources().InFlightBytes - 1
	require.NoError(t, s.reserveMemory(context.Background(), held))
	beforeFailure := s.Resources()
	_, err = b.compactColumnEnds(256)
	require.Error(t, err)
	require.Equal(t, beforeFailure, s.Resources())
	require.Same(t, &first[0], &b.d.compact.columnEnds[0])
	s.releaseMemory(held)
	require.NoError(t, b.Close())
	require.Nil(t, b.d.compact.columnEnds)
	require.Zero(t, s.Resources().InFlightBytes)
}

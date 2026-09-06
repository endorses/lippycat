package offline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourcePeaksIncludeCoexistenceAndSurviveCleanup(t *testing.T) {
	s := newTestStorage(t)
	a, err := s.NewScratchFile()
	require.NoError(t, err)
	b, err := s.NewScratchFile()
	require.NoError(t, err)
	_, err = a.Write(make([]byte, 100))
	require.NoError(t, err)
	_, err = b.Write(make([]byte, 200))
	require.NoError(t, err)
	require.NoError(t, a.Close())
	require.NoError(t, b.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.EqualValues(t, 300, s.Peaks().DiskBytes)
	require.NoError(t, s.reserveMemory(context.Background(), 100))
	s.cacheFrame(cacheKey{}, make([]byte, 50))
	require.EqualValues(t, 342, s.Peaks().MemoryBytes)
	s.releaseMemory(100)
	s.discardDatasetCache(nil)
	require.Zero(t, s.Resources().CachedBytes)
	require.Error(t, s.reserveMemory(context.Background(), s.limits.CacheBytes+1))
	require.Error(t, s.reserveDisk(s.limits.DiskBytes+1))
	require.Equal(t, ResourcePeaks{DiskBytes: 300, MemoryBytes: 342}, s.Peaks())
	require.NoError(t, s.Close())
}

package offline

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScratchSharedBudgetAndReset(t *testing.T) {
	s := newTestStorage(t)
	d := testStorageDataset(t, s)
	baseline := s.Resources().DiskBytes
	s.limits.DiskBytes = baseline + 12
	f, err := s.NewScratchFile()
	require.NoError(t, err)
	_, err = f.Write([]byte("abcdefgh"))
	require.NoError(t, err)
	require.Equal(t, baseline+8, s.Resources().DiskBytes)
	_, err = f.Write([]byte("12345"))
	require.ErrorContains(t, err, "disk budget")
	require.Equal(t, baseline+8, s.Resources().DiskBytes)
	data := make([]byte, 4)
	_, err = f.ReadAt(data, 2)
	require.NoError(t, err)
	require.Equal(t, "cdef", string(data))
	require.NoError(t, f.Reset())
	require.Equal(t, baseline, s.Resources().DiskBytes)
	_, err = f.Write([]byte("new"))
	require.NoError(t, err)
	require.NoError(t, f.Close())
	require.NoError(t, f.Close())
	require.Equal(t, baseline, s.Resources().DiskBytes)
	_, err = d.Detail(context.Background(), Token{Dataset: 1}, 0)
	require.NoError(t, err)
	require.NoError(t, d.Close())
	require.NoError(t, s.Close())
}

func TestScratchFailedCleanupRetainsChargeAndOwner(t *testing.T) {
	s := newTestStorage(t)
	f, err := s.NewScratchFile()
	require.NoError(t, err)
	_, err = f.Write([]byte("data"))
	require.NoError(t, err)
	path := f.path
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0600))
	f.path = filepath.Join(blocker, "child")
	require.Error(t, f.Close())
	require.EqualValues(t, 4, s.Resources().DiskBytes)
	require.Contains(t, s.scratch, f)
	require.Error(t, s.Close())
	f.path = path
	require.NoError(t, s.Close(), "storage retries abandoned scratch cleanup")
	require.Zero(t, s.Resources().DiskBytes)
	require.Empty(t, s.scratch)
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
}

func TestScratchConcurrentStorageClose(t *testing.T) {
	for range 100 {
		s := newTestStorage(t)
		start := make(chan struct{})
		done := make(chan error, 1)
		go func() { <-start; done <- s.Close() }()
		close(start)
		f, err := s.NewScratchFile()
		if err == nil {
			require.NoError(t, f.Close())
		}
		// A concurrent create either fails after closure, is cleaned by Close,
		// or causes Close to report an active owner. A final Close must converge.
		<-done
		require.NoError(t, s.Close())
		require.Empty(t, s.scratch)
		entries, err := os.ReadDir(s.limits.Directory)
		require.NoError(t, err)
		require.Empty(t, entries)
	}
}

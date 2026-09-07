package capture

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestLocatorSortBufferFallsBackWithoutChangingDiskAdmission(t *testing.T) {
	for _, pressure := range []bool{false, true} {
		ctx := context.Background()
		s, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), CacheBytes: 64 << 10, MaxRecordBytes: 16 << 10, DiskBytes: 1 << 20, MaxSources: 1})
		require.NoError(t, err)
		f, err := s.NewScratchFile()
		require.NoError(t, err)
		var held interface{ Close() error }
		if pressure {
			held, err = s.ReserveTransient(ctx, s.MemoryLimit())
			require.NoError(t, err)
		}
		require.NoError(t, bufferLocatorSortOutput(ctx, f))
		want := []byte("ordering keys retain their disk admission")
		n, err := f.Write(want)
		require.NoError(t, err)
		require.Equal(t, len(want), n)
		require.EqualValues(t, len(want), s.Resources().DiskBytes)
		require.NoError(t, f.FlushWrites())
		got := make([]byte, len(want))
		_, err = f.ReadAt(got, 0)
		require.NoError(t, err)
		require.Equal(t, want, got)
		if held != nil {
			require.NoError(t, held.Close())
		}
		require.Zero(t, s.Resources().InFlightBytes)
		require.NoError(t, f.Reset())
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		require.ErrorIs(t, bufferLocatorSortOutput(cancelled, f), context.Canceled)
		require.NoError(t, f.Close())
		require.NoError(t, s.Close())
		require.Zero(t, s.Resources().DiskBytes)
	}
}

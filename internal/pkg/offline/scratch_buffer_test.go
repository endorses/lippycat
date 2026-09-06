package offline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScratchBufferAccountsAdmissionAndFlushesReads(t *testing.T) {
	s := newTestStorage(t)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	s.limits.DiskBytes = 8
	f, err := s.NewScratchFile()
	require.NoError(t, err)
	require.NoError(t, f.BufferWrites(context.Background(), 256))
	require.EqualValues(t, 384, s.Resources().InFlightBytes)
	n, err := f.Write([]byte("abcdefgh"))
	require.NoError(t, err)
	require.Equal(t, 8, n)
	require.EqualValues(t, 8, s.Resources().DiskBytes)
	stat, err := f.file.Stat()
	require.NoError(t, err)
	require.Zero(t, stat.Size(), "disk admission precedes physical writes")
	n, err = f.Write([]byte("!"))
	require.ErrorContains(t, err, "disk budget")
	require.Zero(t, n)
	require.EqualValues(t, 8, s.Resources().DiskBytes)
	data := make([]byte, 4)
	n, err = f.ReadAt(data, 2)
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, "cdef", string(data))
	stat, err = f.file.Stat()
	require.NoError(t, err)
	require.EqualValues(t, 8, stat.Size())
	require.NoError(t, f.Reset())
	require.Zero(t, s.Resources().DiskBytes)
	_, err = f.Write([]byte("pending"))
	require.NoError(t, err)
	require.NoError(t, f.Reset(), "reset discards unflushed bytes")
	_, err = f.Write([]byte("new"))
	require.NoError(t, err)
	data = make([]byte, 3)
	_, err = f.ReadAt(data, 0)
	require.NoError(t, err)
	require.Equal(t, "new", string(data))
	require.NoError(t, f.Close())
	require.NoError(t, f.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestScratchBufferedFailureRemainsPoisonedUntilCleanup(t *testing.T) {
	s := newTestStorage(t)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	f, err := s.NewScratchFile()
	require.NoError(t, err)
	require.NoError(t, f.BufferWrites(context.Background(), 256))
	_, err = f.Write([]byte("pending"))
	require.NoError(t, err)
	require.NoError(t, f.file.Close())
	_, err = f.ReadAt(make([]byte, 7), 0)
	require.Error(t, err)
	n, err := f.Write([]byte("more"))
	require.Error(t, err)
	require.Zero(t, n)
	require.EqualValues(t, 7, s.Resources().DiskBytes)
	require.Error(t, f.Close())
	require.NoError(t, f.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestScratchBufferHonorsSmallRecordAndMemoryBudgets(t *testing.T) {
	for _, limit := range []uint64{128, 256, 1024} {
		s := newTestStorage(t)
		s.limits.MaxRecordBytes = limit
		f, err := s.NewScratchFile()
		require.NoError(t, err)
		require.NoError(t, f.BufferWrites(context.Background(), 32<<10))
		if limit < 256 {
			require.Nil(t, f.buffer)
			require.Zero(t, s.Resources().InFlightBytes)
		} else {
			require.EqualValues(t, limit, f.buffer.Size())
			require.Equal(t, limit+128, s.Resources().InFlightBytes)
		}
		_, err = f.Write([]byte("data"))
		require.NoError(t, err)
		require.NoError(t, s.Close())
		require.Zero(t, s.Resources().InFlightBytes)
	}
	s := newTestStorage(t)
	f, err := s.NewScratchFile()
	require.NoError(t, err)
	s.limits.CacheBytes = 256
	require.ErrorContains(t, f.BufferWrites(context.Background(), 256), "allocation budget")
	require.Nil(t, f.buffer)
	require.Zero(t, s.Resources().InFlightBytes)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, f.BufferWrites(ctx, 0), context.Canceled)
	require.NoError(t, s.Close())
}

func TestBackingSealFlushesBufferedBytesAndPoisonsFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		s := newTestStorage(t)
		r := s.NewBackingRegistry()
		_, err := r.AppendDerived(context.Background(), 0, nil)
		require.NoError(t, err)
		f := r.entries[0].scratch
		require.NoError(t, f.BufferWrites(context.Background(), 256))
		loc, err := r.AppendDerived(context.Background(), 0, []byte("buffered payload"))
		require.NoError(t, err)
		if fail {
			require.NoError(t, f.file.Close())
			require.ErrorContains(t, r.Seal(), "flush offline backing")
			require.Error(t, r.failure)
			_, err = r.Read(context.Background(), loc)
			require.Error(t, err)
			require.Error(t, r.Close())
		} else {
			require.NoError(t, r.Seal())
			require.Nil(t, f.buffer)
			require.Zero(t, f.bufferBytes)
			require.EqualValues(t, 512, s.Resources().InFlightBytes, "only backing metadata remains charged")
			lease, err := r.Read(context.Background(), loc)
			require.NoError(t, err)
			require.Equal(t, "buffered payload", string(lease.Bytes))
			require.NoError(t, lease.Close())
		}
		require.NoError(t, r.Close())
		require.NoError(t, s.Close())
		require.Zero(t, s.Resources().DiskBytes)
		require.Zero(t, s.Resources().InFlightBytes)
	}
}

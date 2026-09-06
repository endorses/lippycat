package offline

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScratchFlushWritesReleasesBufferBeforeReplay(t *testing.T) {
	s := newTestStorage(t)
	f, err := s.NewScratchFile()
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	before := s.Resources().InFlightBytes
	require.NoError(t, f.BufferWrites(context.Background(), 2048))
	_, err = f.Write([]byte("ordered keys"))
	require.NoError(t, err)
	require.Greater(t, s.Resources().InFlightBytes, before)
	require.NoError(t, f.FlushWrites())
	require.Equal(t, before, s.Resources().InFlightBytes)
	require.Nil(t, f.buffer)
	require.NoError(t, f.FlushWrites())
	data := make([]byte, len("ordered keys"))
	_, err = f.ReadAt(data, 0)
	require.NoError(t, err)
	require.Equal(t, "ordered keys", string(data))
	_, err = f.Write([]byte(" more"))
	require.NoError(t, err)
	got, err := os.ReadFile(f.path)
	require.NoError(t, err)
	require.Equal(t, "ordered keys more", string(got))
}

func TestScratchFailedFlushRetainsErrorAndAdmission(t *testing.T) {
	s := newTestStorage(t)
	f, err := s.NewScratchFile()
	require.NoError(t, err)
	require.NoError(t, f.BufferWrites(context.Background(), 2048))
	_, err = f.Write([]byte("pending keys"))
	require.NoError(t, err)
	before := s.Resources()
	// Closing the underlying handle simulates a failed physical write after
	// buffered Write had admitted and accepted the ordering keys.
	require.NoError(t, f.file.Close())
	require.Error(t, f.FlushWrites())
	require.NotNil(t, f.buffer)
	require.Equal(t, before, s.Resources())
	_, err = f.ReadAt(make([]byte, 1), 0)
	require.Error(t, err)
	require.Error(t, f.Close())
	require.Zero(t, s.Resources().InFlightBytes)
	require.Zero(t, s.Resources().DiskBytes)
}

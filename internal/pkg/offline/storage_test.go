package offline

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func newTestStorage(t *testing.T) *Storage {
	t.Helper()
	s, err := NewStorage(ResourceLimits{Directory: t.TempDir(), DiskBytes: 8 << 20, CacheBytes: 1 << 20, MaxRecordBytes: 16 << 10, MaxSources: 2})
	require.NoError(t, err)
	return s
}
func testStorageDataset(t *testing.T, s *Storage) *diskDataset {
	t.Helper()
	b, err := s.NewBuilder(1, nil)
	require.NoError(t, err)
	require.NoError(t, b.Append(context.Background(), Detail{Packet: types.PacketDisplay{Length: 3, RawData: []byte{1, 2, 3}, Protocol: "UDP"}}))
	d, err := b.Finish(context.Background())
	require.NoError(t, err)
	return d.(*diskDataset)
}
func TestStoragePrivateDirectoryManifestAndCleanup(t *testing.T) {
	s := newTestStorage(t)
	d := testStorageDataset(t, s)
	info, err := os.Stat(d.dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	_, err = os.Stat(filepath.Join(d.dir, "manifest"))
	require.NoError(t, err)
	entries, err := os.ReadDir(d.dir)
	require.NoError(t, err)
	var actual uint64
	for _, entry := range entries {
		st, e := entry.Info()
		require.NoError(t, e)
		actual += uint64(st.Size())
		require.Equal(t, os.FileMode(0600), st.Mode().Perm())
	}
	require.Equal(t, actual, s.Resources().DiskBytes)
	require.Error(t, s.Close())
	require.NoError(t, d.Close())
	require.NoError(t, d.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.NoError(t, s.Close())
	require.NoError(t, s.Close())
	_, err = os.Stat(d.dir)
	require.True(t, os.IsNotExist(err))
}
func TestStorageWriteFlushErrorsNeverPublish(t *testing.T) {
	for _, stage := range []string{"write", "flush"} {
		t.Run(stage, func(t *testing.T) {
			s := newTestStorage(t)
			b, err := s.NewBuilder(1, nil)
			require.NoError(t, err)
			if stage == "write" {
				require.NoError(t, b.d.summaries.Close())
				require.Error(t, b.Append(context.Background(), Detail{}))
			} else {
				require.NoError(t, b.Append(context.Background(), Detail{}))
				require.NoError(t, b.d.details.Close())
			}
			_, err = b.Finish(context.Background())
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
			require.True(t, os.IsNotExist(err))
			require.Error(t, b.Close()) // closed stream cleanup errors are surfaced
			require.Zero(t, s.Resources().DiskBytes)
			require.NoError(t, s.Close())
		})
	}
}
func TestStorageCorruptionRejected(t *testing.T) {
	for _, kind := range []string{"offset", "offset_length", "version", "truncated", "frame_id"} {
		t.Run(kind, func(t *testing.T) {
			s := newTestStorage(t)
			d := testStorageDataset(t, s)
			writable := func(f *os.File) *os.File {
				v, e := os.OpenFile(f.Name(), os.O_RDWR, 0)
				require.NoError(t, e)
				t.Cleanup(func() { require.NoError(t, v.Close()) })
				return v
			}
			offsets, details := writable(d.offsets), writable(d.details)
			switch kind {
			case "offset":
				var bad [8]byte
				binary.LittleEndian.PutUint64(bad[:], ^uint64(0))
				_, err := offsets.WriteAt(bad[:], 32)
				require.NoError(t, err)
			case "offset_length":
				var bad [8]byte
				binary.LittleEndian.PutUint64(bad[:], 1)
				_, err := offsets.WriteAt(bad[:], 40)
				require.NoError(t, err)
			case "version":
				_, err := details.WriteAt([]byte{255, 255}, 8)
				require.NoError(t, err)
			case "truncated":
				require.NoError(t, details.Truncate(20))
			case "frame_id":
				_, err := details.WriteAt([]byte{255}, 28)
				require.NoError(t, err)
			}
			_, err := d.Detail(context.Background(), Token{Dataset: 1}, 0)
			require.Error(t, err)
			require.NoError(t, d.Close())
			require.NoError(t, s.Close())
		})
	}
}
func TestStorageSharedDiskLimitsAndFailureCleanup(t *testing.T) {
	s := newTestStorage(t)
	d := testStorageDataset(t, s)
	s.limits.DiskBytes = s.Resources().DiskBytes + 48
	b, err := s.NewBuilder(2, nil)
	require.NoError(t, err)
	require.Error(t, b.Append(context.Background(), Detail{}))
	_, err = b.Finish(context.Background())
	require.Error(t, err)
	require.NoError(t, b.Close())
	require.Equal(t, d.ownedBytes, s.Resources().DiskBytes)
	require.NoError(t, d.Close())
	require.NoError(t, s.Close())
}
func TestStorageCancelledAndOversizedRecords(t *testing.T) {
	for _, kind := range []string{"cancelled", "oversized", "negative"} {
		t.Run(kind, func(t *testing.T) {
			s := newTestStorage(t)
			b, err := s.NewBuilder(1, nil)
			require.NoError(t, err)
			ctx := context.Background()
			v := Detail{}
			switch kind {
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "oversized":
				v.Packet.RawData = make([]byte, s.limits.MaxRecordBytes+1)
			case "negative":
				v.Packet.Length = -1
			}
			require.Error(t, b.Append(ctx, v))
			_, err = b.Finish(context.Background())
			require.Error(t, err)
			require.NoError(t, b.Close())
			require.NoError(t, s.Close())
		})
	}
}

func TestStorageCleanupCanRetryAfterRemovalFailure(t *testing.T) {
	s := newTestStorage(t)
	d := testStorageDataset(t, s)
	original := d.dir
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	d.dir = filepath.Join(blocker, "child")
	require.Error(t, d.Close())
	require.NotZero(t, s.Resources().DiskBytes)
	d.dir = original
	require.NoError(t, d.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.NoError(t, s.Close())
}

func TestStorageManifestPreservesExtendedTimestampDomain(t *testing.T) {
	s := newTestStorage(t)
	b, err := s.NewBuilder(1, nil)
	require.NoError(t, err)
	instant := time.Date(12000, time.January, 2, 3, 4, 5, 123, time.UTC)
	require.NoError(t, b.Append(context.Background(), Detail{Packet: types.PacketDisplay{Timestamp: instant}}))
	dataset, err := b.Finish(context.Background())
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(dataset.(*diskDataset).dir, "manifest"))
	require.NoError(t, err)
	var manifest struct {
		Statistics struct{ First, Last manifestTimestamp }
	}
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Equal(t, instant.Unix(), manifest.Statistics.First.Seconds)
	require.Equal(t, uint32(123), manifest.Statistics.First.Nanoseconds)
	require.NoError(t, dataset.Close())
	require.NoError(t, s.Close())
}

func TestStorageRejectsStatisticsOverflow(t *testing.T) {
	s := newTestStorage(t)
	b, err := s.NewBuilder(1, nil)
	require.NoError(t, err)
	b.accumulator.stats.Bytes = ^uint64(0) - 1
	require.ErrorContains(t, b.Append(context.Background(), Detail{Packet: types.PacketDisplay{Length: 2}}), "byte total")
	_, err = b.Finish(context.Background())
	require.Error(t, err)
	require.NoError(t, b.Close())
	require.NoError(t, s.Close())
}

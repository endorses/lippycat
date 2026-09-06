package capture

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

// The consumer and replay producer charge one session budget concurrently.
// Optional prefetch must leave enough headroom to store a completed packet.
func TestOfflineLocatorReplayLeavesConsumerHeadroom(t *testing.T) {
	ctx := context.Background()
	storage, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 8 << 20, CacheBytes: 128 << 10, MaxRecordBytes: 16 << 10, MaxSources: 2})
	require.NoError(t, err)
	defer func() { require.NoError(t, storage.Close()) }()
	timestamps := make([]time.Time, 90)
	for i := range timestamps {
		timestamps[i] = time.Unix(int64(i), 0)
	}
	path := writeTimestampedTestPCAP(t, timestamps)
	stream, err := PrepareOfflineLocatorStream(ctx, offlineTestDevices(t, path, path), "", storage, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, stream.Close()) }()
	count := 0
	require.NoError(t, stream.Replay(ctx, func(ctx context.Context, packets <-chan PacketInfo) error {
		for range packets {
			scratch, err := storage.ReserveTransient(ctx, 80<<10)
			if err != nil {
				return err
			}
			count++
			if err := scratch.Close(); err != nil {
				return err
			}
		}
		return nil
	}))
	require.Equal(t, 180, count)
}

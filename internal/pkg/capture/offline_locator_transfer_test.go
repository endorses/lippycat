package capture

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineLocatorBackingTransfer(t *testing.T) {
	ctx := context.Background()
	storage := sortTestStorage(t, 32<<20)
	path := writeTimestampedTestPCAP(t, []time.Time{time.Unix(100, 123)})
	stream, err := PrepareOfflineLocatorStream(ctx, offlineTestDevices(t, path), "", storage, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, stream.Close()) })
	registry := stream.Backings()
	require.NoError(t, stream.TransferBackings())
	t.Cleanup(func() { require.NoError(t, registry.Close()) })
	require.Error(t, stream.TransferBackings())
	var locator offline.Locator
	var want []byte
	require.NoError(t, stream.Replay(ctx, func(_ context.Context, packets <-chan PacketInfo) error {
		for packet := range packets {
			locator = packet.Provenance.Locator
			want = append([]byte(nil), packet.Packet.Data()...)
		}
		return nil
	}))
	require.NotEmpty(t, want)
	require.NoError(t, stream.Close())
	require.Error(t, stream.TransferBackings())
	lease, err := registry.Read(ctx, locator)
	require.NoError(t, err)
	require.Equal(t, want, lease.Bytes)
	require.NoError(t, lease.Close())
	require.NoError(t, registry.Close())
	_, err = registry.Read(ctx, locator)
	require.Error(t, err)
}

package offline

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCacheEvictionOwnershipAndPins(t *testing.T) {
	ctx := context.Background()
	s, err := NewStorage(ResourceLimits{Directory: t.TempDir(), DiskBytes: 8 << 20, CacheBytes: 128 << 10, MaxRecordBytes: 16 << 10, MaxSources: 1})
	require.NoError(t, err)
	b, err := s.NewBuilder(1, nil)
	require.NoError(t, err)
	for i := 0; i < 80; i++ {
		require.NoError(t, b.Append(ctx, Detail{Packet: types.PacketDisplay{Length: 2048, RawData: make([]byte, 2048), HTTPData: &types.HTTPMetadata{Headers: map[string]string{"id": "original"}}}}))
	}
	ds, err := b.Finish(ctx)
	require.NoError(t, err)
	d := ds.(*diskDataset)
	token := Token{Dataset: 1}
	first, err := d.Detail(ctx, token, 0)
	require.NoError(t, err)
	first.Packet.RawData[0] = 255
	first.Packet.HTTPData.Headers["id"] = "mutated"
	again, err := d.Detail(ctx, token, 0)
	require.NoError(t, err)
	require.Zero(t, again.Packet.RawData[0])
	require.Equal(t, "original", again.Packet.HTTPData.Headers["id"])
	pin, err := d.PinDetail(ctx, token, 0)
	require.NoError(t, err)
	require.Positive(t, s.Resources().PinnedBytes)
	for i := 1; i < 80; i++ {
		_, err := d.Detail(ctx, token, PacketID(i))
		require.NoError(t, err)
		usage := s.Resources()
		require.LessOrEqual(t, usage.CachedBytes+usage.PinnedBytes+usage.InFlightBytes+usage.PrefetchBytes, s.limits.CacheBytes)
	}
	require.Nil(t, s.cached(cacheKey{d, 0, 2}), "first frame should be evicted under pressure")
	require.Zero(t, pin.Value.Packet.RawData[0])
	again, err = d.Detail(ctx, token, 0)
	require.NoError(t, err)
	require.Equal(t, "original", again.Packet.HTTPData.Headers["id"])
	closed := make(chan error, 1)
	go func() { closed <- d.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("dataset closed with active pin: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	require.NoError(t, pin.Close())
	require.NoError(t, pin.Close())
	select {
	case err := <-closed:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("close failed to join pin")
	}
	require.Equal(t, ResourceUsage{}, s.Resources())
	require.NoError(t, s.Close())
}

func TestConcurrentCacheReadersRemainBounded(t *testing.T) {
	s := newTestStorage(t)
	d := testStorageDataset(t, s)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				pin, err := d.PinDetail(ctx, Token{Dataset: 1}, 0)
				if err != nil {
					t.Error(err)
					return
				}
				if len(pin.Value.Packet.RawData) != 3 {
					t.Error("incomplete pin")
				}
				if err := pin.Close(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	require.Zero(t, s.Resources().PinnedBytes)
	require.Zero(t, s.Resources().InFlightBytes)
	require.NoError(t, d.Close())
	require.NoError(t, s.Close())
}

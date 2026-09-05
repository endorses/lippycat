//go:build tui || all

package tui

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestOfflineBrowserSupersededResultReleasesPinBudget(t *testing.T) {
	limits := offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 64 << 20, CacheBytes: (3 << 20) + (128 << 10), MaxRecordBytes: 1 << 20, MaxSources: 1}
	storage, err := offline.NewStorage(limits)
	require.NoError(t, err)
	builder, err := storage.NewBuilder(1, nil)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		require.NoError(t, builder.Append(context.Background(), offline.Detail{Packet: types.PacketDisplay{RawData: make([]byte, 256<<10)}}))
	}
	dataset, err := builder.Finish(context.Background())
	require.NoError(t, err)
	b := &offlineBrowser{dataset: dataset, results: make(map[*offlineBrowseResult]struct{})}
	defer func() {
		require.NoError(t, b.close())
		require.NoError(t, dataset.Close())
		require.NoError(t, storage.Close())
	}()
	first := b.load(offline.Token{Dataset: 1, Query: 1, Request: 1}, 0, 0, 1, limits.CacheBytes/4, false)().(offlineBrowseMsg)
	require.NoError(t, first.result.err)
	second := b.load(offline.Token{Dataset: 1, Query: 1, Request: 2}, 1, 1, 1, limits.CacheBytes/4, false)().(offlineBrowseMsg)
	require.NoError(t, second.result.err)
}

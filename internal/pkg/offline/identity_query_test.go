package offline

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestAllPacketsIdentityProjection(t *testing.T) {
	ctx := context.Background()
	storage := newTestStorage(t)
	builder, err := storage.NewBuilder(7, nil)
	require.NoError(t, err)
	for i := 0; i < 1000; i++ {
		require.NoError(t, builder.Append(ctx, Detail{Packet: types.PacketDisplay{Length: i + 1}}))
	}
	dataset, err := builder.Finish(ctx)
	require.NoError(t, err)
	before := dataset.Resources().DiskBytes
	token := Token{Dataset: 7, Query: 9, Request: 1}
	query, err := AllPackets(ctx, dataset, token)
	require.NoError(t, err)
	require.Equal(t, before, dataset.Resources().DiskBytes)
	require.Equal(t, dataset.Statistics(), query.Statistics())
	page, err := query.Page(ctx, PageRequest{Token: token, Row: 997, Limit: 10, MaxBytes: 64 << 10})
	require.NoError(t, err)
	require.Len(t, page.Rows, 3)
	require.Equal(t, PacketID(997), page.Rows[0].ID)
	require.NoError(t, page.Close())
	var seen uint64
	require.NoError(t, query.Iterate(ctx, func(d Detail) error { require.Equal(t, PacketID(seen), d.ID); seen++; return nil }))
	require.Equal(t, uint64(1000), seen)
	require.NoError(t, query.Close())
	require.Equal(t, before, dataset.Resources().DiskBytes)
	_, err = query.Page(ctx, PageRequest{Token: token, Limit: 1, MaxBytes: 64 << 10})
	require.Error(t, err)
	_, err = AllPackets(ctx, dataset, Token{Dataset: 8})
	require.Error(t, err)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = AllPackets(cancelled, dataset, token)
	require.ErrorIs(t, err, context.Canceled)
	query, err = AllPackets(ctx, dataset, token)
	require.NoError(t, err)
	require.NoError(t, dataset.Close())
	require.NoError(t, query.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	require.NoError(t, storage.Close())
}

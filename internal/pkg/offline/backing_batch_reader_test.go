package offline

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackingBatchReaderLeaseReuseAndOwnedFallback(t *testing.T) {
	s, registry, path := backingFixture(t)
	ctx := context.Background()
	input, err := registry.Open(ctx, path, 0, BackingSource, false)
	require.NoError(t, err)
	require.NoError(t, input.Close())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	loc, err := registry.Locator(input.ID, 0, raw)
	require.NoError(t, err)
	baseline := s.Resources().InFlightBytes
	reader, err := registry.NewBatchReader(ctx, 32)
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	lease, first, err := reader.ReadBatch(ctx, []Locator{loc}, 64)
	require.NoError(t, err)
	require.Equal(t, raw, first[0])
	require.Equal(t, len(first[0]), cap(first[0]))
	require.Same(t, &reader.buffer[0], &first[0][0])
	_, _, err = reader.ReadBatch(ctx, []Locator{loc}, 64)
	require.ErrorContains(t, err, "active")
	require.ErrorContains(t, reader.Close(), "active")
	require.NoError(t, lease.Close())
	require.NoError(t, lease.Close())
	lease, second, err := reader.ReadBatch(ctx, []Locator{loc}, 64)
	require.NoError(t, err)
	require.Same(t, &first[0][0], &second[0][0])
	require.NoError(t, lease.Close())

	// Two duplicate locators exceed the 32-byte reusable slab and retain
	// the independent allocation contract of the public ReadBatch path.
	lease, large, err := reader.ReadBatch(ctx, []Locator{loc, loc}, 64)
	require.NoError(t, err)
	require.NotSame(t, &reader.buffer[0], &large[0][0])
	require.Equal(t, [][]byte{raw, raw}, large)
	require.NoError(t, lease.Close())
	ownedLease, owned, err := registry.ReadBatch(ctx, []Locator{loc}, 64)
	require.NoError(t, err)
	require.NotSame(t, &reader.buffer[0], &owned[0][0])
	lease, _, err = reader.ReadBatch(ctx, []Locator{loc}, 64)
	require.NoError(t, err)
	require.Equal(t, raw, owned[0])
	require.NoError(t, lease.Close())
	require.NoError(t, ownedLease.Close())
	require.NoError(t, reader.Close())
	require.Equal(t, baseline, s.Resources().InFlightBytes)
	_, _, err = reader.ReadBatch(ctx, []Locator{loc}, 64)
	require.ErrorContains(t, err, "closed")
}

func TestBackingBatchReaderCancellationAndSourceChange(t *testing.T) {
	s, registry, path := backingFixture(t)
	ctx := context.Background()
	input, err := registry.Open(ctx, path, 0, BackingSource, false)
	require.NoError(t, err)
	require.NoError(t, input.Close())
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	loc, err := registry.Locator(input.ID, 0, raw)
	require.NoError(t, err)
	reader, err := registry.NewBatchReader(ctx, 64)
	require.NoError(t, err)
	defer func() { require.NoError(t, reader.Close()) }()
	baseline := s.Resources()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, _, err = reader.ReadBatch(cancelled, []Locator{loc}, 64)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, baseline, s.Resources())
	info, err := os.Stat(path)
	require.NoError(t, err)
	raw[0] ^= 1
	require.NoError(t, os.WriteFile(path, raw, 0600))
	require.NoError(t, os.Chtimes(path, info.ModTime(), info.ModTime()))
	_, _, err = reader.ReadBatch(ctx, []Locator{loc}, 64)
	require.ErrorIs(t, err, ErrSourceChanged)
	require.Equal(t, baseline, s.Resources())
	require.False(t, reader.active)
}

package offline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompactProjectionAdmission(t *testing.T) {
	storage := newTestStorage(t)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	d := &diskDataset{storage: storage}
	// Enumerate all presence combinations, including the first-answer projection.
	// The generic graph measurer independently checks the fixed allocation charge.
	for presence := uint8(0); presence < 32; presence++ {
		for _, answer := range []bool{false, true} {
			row := compactRow{Projection: compactProjection{Presence: presence, AnswerPresent: answer}}
			summary, held, err := d.materializeCompactSummary(context.Background(), row, 7)
			require.NoError(t, err)
			require.Equal(t, PacketID(7), summary.ID)
			actual, err := compactRecordMemory(&summary, storage.limits.MaxRecordBytes)
			require.NoError(t, err)
			require.Equal(t, actual, held)
			require.Equal(t, held, storage.Resources().InFlightBytes)
			storage.releaseMemory(held)
			require.Zero(t, storage.Resources().InFlightBytes)
		}
	}
}

func TestCompactProjectionRejectsExhaustionAndCancellation(t *testing.T) {
	storage := newTestStorage(t)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	d := &diskDataset{storage: storage}
	row := compactRow{Projection: compactProjection{Presence: 31, AnswerPresent: true}}
	require.NoError(t, storage.reserveMemory(context.Background(), storage.limits.CacheBytes))
	summary, held, err := d.materializeCompactSummary(context.Background(), row, 7)
	require.ErrorContains(t, err, "budget exhausted")
	require.Equal(t, Summary{}, summary)
	require.Zero(t, held)
	require.Equal(t, storage.limits.CacheBytes, storage.Resources().InFlightBytes)
	storage.releaseMemory(storage.limits.CacheBytes)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	summary, held, err = d.materializeCompactSummary(ctx, row, 7)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, Summary{}, summary)
	require.Zero(t, held)
	require.Zero(t, storage.Resources().InFlightBytes)
}

package offline

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestQueryProgressCompleteAndBounded(t *testing.T) {
	const count = 2051
	d := queryDataset(t, count)
	for _, tc := range []struct {
		name    string
		match   Predicate
		matches uint64
	}{
		{"empty", func(Summary) bool { return false }, 0},
		{"all", nil, count},
		{"edges", func(s Summary) bool { return s.ID == 0 || s.ID == count/2 || s.ID == count-1 }, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseline := d.Resources().DiskBytes
			token := Token{Dataset: 7, Query: 2, Request: 3}
			var progress []QueryProgress
			q, err := d.Query(context.Background(), QuerySpec{Token: token, Match: tc.match, Progress: func(p QueryProgress) {
				progress = append(progress, p)
				usage := d.storage.Resources()
				require.Zero(t, usage.InFlightBytes, "summary lease released before reporting")
				require.LessOrEqual(t, usage.CachedBytes+usage.PinnedBytes+usage.PrefetchBytes+usage.InFlightBytes, d.storage.limits.CacheBytes)
			}})
			require.NoError(t, err)
			require.Len(t, progress, 4)
			require.Equal(t, QueryProgress{Token: token, Total: count}, progress[0])
			require.Equal(t, QueryProgress{Token: token, Scanned: count, Matched: tc.matches, Total: count}, progress[len(progress)-1])
			for i := 1; i < len(progress); i++ {
				require.Greater(t, progress[i].Scanned, progress[i-1].Scanned)
				require.GreaterOrEqual(t, progress[i].Matched, progress[i-1].Matched)
			}
			require.Equal(t, tc.matches, q.Count())
			require.Equal(t, tc.matches, q.Statistics().Packets)
			require.EqualValues(t, count, d.Statistics().Packets)
			require.NoError(t, q.Close())
			require.Equal(t, baseline, d.Resources().DiskBytes)
		})
	}
}

func TestQueryProgressCancellationAndEmptyDataset(t *testing.T) {
	d := queryDataset(t, 2051)
	baseline := d.Resources().DiskBytes
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q, err := d.Query(ctx, QuerySpec{Token: Token{Dataset: 7, Query: 1}, Progress: func(p QueryProgress) {
		if p.Scanned == 1024 {
			cancel()
		}
	}})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, q)
	require.Equal(t, baseline, d.Resources().DiskBytes)
	empty := queryDataset(t, 0)
	calls := 0
	q, err = empty.Query(context.Background(), QuerySpec{Token: Token{Dataset: 7, Query: 1}, Progress: func(p QueryProgress) {
		calls++
		require.Zero(t, p.Scanned)
		require.Zero(t, p.Matched)
		require.Zero(t, p.Total)
	}})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.NoError(t, q.Close())
}

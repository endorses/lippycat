//go:build li

package li

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStateSharedBudgetPreservesRichPayload(t *testing.T) {
	want := stateFixture(t)
	data, err := MarshalStateSnapshot(want)
	require.NoError(t, err)
	original := bytes.Clone(data)
	got, err := UnmarshalStateSnapshotWithBudget(data, 1<<20)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, original, data)
	for _, budget := range []int64{-1, 0, 64 << 10, maxStateDecodeBytes + 1} {
		got, err := UnmarshalStateSnapshotWithBudget(data, budget)
		require.ErrorIs(t, err, ErrStateSnapshot)
		require.Nil(t, got)
	}
}

func TestStateSharedBudgetRejectsMapExpansionBeforeTypedDecode(t *testing.T) {
	want := emptyStateFixture()
	for range 8192 {
		want.Generations[uuid.New()] = 2
	}
	data, err := MarshalStateSnapshot(want)
	require.NoError(t, err)
	ordinary, err := UnmarshalStateSnapshot(data)
	require.NoError(t, err)
	require.Equal(t, want, ordinary)
	got, err := UnmarshalStateSnapshotWithBudget(data, int64(4*len(data)+128<<10))
	require.ErrorContains(t, err, "decode memory limit")
	require.Nil(t, got)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, err = UnmarshalStateSnapshotWithBudget(data, 16<<20)
	runtime.ReadMemStats(&after)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(16<<20), "reservation includes parser, typed map and semantic indexes")
	for _, invalid := range [][]byte{append(bytes.Clone(data), []byte(`{}`)...),
		bytes.Replace(data, []byte(`"version":2`), []byte(`"version":2,"PRIVATE":true`), 1),
		bytes.Replace(data, []byte(`"version":2`), []byte(`"version":1`), 1)} {
		got, err = UnmarshalStateSnapshotWithBudget(invalid, 16<<20)
		require.ErrorIs(t, err, ErrStateSnapshot)
		require.Nil(t, got)
		require.NotContains(t, err.Error(), "PRIVATE")
	}
}

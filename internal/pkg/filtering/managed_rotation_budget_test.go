package filtering

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestEncryptedFilterSharedBudgetPreservesRichPayload(t *testing.T) {
	yaml, err := os.ReadFile("../processor/filtering/testdata/legacy_filters.yaml")
	require.NoError(t, err)
	want, err := UnmarshalManagedYAML(yaml)
	require.NoError(t, err)
	data, err := MarshalEncryptedFilters(want)
	require.NoError(t, err)
	original := bytes.Clone(data)
	got, err := UnmarshalEncryptedFiltersWithBudget(data, 1<<20)
	require.NoError(t, err)
	require.Equal(t, original, data)
	for id, filter := range want {
		require.True(t, proto.Equal(filter, got[id]), id)
	}
	for _, budget := range []int64{-1, 0, 64 << 10, maxManagedDecodeBytes + 1} {
		got, err := UnmarshalEncryptedFiltersWithBudget(data, budget)
		require.ErrorIs(t, err, ErrManagedSnapshot)
		require.Nil(t, got)
	}
}

func TestEncryptedFilterSharedBudgetRejectsExpansionBeforeTypedDecode(t *testing.T) {
	var source bytes.Buffer
	source.WriteString(`{"version":1,"filters":[`)
	for n := range 4096 {
		if n != 0 {
			source.WriteByte(',')
		}
		fmt.Fprintf(&source, `{"id":"f%d","type":"sip_user","pattern":"PRIVATE","enabled":true}`, n)
	}
	source.WriteString(`]}`)
	data := source.Bytes()
	ordinary, err := UnmarshalEncryptedFilters(data)
	require.NoError(t, err)
	require.Len(t, ordinary, 4096)
	// Source scratch alone fits; typed-entry/index admission must still fail.
	got, err := UnmarshalEncryptedFiltersWithBudget(data, int64(4*len(data)+128<<10))
	require.ErrorContains(t, err, "decode memory limit")
	require.NotContains(t, err.Error(), "PRIVATE")
	require.Nil(t, got)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, err = UnmarshalEncryptedFiltersWithBudget(data, 16<<20)
	runtime.ReadMemStats(&after)
	require.NoError(t, err)
	require.Len(t, got, 4096)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(16<<20), "reservation covers parser and typed expansion together")
	// The narrow path retains complete schema/semantic/trailing validation.
	for _, invalid := range [][]byte{append(bytes.Clone(data), []byte(`{}`)...),
		[]byte(`{"version":1,"filters":[{"id":"ok","type":"sip_user","pattern":"x"},{"id":"bad","type":"PRIVATE"}]}`),
		[]byte(`{"version":1,"filters":[],"filters":[]}`)} {
		got, err = UnmarshalEncryptedFiltersWithBudget(invalid, 16<<20)
		require.ErrorIs(t, err, ErrManagedSnapshot)
		require.Nil(t, got)
		require.NotContains(t, err.Error(), "PRIVATE")
	}
}

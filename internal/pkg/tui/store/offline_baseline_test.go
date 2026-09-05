//go:build tui || all

package store

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/stretchr/testify/require"
)

// TestOfflineRetentionBaseline records the transitional slice-backed behavior.
// Replace this expectation with dataset completeness when offline queries ship;
// the live packet ring must continue to have bounded retention.
func TestOfflineRetentionBaseline(t *testing.T) {
	const capacity, count = 10_000, 100_000
	ps := NewPacketStore(capacity)
	batch := make([]components.PacketDisplay, 100)
	for start := 0; start < count; start += len(batch) {
		for i := range batch {
			batch[i] = components.PacketDisplay{Info: fmt.Sprintf("packet-%06d", start+i), Length: 256}
		}
		ps.AddPacketBatch(batch)
	}
	_, retained, processed, matched := ps.GetBufferInfo()
	require.Equal(t, count, int(processed))
	require.Equal(t, capacity, retained)
	require.Equal(t, count, int(matched))
	require.Equal(t, capacity, ps.FilteredCount())
	for _, tc := range []struct {
		needle string
		want   int
	}{
		{"packet-000000", 0}, {"packet-050000", 0}, {"packet-099999", 1},
	} {
		chain := filters.NewFilterChain()
		chain.Add(filters.NewTextFilter(tc.needle, []string{"info"}))
		ps.SetFilter(chain)
		require.Equal(t, tc.want, ps.FilteredCount(), tc.needle)
	}
	ps.ClearFilter()
	require.Equal(t, capacity, ps.FilteredCount())
	_, _, processed, matched = ps.GetBufferInfo()
	require.Equal(t, count, int(processed))
	require.Equal(t, capacity, int(matched), "filter reapplication recomputes matches from retention")
}

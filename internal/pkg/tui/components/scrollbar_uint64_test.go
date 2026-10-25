//go:build tui || all

package components

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScrollbarUint64PreservesDistantLogicalOffsets(t *testing.T) {
	const total, visible = uint64(math.MaxUint64), uint64(10)
	start, size := ScrollbarThumb64(total, visible, total-visible, 30)
	require.Equal(t, 1, size)
	require.Equal(t, 29, start)
	require.Zero(t, ScrollbarOffsetForRow64(total, visible, 30, 0, 0))
	require.Equal(t, total-visible, ScrollbarOffsetForRow64(total, visible, 30, 29, 0))
	require.Equal(t, total-visible, ScrollbarOffsetForDrag64(total, visible, 30, 0, 0, 29))
	require.Zero(t, ScrollbarOffsetForDrag64(total, visible, 30, total-visible, 29, 0))
	previous := uint64(0)
	for row := 0; row < 30; row++ {
		offset := ScrollbarOffsetForRow64(total, visible, 30, row, 0)
		require.GreaterOrEqual(t, offset, previous)
		require.LessOrEqual(t, offset, total-visible)
		previous = offset
	}
	for _, values := range [][3]uint64{{0, 0, 0}, {5, 10, 0}, {100, 10, 40}, {10000, 30, 9999}} {
		a, b := ScrollbarThumb(int(values[0]), int(values[1]), int(values[2]), 30)
		x, y := ScrollbarThumb64(values[0], values[1], values[2], 30)
		require.Equal(t, a, x)
		require.Equal(t, b, y)
	}
}

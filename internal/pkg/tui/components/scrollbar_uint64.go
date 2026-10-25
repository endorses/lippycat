//go:build tui || all

package components

import (
	"math/bits"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// roundedScale evaluates value*scale/divisor without narrowing logical rows or
// overflowing a uint64 multiplication. Terminal geometry bounds scale.
func roundedScale(value, scale, divisor uint64) uint64 {
	if divisor == 0 {
		return 0
	}
	hi, lo := bits.Mul64(value, scale)
	lo, carry := bits.Add64(lo, divisor/2, 0)
	hi += carry
	quotient, _ := bits.Div64(hi, lo, divisor)
	return quotient
}

func ScrollbarThumb64(total, visible, offset uint64, height int) (start, size int) {
	if height <= 0 || visible == 0 || total <= visible {
		return 0, 0
	}
	size = max(1, min(height, int(roundedScale(visible, uint64(height), total))))
	travel, maximum := height-size, total-visible
	if travel > 0 {
		start = int(roundedScale(min(offset, maximum), uint64(travel), maximum))
	}
	return start, size
}

func ScrollbarOffsetForRow64(total, visible uint64, height, row, grab int) uint64 {
	if height <= 0 || visible == 0 || total <= visible {
		return 0
	}
	_, size := ScrollbarThumb64(total, visible, 0, height)
	travel := height - size
	if travel <= 0 {
		return 0
	}
	return roundedScale(total-visible, uint64(max(0, min(row-grab, travel))), uint64(travel))
}

func ScrollbarOffsetForDrag64(total, visible uint64, height int, startOffset uint64, startRow, row int) uint64 {
	if height <= 0 || visible == 0 || total <= visible {
		return 0
	}
	_, size := ScrollbarThumb64(total, visible, 0, height)
	travel := height - size
	if travel <= 0 {
		return 0
	}
	delta := max(-travel, min(row-startRow, travel))
	magnitude := delta
	if magnitude < 0 {
		magnitude = -magnitude
	}
	change := roundedScale(total-visible, uint64(magnitude), uint64(travel))
	startOffset = min(startOffset, total-visible)
	if delta < 0 {
		return startOffset - min(startOffset, change)
	}
	return startOffset + min(total-visible-startOffset, change)
}

func RenderScrollbar64(total, visible, offset uint64, height int, theme themes.Theme) string {
	start, size := ScrollbarThumb64(total, visible, offset, height)
	if size == 0 {
		return ""
	}
	thumb := lipgloss.NewStyle().Foreground(theme.Foreground).Render("▉")
	lines := make([]string, height)
	for row := range lines {
		lines[row] = " "
		if row >= start && row < start+size {
			lines[row] = thumb
		}
	}
	return strings.Join(lines, "\n")
}

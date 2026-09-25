//go:build tui || all

package components

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

type scrollbarDrag struct {
	active      bool
	startRow    int
	startOffset int
}

// handleScrollbarMouse consumes presses on the bar and subsequent drag events.
// A track press centers the thumb at the pointer; a thumb press retains its
// original grab position. The caller supplies the bar's terminal coordinates.
func handleScrollbarMouse(msg tea.MouseMsg, x, top, total, visible, offset, height int, drag *scrollbarDrag) (int, bool) {
	if msg.Action == tea.MouseActionRelease {
		if drag.active {
			drag.active = false
			return offset, true
		}
		return offset, false
	}
	if msg.Action == tea.MouseActionMotion {
		if !drag.active {
			return offset, false
		}
		return ScrollbarOffsetForDrag(total, visible, height, drag.startOffset, drag.startRow, msg.Y-top), true
	}
	if msg.Button != tea.MouseButtonLeft || msg.Action != tea.MouseActionPress || msg.X != x || msg.Y < top || msg.Y >= top+height {
		return offset, false
	}
	start, size := ScrollbarThumb(total, visible, offset, height)
	row := msg.Y - top
	drag.active = true
	if row >= start && row < start+size {
		drag.startRow = row
		drag.startOffset = offset
		return offset, true
	}
	newOffset := ScrollbarOffsetForRow(total, visible, height, row, size/2)
	drag.startRow = row
	drag.startOffset = newOffset
	return newOffset, true
}

// ScrollbarThumb returns the thumb's first row and height. All measurements are
// in terminal cells or content lines, so callers can use these for hit testing.
func ScrollbarThumb(total, visible, offset, height int) (start, size int) {
	if height <= 0 {
		return 0, 0
	}
	if total <= visible || total <= 0 || visible <= 0 {
		return 0, height
	}
	size = max(1, min(height, (visible*height+total/2)/total))
	maxOffset := total - visible
	maxStart := height - size
	offset = max(0, min(offset, maxOffset))
	if maxStart > 0 {
		start = (offset*maxStart + maxOffset/2) / maxOffset
	}
	return start, size
}

// ScrollbarOffsetForRow maps a pointer position to the viewport offset. grab
// is the row inside the thumb where the drag started; use zero for track clicks.
func ScrollbarOffsetForRow(total, visible, height, row, grab int) int {
	if total <= visible || visible <= 0 || height <= 0 {
		return 0
	}
	_, size := ScrollbarThumb(total, visible, 0, height)
	travel := height - size
	if travel <= 0 {
		return 0
	}
	position := max(0, min(row-grab, travel))
	return (position*(total-visible) + travel/2) / travel
}

// ScrollbarOffsetForDrag moves from the offset at mouse-down. This avoids a
// one-line jump caused by inverting a rounded thumb position on the first move.
func ScrollbarOffsetForDrag(total, visible, height, startOffset, startRow, row int) int {
	if total <= visible || visible <= 0 || height <= 0 {
		return 0
	}
	_, size := ScrollbarThumb(total, visible, 0, height)
	travel := height - size
	if travel <= 0 {
		return 0
	}
	delta := max(-travel, min(row-startRow, travel))
	magnitude := delta
	if magnitude < 0 {
		magnitude = -magnitude
	}
	change := (magnitude*(total-visible) + travel/2) / travel
	if delta < 0 {
		change = -change
	}
	return max(0, min(startOffset+change, total-visible))
}

// RenderScrollbar draws a one-cell-wide scrollbar with a visible track, even
// when the content currently fits the viewport.
func RenderScrollbar(total, visible, offset, height int, theme themes.Theme) string {
	if height <= 0 {
		return ""
	}
	start, size := ScrollbarThumb(total, visible, offset, height)
	track := lipgloss.NewStyle().Foreground(theme.BorderColor).Render("│")
	thumb := lipgloss.NewStyle().Foreground(theme.Foreground).Render("▉")
	lines := make([]string, height)
	for row := range lines {
		lines[row] = track
		if row >= start && row < start+size {
			lines[row] = thumb
		}
	}
	return strings.Join(lines, "\n")
}

// OverlayScrollbar replaces one column in an already rendered pane. x and y
// are pane-relative. Short lines are padded to the bar, and ANSI-aware cutting
// keeps colored content and wide runes aligned.
func OverlayScrollbar(pane string, x, y int, bar string) string {
	if x < 0 || y < 0 || bar == "" {
		return pane
	}
	lines := strings.Split(pane, "\n")
	barLines := strings.Split(bar, "\n")
	for i, cell := range barLines {
		row := y + i
		if row >= len(lines) {
			break
		}
		width := ansi.StringWidth(lines[row])
		if x >= width {
			lines[row] += strings.Repeat(" ", x-width) + cell
			continue
		}
		lines[row] = ansi.Cut(lines[row], 0, x) + cell + ansi.Cut(lines[row], x+1, width)
	}
	return strings.Join(lines, "\n")
}

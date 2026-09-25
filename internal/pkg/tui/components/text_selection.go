//go:build tui || all

package components

import (
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/selection"
)

// TextSelectionAt returns a selectable region in outer-pane coordinates. Dump
// columns are independent regions so a multiline ASCII drag never includes hex.
func (d *DetailsPanel) TextSelectionAt(x, y int) (selection.Rect, bool) {
	if !d.ready {
		return selection.Rect{}, false
	}
	body := selection.Rect{X: 3, Y: 2, Width: d.viewport.Width, Height: d.viewport.Height}
	if !body.Contains(x, y) {
		return selection.Rect{}, false
	}
	lines := strings.Split(ansi.Strip(d.viewport.View()), "\n")
	row := y - body.Y
	if row >= len(lines) {
		return body, true
	}
	offsetWidth, ok := selectionHexRow(lines[row])
	if !ok {
		return body, true
	}
	left, width := 0, offsetWidth
	switch column := x - body.X; {
	case column >= offsetWidth+52:
		left, width = offsetWidth+52, 16
	case column >= offsetWidth+2 && column < offsetWidth+51:
		left, width = offsetWidth+2, 49
	case column >= offsetWidth:
		return selection.Rect{}, false // Gaps between offset, hex, and ASCII.
	}
	first, last := row, row
	for first > 0 {
		if w, valid := selectionHexRow(lines[first-1]); !valid || w != offsetWidth {
			break
		}
		first--
	}
	for last+1 < len(lines) {
		if w, valid := selectionHexRow(lines[last+1]); !valid || w != offsetWidth {
			break
		}
		last++
	}
	region := selection.Rect{X: body.X + left, Y: body.Y + first, Width: width, Height: last - first + 1}
	return selectionIntersection(region, body), true
}

// selectionHexRow recognizes renderHexDump rows, including its space-padded
// final row and offsets wider than four digits. Arbitrary metadata is not a dump.
func selectionHexRow(line string) (int, bool) {
	offsetWidth := strings.Index(line, "  ")
	if offsetWidth < 4 || len(line) < offsetWidth+52 {
		return 0, false
	}
	for i := 0; i < offsetWidth; i++ {
		if !selectionHexDigit(line[i]) {
			return 0, false
		}
	}
	filled := false
	padding := false
	for i := 0; i < 16; i++ {
		start := offsetWidth + 2 + i*3
		if i >= 8 {
			start++
		}
		if line[start:start+3] == "   " {
			padding = true
			continue
		}
		if padding || !selectionHexDigit(line[start]) || !selectionHexDigit(line[start+1]) || line[start+2] != ' ' {
			return 0, false
		}
		filled = true
	}
	return offsetWidth, filled && line[offsetWidth+26] == ' ' && line[offsetWidth+51] == ' '
}

func selectionHexDigit(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f'
}

// TextSelectionAt keeps graph-box drags within that node. Table/tree views use
// the viewport as one region, and the rightmost scrollbar is never selectable.
func (n *NodesView) TextSelectionAt(x, y int) (selection.Rect, bool) {
	body := selection.Rect{Width: n.width, Height: n.viewport.Height}
	if !n.ready || n.showModal || !body.Contains(x, y) {
		return selection.Rect{}, false
	}
	if n.viewMode == "graph" {
		best := body
		found := false
		consider := func(left, top, right, bottom int) {
			// Graph click regions store an exclusive right edge but an inclusive
			// bottom edge; remove each visible border before clipping.
			region := selection.Rect{X: left + 1, Y: top + 1 - n.viewport.YOffset, Width: right - left - 2, Height: bottom - top - 1}
			region = selectionIntersection(region, body)
			if region.Contains(x, y) && (!found || region.Width*region.Height < best.Width*best.Height) {
				best, found = region, true
			}
		}
		for _, box := range n.processorBoxRegions {
			consider(box.startCol, box.startLine, box.endCol, box.endLine)
		}
		for _, box := range n.hunterBoxRegions {
			consider(box.startCol, box.startLine, box.endCol, box.endLine)
		}
		if found {
			return best, true
		}
	}
	return body, true
}

// TextSelectionAt excludes the fixed help section/search controls.
func (h *HelpView) TextSelectionAt(x, y int) (selection.Rect, bool) {
	body := selection.Rect{Y: 1, Width: h.viewport.Width, Height: h.viewport.Height}
	return body, h.ready && body.Contains(x, y)
}

// TextSelectionAt isolates dashboard cards, including cards whose top or bottom
// has scrolled out of view. Unboxed statistics remain one selectable pane.
func (s *StatisticsView) TextSelectionAt(x, y int) (selection.Rect, bool) {
	body := selection.Rect{Width: s.width, Height: s.viewport.Height}
	if !s.ready || !body.Contains(x, y) {
		return selection.Rect{}, false
	}
	if (s.stats == nil || s.stats.TotalPackets == 0) && s.offlineGlobal == nil {
		return body, true
	}
	// The navigation row scrolls with the statistics content. Empty and offline-
	// only views do not render that row.
	if s.stats != nil && s.stats.TotalPackets > 0 && s.viewport.YOffset == 0 {
		body.Y, body.Height = 1, max(0, body.Height-1)
		if !body.Contains(x, y) {
			return selection.Rect{}, false
		}
	}
	lines := selectionViewportLines(s.viewport)
	if region, ok := selectionCardAt(lines, x, y+s.viewport.YOffset); ok {
		region.Y -= s.viewport.YOffset
		return selectionIntersection(region, body), true
	}
	return body, true
}

func selectionViewportLines(v viewport.Model) []string {
	v.Height = max(1, v.TotalLineCount())
	v.GotoTop()
	return strings.Split(ansi.Strip(v.View()), "\n")
}

var selectionCardTop = regexp.MustCompile(`╭─+╮|┌─+┐|┏━+┓`)

func selectionCardAt(lines []string, x, y int) (selection.Rect, bool) {
	var best selection.Rect
	found := false
	for top := 0; top < len(lines) && top < y; top++ {
		for _, match := range selectionCardTop.FindAllStringIndex(lines[top], -1) {
			left := ansi.StringWidth(lines[top][:match[0]])
			width := ansi.StringWidth(lines[top][match[0]:match[1]])
			if x <= left || x >= left+width-1 {
				continue
			}
			for bottom := top + 1; bottom < len(lines); bottom++ {
				start := ansi.Cut(lines[bottom], left, left+1)
				end := ansi.Cut(lines[bottom], left+width-1, left+width)
				if (start == "╰" && end == "╯") || (start == "└" && end == "┘") || (start == "┗" && end == "┛") {
					candidate := selection.Rect{X: left + 1, Y: top + 1, Width: width - 2, Height: bottom - top - 1}
					if candidate.Contains(x, y) && (!found || candidate.Width*candidate.Height < best.Width*best.Height) {
						best, found = candidate, true
					}
					break
				}
			}
		}
	}
	return best, found
}

func selectionIntersection(a, b selection.Rect) selection.Rect {
	left, top := max(a.X, b.X), max(a.Y, b.Y)
	right, bottom := min(a.X+a.Width, b.X+b.Width), min(a.Y+a.Height, b.Y+b.Height)
	return selection.Rect{X: left, Y: top, Width: max(0, right-left), Height: max(0, bottom-top)}
}

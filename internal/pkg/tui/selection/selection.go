// Package selection implements pane-local selection of rendered terminal text.
package selection

import (
	"strings"
	"unicode"

	"github.com/charmbracelet/x/ansi"
)

// Rect is a rectangle in terminal cells, with an exclusive right and bottom edge.
type Rect struct {
	X, Y, Width, Height int
}

// Contains reports whether a terminal cell is inside the rectangle.
func (r Rect) Contains(x, y int) bool {
	return r.Width > 0 && r.Height > 0 && x >= r.X && y >= r.Y && x-r.X < r.Width && y-r.Y < r.Height
}

type point struct{ x, y int }

type token struct {
	text     string
	x, width int
}

// Selection holds an immutable rendered snapshot and a movable selection end.
// A zero Selection is empty. Copying a Selection produces independent endpoints.
type Selection struct {
	view    string
	lines   [][]token
	region  Rect
	start   point
	end     point
	dragged bool
}

// New freezes view and starts a selection at the given terminal cell. The start
// and later endpoints are clamped to region; rows outside the snapshot are ignored.
func New(view string, region Rect, x, y int) Selection {
	s := Selection{view: view}
	rows := strings.Split(view, "\n")
	right, bottom := region.X+region.Width, min(region.Y+region.Height, len(rows))
	region.X, region.Y = max(0, region.X), max(0, region.Y)
	region.Width, region.Height = right-region.X, bottom-region.Y
	if region.Width <= 0 || region.Height <= 0 {
		return s
	}
	s.region = region
	s.start = s.clamp(x, y)
	s.end = s.start
	s.lines = make([][]token, len(rows))
	for i, row := range rows {
		s.lines[i] = tokenize(row)
	}
	return s
}

// Move clamps the endpoint to the original pane. Once the pointer has moved,
// Dragged remains true even if it returns to the initial cell or stays outside
// the pane with its endpoint clamped to the initial cell.
func (s *Selection) Move(x, y int) {
	if s.region.Width <= 0 || s.region.Height <= 0 {
		return
	}
	s.end = s.clamp(x, y)
	s.dragged = s.dragged || x != s.start.x || y != s.start.y
}

func (s Selection) clamp(x, y int) point {
	return point{
		x: max(s.region.X, min(x, s.region.X+s.region.Width-1)),
		y: max(s.region.Y, min(y, s.region.Y+s.region.Height-1)),
	}
}

// Dragged reports whether the pointer has moved from the starting cell.
func (s Selection) Dragged() bool { return s.dragged }

// Text returns the selected plain text without trailing whitespace on each line
// or blank lines at the end. Indentation and internal blank lines are preserved.
// Endpoints are inclusive. Wide glyphs and combining sequences remain intact,
// and a glyph straddling the pane boundary is never copied.
func (s Selection) Text() string {
	if !s.dragged {
		return ""
	}
	start, end := s.ordered()
	lines := make([]string, 0, end.y-start.y+1)
	for y := start.y; y <= end.y; y++ {
		var line strings.Builder
		for _, t := range s.lines[y] {
			if s.selected(t, y) {
				line.WriteString(t.text)
			}
		}
		lines = append(lines, strings.TrimRightFunc(line.String(), unicode.IsSpace))
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// Solarized violet (#6c71c4) with bold base3 text (#fdf6e3) distinguishes text
// selection from cyan-selected rows without relying on the terminal's palette.
// Reapply after original SGR sequences, which may reset colors or reverse video.
const highlight = "\x1b[0;1;38;2;253;246;227;48;2;108;113;196m"
const reset = "\x1b[0m"

// View returns the frozen screen with the selection highlighted. Original
// styling is restored outside the selection, including styles spanning rows.
func (s Selection) View() string {
	if !s.dragged {
		return s.view
	}
	var out, styles strings.Builder
	for y, line := range s.lines {
		active := false
		textEnd := s.selectedTextEnd(y)
		for _, t := range line {
			if t.width == 0 {
				out.WriteString(t.text)
				if isSGR(t.text) {
					if t.text == "\x1b[m" || t.text == reset || t.text == "\x9bm" || t.text == "\x9b0m" {
						styles.Reset()
					} else {
						styles.WriteString(t.text)
					}
					if active {
						out.WriteString(highlight)
					}
				}
				continue
			}
			selected := t.x < textEnd && s.selected(t, y)
			if selected && !active {
				out.WriteString(highlight)
			} else if !selected && active {
				out.WriteString(reset)
				out.WriteString(styles.String())
			}
			active = selected
			out.WriteString(t.text)
		}
		if active {
			out.WriteString(reset)
			out.WriteString(styles.String())
		}
		if y < len(s.lines)-1 {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// selectedTextEnd excludes trailing padding from the highlight, matching Text.
// Only inspect the selected pane and range: adjacent panes and unselected words
// must not make whitespace at the end of this selection appear significant.
func (s Selection) selectedTextEnd(y int) int {
	line := s.lines[y]
	for i := len(line) - 1; i >= 0; i-- {
		t := line[i]
		if s.selected(t, y) && strings.TrimSpace(t.text) != "" {
			return t.x + t.width
		}
	}
	return s.region.X
}

func (s Selection) ordered() (point, point) {
	if s.start.y > s.end.y || (s.start.y == s.end.y && s.start.x > s.end.x) {
		return s.end, s.start
	}
	return s.start, s.end
}

func (s Selection) selected(t token, y int) bool {
	start, end := s.ordered()
	if t.width == 0 || y < start.y || y > end.y || t.x < s.region.X || t.x+t.width > s.region.X+s.region.Width {
		return false
	}
	left, right := s.region.X, s.region.X+s.region.Width
	if y == start.y {
		left = start.x
	}
	if y == end.y {
		right = end.x + 1
	}
	return t.x < right && t.x+t.width > left
}

func isSGR(s string) bool {
	return (strings.HasPrefix(s, "\x1b[") || strings.HasPrefix(s, "\x9b")) && strings.HasSuffix(s, "m")
}

func tokenize(line string) []token {
	var tokens []token
	x := 0
	for len(line) > 0 {
		var text string
		var width int
		if line[0] < ' ' || (line[0] >= 0x7f && line[0] < 0xa0) {
			var n int
			text, width, n, _ = ansi.DecodeSequence(line, ansi.NormalState, nil)
			if n == 0 { // Always make progress for malformed terminal data.
				n = 1
				text = line[:n]
			}
			line = line[n:]
		} else {
			// DecodeSequence splits ASCII bases from combining marks; decode
			// printable text as complete graphemes instead.
			text, line, width, _ = ansi.FirstGraphemeCluster(line, -1)
		}
		tokens = append(tokens, token{text: text, x: x, width: width})
		x += width
	}
	return tokens
}

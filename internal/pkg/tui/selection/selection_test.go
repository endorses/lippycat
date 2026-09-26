package selection

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
)

func TestRectContains(t *testing.T) {
	r := Rect{X: 5, Y: 2, Width: 4, Height: 3}
	require.True(t, r.Contains(5, 2))
	require.True(t, r.Contains(8, 4))
	for _, p := range []point{{4, 2}, {9, 2}, {5, 1}, {5, 5}} {
		require.False(t, r.Contains(p.x, p.y))
	}
	require.False(t, (Rect{}).Contains(0, 0))
}

func TestSelectionForwardAndReverse(t *testing.T) {
	view := "prefix\n0123456789\nabcdefghij\nklmnopqrst\nsuffix"
	region := Rect{X: 2, Y: 1, Width: 6, Height: 3}
	for _, reverse := range []bool{false, true} {
		start, end := point{4, 1}, point{5, 3}
		if reverse {
			start, end = end, start
		}
		s := New(view, region, start.x, start.y)
		s.Move(end.x, end.y)
		require.Equal(t, "4567\ncdefgh\nmnop", s.Text())
		require.Equal(t, view, ansi.Strip(s.View()))
	}
}

func TestSelectionClampsToPane(t *testing.T) {
	view := "list |alpha |right\nlist | beta |right\nlist |gamma |right"
	r := Rect{X: 6, Y: 0, Width: 6, Height: 3}
	s := New(view, r, 8, 0)
	s.Move(100, 100)
	require.Equal(t, "pha\n beta\ngamma", s.Text())
	require.NotContains(t, s.Text(), "list")
	require.NotContains(t, s.Text(), "right")
	require.NotContains(t, s.Text(), "|")

	s = New(view, r, 8, 2)
	s.Move(-100, -100)
	require.Equal(t, "alpha\n beta\ngam", s.Text())
}

func TestSelectionClickAndStickyDrag(t *testing.T) {
	view := "hello"
	s := New(view, Rect{Width: 5, Height: 1}, 1, 0)
	require.False(t, s.Dragged())
	require.Empty(t, s.Text())
	require.Equal(t, view, s.View())
	s.Move(1, 0)
	require.False(t, s.Dragged())
	s.Move(2, 0)
	require.True(t, s.Dragged())
	s.Move(1, 0)
	require.True(t, s.Dragged())
	require.Equal(t, "e", s.Text())
	require.Equal(t, "h"+highlight+"e"+reset+"llo", s.View())

	copy := s
	copy.Move(4, 0)
	require.Equal(t, "e", s.Text(), "value copies have independent endpoints")
	require.Equal(t, "ello", copy.Text())

	s = New(view, Rect{Width: 5, Height: 1}, 4, 0)
	s.Move(10, 0)
	require.True(t, s.Dragged(), "outward drags from a pane edge are still drags")
	require.Equal(t, "o", s.Text())
}

func TestSelectionHighlightsAcrossOriginalResets(t *testing.T) {
	view := "\x1b[31ma\x1b[0mb\x1b[34mc\x1b[0md"
	s := New(view, Rect{Width: 4, Height: 1}, 0, 0)
	s.Move(2, 0)
	require.Equal(t, "abc", s.Text())
	require.Equal(t,
		"\x1b[31m"+highlight+"a\x1b[0m"+highlight+"b\x1b[34m"+highlight+"c\x1b[0m"+highlight+reset+"d",
		s.View())
	require.Equal(t, ansi.Strip(view), ansi.Strip(s.View()))
}

func TestSelectionRestoresOriginalStylesAcrossRows(t *testing.T) {
	view := "\x1b[1;31mABCD\nEFGH\x1b[0m"
	s := New(view, Rect{X: 1, Width: 2, Height: 2}, 1, 0)
	s.Move(2, 1)
	require.Equal(t, "BC\nFG", s.Text())
	require.Equal(t,
		"\x1b[1;31mA"+highlight+"BC"+reset+"\x1b[1;31mD\nE"+highlight+"FG"+reset+"\x1b[1;31mH\x1b[0m",
		s.View())
}

func TestSelectionGraphemes(t *testing.T) {
	for _, tc := range []struct {
		name, view, want string
		start, end       int
	}{
		{name: "wide glyph end", view: "A界Z", start: 0, end: 1, want: "A界"},
		{name: "wide glyph start", view: "A界Z", start: 2, end: 3, want: "界Z"},
		{name: "combining mark", view: "Ae\u0301Z", start: 0, end: 1, want: "Ae\u0301"},
		{name: "combining reverse", view: "Ae\u0301Z", start: 2, end: 1, want: "e\u0301Z"},
		{name: "emoji with modifier", view: "A👍🏽Z", start: 2, end: 3, want: "👍🏽Z"},
		{name: "emoji joiner", view: "A👨‍👩‍👧‍👦Z", start: 0, end: 1, want: "A👨‍👩‍👧‍👦"},
		{name: "emoji keycap", view: "A1️⃣Z", start: 0, end: 1, want: "A1️⃣"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(tc.view, Rect{Width: 20, Height: 1}, tc.start, 0)
			s.Move(tc.end, 0)
			require.Equal(t, tc.want, s.Text())
			require.Equal(t, tc.view, ansi.Strip(s.View()))
			require.Equal(t, ansi.StringWidth(tc.view), ansi.StringWidth(s.View()))
		})
	}
}

func TestSelectionNeverIncludesGlyphOutsidePane(t *testing.T) {
	view := "A界中Z"
	s := New(view, Rect{X: 2, Width: 2, Height: 1}, 2, 0)
	s.Move(3, 0)
	require.Empty(t, s.Text(), "both wide glyphs cross a pane boundary")
	require.Equal(t, view, s.View())
}

func TestSelectionEmptyAndTrailingLines(t *testing.T) {
	view := "  a  \n\n b c \n"
	s := New(view, Rect{Width: 5, Height: 4}, 0, 0)
	s.Move(4, 3)
	require.Equal(t, "  a\n\n b c", s.Text())
	require.Equal(t, view, ansi.Strip(s.View()))
	before, after := strings.Split(view, "\n"), strings.Split(s.View(), "\n")
	require.Len(t, after, len(before))
	for i := range before {
		require.Equal(t, ansi.StringWidth(before[i]), ansi.StringWidth(after[i]))
	}

	s = New("", Rect{Width: 5, Height: 1}, 0, 0)
	s.Move(1, 0)
	require.Empty(t, s.Text())
	require.Empty(t, s.View())
}

func TestSelectionExcludesPanePaddingFromHighlight(t *testing.T) {
	view := "L|head    |R\nL|        |R\nL|  • end |R\nL|        |R\nL|        |R"
	wantView := "L|" + highlight + "head" + reset + "    |R\nL|        |R\nL|" + highlight + "  • end" + reset + " |R\nL|        |R\nL|        |R"
	for _, reverse := range []bool{false, true} {
		start, end := point{2, 0}, point{9, 4}
		if reverse {
			start, end = end, start
		}
		s := New(view, Rect{X: 2, Width: 8, Height: 5}, start.x, start.y)
		s.Move(end.x, end.y)
		require.Equal(t, "head\n\n  • end", s.Text())
		require.Equal(t, wantView, s.View())
		require.Equal(t, view, ansi.Strip(s.View()))
	}
}

func TestSelectionTrimsOnlySelectedTrailingWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name, view, wantText, wantView string
		end                            int
	}{
		{"partial line", "word   next", "word", highlight + "word" + reset + "   next", 6},
		{"interior spaces", "word   next", "word   next", highlight + "word   next" + reset, 10},
		{"unicode padding", "界\u00a0\u2003", "界", highlight + "界" + reset + "\u00a0\u2003", 3},
		{"blank selection", "    ", "", "    ", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(tc.view, Rect{Width: ansi.StringWidth(tc.view), Height: 1}, 0, 0)
			s.Move(tc.end, 0)
			require.Equal(t, tc.wantText, s.Text())
			require.Equal(t, tc.wantView, s.View())
		})
	}
}

func TestSelectionInvalidOrOffscreenRegion(t *testing.T) {
	var zero Selection
	zero.Move(100, 100)
	require.False(t, zero.Dragged())
	require.Empty(t, zero.Text())
	require.Empty(t, zero.View())
	for _, region := range []Rect{{}, {Width: -1, Height: 1}, {Y: 4, Width: 8, Height: 1}} {
		s := New("text", region, 0, 0)
		s.Move(100, 100)
		require.False(t, s.Dragged())
		require.Empty(t, s.Text())
		require.Equal(t, "text", s.View())
	}
	s := New("abc\ndef", Rect{X: -2, Y: -2, Width: 20, Height: 20}, 0, 0)
	s.Move(100, 100)
	require.Equal(t, "abc\ndef", s.Text())
}

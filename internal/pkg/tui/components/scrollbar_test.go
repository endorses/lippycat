//go:build tui || all

package components

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

func TestScrollbarEndpointsAndDrag(t *testing.T) {
	start, size := ScrollbarThumb(100, 20, 0, 10)
	if start != 0 || size != 2 {
		t.Fatalf("top thumb = (%d, %d), want (0, 2)", start, size)
	}
	start, size = ScrollbarThumb(100, 20, 80, 10)
	if start != 8 || size != 2 {
		t.Fatalf("bottom thumb = (%d, %d), want (8, 2)", start, size)
	}
	if got := ScrollbarOffsetForRow(100, 20, 10, 9, 1); got != 80 {
		t.Fatalf("bottom drag offset = %d, want 80", got)
	}
	if got := ScrollbarOffsetForRow(100, 20, 10, -10, 0); got != 0 {
		t.Fatalf("clamped top drag offset = %d, want 0", got)
	}
	if got := ScrollbarOffsetForRow(8, 20, 10, 5, 0); got != 0 {
		t.Fatalf("fitting content offset = %d, want 0", got)
	}
	if got := ScrollbarOffsetForDrag(100, 20, 10, 17, 2, 2); got != 17 {
		t.Fatalf("stationary drag offset = %d, want 17", got)
	}
}

func TestOverlayScrollbarPreservesWidthAndColor(t *testing.T) {
	pane := "\x1b[31mhello   \x1b[0m\n12345678"
	bar := RenderScrollbar(100, 20, 0, 2, themes.Solarized())
	got := OverlayScrollbar(pane, 7, 0, bar)
	for i, line := range strings.Split(got, "\n") {
		if width := ansi.StringWidth(line); width != 8 {
			t.Errorf("line %d width = %d, want 8", i, width)
		}
	}
	if !strings.Contains(got, "\x1b[31m") {
		t.Fatal("original color was lost")
	}
	short := OverlayScrollbar("abc", 7, 0, bar)
	if got := ansi.Strip(strings.Split(short, "\n")[0]); got != "abc    ▉" {
		t.Fatalf("short line = %q, want padded content and scrollbar", got)
	}
}

func TestTabScrollbarsReserveContentColumn(t *testing.T) {
	nodes := NewNodesView()
	nodes.SetSize(8, 3)
	nodes.viewport.SetContent("1234567")
	if got := ansi.Strip(strings.Split(nodes.View(), "\n")[0]); got != "1234567▉" {
		t.Errorf("nodes first row = %q", got)
	}

	stats := NewStatisticsView()
	stats.SetSize(8, 3)
	stats.stats = &Statistics{
		TotalPackets:   1,
		ProtocolCounts: NewBoundedCounter(10),
		SourceCounts:   NewBoundedCounter(10),
		DestCounts:     NewBoundedCounter(10),
	}
	stats.viewport.SetContent("1234567")
	stats.dirty = false
	if got := ansi.Strip(strings.Split(stats.View(), "\n")[0]); got != "1234567▉" {
		t.Errorf("statistics first row = %q", got)
	}

	help := NewHelpView()
	help.SetSize(8, 4)
	help.HandleContentLoaded(HelpContentLoadedMsg{Section: SectionKeybindings, RenderedContent: "1234567"})
	if got := ansi.Strip(strings.Split(help.View(), "\n")[1]); got != "1234567▉" {
		t.Errorf("help first content row = %q", got)
	}
}

func TestScrollbarMouseClickAndDrag(t *testing.T) {
	var drag scrollbarDrag
	offset, handled := handleScrollbarMouse(tea.MouseMsg{X: 79, Y: 13, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}, 79, 6, 100, 20, 0, 10, &drag)
	if !handled || offset <= 0 || !drag.active {
		t.Fatalf("track click: offset=%d handled=%v active=%v", offset, handled, drag.active)
	}
	offset, handled = handleScrollbarMouse(tea.MouseMsg{X: 78, Y: 15, Action: tea.MouseActionMotion}, 79, 6, 100, 20, offset, 10, &drag)
	if !handled || offset != 80 {
		t.Fatalf("drag to bottom: offset=%d handled=%v", offset, handled)
	}
	_, handled = handleScrollbarMouse(tea.MouseMsg{Action: tea.MouseActionRelease}, 79, 6, 100, 20, offset, 10, &drag)
	if !handled || drag.active {
		t.Fatalf("release: handled=%v active=%v", handled, drag.active)
	}
}

func TestScrollbarThumbPressDoesNotJump(t *testing.T) {
	var drag scrollbarDrag
	start, _ := ScrollbarThumb(100, 20, 17, 10)
	press := tea.MouseMsg{X: 79, Y: 6 + start, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}
	offset, handled := handleScrollbarMouse(press, 79, 6, 100, 20, 17, 10, &drag)
	if !handled || offset != 17 {
		t.Fatalf("thumb press: offset=%d handled=%v, want unchanged offset 17", offset, handled)
	}
	offset, handled = handleScrollbarMouse(tea.MouseMsg{X: 79, Y: press.Y, Action: tea.MouseActionMotion}, 79, 6, 100, 20, offset, 10, &drag)
	if !handled || offset != 17 {
		t.Fatalf("stationary thumb drag: offset=%d handled=%v, want unchanged offset 17", offset, handled)
	}
}

//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type footerHintExpectation struct {
	text string
	key  tea.KeyMsg
}

func footerRuneHint(text, key string) footerHintExpectation {
	return footerHintExpectation{text: text, key: tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}}
}

// Check rendered terminal cells rather than the layout's internal hit ranges.
func assertFooterHints(t *testing.T, footer *Footer, hints []footerHintExpectation) {
	t.Helper()
	before := *footer
	line := strings.Split(ansi.Strip(footer.View()), "\n")[1]
	expected := make(map[int]tea.KeyMsg)
	for _, hint := range hints {
		index := strings.Index(line, " "+hint.text+" ")
		require.NotEqual(t, -1, index, "missing hint %q in %q", hint.text, line)
		start := lipgloss.Width(line[:index+1])
		for x := start; x < start+lipgloss.Width(hint.text); x++ {
			expected[x] = hint.key
		}
	}
	for x := -1; x <= footer.width; x++ {
		got, hit := footer.KeyAtX(x)
		want, exists := expected[x]
		require.Equal(t, exists, hit, "column %d in %q", x, line)
		if exists {
			assert.Equal(t, want, got, "column %d in %q", x, line)
		}
	}
	assert.Equal(t, before, *footer, "rendering and hit testing must be read-only")
}

func TestFooterClickableHintsAcrossTabs(t *testing.T) {
	general := []footerHintExpectation{
		{text: "Space: pause", key: tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}},
		footerRuneHint("p: protocol", "p"),
		footerRuneHint("q: quit", "q"),
	}
	tests := []struct {
		name  string
		tab   int
		hints []footerHintExpectation
	}{
		{"capture", 0, []footerHintExpectation{
			footerRuneHint("/: filter", "/"), footerRuneHint("d: details", "d"),
			footerRuneHint("t: time", "t"), footerRuneHint("w: save", "w"),
			footerRuneHint("x: flush", "x"),
		}},
		{"nodes", 1, []footerHintExpectation{
			footerRuneHint("f: filters", "f"), footerRuneHint("a: add", "a"),
			footerRuneHint("d: delete", "d"), footerRuneHint("s: select", "s"),
			footerRuneHint("v: view", "v"),
		}},
		{"statistics", 2, []footerHintExpectation{
			footerRuneHint("v: view", "v"), footerRuneHint("1: overview", "1"),
			footerRuneHint("2: distributed", "2"), footerRuneHint("e: export", "e"),
		}},
		{"settings", 3, []footerHintExpectation{
			{text: "Enter: edit/toggle", key: tea.KeyMsg{Type: tea.KeyEnter}},
			{text: "Esc: cancel", key: tea.KeyMsg{Type: tea.KeyEsc}},
			{text: "←: previous", key: tea.KeyMsg{Type: tea.KeyLeft}},
			{text: "→: next", key: tea.KeyMsg{Type: tea.KeyRight}},
		}},
		{"help", 4, []footerHintExpectation{
			footerRuneHint("/: search", "/"), footerRuneHint("1: keys", "1"),
			footerRuneHint("2: filters", "2"), footerRuneHint("3: commands", "3"),
			footerRuneHint("4: workflows", "4"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			footer := NewFooter()
			footer.SetWidth(400)
			footer.SetActiveTab(tt.tab)
			assertFooterHints(t, &footer, append(tt.hints, general...))
		})
	}
}

func TestFooterClickableDynamicHints(t *testing.T) {
	for _, mode := range []string{"packets", "calls", "events"} {
		t.Run(mode, func(t *testing.T) {
			footer := NewFooter()
			footer.SetWidth(400)
			footer.SetViewMode(mode)
			footer.SetPaused(true)
			footer.SetStreamingSave(true)
			footer.SetHasEvents(true)
			hints := []footerHintExpectation{
				footerRuneHint("/: filter", "/"), footerRuneHint("d: details", "d"),
				footerRuneHint("t: time", "t"), footerRuneHint("v: view", "v"),
				footerRuneHint("w: stop", "w"), footerRuneHint("x: flush", "x"),
				{text: "Space: resume", key: tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}},
				footerRuneHint("p: protocol", "p"), footerRuneHint("q: quit", "q"),
			}
			assertFooterHints(t, &footer, hints)
			switch mode {
			case "packets":
				footer.SetHasFilter(true)
				footer.SetFilterCount(2)
			case "calls":
				footer.SetHasCallFilter(true)
				footer.SetCallFilterCount(2)
			case "events":
				footer.SetHasEventFilter(true)
				footer.SetEventFilterCount(2)
			}
			clear, clearAll := "c: clear", "C: clear all"
			if mode == "events" {
				clear, clearAll = "c: remove event filter", "C: clear event filters"
			}
			assertFooterHints(t, &footer, append(hints, footerRuneHint(clear, "c"), footerRuneHint(clearAll, "C")))
		})
	}

	t.Run("help search", func(t *testing.T) {
		footer := NewFooter()
		footer.SetWidth(400)
		footer.SetActiveTab(4)
		footer.SetHasHelpSearch(true)
		assertFooterHints(t, &footer, []footerHintExpectation{
			footerRuneHint("/: search", "/"), footerRuneHint("n: next", "n"),
			footerRuneHint("N: previous", "N"), footerRuneHint("c: clear", "c"),
			footerRuneHint("1: keys", "1"), footerRuneHint("2: filters", "2"),
			footerRuneHint("3: commands", "3"), footerRuneHint("4: workflows", "4"),
			{text: "Space: pause", key: tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}},
			footerRuneHint("p: protocol", "p"), footerRuneHint("q: quit", "q"),
		})
	})
}

func TestFooterFilterInputHints(t *testing.T) {
	for _, mode := range []string{"packets", "calls", "events"} {
		t.Run(mode, func(t *testing.T) {
			footer := NewFooter()
			footer.SetWidth(200)
			switch mode {
			case "packets":
				footer.SetFilterMode(true)
			case "calls":
				footer.SetCallFilterMode(true)
			case "events":
				footer.SetEventFilterMode(true)
			}
			assertFooterHints(t, &footer, []footerHintExpectation{
				{text: "Enter: apply", key: tea.KeyMsg{Type: tea.KeyEnter}},
				{text: "Esc: cancel", key: tea.KeyMsg{Type: tea.KeyEsc}},
				{text: "↑: older history", key: tea.KeyMsg{Type: tea.KeyUp}},
				{text: "↓: newer history", key: tea.KeyMsg{Type: tea.KeyDown}},
			})
		})
	}
}

func TestFooterResponsiveHitRegions(t *testing.T) {
	footer := NewFooter()
	footer.SetWidth(100)
	assertFooterHints(t, &footer, []footerHintExpectation{
		footerRuneHint("/:flt", "/"), footerRuneHint("d:det", "d"),
		footerRuneHint("t:tm", "t"), footerRuneHint("w:sav", "w"),
		footerRuneHint("x:flsh", "x"),
		{text: "Space:pse", key: tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}},
		footerRuneHint("p:prt", "p"), footerRuneHint("q:qt", "q"),
	})
	footer.SetWidth(40)
	assertFooterHints(t, &footer, []footerHintExpectation{
		footerRuneHint("/", "/"), footerRuneHint("d", "d"), footerRuneHint("w", "w"),
		{text: "Space", key: tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}},
		footerRuneHint("p", "p"), footerRuneHint("q", "q"),
	})
	footer.SetWidth(20)
	assertFooterHints(t, &footer, []footerHintExpectation{
		footerRuneHint("/", "/"), footerRuneHint("d", "d"), footerRuneHint("w", "w"),
	})
	footer.SetWidth(3)
	assertFooterHints(t, &footer, []footerHintExpectation{footerRuneHint("/", "/")})
	footer.SetWidth(2)
	assertFooterHints(t, &footer, nil)

	footer.SetWidth(40)
	footer.SetFilterMode(true)
	assertFooterHints(t, &footer, []footerHintExpectation{
		{text: "Enter", key: tea.KeyMsg{Type: tea.KeyEnter}},
		{text: "Esc", key: tea.KeyMsg{Type: tea.KeyEsc}},
		{text: "↑", key: tea.KeyMsg{Type: tea.KeyUp}},
		{text: "↓", key: tea.KeyMsg{Type: tea.KeyDown}},
	})
}

func TestFooterStaysWithinTerminalWidth(t *testing.T) {
	for tab := range 5 {
		for _, filterMode := range []bool{false, true} {
			for _, width := range []int{-1, 0, 1, 2, 3, 10, 20, 40, 79, 80, 100, 119, 120, 140, 200, 400} {
				t.Run(fmt.Sprintf("tab%d/filter%t/width%d", tab, filterMode, width), func(t *testing.T) {
					footer := NewFooter()
					footer.SetActiveTab(tab)
					footer.SetWidth(width)
					footer.SetHasHelpSearch(true)
					footer.SetHasFilter(true)
					footer.SetFilterCount(2)
					footer.SetFilterMode(filterMode)
					lines := strings.Split(footer.View(), "\n")
					require.Len(t, lines, 2)
					for _, line := range lines {
						assert.Equal(t, max(0, width), lipgloss.Width(line))
					}
					_, hit := footer.KeyAtX(width)
					assert.False(t, hit)
				})
			}
		}
	}
}

func TestFooterHitTestingBeforeRender(t *testing.T) {
	footer := NewFooter()
	footer.SetActiveTab(3)
	footer.SetWidth(400)
	before := footer
	key, hit := footer.KeyAtX(1)
	require.True(t, hit)
	assert.Equal(t, tea.KeyMsg{Type: tea.KeyEnter}, key)
	assert.Equal(t, before, footer)

	footer.SetActiveTab(4)
	key, hit = footer.KeyAtX(1)
	require.True(t, hit)
	assert.Equal(t, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}}, key)
	footer.SetWidth(2)
	_, hit = footer.KeyAtX(1)
	assert.False(t, hit)
}

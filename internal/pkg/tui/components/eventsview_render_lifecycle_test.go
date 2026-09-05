//go:build tui || all

package components

import (
	"math/rand"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/require"
)

// Exercise the cache through the component's public mutation paths, comparing
// each result with the independent pre-cache renderer. Repeated IDs and full
// replacement deliberately prevent stable IDs from serving as row cache keys.
func TestEventsViewRandomizedRenderLifecycle(t *testing.T) {
	rng := rand.New(rand.NewSource(707))
	pool := benchmarkEventItems(91)
	view := NewEventsView()
	view.SetEvents(pool[:40])
	width, height := 100, 14
	for step := range 350 {
		switch rng.Intn(8) {
		case 0:
			start := rng.Intn(len(pool) - 6)
			view.AppendEvents(pool[start : start+1+rng.Intn(5)])
		case 1:
			view.TrimOldEvents(rng.Intn(8))
		case 2:
			start := rng.Intn(len(pool) - 30)
			view.SetEvents(pool[start : start+rng.Intn(30)])
		case 3:
			if len(view.items) > 0 {
				view.SetSelectedID(view.items[rng.Intn(len(view.items))].Event.Envelope().EventID)
			}
		case 4:
			width, height = 18+rng.Intn(170), 1+rng.Intn(22)
			view.SetSize(width, height)
		case 5:
			theme := themes.Solarized()
			if rng.Intn(2) == 0 {
				theme.SelectionBg = lipgloss.Color("#ff0022")
				theme.DNSColor = lipgloss.Color("#44cc11")
			}
			view.SetTheme(theme)
		case 6:
			view.SelectNext()
		case 7:
			view.SelectPrevious()
		}
		if len(view.items) > 100 {
			view.TrimOldEvents(len(view.items) - 100)
		}
		// A render between mutation and preparation must remain correct. It
		// cannot commit geometry or invalidate the prepared hit-testing state.
		focused := rng.Intn(2) == 0
		require.Equal(t, legacyEventTimeline(view, width, height, focused), view.RenderTimeline(width, height, focused), "unprepared step %d", step)
		view.PrepareLayout(width, height, 0, 0)
		for _, geometry := range [][2]int{{width, height}, {width + 3, height + 2}, {width, height}} {
			for _, focused := range []bool{false, true} {
				require.Equal(t, legacyEventTimeline(view, geometry[0], geometry[1], focused), view.RenderTimeline(geometry[0], geometry[1], focused), "prepared step %d geometry %v focus %v", step, geometry, focused)
			}
		}
	}
}

func TestEventsViewRenderDuplicateNavigationOffset(t *testing.T) {
	view := NewEventsView()
	view.SetEvents([]EventItem{
		{Event: dnsEvent("same", "first.example")},
		{Event: dnsEvent("same", "second.example")},
		{Event: dnsEvent("other", "third.example")},
	})
	view.PrepareLayout(180, 6, 0, 0)
	view.SelectNext()
	// Selection is ID-based, while navigation preserves its existing visual
	// offset. The cached renderer must use exactly that committed offset.
	require.Equal(t, legacyEventTimeline(view, 180, 6, true), view.RenderTimeline(180, 6, true))
	view.PrepareLayout(180, 6, 0, 0)
	require.Equal(t, legacyEventTimeline(view, 180, 6, true), view.RenderTimeline(180, 6, true))
}

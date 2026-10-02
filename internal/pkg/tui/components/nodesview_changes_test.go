//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/components/nodesview"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func changeViewFixture() (NodesView, []ProcessorInfo, *time.Time) {
	now := time.Unix(100, 0)
	n := NewNodesView()
	n.changeNow = func() time.Time { return now }
	n.SetRemoteChanges(true)
	n.SetSize(150, 20)
	p := []ProcessorInfo{{Address: "processor-b", ConnectionState: ProcessorConnectionStateConnected, Hunters: []HunterInfo{{ID: "hunter", Hostname: "edge", CPUPercent: 10, MemoryRSSBytes: 1000000, ActiveFilters: 2, PacketsCaptured: 10}}}}
	n.SetProcessors(p)
	return n, p, &now
}

func TestNodesChangesRemoteBaselineAndExpiry(t *testing.T) {
	n, p, now := changeViewFixture()
	key := nodesview.NodeKey{ProcessorAddr: p[0].Address, HunterID: "hunter"}
	assert.Equal(t, nodesview.NodeChanges{}, n.changeState[key])
	assert.NotContains(t, ansi.Strip(n.View()), "↑")
	p[0].Hunters[0].CPUPercent = 15
	n.SetProcessors(p)
	assert.True(t, n.changeState[key].CPU.Changed)
	assert.Contains(t, ansi.Strip(n.View()), "↑")
	*now = now.Add(500 * time.Millisecond)
	n.SetProcessors(p)
	*now = now.Add(500 * time.Millisecond)
	assert.True(t, n.AdvanceChanges(*now))
	assert.False(t, n.changeState[key].CPU.Changed)
	assert.NotContains(t, ansi.Strip(n.View()), "↑")
	assert.False(t, n.AdvanceChanges(now.Add(time.Second)))
	n.SetRemoteChanges(false)
	p[0].Hunters[0].CPUPercent = 20
	n.SetProcessors(p)
	assert.Empty(t, n.changeState)
	assert.Equal(t, n.height, n.viewport.Height)
	n.SetRemoteChanges(true)
	assert.Equal(t, nodesview.NodeChanges{}, n.changeState[key], "reenabling establishes a baseline")
}

func TestNodesChangesSelectionKeepsOwningProcessorIdentity(t *testing.T) {
	n, p, _ := changeViewFixture()
	n.selectedIndex, n.selectedProcessorAddr = 0, ""
	p = append(p, ProcessorInfo{Address: "processor-a", ConnectionState: ProcessorConnectionStateConnected, Hunters: []HunterInfo{{ID: "hunter", Hostname: "other-edge"}}})
	n.SetProcessors(p)
	require.NotNil(t, n.GetSelectedHunter())
	assert.Equal(t, "processor-b", n.GetSelectedHunter().ProcessorAddr)
	assert.Equal(t, "edge", n.GetSelectedHunter().Hostname)
	p[0].Hunters = append(p[0].Hunters, HunterInfo{ID: "aaa", Hostname: "earlier"})
	n.SetProcessors(p)
	assert.Equal(t, "hunter", n.GetSelectedHunter().ID)
	assert.Equal(t, "processor-b", n.GetSelectedHunter().ProcessorAddr)
	// Removing the selected hunter chooses its owning processor, not the
	// identically named hunter on another processor.
	n.NodeRemoved("processor-b", "hunter", "edge")
	p[0].Hunters = p[0].Hunters[1:]
	n.SetProcessors(p)
	assert.Nil(t, n.GetSelectedHunter())
	assert.Equal(t, "processor-b", n.GetSelectedProcessorAddr())
	assert.NotContains(t, n.changeState, nodesview.NodeKey{ProcessorAddr: "processor-b", HunterID: "hunter"})
	assert.Contains(t, n.recentChange, "edge disconnected")
	n.SetProcessors(p[1:])
	assert.Equal(t, "processor-a", n.GetSelectedProcessorAddr(), "removed owner chooses a valid deterministic neighbor")
}

func TestNodesChangesEventSlotFixedAndShortTerminals(t *testing.T) {
	n, p, now := changeViewFixture()
	baselineHeight := len(strings.Split(n.View(), "\n"))
	assert.Equal(t, n.height-1, n.viewport.Height)
	n.NodeJoined(p[0].Address, "new", "new-edge")
	p[0].Hunters = append(p[0].Hunters, HunterInfo{ID: "new", Hostname: "new-edge"})
	n.SetProcessors(p)
	assert.Equal(t, baselineHeight, len(strings.Split(n.View(), "\n")))
	lines := strings.Split(ansi.Strip(n.View()), "\n")
	assert.Contains(t, lines[len(lines)-1], "new-edge joined")
	*now = now.Add(30 * time.Second)
	n.AdvanceChanges(*now)
	assert.Equal(t, baselineHeight, len(strings.Split(n.View(), "\n")))
	assert.Empty(t, n.recentChange)
	n.SetSize(40, 5)
	assert.Zero(t, n.recentEventHeight())
	assert.Equal(t, 5, n.viewport.Height)
	assert.Len(t, strings.Split(n.View(), "\n"), 5)
}

func TestNodesChangesEventSlotExcludedFromInputAndScrollbar(t *testing.T) {
	n, p, _ := changeViewFixture()
	for i := 0; i < 40; i++ {
		p[0].Hunters = append(p[0].Hunters, HunterInfo{ID: fmt.Sprintf("h-%02d", i)})
	}
	n.SetSize(150, 10)
	n.SetProcessors(p)
	n.selectedIndex, n.selectedProcessorAddr = -1, p[0].Address
	n.viewport.SetYOffset(0)
	// Guard the reserved event line even if an offscreen node has that content
	// line number. Mouse coordinates include five lines of surrounding TUI.
	n.hunterLines[n.viewport.Height] = 0
	n.handleMouseClick(tea.MouseMsg{X: 4, Y: 5 + n.viewport.Height, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	assert.Equal(t, -1, n.selectedIndex)
	assert.Equal(t, p[0].Address, n.selectedProcessorAddr)
	_, selectable := n.TextSelectionAt(4, n.viewport.Height)
	assert.False(t, selectable)
	region, selectable := n.TextSelectionAt(4, n.viewport.Height-1)
	require.True(t, selectable)
	assert.Equal(t, n.viewport.Height, region.Height)
	_, selectable = n.TextSelectionAt(n.displayWidth-1, 0)
	assert.False(t, selectable)
	n.Update(tea.MouseMsg{X: n.displayWidth - 1, Y: 5 + n.viewport.Height, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	assert.False(t, n.scrollbarDrag.active)
	assert.Zero(t, n.viewport.YOffset)
	// Actual table rows remain clickable with the fixed slot present.
	for line, index := range n.hunterLines {
		if line < n.viewport.Height {
			n.handleMouseClick(tea.MouseMsg{X: 4, Y: 5 + line, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
			assert.Equal(t, index, n.selectedIndex)
			return
		}
	}
	t.Fatal("expected a visible hunter row")
}

func TestNodesChangesQuietAndViewSwitchPreserveExpiry(t *testing.T) {
	n, p, now := changeViewFixture()
	n.selectedIndex, n.selectedProcessorAddr = 0, ""
	p[0].Hunters[0].CPUPercent = 20
	p[0].Hunters[0].MemoryRSSBytes = 2000000
	n.SetProcessors(p)
	before := ansi.Strip(n.View())
	n.SetHighlightMode("quiet")
	assert.Equal(t, "quiet", n.highlightMode)
	assert.Equal(t, before, ansi.Strip(n.View()), "quiet keeps textual change markers")
	key := nodesview.NodeKey{ProcessorAddr: p[0].Address, HunterID: "hunter"}
	change := n.changeState[key]
	*now = now.Add(500 * time.Millisecond)
	require.True(t, n.ToggleView())
	assert.Equal(t, "graph", n.GetViewMode())
	assert.Equal(t, change, n.changeState[key])
	assert.Contains(t, ansi.Strip(n.View()), "↑")
	*now = now.Add(500 * time.Millisecond)
	n.AdvanceChanges(*now)
	assert.False(t, n.changeState[key].CPU.Changed)
	require.True(t, n.ToggleView())
	assert.NotContains(t, ansi.Strip(n.View()), "↑", "switching back cannot replay expired cues")
	n.SetHighlightMode("unknown")
	assert.Equal(t, "normal", n.highlightMode)
}

func TestNodesChangesExpiryPreservesScrollPosition(t *testing.T) {
	n, p, now := changeViewFixture()
	for i := 0; i < 40; i++ {
		p[0].Hunters = append(p[0].Hunters, HunterInfo{ID: fmt.Sprintf("h-%02d", i)})
	}
	n.SetSize(100, 8)
	n.SetProcessors(p)
	p[0].Hunters[0].CPUPercent = 90
	n.SetProcessors(p)
	n.viewport.SetYOffset(10)
	require.Equal(t, 10, n.viewport.YOffset)
	*now = now.Add(time.Second)
	require.True(t, n.AdvanceChanges(*now))
	assert.Equal(t, 10, n.viewport.YOffset)
}

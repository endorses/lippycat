//go:build tui || all

package components

import (
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/components/nodesview"
)

func (n *NodesView) changesTime() time.Time {
	if n.changeNow != nil {
		return n.changeNow()
	}
	return time.Now()
}

func (n *NodesView) ensureChanges() {
	if n.changes == nil {
		n.changes = &nodesview.ChangeTracker{}
	}
}

func (n *NodesView) observeNodeChanges() {
	if !n.remoteChanges {
		return
	}
	n.ensureChanges()
	now := n.changesTime()
	n.changes.Observe(convertProcessorInfos(n.processors), now)
	n.changes.Advance(now)
	n.changeState = n.changes.Snapshot()
	n.recentChange = n.changes.RecentText(now)
}

// SetRemoteChanges gates all change presentation to remote capture mode.
func (n *NodesView) SetRemoteChanges(enabled bool) {
	if n.remoteChanges == enabled {
		return
	}
	n.remoteChanges = enabled
	n.ResetChanges()
	if n.ready {
		n.SetSize(n.displayWidth, n.height)
	}
}

func (n *NodesView) SetHighlightMode(mode string) {
	if mode != "quiet" {
		mode = "normal"
	}
	if n.highlightMode == mode {
		return
	}
	n.highlightMode = mode
	n.updateViewportContent()
}

// ResetChanges starts a new presentation session with a quiet baseline.
func (n *NodesView) ResetChanges() {
	n.ensureChanges()
	n.changes.Reset()
	n.changeState = nil
	n.recentChange = ""
	n.observeNodeChanges()
	n.updateViewportContent()
}

// NodeBaseline identifies existing topology or nodes revealed by subscription.
func (n *NodesView) NodeBaseline(processorAddr, hunterID, name string) {
	if !n.remoteChanges {
		return
	}
	n.ensureChanges()
	n.changes.Baseline(nodesview.NodeKey{ProcessorAddr: processorAddr, HunterID: hunterID}, name)
}

// NodeJoined is called only for confirmed additions, before snapshot replacement.
func (n *NodesView) NodeJoined(processorAddr, hunterID, name string) {
	if !n.remoteChanges {
		return
	}
	n.ensureChanges()
	n.changes.Joined(nodesview.NodeKey{ProcessorAddr: processorAddr, HunterID: hunterID}, name, n.changesTime())
}

// NodeRemoved records a confirmed removal before its row is discarded.
func (n *NodesView) NodeRemoved(processorAddr, hunterID, name string) {
	if !n.remoteChanges {
		return
	}
	n.ensureChanges()
	n.changes.Removed(nodesview.NodeKey{ProcessorAddr: processorAddr, HunterID: hunterID}, name, n.changesTime())
}

// AdvanceChanges uses the model's single tick chain. It returns whether a visible
// highlight or event age changed; ordinary ticks do not rebuild node content.
func (n *NodesView) AdvanceChanges(now time.Time) bool {
	if !n.remoteChanges || n.changes == nil || !n.changes.Advance(now) {
		return false
	}
	n.changeState = n.changes.Snapshot()
	n.recentChange = n.changes.RecentText(now)
	if n.ready {
		// Expiry must not recenter a graph or undo the user's scroll position.
		offset := n.viewport.YOffset
		n.viewport.SetContent(n.renderContent())
		n.viewport.SetYOffset(offset)
	}
	return true
}

func (n *NodesView) recentEventHeight() int {
	if n.remoteChanges && n.height >= 6 {
		return 1
	}
	return 0
}

func (n *NodesView) renderRecentChange() string {
	return lipgloss.NewStyle().Foreground(n.theme.Foreground).Render(ansi.Truncate(n.recentChange, n.width, "…"))
}

//go:build tui || all

package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Keep the pointer's offset from the split so either adjacent border can be
// grabbed without moving the panes on press. Preferences are shared by the
// three capture views, with a separate proportion for each orientation.
type capturePaneDrag struct {
	mode                captureLayoutMode
	view                string
	width, height, top  int
	press, initialSplit int
}

func (d capturePaneDrag) valid(m Model) bool {
	return m.uiState.Tabs.GetActive() == 0 && m.responsiveCaptureView() &&
		m.textSelectionAllowed() && m.uiState.ViewMode == d.view &&
		m.captureLayout().Mode == d.mode && m.uiState.Width == d.width &&
		m.captureContentHeight() == d.height && m.captureContentOrigin() == d.top
}

func (m Model) handleCaptureResize(msg tea.MouseMsg) (Model, bool) {
	if d := m.captureResizeDrag; d != nil {
		if !d.valid(m) {
			m.captureResizeDrag = nil
			return m, true
		}
		switch msg.Action {
		case tea.MouseActionRelease:
			// Release coordinates are missing in some terminals. The last
			// motion determines the split, just as for text selection.
			m.captureResizeDrag = nil
			return m, true
		case tea.MouseActionMotion:
			if msg.Button != tea.MouseButtonLeft {
				m.captureResizeDrag = nil
				return m, true
			}
			if d.mode == captureSideBySide {
				listMin, detailMin := m.capturePaneMinWidths()
				split := min(d.width-detailMin, max(listMin, d.initialSplit+msg.X-d.press))
				m.captureSideRatio = float64(split) / float64(d.width)
			} else {
				split := min(d.height-14, max(10, d.initialSplit+msg.Y-d.press))
				m.captureStackRatio = float64(split) / float64(d.height)
			}
			m.prepareCaptureLayout()
			return m, true
		default:
			// A new press ends a gesture whose release was omitted.
			m.captureResizeDrag = nil
		}
	}
	if msg.Action != tea.MouseActionPress || msg.Button != tea.MouseButtonLeft ||
		m.uiState.Tabs.GetActive() != 0 || !m.responsiveCaptureView() || !m.textSelectionAllowed() {
		return m, false
	}
	l := m.captureLayout()
	top := m.captureContentOrigin()
	x, y := msg.X, msg.Y-top
	press, split := 0, 0
	switch l.Mode {
	case captureSideBySide:
		if y < 0 || y >= l.List.Height || (x != l.List.Width-1 && x != l.Details.X) {
			return m, false
		}
		press, split = msg.X, l.List.Width
	case captureStacked:
		if x < 0 || x >= l.List.Width || (y != l.List.Height-1 && y != l.Details.Y) {
			return m, false
		}
		press, split = msg.Y, l.List.Height
	default:
		return m, false
	}
	m.captureResizeDrag = &capturePaneDrag{
		mode: l.Mode, view: m.uiState.ViewMode,
		width: m.uiState.Width, height: m.captureContentHeight(), top: top,
		press: press, initialSplit: split,
	}
	m.textSelection = nil
	m.scrollDrag = ""
	m.uiState.LastClickTime = time.Time{}
	m.uiState.LastEventClickTime = time.Time{}
	m.offlineLastClickValid = false
	return m, true
}

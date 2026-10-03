//go:build tui || all

package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type captureRect struct{ X, Y, Width, Height int }

func (r captureRect) contains(x, y int) bool {
	return r.Width > 0 && r.Height > 0 && x >= r.X && y >= r.Y && x < r.X+r.Width && y < r.Y+r.Height
}

type captureLayoutMode int

const (
	captureListOnly captureLayoutMode = iota
	captureSideBySide
	captureStacked
	captureDetailsOnly
)

type captureLayout struct {
	Mode          captureLayoutMode
	List, Details captureRect
}

func (m Model) responsiveCaptureView() bool {
	return m.uiState.ViewMode == "packets" || m.uiState.ViewMode == "events" || m.uiState.ViewMode == "calls"
}

func (m Model) captureDetailsEnabled() bool {
	switch m.uiState.ViewMode {
	case "events":
		return m.uiState.EventShowDetails
	case "calls":
		return m.uiState.CallsView.IsShowingDetails()
	default:
		return m.uiState.ShowDetails
	}
}

func (m *Model) setCaptureDetails(enabled bool) {
	switch m.uiState.ViewMode {
	case "events":
		m.uiState.EventShowDetails = enabled
	case "calls":
		if m.uiState.CallsView.IsShowingDetails() != enabled {
			m.uiState.CallsView.ToggleDetails()
		}
	default:
		m.uiState.ShowDetails = enabled
	}
}

// Pane minima describe useful content, rather than a particular terminal size.
// Below these widths, long detail values wrap in a stacked or single pane.
func (m Model) captureLayout() captureLayout {
	w, h := max(0, m.uiState.Width), m.captureContentHeight()
	full := captureRect{Width: w, Height: h}
	layout := captureLayout{List: full}
	if !m.captureDetailsEnabled() || w == 0 || h == 0 {
		return layout
	}
	listMin, detailMin := 72, 56
	if m.uiState.ViewMode == "events" {
		listMin, detailMin = 64, 40
	}
	if m.uiState.ViewMode == "calls" {
		listMin, detailMin = 48, 40
	}
	if w >= listMin+detailMin && h >= 8 {
		dw := min(80, w-listMin)
		return captureLayout{captureSideBySide, captureRect{Width: w - dw, Height: h}, captureRect{X: w - dw, Width: dw, Height: h}}
	}
	// Ten list rows and fourteen detail rows include their border/padding.
	if w >= max(40, detailMin) && h >= 24 {
		lh := max(10, h/3)
		return captureLayout{captureStacked, captureRect{Width: w, Height: lh}, captureRect{Y: lh, Width: w, Height: h - lh}}
	}
	if m.uiState.FocusedPane == "right" {
		return captureLayout{Mode: captureDetailsOnly, Details: full}
	}
	return layout
}

// Short terminals progressively omit decorative chrome to retain useful rows.
// The same strings determine rendering and mouse coordinates.
func (m Model) captureChrome() (header, tabs, bottom string) {
	header, tabs = m.uiState.Header.View(), m.uiState.Tabs.View()
	footer := m.uiState.Footer.View()
	if m.uiState.Height < 12 {
		if i := strings.IndexByte(footer, '\n'); i >= 0 {
			footer = footer[i+1:]
		}
	}
	extra := ""
	switch {
	case m.uiState.FilterMode:
		extra = m.uiState.FilterInput.View()
	case m.uiState.CallFilterMode:
		extra = m.uiState.CallFilterInput.View()
	case m.uiState.EventFilterMode:
		extra = m.uiState.EventFilterInput.View()
	}
	bottom = footer
	if extra != "" {
		bottom = extra + "\n" + footer
	}
	if m.uiState.Height-lipgloss.Height(bottom)-lipgloss.Height(header)-lipgloss.Height(tabs) < 8 {
		header = ""
	}
	if m.uiState.Height-lipgloss.Height(bottom)-nonemptyHeight(header)-lipgloss.Height(tabs) < 8 {
		tabs = ""
	}
	// Keep one content row even at extremely small sizes. The final hint row
	// stays at the bottom, including while a filter is displayed.
	maxBottom := max(0, m.uiState.Height-1)
	lines := strings.Split(bottom, "\n")
	if len(lines) > maxBottom {
		bottom = strings.Join(lines[len(lines)-maxBottom:], "\n")
	}
	return
}

func nonemptyHeight(s string) int {
	if s == "" {
		return 0
	}
	return lipgloss.Height(s)
}

func (m Model) captureContentOrigin() int {
	if m.uiState.Tabs.GetActive() != 0 || !m.responsiveCaptureView() {
		return nonemptyHeight(m.uiState.Header.View()) + nonemptyHeight(m.uiState.Tabs.View())
	}
	h, t, _ := m.captureChrome()
	return nonemptyHeight(h) + nonemptyHeight(t)
}

func (m Model) captureContentHeight() int {
	if m.uiState.Tabs.GetActive() != 0 || !m.responsiveCaptureView() {
		filterHeight := nonemptyHeight(m.renderBottomArea(m.uiState.Footer.View())) - nonemptyHeight(m.uiState.Footer.View())
		return max(0, m.standardContentHeight()-filterHeight)
	}
	h, t, b := m.captureChrome()
	return max(0, m.uiState.Height-nonemptyHeight(h)-nonemptyHeight(t)-nonemptyHeight(b))
}

// standardContentHeight budgets the persistent chrome on non-responsive tabs.
func (m Model) standardContentHeight() int {
	return max(0, m.uiState.Height-nonemptyHeight(m.uiState.Header.View())-
		nonemptyHeight(m.uiState.Tabs.View())-nonemptyHeight(m.uiState.Footer.View()))
}

func fitCapturePane(view string, width, height int) string {
	if width <= 0 || height <= 0 {
		return ""
	}
	lines := strings.Split(view, "\n")
	for len(lines) < height {
		lines = append(lines, "")
	}
	lines = lines[:height]
	for i, line := range lines {
		line = ansi.Truncate(line, width, "")
		lines[i] = line + strings.Repeat(" ", max(0, width-lipgloss.Width(line)))
	}
	return strings.Join(lines, "\n")
}

func (m Model) captureDetailsFocused() bool {
	return m.responsiveCaptureView() && m.uiState.FocusedPane == "right" && m.captureLayout().Details.Width > 0
}

func (m *Model) prepareCaptureLayout() {
	if !m.responsiveCaptureView() {
		return
	}
	l := m.captureLayout()
	previousInspection := m.captureInspectionMode
	inspecting := m.uiState.Tabs.GetActive() == 0 && l.Mode == captureDetailsOnly
	m.captureInspectionMode = ""
	if inspecting {
		m.captureInspectionMode = m.uiState.ViewMode
	}
	if inspecting && m.uiState.ViewMode == "packets" && previousInspection != "packets" {
		m.updateDetailsPanel()
	}
	eventSelectionChanged := false
	if m.eventStore != nil && m.uiState.EventsView != nil {
		eventSelectionChanged = m.eventStore.SetInspecting(inspecting && m.uiState.ViewMode == "events", m.uiState.EventsView.SelectedID())
	}
	m.uiState.PacketList.SetInspecting(inspecting && m.uiState.ViewMode == "packets")
	// Offline packet bytes belong to a charged DetailPin; never retain them
	// after the browser releases it. Its immutable cursor preserves identity.
	m.uiState.DetailsPanel.SetInspecting(inspecting && m.uiState.ViewMode == "packets" && m.offlineSession == nil)
	if m.uiState.EventsView != nil {
		m.uiState.EventsView.SetInspecting(inspecting && m.uiState.ViewMode == "events")
	}
	m.uiState.CallsView.SetInspecting(inspecting && m.uiState.ViewMode == "calls")
	if eventSelectionChanged || (previousInspection == "events" && m.captureInspectionMode != "events") {
		m.syncEventsView()
	}
	if previousInspection == "packets" && m.captureInspectionMode != "packets" {
		m.updateDetailsPanel()
	}
	switch m.uiState.ViewMode {
	case "events":
		m.prepareEventsViewLayout()
	case "calls":
		if l.List.Width > 0 {
			m.uiState.CallsView.SetSize(l.List.Width, l.List.Height)
		}
		m.uiState.CallsView.PrepareDetails(l.Details.Width, l.Details.Height)
	default:
		if l.List.Width > 0 {
			w := l.List.Width
			if l.Details.Width > 0 {
				w += 2
			} // PacketList's split border includes two fewer cells.
			m.uiState.PacketList.SetSize(w, l.List.Height)
			m.uiState.PacketList.PrepareLayout(l.Details.Width > 0)
		}
		if l.Details.Width > 0 {
			m.uiState.DetailsPanel.SetSize(l.Details.Width, l.Details.Height)
		}
	}
}

func (m Model) toggleCaptureDetails() (Model, tea.Cmd) {
	visible := m.captureLayout().Details.Width > 0
	if m.uiState.ViewMode == "events" && m.eventViewDirty {
		m.syncEventsView()
	}
	m.setCaptureDetails(!visible)
	layout := m.captureLayout()
	if visible || layout.Mode == captureSideBySide || layout.Mode == captureStacked {
		m.focusCapturePane("left")
	} else {
		m.focusCapturePane("right")
	}
	return m, nil
}

// Explicit replacement/clear releases the bounded inspection snapshots.
func (m *Model) resetCaptureInspection() {
	m.captureInspectionMode = ""
	m.uiState.FocusedPane = "left"
	if m.eventStore != nil {
		m.eventStore.SetInspecting(false, "")
	}
	m.uiState.PacketList.SetInspecting(false)
	m.uiState.DetailsPanel.SetInspecting(false)
	m.uiState.CallsView.SetInspecting(false)
	if m.uiState.EventsView != nil {
		m.uiState.EventsView.SetInspecting(false)
	}
}

// Focus changes prepare inspection state before any selection or scroll input.
func (m *Model) focusCapturePane(pane string) {
	changed := m.uiState.FocusedPane != pane
	if changed && pane == "right" && m.uiState.ViewMode == "packets" {
		// Refresh before SetInspecting captures its immutable snapshot. The
		// list may have advanced while the details pane was hidden.
		m.updateDetailsPanel()
	}
	m.uiState.FocusedPane = pane
	m.prepareCaptureLayout()
	if pane == "left" && m.uiState.ViewMode == "packets" {
		m.updateDetailsPanel()
	}
}

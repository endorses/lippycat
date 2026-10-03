//go:build tui || all

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// toastOverlay shares exact placement between rendering and mouse handling.
func (m Model) toastOverlay() (string, captureRect) {
	if !m.uiState.Toast.IsActive() || m.uiState.FilterMode ||
		m.uiState.CallFilterMode || m.uiState.EventFilterMode ||
		m.activeModal() != nil || m.textSelection != nil ||
		(m.uiState.DevConsole != nil && m.uiState.DevConsole.IsVisible()) {
		return "", captureRect{}
	}
	view := m.uiState.Toast.OverlayView(m.uiState.Width, m.captureContentHeight())
	if view == "" {
		return "", captureRect{}
	}
	w, h := lipgloss.Width(view), lipgloss.Height(view)
	return view, captureRect{
		X:     (m.uiState.Width - w) / 2,
		Y:     m.captureContentOrigin() + m.captureContentHeight() - h,
		Width: w, Height: h,
	}
}

func (m Model) overlayToast(view string) string {
	toast, rect := m.toastOverlay()
	if toast == "" {
		return view
	}
	lines := strings.Split(view, "\n")
	for i, line := range strings.Split(toast, "\n") {
		row := rect.Y + i
		lines[row] = ansi.Cut(lines[row], 0, rect.X) +
			fitCapturePane(line, rect.Width, 1) +
			ansi.Cut(lines[row], rect.X+rect.Width, m.uiState.Width)
	}
	return strings.Join(lines, "\n")
}

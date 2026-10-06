//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func captureResizeBorder(m Model, details bool) (int, int) {
	l := m.captureLayout()
	if l.Mode == captureStacked {
		y := l.List.Y + l.List.Height - 1
		if details {
			y = l.Details.Y
		}
		return l.List.X + l.List.Width/2, m.captureContentOrigin() + y
	}
	x := l.List.X + l.List.Width - 1
	if details {
		x = l.Details.X
	}
	return x, m.captureContentOrigin() + l.List.Height/2
}

func captureResizeMotion(x, y int) tea.MouseMsg {
	return tea.MouseMsg{X: x, Y: y, Button: tea.MouseButtonLeft, Action: tea.MouseActionMotion}
}

func TestCapturePaneResizeNewPressEndsMissingRelease(t *testing.T) {
	m := responsiveDetailModel(t, "packets", 180, 40)
	m = responsiveDetailKey(t, m, 'd')
	x, y := captureResizeBorder(m, false)
	m = updateEventRenderModel(t, m, selectionPress(x, y))
	require.NotNil(t, m.captureResizeDrag)
	before := m.captureLayout()
	m = updateEventRenderModel(t, m, selectionPress(5, m.captureContentOrigin()+3))
	require.Nil(t, m.captureResizeDrag)
	require.NotNil(t, m.textSelection)
	m = updateEventRenderModel(t, m, captureResizeMotion(15, m.captureContentOrigin()+3))
	require.Equal(t, before, m.captureLayout())
}

func TestCapturePaneResizeEitherBorder(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, stacked := range []bool{false, true} {
			for _, detailsBorder := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/stacked=%t/details-border=%t", mode, stacked, detailsBorder), func(t *testing.T) {
					width, height := 180, 40
					if stacked {
						width, height = 80, 50
					}
					m := responsiveDetailModel(t, mode, width, height)
					m = responsiveDetailKey(t, m, 'd')
					before := m.captureLayout()
					selected, focused := responsiveSelected(m), m.uiState.FocusedPane
					x, y := captureResizeBorder(m, detailsBorder)
					m = updateEventRenderModel(t, m, selectionPress(x, y))
					require.Nil(t, m.textSelection)
					require.Empty(t, m.scrollDrag)
					if stacked {
						y += 4
					} else {
						x += 8
					}
					m = updateEventRenderModel(t, m, captureResizeMotion(x, y))
					after := m.captureLayout()
					require.Equal(t, before.Mode, after.Mode)
					if stacked {
						require.Equal(t, before.List.Height+4, after.List.Height)
						require.Equal(t, before.Details.Height-4, after.Details.Height)
						require.Equal(t, after.List.Height, after.Details.Y)
					} else {
						require.Equal(t, before.List.Width+8, after.List.Width)
						require.Equal(t, before.Details.Width-8, after.Details.Width)
						require.Equal(t, after.List.Width, after.Details.X)
					}
					require.Equal(t, selected, responsiveSelected(m))
					require.Equal(t, focused, m.uiState.FocusedPane)
					require.Nil(t, m.textSelection)
					require.Empty(t, m.scrollDrag)
					m = updateEventRenderModel(t, m, tea.MouseMsg{Action: tea.MouseActionRelease})
					m = updateEventRenderModel(t, m, captureResizeMotion(x+10, y+10))
					require.Equal(t, after, m.captureLayout(), "release must end resizing")
					view := m.View()
					require.LessOrEqual(t, lipgloss.Height(view), height)
					for _, line := range strings.Split(view, "\n") {
						require.LessOrEqual(t, lipgloss.Width(line), width)
					}
				})
			}
		}
	}
}

func TestCapturePaneResizeClampsBothPanes(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, stacked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stacked=%t", mode, stacked), func(t *testing.T) {
				width, height := 180, 40
				if stacked {
					width, height = 80, 50
				}
				m := responsiveDetailModel(t, mode, width, height)
				m = responsiveDetailKey(t, m, 'd')
				x, y := captureResizeBorder(m, false)
				m = updateEventRenderModel(t, m, selectionPress(x, y))
				m = updateEventRenderModel(t, m, captureResizeMotion(-1000, -1000))
				low := m.captureLayout()
				m = updateEventRenderModel(t, m, captureResizeMotion(1000, 1000))
				high := m.captureLayout()
				require.Equal(t, low.Mode, high.Mode)
				if stacked {
					require.GreaterOrEqual(t, low.List.Height, 10)
					require.GreaterOrEqual(t, high.Details.Height, 14)
					require.Greater(t, high.List.Height, low.List.Height)
					require.Equal(t, m.captureContentHeight(), high.List.Height+high.Details.Height)
				} else {
					listMin, detailMin := 72, 56
					if mode == "events" {
						listMin, detailMin = 64, 40
					} else if mode == "calls" {
						listMin, detailMin = components.CallsTableMinWidth, 40
					}
					require.GreaterOrEqual(t, low.List.Width, listMin)
					require.GreaterOrEqual(t, high.Details.Width, detailMin)
					require.Greater(t, high.List.Width, low.List.Width)
					require.Equal(t, width, high.List.Width+high.Details.Width)
				}
			})
		}
	}
}

func TestCapturePaneResizeRequiresSplitBorder(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		t.Run(mode, func(t *testing.T) {
			m := responsiveDetailModel(t, mode, 180, 40)
			m = responsiveDetailKey(t, m, 'd')
			before := m.captureLayout()
			m = updateEventRenderModel(t, m, tea.MouseMsg{X: before.Details.X, Y: m.captureContentOrigin() + 3, Button: tea.MouseButtonRight, Action: tea.MouseActionPress})
			m = updateEventRenderModel(t, m, captureResizeMotion(20, 20))
			require.Equal(t, before, m.captureLayout(), "right click must not start resizing")
			m = updateEventRenderModel(t, m, tea.MouseMsg{Action: tea.MouseActionRelease})
			m = responsiveDetailKey(t, m, 'd')
			before = m.captureLayout()
			m = updateEventRenderModel(t, m, selectionPress(before.List.Width-1, m.captureContentOrigin()+3))
			m = updateEventRenderModel(t, m, captureResizeMotion(20, 20))
			require.Equal(t, before, m.captureLayout(), "single-pane borders must not resize")
		})
	}
}

func TestCapturePaneResizeCanceledByContextChange(t *testing.T) {
	for _, change := range []string{"key", "window", "tab", "view", "modal"} {
		t.Run(change, func(t *testing.T) {
			m := responsiveDetailModel(t, "packets", 180, 40)
			m = responsiveDetailKey(t, m, 'd')
			x, y := captureResizeBorder(m, false)
			m = updateEventRenderModel(t, m, selectionPress(x, y))
			require.NotNil(t, m.captureResizeDrag)
			switch change {
			case "key":
				m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
			case "window":
				m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 190, Height: 40})
			case "tab":
				m.uiState.Tabs.SetActive(1)
			case "view":
				m.uiState.ViewMode = "events"
				m.setCaptureDetails(true)
			case "modal":
				m.uiState.ConfirmDialog.Activate("Confirm test action?")
			}
			before := m.captureLayout()
			m = updateEventRenderModel(t, m, captureResizeMotion(x+20, y+4))
			require.Nil(t, m.captureResizeDrag)
			require.Equal(t, before, m.captureLayout(), "a stale gesture must not alter the new layout")
		})
	}
}

func TestCapturePaneResizeRetainsSeparateOrientationPreferences(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		t.Run(mode, func(t *testing.T) {
			m := responsiveDetailModel(t, mode, 180, 40)
			m = responsiveDetailKey(t, m, 'd')
			x, y := captureResizeBorder(m, false)
			m = updateEventRenderModel(t, m, selectionPress(x, y))
			m = updateEventRenderModel(t, m, captureResizeMotion(x+8, y))
			m = updateEventRenderModel(t, m, tea.MouseMsg{Action: tea.MouseActionRelease})
			side := m.captureLayout()
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 80, Height: 50})
			require.Equal(t, captureStacked, m.captureLayout().Mode)
			x, y = captureResizeBorder(m, true)
			m = updateEventRenderModel(t, m, selectionPress(x, y))
			m = updateEventRenderModel(t, m, captureResizeMotion(x, y+4))
			m = updateEventRenderModel(t, m, tea.MouseMsg{Action: tea.MouseActionRelease})
			stacked := m.captureLayout()
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 180, Height: 40})
			require.Equal(t, side, m.captureLayout())
			m = responsiveDetailKey(t, m, 'd')
			m = responsiveDetailKey(t, m, 'd')
			require.Equal(t, side, m.captureLayout(), "closing details must retain the split preference")
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 80, Height: 50})
			require.Equal(t, stacked, m.captureLayout())
		})
	}
}

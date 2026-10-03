//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func TestCaptureToastOverlayPreservesLayout(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, size := range [][2]int{{180, 40}, {80, 50}, {80, 32}, {60, 20}, {12, 6}, {1, 1}} {
			t.Run(fmt.Sprintf("%s/%dx%d", mode, size[0], size[1]), func(t *testing.T) {
				m := responsiveDetailModel(t, mode, size[0], size[1])
				m = responsiveDetailKey(t, m, 'd')
				before, layout := m.View(), m.captureLayout()
				m.uiState.Toast.Show("Saved 世界\n"+strings.Repeat("long ", 50), components.ToastInfo, time.Second)
				m.prepareCaptureLayout()
				require.Equal(t, layout, m.captureLayout())
				_, rect := m.captureToast()
				after := m.View()
				require.Equal(t, size[1], lipgloss.Height(after))
				oldLines, newLines := strings.Split(ansi.Strip(before), "\n"), strings.Split(ansi.Strip(after), "\n")
				for y, line := range newLines {
					require.Equal(t, size[0], lipgloss.Width(line))
					if y < rect.Y || y >= rect.Y+rect.Height {
						require.Equal(t, oldLines[y], line)
					} else {
						require.Equal(t, ansi.Cut(oldLines[y], 0, rect.X), ansi.Cut(line, 0, rect.X))
						require.Equal(t, ansi.Cut(oldLines[y], rect.X+rect.Width, size[0]), ansi.Cut(line, rect.X+rect.Width, size[0]))
					}
				}
				m = updateEventRenderModel(t, m, components.ToastTickMsg{Time: time.Now().Add(time.Hour)})
				require.False(t, m.uiState.Toast.IsActive())
				require.Equal(t, layout, m.captureLayout())
				require.Equal(t, before, m.View())
			})
		}
	}
}

func TestCaptureToastDismissDoesNotSelectUnderlyingPacket(t *testing.T) {
	m := responsiveDetailModel(t, "packets", 180, 40)
	m.uiState.Toast.Show("First", components.ToastInfo, time.Hour)
	m.uiState.Toast.Show("Second", components.ToastInfo, time.Hour)
	selected := responsiveSelected(m)
	_, rect := m.captureToast()
	press := tea.MouseMsg{X: rect.X, Y: rect.Y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}
	m = updateEventRenderModel(t, m, press)
	view, _ := m.captureToast()
	require.Contains(t, view, "Second")
	require.Equal(t, selected, responsiveSelected(m))
	_, rect = m.captureToast()
	press.X, press.Y = rect.X, rect.Y
	m = updateEventRenderModel(t, m, press)
	require.False(t, m.uiState.Toast.IsActive())
	require.Equal(t, selected, responsiveSelected(m))
}

func TestCaptureToastHiddenDuringFilterInput(t *testing.T) {
	m := responsiveDetailModel(t, "packets", 80, 50)
	m.uiState.Toast.Show("Notification", components.ToastInfo, time.Hour)
	m.uiState.FilterMode = true
	view, rect := m.captureToast()
	require.Empty(t, view)
	require.Zero(t, rect)
}

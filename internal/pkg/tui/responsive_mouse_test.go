//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestResponsiveCaptureMouseRegions(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 50}, {Width: 80, Height: 20}, {Width: 30, Height: 8}} {
			t.Run(fmt.Sprintf("%s/%dx%d", mode, size.Width, size.Height), func(t *testing.T) {
				m := selectionTestModel(t, mode)
				m.setCaptureDetails(true)
				m.uiState.FocusedPane = "right"
				m, _ = m.handleWindowSizeMsg(size)
				layout := m.captureLayout()
				require.Positive(t, layout.Details.Width)
				if size.Height == 50 {
					require.Equal(t, captureStacked, layout.Mode)
				} else {
					require.Equal(t, captureDetailsOnly, layout.Mode)
				}
				x, y, w, h := components.DetailPaneGeometry(layout.Details.Width, layout.Details.Height)
				require.Positive(t, w)
				require.Positive(t, h)
				x += layout.Details.X
				y += m.captureContentOrigin() + layout.Details.Y
				region, ok := m.textSelectionRegion(x, y)
				require.True(t, ok)
				require.GreaterOrEqual(t, region.X, layout.Details.X)
				require.GreaterOrEqual(t, region.Y, m.captureContentOrigin()+layout.Details.Y)
				require.LessOrEqual(t, region.X+region.Width, layout.Details.X+layout.Details.Width)
				m, _ = m.handleMouse(selectionPress(x, y))
				require.Equal(t, "right", m.uiState.FocusedPane)
				if layout.List.Width > 0 {
					m, _ = m.handleMouse(selectionPress(layout.List.X+3, m.captureContentOrigin()+layout.List.Y+3))
					require.Equal(t, "left", m.uiState.FocusedPane)
				}
			})
		}
	}
}

func TestResponsiveDetailsMouseWheelAndScrollbar(t *testing.T) {
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 50}, {Width: 40, Height: 20}} {
		m := selectionTestModel(t, "packets")
		m.uiState.FocusedPane = "right"
		m, _ = m.handleWindowSizeMsg(size)
		m.uiState.DetailsPanel.SetPacket(&types.PacketDisplay{RawData: []byte(strings.Repeat("packet bytes", 200))})
		layout := m.captureLayout()
		bx, by, _, height := components.DetailPaneGeometry(layout.Details.Width, layout.Details.Height)
		top := m.captureContentOrigin() + layout.Details.Y
		_, _, before := m.uiState.DetailsPanel.ScrollState()
		m, _ = m.handleMouse(tea.MouseMsg{X: layout.Details.X + bx, Y: top + by, Button: tea.MouseButtonWheelDown, Action: tea.MouseActionPress})
		_, _, after := m.uiState.DetailsPanel.ScrollState()
		require.Greater(t, after, before)
		barX := layout.Details.X + layout.Details.Width - 1
		if bx >= 3 {
			barX--
		}
		m, _ = m.handleMouse(selectionPress(barX, top+by+height-1))
		require.Equal(t, "details", m.scrollDrag)
		_, _, offset := m.uiState.DetailsPanel.ScrollState()
		require.Greater(t, offset, after)
		m, _ = m.handleMouse(tea.MouseMsg{Action: tea.MouseActionRelease})
		require.Empty(t, m.scrollDrag)
	}
}

func TestPacketMouseNavigationReleasesInspectionBeforeSelecting(t *testing.T) {
	for _, gesture := range []string{"click", "wheel", "scrollbar"} {
		t.Run(gesture, func(t *testing.T) {
			m := selectionTestModel(t, "packets")
			packets := make([]components.PacketDisplay, 100)
			for i := range packets {
				packets[i] = components.PacketDisplay{Timestamp: time.Unix(int64(i+1), 0), SrcIP: fmt.Sprintf("packet-source-%03d", i)}
			}
			m.uiState.PacketList.SetPackets(packets)
			m.uiState.PacketList.SetCursor(0)
			m.updateDetailsPanel()
			m.focusCapturePane("right")
			origin := m.captureContentOrigin()
			var msg tea.MouseMsg
			switch gesture {
			case "click":
				msg = selectionPress(5, origin+4)
			case "wheel":
				msg = tea.MouseMsg{X: 5, Y: origin + 4, Button: tea.MouseButtonWheelDown, Action: tea.MouseActionPress}
			case "scrollbar":
				msg = selectionPress(m.captureLayout().List.Width-2, origin+m.captureLayout().List.Height-3)
			}
			m, _ = m.handleMouse(msg)
			require.Equal(t, "left", m.uiState.FocusedPane)
			require.Greater(t, m.uiState.PacketList.GetCursor(), 0)
			require.Contains(t, ansi.Strip(m.uiState.DetailsPanel.View(false)), m.uiState.PacketList.GetSelectedPacket().SrcIP)
		})
	}
}

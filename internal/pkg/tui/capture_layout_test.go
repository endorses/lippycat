//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func responsiveDetailModel(t *testing.T, mode string, width, height int) Model {
	t.Helper()
	m := NewModel(128, 8, "test0", "", nil, false, false, "", false)
	t.Cleanup(m.Shutdown)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = mode
	switch mode {
	case "packets":
		packets := []components.PacketDisplay{
			{Timestamp: time.Unix(1, 0), Info: "first packet", Protocol: "TCP"},
			{Timestamp: time.Unix(2, 0), Info: "selected packet", Protocol: "TCP", RawData: make([]byte, 1024)},
		}
		m.packetStore.AddPacketBatch(packets)
		m.uiState.PacketList.SetPackets(packets)
	case "events":
		m.eventStore.AddBatch([]events.Event{
			events.NewDNSEvent(testEventEnvelope("first-event", 1)),
			events.NewDNSEvent(testEventEnvelope("selected-event", 2)),
		})
		m.syncEventsView()
	case "calls":
		m.uiState.CallsView.SetCalls([]components.Call{
			{CallID: "first-call", From: "sip:alice@example.test", To: "sip:bob@example.test"},
			{CallID: "selected-call", From: "sip:alice@example.test", To: "sip:bob@example.test", SDPEndpoints: []string{"192.0.2.1:4000", "192.0.2.2:4002"}},
		})
		m.uiState.CallsView.SetSelected(1)
	}
	return updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: width, Height: height})
}

func responsiveDetailKey(t *testing.T, m Model, key rune) Model {
	t.Helper()
	return updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
}

func responsiveSelected(m Model) string {
	switch m.uiState.ViewMode {
	case "events":
		return m.uiState.EventsView.SelectedID()
	case "calls":
		return m.uiState.CallsView.GetSelected().CallID
	default:
		return m.uiState.PacketList.GetSelectedPacket().Info
	}
}

func responsiveDetailScroll(m Model) (int, int, int) {
	switch m.uiState.ViewMode {
	case "events":
		return m.uiState.EventsView.DetailsScrollState()
	case "calls":
		return m.uiState.CallsView.DetailsScrollState()
	default:
		return m.uiState.DetailsPanel.ScrollState()
	}
}

func TestResponsivePacketOpenRefreshesBeforeInspection(t *testing.T) {
	for _, entry := range []string{"d", "right", "mouse"} {
		t.Run(entry, func(t *testing.T) {
			width, height := 180, 40
			if entry == "d" {
				width, height = 80, 24
			}
			m := responsiveDetailModel(t, "packets", width, height)
			m.doFullPacketListRefresh(false)
			m.updateDetailsPanel()
			m = responsiveDetailKey(t, m, 'd')
			if entry == "d" {
				m = responsiveDetailKey(t, m, 'd')
			} else {
				m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
			}
			m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEnd})
			m.packetStore.AddPacketBatch([]components.PacketDisplay{{
				Timestamp: time.Unix(3, 0), Protocol: "TCP", SrcIP: "203.0.113.99", Info: "new arrival",
			}})
			// The packet list can advance while hidden/throttled details still
			// contain the previous packet, as in normal live ingress.
			m.updatePacketListIncremental()
			require.Equal(t, "new arrival", responsiveSelected(m))
			switch entry {
			case "d":
				m = responsiveDetailKey(t, m, 'd')
			case "right":
				m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRight})
			case "mouse":
				r := m.captureLayout().Details
				m = updateEventRenderModel(t, m, tea.MouseMsg{X: r.X + 3, Y: m.captureContentOrigin() + r.Y + 2, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
				m = updateEventRenderModel(t, m, tea.MouseMsg{Action: tea.MouseActionRelease})
			}
			require.True(t, m.captureDetailsFocused())
			require.Contains(t, m.uiState.DetailsPanel.View(true), "203.0.113.99")
		})
	}
}

func TestResponsiveDetailsToggleAtEveryLayout(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, size := range []struct {
			width, height int
			layout        captureLayoutMode
		}{
			{180, 40, captureSideBySide},
			{80, 50, captureStacked},
			{80, 24, captureDetailsOnly},
		} {
			t.Run(fmt.Sprintf("%s/%dx%d", mode, size.width, size.height), func(t *testing.T) {
				m := responsiveDetailModel(t, mode, size.width, size.height)
				selected := responsiveSelected(m)
				require.Equal(t, captureListOnly, m.captureLayout().Mode)
				m = responsiveDetailKey(t, m, 'd')
				require.True(t, m.captureDetailsEnabled())
				require.Equal(t, size.layout, m.captureLayout().Mode)
				require.Equal(t, size.layout == captureDetailsOnly, m.captureDetailsFocused())
				m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
				require.Equal(t, "left", m.uiState.FocusedPane)
				require.True(t, m.captureDetailsEnabled(), "Esc returns focus without changing the detail preference")
				if size.layout == captureDetailsOnly {
					require.Equal(t, captureListOnly, m.captureLayout().Mode)
					m = responsiveDetailKey(t, m, 'd')
					require.Equal(t, captureDetailsOnly, m.captureLayout().Mode)
				}
				m = responsiveDetailKey(t, m, 'd')
				require.False(t, m.captureDetailsEnabled())
				require.Equal(t, captureListOnly, m.captureLayout().Mode)
				require.Equal(t, selected, responsiveSelected(m))
			})
		}
	}
}

func TestResponsiveDetailsResizePreservesFocusAndHiddenPreference(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		t.Run(mode, func(t *testing.T) {
			m := responsiveDetailModel(t, mode, 180, 40)
			m = responsiveDetailKey(t, m, 'd')
			m.focusCapturePane("right")
			selected := responsiveSelected(m)
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
			require.Equal(t, captureDetailsOnly, m.captureLayout().Mode)
			require.Equal(t, selected, responsiveSelected(m))
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 80, Height: 50})
			require.Equal(t, captureStacked, m.captureLayout().Mode)
			require.True(t, m.captureDetailsFocused())
			m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
			require.Equal(t, captureListOnly, m.captureLayout().Mode, "shrinking while browsing keeps the list")
			m = responsiveDetailKey(t, m, 'd')
			m = responsiveDetailKey(t, m, 'd')
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 180, Height: 40})
			require.False(t, m.captureDetailsEnabled())
			require.Equal(t, captureListOnly, m.captureLayout().Mode, "explicitly closed details stay closed after expansion")
		})
	}
}

func TestResponsiveDetailsKeyboardScrollPreservesSelection(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		t.Run(mode, func(t *testing.T) {
			m := responsiveDetailModel(t, mode, 80, 18)
			m = responsiveDetailKey(t, m, 'd')
			selected := responsiveSelected(m)
			total, visible, _ := responsiveDetailScroll(m)
			require.Greater(t, total, visible, "fixture must have scrollable details")
			m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyDown})
			_, _, offset := responsiveDetailScroll(m)
			require.Greater(t, offset, 0)
			require.Equal(t, selected, responsiveSelected(m))
			m = responsiveDetailKey(t, m, 'd')
			m = responsiveDetailKey(t, m, 'd')
			_, _, reopenedOffset := responsiveDetailScroll(m)
			require.Equal(t, offset, reopenedOffset)
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 70, Height: 18})
			_, _, resizedOffset := responsiveDetailScroll(m)
			require.Equal(t, offset, resizedOffset)
			require.Equal(t, selected, responsiveSelected(m))
		})
	}
}

func TestResponsiveCaptureRenderingFitsTerminal(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, size := range [][2]int{{180, 40}, {80, 50}, {80, 24}, {40, 10}, {20, 5}, {1, 1}} {
			t.Run(fmt.Sprintf("%s/%dx%d", mode, size[0], size[1]), func(t *testing.T) {
				m := responsiveDetailModel(t, mode, size[0], size[1])
				for _, details := range []bool{false, true} {
					if details {
						m = responsiveDetailKey(t, m, 'd')
					}
					view := m.View()
					require.LessOrEqual(t, lipgloss.Height(view), size[1])
					for _, line := range strings.Split(view, "\n") {
						require.LessOrEqual(t, lipgloss.Width(line), size[0])
					}
				}
			})
		}
	}
}

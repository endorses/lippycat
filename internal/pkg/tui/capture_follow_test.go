//go:build tui || all

package tui

import (
	"fmt"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

func appendCaptureFollowItem(m *Model, id string) {
	switch m.uiState.ViewMode {
	case "packets":
		m.uiState.PacketList.AppendPackets([]components.PacketDisplay{{Timestamp: time.Now(), Info: id, SrcIP: id}})
		m.updateDetailsPanel()
	case "events":
		m.eventStore.AddEvent(events.NewDNSEvent(testEventEnvelope(id, uint64(m.eventStore.Stats().Retained+1))))
		m.syncEventsView()
	case "calls":
		m.uiState.CallsView.SetCalls(append(m.uiState.CallsView.GetCalls(), components.Call{CallID: id}))
	}
	m.prepareCaptureLayout()
}

func TestSplitDetailsToggleAndFocusKeepFollowing(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, size := range [][2]int{{180, 40}, {80, 50}} {
			t.Run(fmt.Sprintf("%s/%dx%d", mode, size[0], size[1]), func(t *testing.T) {
				m := responsiveDetailModel(t, mode, size[0], size[1])
				m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEnd})
				m = responsiveDetailKey(t, m, 'd')
				require.Equal(t, "left", m.uiState.FocusedPane)
				require.Empty(t, m.captureInspectionMode)
				appendCaptureFollowItem(&m, "after-open")
				require.Equal(t, "after-open", responsiveSelected(m))
				m.focusCapturePane("right")
				require.Empty(t, m.captureInspectionMode, "split details focus must not pin")
				appendCaptureFollowItem(&m, "after-focus")
				require.Equal(t, "after-focus", responsiveSelected(m))
				m = responsiveDetailKey(t, m, 'd')
				require.Equal(t, "left", m.uiState.FocusedPane)
				appendCaptureFollowItem(&m, "after-close")
				require.Equal(t, "after-close", responsiveSelected(m))
			})
		}
	}
}

func TestFullAreaDetailsPinAndRestorePriorFollowing(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, following := range []bool{true, false} {
			for _, exit := range []string{"d", "esc", "resize"} {
				t.Run(fmt.Sprintf("%s/follow=%v/%s", mode, following, exit), func(t *testing.T) {
					m := responsiveDetailModel(t, mode, 80, 24)
					key := tea.KeyHome
					if following {
						key = tea.KeyEnd
					}
					m = updateEventRenderModel(t, m, tea.KeyMsg{Type: key})
					selected := responsiveSelected(m)
					m = responsiveDetailKey(t, m, 'd')
					require.Equal(t, captureDetailsOnly, m.captureLayout().Mode)
					require.Equal(t, mode, m.captureInspectionMode)
					appendCaptureFollowItem(&m, "while-pinned")
					require.Equal(t, selected, responsiveSelected(m))
					switch exit {
					case "d":
						m = responsiveDetailKey(t, m, 'd')
					case "esc":
						m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyEsc})
					case "resize":
						m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 180, Height: 40})
					}
					require.Empty(t, m.captureInspectionMode)
					appendCaptureFollowItem(&m, "after-return")
					if following {
						require.Equal(t, "after-return", responsiveSelected(m))
					} else {
						require.Equal(t, selected, responsiveSelected(m))
					}
				})
			}
		}
	}
}

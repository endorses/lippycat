//go:build tui || all

package tui

import (
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func TestFocusedDetailsTopBottomBindings(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, size := range []struct {
			width, height int
			layout        captureLayoutMode
		}{{180, 24, captureSideBySide}, {100, 40, captureStacked}, {100, 24, captureDetailsOnly}} {
			t.Run(fmt.Sprintf("%s/%dx%d", mode, size.width, size.height), func(t *testing.T) {
				m := responsiveDetailModel(t, mode, size.width, size.height)
				if mode == "calls" {
					calls := m.uiState.CallsView.GetCalls()
					calls[1].SDPEndpoints = make([]string, 40)
					for i := range calls[1].SDPEndpoints {
						calls[1].SDPEndpoints[i] = fmt.Sprintf("192.0.2.%d:4000", i+1)
					}
					m.uiState.CallsView.SetCalls(calls)
				}
				m = responsiveDetailKey(t, m, 'd')
				if size.layout != captureDetailsOnly {
					m = updateEventRenderModel(t, m, tea.KeyMsg{Type: tea.KeyRight})
				}
				require.Equal(t, size.layout, m.captureLayout().Mode)
				require.True(t, m.captureDetailsFocused())
				selected := responsiveSelected(m)
				for _, pair := range [][2]tea.KeyMsg{
					{{Type: tea.KeyHome}, {Type: tea.KeyEnd}},
					{{Type: tea.KeyRunes, Runes: []rune{'g'}}, {Type: tea.KeyRunes, Runes: []rune{'G'}}},
				} {
					m = updateEventRenderModel(t, m, pair[1])
					total, visible, offset := responsiveDetailScroll(m)
					require.Greater(t, total, visible, "fixture must be scrollable")
					require.Equal(t, total-visible, offset)
					require.Equal(t, selected, responsiveSelected(m))
					m = updateEventRenderModel(t, m, pair[0])
					_, _, offset = responsiveDetailScroll(m)
					require.Zero(t, offset)
					require.Equal(t, selected, responsiveSelected(m))
				}
				m = responsiveDetailKey(t, m, 'd')
				require.Equal(t, captureListOnly, m.captureLayout().Mode)
				require.Equal(t, "left", m.uiState.FocusedPane)
			})
		}
	}
}

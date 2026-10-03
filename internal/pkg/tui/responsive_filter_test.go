//go:build tui || all

package tui

import (
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func responsiveFilterModel(t *testing.T, mode string) Model {
	t.Helper()
	m := responsiveDetailModel(t, mode, 80, 24)
	if mode == "calls" {
		m.callStore.AddOrUpdateCalls([]components.Call{{CallID: "first-call"}, {CallID: "selected-call"}})
	}
	m = responsiveDetailKey(t, m, 'd')
	require.Equal(t, "right", m.uiState.FocusedPane)
	return m
}

func applyResponsiveFilter(t *testing.T, m Model, value string) Model {
	t.Helper()
	switch m.uiState.ViewMode {
	case "packets":
		cmd := m.parseAndApplyFilter(value)
		if value != "" {
			m, _ = m.handlePacketFilter(packetFilterResult(t, cmd))
		}
	case "calls":
		m.parseAndApplyCallFilter(value)
	case "events":
		m.uiState.EventFilterInput.Clear()
		for _, r := range value {
			m.uiState.EventFilterInput.InsertRune(r)
		}
		updated, _ := m.handleEventFilterInput(tea.KeyMsg{Type: tea.KeyEnter})
		m = updated.(Model)
	}
	m.prepareCaptureLayout()
	return m
}

func TestResponsiveFiltersReleaseExcludedInspection(t *testing.T) {
	previousConfig, previousHistory := viper.ConfigFileUsed(), viper.Get("watch.event_filter_history")
	viper.SetConfigFile(filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { viper.SetConfigFile(previousConfig); viper.Set("watch.event_filter_history", previousHistory) })
	for _, tc := range []struct{ mode, filter, old string }{{"packets", "info:absent", "selected packet"}, {"events", "kind:http", "selected-event"}, {"calls", "callid:absent", "selected-call"}} {
		t.Run(tc.mode, func(t *testing.T) {
			m := responsiveFilterModel(t, tc.mode)
			m = applyResponsiveFilter(t, m, tc.filter)
			require.Equal(t, "left", m.uiState.FocusedPane)
			switch tc.mode {
			case "packets":
				require.Empty(t, m.uiState.PacketList.GetPackets())
				require.NotContains(t, m.uiState.DetailsPanel.View(false), tc.old)
			case "events":
				_, found := m.uiState.EventsView.DetailSelection()
				require.False(t, found)
				require.NotContains(t, m.uiState.EventsView.RenderDetails(80, 30, false), tc.old)
			case "calls":
				require.Nil(t, m.uiState.CallsView.GetSelected())
				require.NotContains(t, m.uiState.CallsView.RenderDetails(80, 30, false), tc.old)
			}
		})
	}
}

func TestResponsiveInvalidFiltersAndCancellationPreserveInspection(t *testing.T) {
	for _, tc := range []struct{ mode, invalid string }{{"packets", ""}, {"events", "unknown:value"}, {"calls", "duration:>invalid"}} {
		t.Run(tc.mode, func(t *testing.T) {
			m := responsiveFilterModel(t, tc.mode)
			selected := responsiveSelected(m)
			m = applyResponsiveFilter(t, m, tc.invalid)
			require.Equal(t, "right", m.uiState.FocusedPane)
			require.Equal(t, selected, responsiveSelected(m))
			var updated tea.Model
			switch tc.mode {
			case "packets":
				updated, _ = m.handleFilterInput(tea.KeyMsg{Type: tea.KeyEsc})
			case "events":
				updated, _ = m.handleEventFilterInput(tea.KeyMsg{Type: tea.KeyEsc})
			case "calls":
				updated, _ = m.handleCallFilterInput(tea.KeyMsg{Type: tea.KeyEsc})
			}
			m = updated.(Model)
			require.Equal(t, "right", m.uiState.FocusedPane)
			require.Equal(t, selected, responsiveSelected(m))
		})
	}
}

func TestResponsiveEmptyFilterInputReleasesInspection(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		t.Run(mode, func(t *testing.T) {
			m := responsiveFilterModel(t, mode)
			var updated tea.Model
			switch mode {
			case "packets":
				m.uiState.FilterInput.Clear()
				updated, _ = m.handleFilterInput(tea.KeyMsg{Type: tea.KeyEnter})
			case "events":
				m.uiState.EventFilterInput.Clear()
				updated, _ = m.handleEventFilterInput(tea.KeyMsg{Type: tea.KeyEnter})
			case "calls":
				m.uiState.CallFilterInput.Clear()
				updated, _ = m.handleCallFilterInput(tea.KeyMsg{Type: tea.KeyEnter})
			}
			m = updated.(Model)
			require.Equal(t, "left", m.uiState.FocusedPane)
		})
	}
}

func TestResponsiveRemovingAndClearingFiltersReleasesInspection(t *testing.T) {
	for _, mode := range []string{"packets", "events", "calls"} {
		for _, action := range []string{"remove", "clear"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				m := responsiveFilterModel(t, mode)
				switch mode {
				case "packets":
					m = applyResponsiveFilter(t, m, "protocol:TCP")
				case "events":
					require.NoError(t, m.eventStore.AddUserFilter("kind:dns"))
					m.syncEventsView()
				case "calls":
					m = applyResponsiveFilter(t, m, "callid:call")
				}
				m.focusCapturePane("right")
				require.Equal(t, "right", m.uiState.FocusedPane)
				switch mode {
				case "packets":
					if action == "remove" {
						m, _ = m.handleRemoveLastFilter()
					} else {
						m, _ = m.handleClearAllFilters()
					}
				case "events":
					if action == "remove" {
						m, _ = m.handleRemoveLastEventFilter()
					} else {
						m, _ = m.handleClearAllEventFilters()
					}
				case "calls":
					if action == "remove" {
						m, _ = m.handleRemoveLastCallFilter()
					} else {
						m, _ = m.handleClearAllCallFilters()
					}
				}
				m.prepareCaptureLayout()
				require.Equal(t, "left", m.uiState.FocusedPane)
			})
		}
	}
}

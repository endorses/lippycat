//go:build tui || all

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
)

type packetFilterMsg struct {
	source *store.PacketStore
	result *store.PacketFilterResult
}

// startPacketFilter installs the filter for new arrivals and freezes a bounded
// snapshot. Only predicate evaluation runs in the command; model and display
// updates stay on the UI loop.
func (m *Model) startPacketFilter(chain *filters.FilterChain) tea.Cmd {
	source := m.packetStore
	scan := source.BeginFilter(chain)
	m.lastFilterState = source.HasFilter()
	m.doFullPacketListRefresh(m.lastFilterState)
	return func() tea.Msg {
		return packetFilterMsg{source: source, result: scan.Run()}
	}
}

func (m Model) handlePacketFilter(msg packetFilterMsg) (Model, tea.Cmd) {
	if m.offlineSession != nil || msg.source != m.packetStore || !m.packetStore.CompleteFilter(msg.result) {
		return m, nil
	}
	// The store prepended historical matches to the arrivals already displayed.
	// Publish once and reset the incremental cursor so no packets are repeated.
	m.lastFilterState = m.packetStore.HasFilter()
	m.doFullPacketListRefresh(m.lastFilterState)
	m.updateDetailsPanel()
	return m, nil
}

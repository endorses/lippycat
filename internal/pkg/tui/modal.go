//go:build tui || all

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// modalAdapter hosts dialogs owned by the application or a larger component.
// Their cancellation callbacks preserve the owner's existing lifecycle.
type modalAdapter struct {
	view    func() string
	dismiss func() tea.Cmd
}

func (m modalAdapter) View() string     { return m.view() }
func (m modalAdapter) Dismiss() tea.Cmd { return m.dismiss() }

// actionModalAdapter exposes owner-managed progress dialogs to shared controls.
type actionModalAdapter struct {
	modalAdapter
	options func() components.ModalRenderOptions
	action  func(string) tea.Cmd
}

func (m actionModalAdapter) ModalOptions() components.ModalRenderOptions { return m.options() }
func (m actionModalAdapter) HandleModalAction(id string) tea.Cmd         { return m.action(id) }
func (m actionModalAdapter) HandleModalFocus(string) tea.Cmd             { return nil }

func (m *Model) offlineModalAction(id string) tea.Cmd {
	var next Model
	var cmd tea.Cmd
	switch id {
	case "cancel":
		next, cmd = m.cancelOffline()
	case "quit":
		next, cmd = m.leaveOffline(nil, true)
	case "retry":
		if !m.offlineCleanupFailed {
			return nil
		}
		if m.offlineLeaving {
			next, cmd = m.leaveOffline(nil, false)
		} else {
			next, cmd = m.retryOfflineCancellation()
		}
	default:
		return nil
	}
	*m = next
	return cmd
}
func (m *Model) offlineFilterModalAction(id string) tea.Cmd {
	if m.offlineFilter == nil {
		return nil
	}
	switch id {
	case "cancel":
		if m.offlineFilter.cancelled {
			return nil
		}
		m.offlineFilter.cancelled = true
		m.offlineFilter.owner.mu.Lock()
		m.offlineFilter.owner.cancel()
		m.offlineFilter.owner.mu.Unlock()
	case "quit":
		next, cmd := m.leaveOffline(nil, true)
		*m = next
		return cmd
	}
	return nil
}

// activeModal is the single source of modal stacking order for rendering and
// backdrop dismissal. New dialogs hosted here inherit shared mouse behavior.
func (m *Model) activeModal() components.Modal {
	switch {
	case m.offlineOpening:
		return actionModalAdapter{modalAdapter: modalAdapter{view: m.offlineModal, dismiss: func() tea.Cmd { return m.offlineModalAction("cancel") }}, options: m.offlineModalOptions, action: m.offlineModalAction}
	case m.offlineFilter != nil:
		return actionModalAdapter{modalAdapter: modalAdapter{view: m.offlineFilterModal, dismiss: func() tea.Cmd { return m.offlineFilterModalAction("cancel") }}, options: m.offlineFilterModalOptions, action: m.offlineFilterModalAction}
	case m.uiState.ProtocolSelector.IsActive():
		return &m.uiState.ProtocolSelector
	case m.uiState.HunterSelector.IsActive():
		return &m.uiState.HunterSelector
	case m.uiState.FilterManager.IsActive():
		return &m.uiState.FilterManager
	case m.uiState.SettingsView.GetPcapFileDialog().IsActive():
		return m.uiState.SettingsView.GetPcapFileDialog()
	case m.uiState.SettingsView.GetNodesFileDialog().IsActive():
		return m.uiState.SettingsView.GetNodesFileDialog()
	case m.uiState.FileDialog.IsActive():
		return &m.uiState.FileDialog
	case m.uiState.ConfirmDialog.IsActive():
		return &m.uiState.ConfirmDialog
	case m.uiState.NodesView.IsModalOpen():
		return m.uiState.NodesView.Modal()
	default:
		return nil
	}
}

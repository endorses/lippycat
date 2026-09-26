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

// activeModal is the single source of modal stacking order for rendering and
// backdrop dismissal. New dialogs hosted here inherit shared mouse behavior.
func (m *Model) activeModal() components.Modal {
	switch {
	case m.offlineOpening:
		return modalAdapter{
			view: m.offlineModal,
			dismiss: func() tea.Cmd {
				next, cmd := m.cancelOffline()
				*m = next
				return cmd
			},
		}
	case m.offlineFilter != nil:
		return modalAdapter{
			view: m.offlineFilterModal,
			dismiss: func() tea.Cmd {
				m.offlineFilter.cancelled = true
				m.offlineFilter.owner.mu.Lock()
				m.offlineFilter.owner.cancel()
				m.offlineFilter.owner.mu.Unlock()
				return nil
			},
		}
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
		return modalAdapter{
			view: func() string { return m.uiState.NodesView.RenderModal(m.uiState.Width, m.uiState.Height) },
			dismiss: func() tea.Cmd {
				m.uiState.NodesView.HideAddNodeModal()
				return nil
			},
		}
	default:
		return nil
	}
}

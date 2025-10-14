//go:build tui || all
// +build tui all

package tui

import (
	"github.com/charmbracelet/lipgloss"
)

// View renders the entire TUI based on current state
func (m Model) View() string {
	if m.uiState.Quitting {
		return "Goodbye!\n"
	}

	// Update header state
	m.uiState.Header.SetState(m.uiState.Capturing, m.uiState.Paused)
	m.uiState.Header.SetPacketCount(m.packetStore.TotalPackets)
	m.uiState.Header.SetInterface(m.interfaceName)
	m.uiState.Header.SetCaptureMode(m.captureMode)
	// Use hunter count (not remote client count) for accurate node display
	m.uiState.Header.SetNodeCount(m.uiState.NodesView.GetHunterCount())
	m.uiState.Header.SetProcessorCount(m.uiState.NodesView.GetProcessorCount())

	// Update footer state
	m.uiState.Footer.SetFilterMode(m.uiState.FilterMode)
	m.uiState.Footer.SetHasFilter(m.packetStore.HasFilter())
	m.uiState.Footer.SetFilterCount(m.packetStore.FilterChain.Count())

	// Render components
	headerView := m.uiState.Header.View()
	tabsView := m.uiState.Tabs.View()
	footerView := m.uiState.Footer.View()

	var mainContent string

	// Calculate content dimensions
	headerHeight := 2
	tabsHeight := 4
	bottomHeight := 4
	contentHeight := m.uiState.Height - headerHeight - tabsHeight - bottomHeight

	// Render main content based on active tab
	switch m.uiState.Tabs.GetActive() {
	case 0: // Live/Remote/Offline Capture
		mainContent = m.renderCaptureTab(contentHeight)
	case 1: // Nodes
		mainContent = m.uiState.NodesView.View()
	case 2: // Statistics
		mainContent = m.uiState.StatisticsView.View()
	case 3: // Settings
		mainContent = m.uiState.SettingsView.View()
	}

	// Combine main views (header + tabs + content)
	mainViews := []string{
		headerView,
		tabsView,
		mainContent,
	}
	mainView := lipgloss.JoinVertical(lipgloss.Left, mainViews...)

	// Render bottom area (footer + filter/toast)
	bottomArea := m.renderBottomArea(footerView)

	fullView := lipgloss.JoinVertical(lipgloss.Left, mainView, bottomArea)

	// Check for active modals and overlay them
	if modalView := m.renderActiveModal(); modalView != "" {
		return modalView
	}

	return fullView
}

// renderCaptureTab renders the Capture tab content (packets or calls)
func (m Model) renderCaptureTab(contentHeight int) string {
	// Check if we should display calls view or packets view
	if m.uiState.ViewMode == "calls" {
		// Render calls view
		m.uiState.CallsView.SetSize(m.uiState.Width, contentHeight)
		return m.uiState.CallsView.View()
	}

	// Render packets view
	minWidthForDetails := 160 // Need enough width for hex dump (~78 chars) + reasonable packet list
	detailsVisible := m.uiState.ShowDetails && m.uiState.Width >= minWidthForDetails

	if detailsVisible {
		// Split pane layout
		leftFocused := m.uiState.FocusedPane == "left"
		rightFocused := m.uiState.FocusedPane == "right"

		detailsWidth := 77 // Hex dump (72) + borders/padding (5)

		// Ensure details panel has the right size set
		m.uiState.DetailsPanel.SetSize(detailsWidth, contentHeight)

		packetListView := m.uiState.PacketList.View(leftFocused, true)
		detailsPanelView := m.uiState.DetailsPanel.View(rightFocused)

		return lipgloss.JoinHorizontal(lipgloss.Top, packetListView, detailsPanelView)
	}

	// Full width packet list - always show unfocused when details are hidden
	return m.uiState.PacketList.View(false, false)
}

// renderBottomArea renders the bottom area (footer + filter input or toast)
func (m Model) renderBottomArea(footerView string) string {
	// Check if any modal is active (hide toast when modal is open)
	modalActive := m.uiState.ProtocolSelector.IsActive() ||
		m.uiState.HunterSelector.IsActive() ||
		m.uiState.FilterManager.IsActive() ||
		m.uiState.SettingsView.IsFileDialogActive() ||
		m.uiState.FileDialog.IsActive() ||
		m.uiState.ConfirmDialog.IsActive() ||
		m.uiState.NodesView.IsModalOpen()

	if m.uiState.FilterMode {
		// Filter (3 lines) + footer (1 line) = 4 lines
		filterView := m.uiState.FilterInput.View()
		return filterView + "\n" + footerView
	}

	if m.uiState.Toast.IsActive() && !modalActive {
		// Toast notification (3 lines with padding) + footer (1 line) = 4 lines
		// Hidden when modal is active
		toastView := m.uiState.Toast.View()
		return toastView + "\n" + footerView
	}

	// All tabs: 3 blank lines + footer (1 line) = 4 lines
	// (Nodes tab hints bar is part of mainContent, not bottomArea)
	return "\n\n\n" + footerView
}

// renderActiveModal checks for active modals and renders them as overlays
func (m Model) renderActiveModal() string {
	// Protocol selector modal
	if m.uiState.ProtocolSelector.IsActive() {
		selectorView := m.uiState.ProtocolSelector.View()
		return lipgloss.Place(
			m.uiState.Width, m.uiState.Height,
			lipgloss.Center, lipgloss.Center,
			selectorView,
		)
	}

	// Hunter selector modal
	if m.uiState.HunterSelector.IsActive() {
		selectorView := m.uiState.HunterSelector.View()
		return lipgloss.Place(
			m.uiState.Width, m.uiState.Height,
			lipgloss.Center, lipgloss.Center,
			selectorView,
		)
	}

	// Filter manager modal
	if m.uiState.FilterManager.IsActive() {
		filterManagerView := m.uiState.FilterManager.View()
		return lipgloss.Place(
			m.uiState.Width, m.uiState.Height,
			lipgloss.Center, lipgloss.Center,
			filterManagerView,
		)
	}

	// Settings file dialogs (for opening PCAP or nodes files)
	if m.uiState.SettingsView.IsFileDialogActive() {
		if m.uiState.SettingsView.GetPcapFileDialog().IsActive() {
			pcapDialog := m.uiState.SettingsView.GetPcapFileDialog()
			pcapDialog.SetSize(m.uiState.Width, m.uiState.Height)
			return pcapDialog.View()
		}
		if m.uiState.SettingsView.GetNodesFileDialog().IsActive() {
			nodesDialog := m.uiState.SettingsView.GetNodesFileDialog()
			nodesDialog.SetSize(m.uiState.Width, m.uiState.Height)
			return nodesDialog.View()
		}
	}

	// File dialog modal (for saving packets)
	if m.uiState.FileDialog.IsActive() {
		// FileDialog uses RenderModal internally which centers it
		return m.uiState.FileDialog.View()
	}

	// Confirm dialog modal
	if m.uiState.ConfirmDialog.IsActive() {
		// ConfirmDialog uses RenderModal internally which centers it
		return m.uiState.ConfirmDialog.View()
	}

	// Add node modal
	if m.uiState.NodesView.IsModalOpen() {
		return m.uiState.NodesView.RenderModal(m.uiState.Width, m.uiState.Height)
	}

	// No modal active
	return ""
}

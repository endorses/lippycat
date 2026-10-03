//go:build tui || all

package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/spf13/viper"
)

// View renders the entire TUI based on current state
func (m Model) View() string {
	if modalView := m.renderActiveModal(); modalView != "" {
		return modalView
	}
	if m.uiState.Quitting {
		return "Goodbye!\n"
	}
	if m.textSelection != nil && m.textSelectionAllowed() {
		return m.textSelection.View()
	}

	if m.uiState.Tabs.GetActive() == 0 && m.responsiveCaptureView() {
		header, tabs, bottom := m.captureChrome()
		parts := []string{}
		for _, part := range []string{header, tabs, m.renderCaptureTab(m.captureContentHeight()), bottom} {
			if part != "" {
				parts = append(parts, part)
			}
		}
		if m.uiState.DevConsole != nil && m.uiState.DevConsole.IsVisible() {
			return m.uiState.DevConsole.View()
		}
		return fitCapturePane(strings.Join(parts, "\n"), m.uiState.Width, m.uiState.Height)
	}

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
	case 4: // Help
		mainContent = m.uiState.HelpView.View()
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

	// Render dev console overlay if visible (LOG_LEVEL=DEBUG only)
	if m.uiState.DevConsole != nil && m.uiState.DevConsole.IsVisible() {
		return m.uiState.DevConsole.View()
	}

	return fullView
}

// renderCaptureTab renders the Capture tab content (packets or calls)
func (m Model) renderCaptureTab(contentHeight int) string {
	if m.responsiveCaptureView() {
		return m.renderResponsiveCapture()
	}

	if m.uiState.ViewMode == "queries" {
		// Render DNS queries view with optional details panel
		minWidthForDetails := 120 // Need enough width for query details
		showDetails := m.uiState.DNSQueriesView.IsShowingDetails()
		detailsVisible := showDetails && m.uiState.Width >= minWidthForDetails

		if detailsVisible {
			// Split pane layout for queries
			detailsWidth := 60 // Query details panel width

			// Calculate available width for queries table
			tableWidth := m.uiState.Width - detailsWidth

			// Render queries table and details side by side
			queriesTableView := m.uiState.DNSQueriesView.RenderTable(tableWidth, contentHeight)
			queryDetailsView := m.uiState.DNSQueriesView.RenderDetails(detailsWidth, contentHeight)

			return lipgloss.JoinHorizontal(lipgloss.Top, queriesTableView, queryDetailsView)
		}

		// Full width queries table
		m.uiState.DNSQueriesView.SetSize(m.uiState.Width, contentHeight)
		return m.uiState.DNSQueriesView.View()
	}

	if m.uiState.ViewMode == "emails" {
		// Render Email sessions view with optional details panel
		minWidthForDetails := 120 // Need enough width for session details
		showDetails := m.uiState.EmailView.IsShowingDetails()
		detailsVisible := showDetails && m.uiState.Width >= minWidthForDetails

		if detailsVisible {
			// Split pane layout for email sessions
			detailsWidth := 60 // Session details panel width

			// Calculate available width for sessions table
			tableWidth := m.uiState.Width - detailsWidth

			// Render sessions table and details side by side
			sessionsTableView := m.uiState.EmailView.RenderTable(tableWidth, contentHeight)
			sessionDetailsView := m.uiState.EmailView.RenderDetails(detailsWidth, contentHeight)

			return lipgloss.JoinHorizontal(lipgloss.Top, sessionsTableView, sessionDetailsView)
		}

		// Full width sessions table
		m.uiState.EmailView.SetSize(m.uiState.Width, contentHeight)
		return m.uiState.EmailView.View()
	}

	if m.uiState.ViewMode == "http" {
		// Render HTTP requests view with optional details panel
		minWidthForDetails := 120 // Need enough width for request details
		showDetails := m.uiState.HTTPView.IsShowingDetails()
		detailsVisible := showDetails && m.uiState.Width >= minWidthForDetails

		if detailsVisible {
			// Split pane layout for HTTP requests
			detailsWidth := 60 // Request details panel width

			// Calculate available width for requests table
			tableWidth := m.uiState.Width - detailsWidth

			// Render requests table and details side by side
			requestsTableView := m.uiState.HTTPView.RenderTable(tableWidth, contentHeight)
			requestDetailsView := m.uiState.HTTPView.RenderDetails(detailsWidth, contentHeight)

			return lipgloss.JoinHorizontal(lipgloss.Top, requestsTableView, requestDetailsView)
		}

		// Full width requests table
		m.uiState.HTTPView.SetSize(m.uiState.Width, contentHeight)
		return m.uiState.HTTPView.View()
	}

	return ""
}

func (m Model) renderResponsiveCapture() string {
	l := m.captureLayout()
	list, details := "", ""
	if l.List.Width > 0 && l.List.Height > 0 {
		total, visible, offset := 0, 0, 0
		switch m.uiState.ViewMode {
		case "events":
			list = m.uiState.EventsView.RenderTimeline(max(1, l.List.Width-2), l.List.Height, m.uiState.FocusedPane == "left" && l.Details.Width > 0)
			total, visible, offset = m.uiState.EventsView.TimelineScrollState(l.List.Height)
		case "calls":
			list = m.uiState.CallsView.RenderTable(l.List.Width, l.List.Height, m.uiState.FocusedPane == "left" && l.Details.Width > 0)
			total, visible, offset = m.uiState.CallsView.TableScrollState(l.List.Height)
		default:
			list = m.uiState.PacketList.View(m.uiState.FocusedPane == "left", l.Details.Width > 0)
			total, visible, offset = int(m.uiState.PacketList.LogicalCount()), m.uiState.PacketList.VisibleRows(), int(m.uiState.PacketList.LogicalOffset())
		}
		list = fitCapturePane(list, l.List.Width, l.List.Height)
		list = m.captureScrollbar(list, total, visible, offset, l.List.Height)
	}
	if l.Details.Width > 0 && l.Details.Height > 0 {
		total, visible, offset := 0, 0, 0
		switch m.uiState.ViewMode {
		case "events":
			details = m.uiState.EventsView.RenderDetails(l.Details.Width, l.Details.Height, m.uiState.FocusedPane == "right")
			total, visible, offset = m.uiState.EventsView.DetailsScrollState()
		case "calls":
			details = m.uiState.CallsView.RenderDetails(l.Details.Width, l.Details.Height, m.uiState.FocusedPane == "right")
			total, visible, offset = m.uiState.CallsView.DetailsScrollState()
		default:
			details = m.uiState.DetailsPanel.View(m.uiState.FocusedPane == "right")
			total, visible, offset = m.uiState.DetailsPanel.ScrollState()
		}
		details = fitCapturePane(details, l.Details.Width, l.Details.Height)
		x, y, _, track := components.DetailPaneGeometry(l.Details.Width, l.Details.Height)
		if x > 0 {
			column := l.Details.Width - 1
			if x >= 3 {
				column--
			}
			details = components.OverlayScrollbar(details, column, y, components.RenderScrollbar(total, visible, offset, track, m.uiState.Theme))
		}
	}
	switch l.Mode {
	case captureSideBySide:
		return lipgloss.JoinHorizontal(lipgloss.Top, list, details)
	case captureStacked:
		return lipgloss.JoinVertical(lipgloss.Left, list, details)
	case captureDetailsOnly:
		return details
	default:
		return list
	}
}

func (m Model) captureScrollbar(pane string, total, visible, offset, height int) string {
	trackHeight := max(0, height-4)
	bar := components.RenderScrollbar(total, visible, offset, trackHeight, m.uiState.Theme)
	return components.OverlayScrollbar(pane, lipgloss.Width(pane)-2, 2, bar)
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
		// Packet filter (3 lines) + footer (1 line) = 4 lines
		filterView := m.uiState.FilterInput.View()
		return filterView + "\n" + footerView
	}

	if m.uiState.CallFilterMode {
		// Call filter (3 lines) + footer (1 line) = 4 lines
		filterView := m.uiState.CallFilterInput.View()
		return filterView + "\n" + footerView
	}

	if m.uiState.EventFilterMode {
		filterView := m.uiState.EventFilterInput.View()
		return filterView + "\n" + footerView
	}

	if m.uiState.Toast.IsActive() && !modalActive {
		// Toast notification (3 lines with padding) + footer (1 line) = 4 lines
		// Hidden when modal is active
		toastView := m.uiState.Toast.View()
		return toastView + "\n" + footerView
	}

	// All tabs: 3 blank lines + footer (2 lines) = 5 lines for bottomArea
	// (Nodes tab hints bar is part of mainContent, not bottomArea)
	return "\n\n\n" + footerView
}

// renderActiveModal checks for active modals and renders them as overlays
func (m Model) renderActiveModal() string {
	return components.RenderHostedModal(m.activeModal(), m.uiState.Width, m.uiState.Height)
}

// prepareViewChrome snapshots presentation state during model updates. Rendering
// must not read the event store or mutate the shared header and footer.
func (m *Model) prepareViewChrome() {
	if m.uiState == nil || m.packetStore == nil || m.callStore == nil || m.eventStore == nil {
		return
	}
	m.prepareCaptureLayout()
	if m.uiState.SettingsView.IsFileDialogActive() {
		if dialog := m.uiState.SettingsView.GetPcapFileDialog(); dialog.IsActive() {
			dialog.SetSize(m.uiState.Width, m.uiState.Height)
		}
		if dialog := m.uiState.SettingsView.GetNodesFileDialog(); dialog.IsActive() {
			dialog.SetSize(m.uiState.Width, m.uiState.Height)
		}
	}

	// Update header state
	m.uiState.Header.SetState(m.uiState.Capturing, m.uiState.Paused)
	m.uiState.Header.SetPacketCount(m.packetStore.PacketsCount, m.packetStore.MaxPackets)
	m.uiState.FilterInput.SetPrompt("/")
	if m.captureMode == components.CaptureModeOffline && m.offlineSession != nil {
		usage := m.offlineSession.Dataset.Resources()
		m.uiState.StatisticsView.SetOfflineResources(len(m.uiState.PacketList.GetPackets()), usage)
		m.uiState.Header.SetDatasetPacketCount(m.offlineSession.Dataset.Count())
		m.uiState.FilterInput.SetPrompt("/ complete dataset:")
	}
	m.uiState.Header.SetInterface(m.interfaceName)
	m.uiState.Header.SetCaptureMode(m.captureMode)
	m.uiState.Header.SetPCAPFileCount(len(m.pcapFiles))
	// Use hunter count (not remote client count) for accurate node display
	m.uiState.Header.SetNodeCount(m.uiState.NodesView.GetHunterCount())
	m.uiState.Header.SetProcessorCount(m.uiState.NodesView.GetProcessorCount())
	if m.offlineSession != nil {
		m.uiState.Header.SetTLSDecryption(m.offlineSession.TLSDecryptor != nil)
	} else {
		m.uiState.Header.SetTLSDecryption(viper.GetBool("watch.tls_decryption_enabled"))
	}

	// Update footer state
	m.uiState.Footer.SetDetailsFocused(m.uiState.Tabs.GetActive() == 0 && m.captureDetailsFocused())
	m.uiState.Footer.SetFilterMode(m.uiState.FilterMode)
	m.uiState.Footer.SetHasFilter(m.packetStore.HasFilter())
	m.uiState.Footer.SetFilterCount(m.packetStore.FilterChain.Count())
	m.uiState.Footer.SetActiveTab(m.uiState.Tabs.GetActive())
	m.uiState.Footer.SetHasProtocolSelection(m.uiState.SelectedProtocol.Name != "All")
	m.uiState.Footer.SetHasEvents(eventScopeAvailable(m.uiState.SelectedProtocol.Name))
	m.uiState.Footer.SetPaused(m.uiState.Paused)
	m.uiState.Footer.SetHasHelpSearch(m.uiState.HelpView.HasActiveSearch())
	m.uiState.Footer.SetViewMode(m.uiState.ViewMode)
	m.uiState.Footer.SetCallFilterMode(m.uiState.CallFilterMode)
	m.uiState.Footer.SetHasCallFilter(m.callStore.HasFilter())
	m.uiState.Footer.SetCallFilterCount(m.callStore.FilterChain.Count())
	m.uiState.Footer.SetEventFilterMode(m.uiState.EventFilterMode)
	m.uiState.Footer.SetHasEventFilter(m.eventStore.HasUserFilters())
	m.uiState.Footer.SetEventFilterCount(m.eventStore.UserFilterCount())
	m.uiState.Footer.SetStatsSubView(m.uiState.StatisticsView.GetSubView())
}

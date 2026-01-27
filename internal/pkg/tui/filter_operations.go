//go:build tui || all

package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
)

// handleFilterInput handles key input when in filter mode
func (m Model) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		// Apply the filter
		filterValue := m.uiState.FilterInput.Value()
		var filterCmd tea.Cmd
		if filterValue != "" {
			filterCmd = m.parseAndApplyFilter(filterValue)
			m.uiState.FilterInput.AddToHistory(filterValue)
			// Save filter history to config
			saveFilterHistory(&m.uiState.FilterInput)
		} else {
			// Empty filter = clear all filters
			m.packetStore.ClearFilter()
			m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
			m.packetStore.MatchedPackets = int64(m.packetStore.PacketsCount)
			m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
			// Reset sync counters for incremental updates
			_, _, total, _ := m.packetStore.GetBufferInfo()
			m.lastSyncedTotal = total
			m.lastSyncedFilteredCount = 0
		}
		m.uiState.FilterMode = false
		m.uiState.FilterInput.Deactivate()
		return m, filterCmd

	case "esc", "ctrl+c":
		// Cancel filter input
		m.uiState.FilterMode = false
		m.uiState.FilterInput.Deactivate()
		return m, nil

	case "up", "ctrl+p":
		m.uiState.FilterInput.HistoryUp()
		return m, nil

	case "down", "ctrl+n":
		m.uiState.FilterInput.HistoryDown()
		return m, nil

	case "left", "ctrl+b":
		m.uiState.FilterInput.CursorLeft()
		return m, nil

	case "right", "ctrl+f":
		m.uiState.FilterInput.CursorRight()
		return m, nil

	case "home", "ctrl+a":
		m.uiState.FilterInput.CursorHome()
		return m, nil

	case "end", "ctrl+e":
		m.uiState.FilterInput.CursorEnd()
		return m, nil

	case "backspace":
		m.uiState.FilterInput.Backspace()
		return m, nil

	case "delete", "ctrl+d":
		m.uiState.FilterInput.Delete()
		return m, nil

	case "ctrl+u":
		m.uiState.FilterInput.DeleteToBeginning()
		return m, nil

	case "ctrl+k":
		m.uiState.FilterInput.DeleteToEnd()
		return m, nil

	default:
		// Insert character(s) - handles both single keypress and paste
		if len(msg.Runes) > 0 {
			for _, r := range msg.Runes {
				m.uiState.FilterInput.InsertRune(r)
			}
		}
		return m, nil
	}
}

// handleOpenFilterManager opens the filter manager modal for the selected node
func (m *Model) handleOpenFilterManager() tea.Cmd {
	// Get selected processor or hunter from nodes view
	selectedProcessorAddr := m.uiState.NodesView.GetSelectedProcessorAddr()
	selectedHunter := m.uiState.NodesView.GetSelectedHunter()

	if selectedProcessorAddr != "" {
		// Open for processor (affects all hunters)
		m.uiState.FilterManager.Activate(selectedProcessorAddr, selectedProcessorAddr, components.NodeTypeProcessor)
		m.uiState.FilterManager.SetSize(m.uiState.Width, m.uiState.Height)

		// Set available hunters from the processor
		hunters := m.uiState.NodesView.GetHuntersForProcessor(selectedProcessorAddr)
		hunterItems := make([]components.HunterSelectorItem, 0, len(hunters))
		for _, h := range hunters {
			hunterItems = append(hunterItems, components.HunterSelectorItem{
				HunterID:     h.ID,
				Hostname:     h.Hostname,
				Interfaces:   h.Interfaces,
				Status:       h.Status,
				RemoteAddr:   h.RemoteAddr,
				Capabilities: h.Capabilities,
			})
		}
		m.uiState.FilterManager.SetAvailableHunters(hunterItems)

		// Load filters from processor via gRPC
		return m.loadFiltersFromProcessor(selectedProcessorAddr, "")
	} else if selectedHunter != nil {
		// Open for specific hunter
		m.uiState.FilterManager.Activate(selectedHunter.ID, selectedHunter.ProcessorAddr, components.NodeTypeHunter)
		m.uiState.FilterManager.SetSize(m.uiState.Width, m.uiState.Height)

		// Set available hunters from the processor
		hunters := m.uiState.NodesView.GetHuntersForProcessor(selectedHunter.ProcessorAddr)
		hunterItems := make([]components.HunterSelectorItem, 0, len(hunters))
		for _, h := range hunters {
			hunterItems = append(hunterItems, components.HunterSelectorItem{
				HunterID:     h.ID,
				Hostname:     h.Hostname,
				Interfaces:   h.Interfaces,
				Status:       h.Status,
				RemoteAddr:   h.RemoteAddr,
				Capabilities: h.Capabilities,
			})
		}
		m.uiState.FilterManager.SetAvailableHunters(hunterItems)

		// Load filters from processor (filtered by hunter ID) via gRPC
		// Note: selectedHunter.ProcessorAddr contains the processor address
		return m.loadFiltersFromProcessor(selectedHunter.ProcessorAddr, selectedHunter.ID)
	}
	return nil
}

// loadFiltersFromProcessor loads filters from a processor via gRPC
func (m *Model) loadFiltersFromProcessor(processorAddr string, hunterID string) tea.Cmd {
	return func() tea.Msg {
		// Get processor from connection manager
		proc, exists := m.connectionMgr.Processors[processorAddr]
		if !exists || proc.Client == nil {
			return components.FiltersLoadedMsg{
				ProcessorAddr: processorAddr,
				Filters:       []*management.Filter{},
				Err:           fmt.Errorf("processor not connected"),
			}
		}

		// Cast client to remotecapture.Client
		client, ok := proc.Client.(*remotecapture.Client)
		if !ok {
			return components.FiltersLoadedMsg{
				ProcessorAddr: processorAddr,
				Filters:       []*management.Filter{},
				Err:           fmt.Errorf("invalid client type"),
			}
		}

		// Call GetFiltersFromProcessor RPC (processor-scoped, multi-level management)
		mgmtClient := management.NewManagementServiceClient(client.GetConn())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Request authorization token for this operation
		tokenResp, err := mgmtClient.RequestAuthToken(ctx, &management.AuthTokenRequest{
			TargetProcessorId: processorAddr,
		})
		if err != nil {
			logger.Warn("Failed to request authorization token, proceeding without token",
				"error", err,
				"processor", processorAddr)
			// Continue without token - will work for directly connected processors (mTLS auth)
			tokenResp = nil
		}

		// Empty ProcessorId means "query this processor" (the one we're connected to)
		// ProcessorId is only used for multi-level topologies to target downstream processors
		resp, err := mgmtClient.GetFiltersFromProcessor(ctx, &management.ProcessorFilterQuery{
			ProcessorId: "", // Empty = query the directly connected processor
			HunterId:    hunterID,
			AuthToken:   tokenResp,
		})
		if err != nil {
			logger.Error("Failed to load filters from processor",
				"error", err,
				"processor", processorAddr,
				"hunter_id", hunterID)
			return components.FiltersLoadedMsg{
				ProcessorAddr: processorAddr,
				Filters:       []*management.Filter{},
				Err:           err,
			}
		}

		return components.FiltersLoadedMsg{
			ProcessorAddr: processorAddr,
			Filters:       resp.Filters,
			Err:           nil,
		}
	}
}

// executeFilterOperation executes a filter create/update/delete operation via gRPC
func (m *Model) executeFilterOperation(msg components.FilterOperationMsg) tea.Cmd {
	return func() tea.Msg {
		// Get processor from connection manager
		proc, exists := m.connectionMgr.Processors[msg.ProcessorAddr]
		if !exists || proc.Client == nil {
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: "",
				Error:         "processor not connected",
			}
		}

		// Cast client to remotecapture.Client
		client, ok := proc.Client.(*remotecapture.Client)
		if !ok {
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: "",
				Error:         "invalid client type",
			}
		}

		// Create management client
		mgmtClient := management.NewManagementServiceClient(client.GetConn())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		var result *management.FilterUpdateResult
		var err error
		var filterPattern string

		// Request authorization token for this operation
		// Token is signed by the processor and authorizes operations on the target
		tokenResp, err := mgmtClient.RequestAuthToken(ctx, &management.AuthTokenRequest{
			TargetProcessorId: msg.ProcessorAddr,
		})
		if err != nil {
			logger.Warn("Failed to request authorization token, proceeding without token",
				"error", err,
				"processor", msg.ProcessorAddr)
			// Continue without token - will work for directly connected processors (mTLS auth)
			tokenResp = nil
		}

		switch msg.Operation {
		case "create", "update", "toggle":
			// UpdateFilterOnProcessor handles both create and update (processor-scoped, multi-level)
			if msg.Filter == nil {
				return components.FilterOperationResultMsg{
					Success:       false,
					Operation:     msg.Operation,
					FilterPattern: "",
					Error:         "filter is nil",
				}
			}
			filterPattern = msg.Filter.Pattern
			// Empty ProcessorId = query the directly connected processor
			result, err = mgmtClient.UpdateFilterOnProcessor(ctx, &management.ProcessorFilterRequest{
				ProcessorId: "",
				Filter:      msg.Filter,
				AuthToken:   tokenResp,
			})

		case "delete":
			// DeleteFilterOnProcessor (processor-scoped, multi-level)
			if msg.FilterID == "" {
				return components.FilterOperationResultMsg{
					Success:       false,
					Operation:     msg.Operation,
					FilterPattern: "",
					Error:         "filter ID is empty",
				}
			}
			filterPattern = msg.FilterID
			// Empty ProcessorId = query the directly connected processor
			result, err = mgmtClient.DeleteFilterOnProcessor(ctx, &management.ProcessorFilterDeleteRequest{
				ProcessorId: "",
				FilterId:    msg.FilterID,
				AuthToken:   tokenResp,
			})

		default:
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: "",
				Error:         fmt.Sprintf("unknown operation: %s", msg.Operation),
			}
		}

		if err != nil {
			logger.Error("Filter operation failed",
				"operation", msg.Operation,
				"error", err,
				"processor", msg.ProcessorAddr)
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: filterPattern,
				Error:         err.Error(),
			}
		}

		if !result.Success {
			return components.FilterOperationResultMsg{
				Success:       false,
				Operation:     msg.Operation,
				FilterPattern: filterPattern,
				Error:         result.Error,
			}
		}

		return components.FilterOperationResultMsg{
			Success:        true,
			Operation:      msg.Operation,
			FilterPattern:  filterPattern,
			Error:          "",
			HuntersUpdated: result.HuntersUpdated,
		}
	}
}

// handleCallFilterInput handles key input when in call filter mode
func (m Model) handleCallFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		// Apply the filter
		filterValue := m.uiState.CallFilterInput.Value()
		var filterCmd tea.Cmd
		if filterValue != "" {
			filterCmd = m.parseAndApplyCallFilter(filterValue)
			m.uiState.CallFilterInput.AddToHistory(filterValue)
			// Save call filter history to config
			saveCallFilterHistory(&m.uiState.CallFilterInput)
		} else {
			// Empty filter = clear all filters
			m.callStore.ClearFilter()
			// Refresh calls view
			if m.callStore.HasFilter() {
				m.uiState.CallsView.SetCalls(m.callStore.GetFilteredCalls())
			} else {
				m.uiState.CallsView.SetCalls(m.callStore.GetCallsInOrder())
			}
		}
		m.uiState.CallFilterMode = false
		m.uiState.CallFilterInput.Deactivate()
		return m, filterCmd

	case "esc", "ctrl+c":
		// Cancel filter input
		m.uiState.CallFilterMode = false
		m.uiState.CallFilterInput.Deactivate()
		return m, nil

	case "up", "ctrl+p":
		m.uiState.CallFilterInput.HistoryUp()
		return m, nil

	case "down", "ctrl+n":
		m.uiState.CallFilterInput.HistoryDown()
		return m, nil

	case "left", "ctrl+b":
		m.uiState.CallFilterInput.CursorLeft()
		return m, nil

	case "right", "ctrl+f":
		m.uiState.CallFilterInput.CursorRight()
		return m, nil

	case "home", "ctrl+a":
		m.uiState.CallFilterInput.CursorHome()
		return m, nil

	case "end", "ctrl+e":
		m.uiState.CallFilterInput.CursorEnd()
		return m, nil

	case "backspace":
		m.uiState.CallFilterInput.Backspace()
		return m, nil

	case "delete", "ctrl+d":
		m.uiState.CallFilterInput.Delete()
		return m, nil

	case "ctrl+u":
		m.uiState.CallFilterInput.DeleteToBeginning()
		return m, nil

	case "ctrl+k":
		m.uiState.CallFilterInput.DeleteToEnd()
		return m, nil

	default:
		// Insert character(s) - handles both single keypress and paste
		if len(msg.Runes) > 0 {
			for _, r := range msg.Runes {
				m.uiState.CallFilterInput.InsertRune(r)
			}
		}
		return m, nil
	}
}

// handleEnterCallFilterMode enters call filter input mode
func (m Model) handleEnterCallFilterMode() (Model, tea.Cmd) {
	m.uiState.CallFilterMode = true
	m.uiState.CallFilterInput.Activate()
	m.uiState.CallFilterInput.Clear()
	// Update filter input with current active filters
	filterCount := m.callStore.FilterChain.Count()
	filterDescs := m.callStore.FilterChain.GetFilterDescriptions()
	m.uiState.CallFilterInput.SetActiveFilters(filterCount, filterDescs)
	return m, nil
}

// handleRemoveLastCallFilter removes the last call filter in the stack
func (m Model) handleRemoveLastCallFilter() (Model, tea.Cmd) {
	if m.callStore.HasFilter() {
		filterCount := m.callStore.FilterChain.Count()
		if m.callStore.RemoveLastFilter() {
			// Show toast notification
			remainingCount := filterCount - 1
			msg := "Last call filter removed"
			if remainingCount > 0 {
				msg = fmt.Sprintf("Last call filter removed (%d remaining)", remainingCount)
			}
			toastCmd := m.uiState.Toast.Show(
				msg,
				components.ToastInfo,
				components.ToastDurationShort,
			)

			// Refresh calls view
			if m.callStore.HasFilter() {
				m.uiState.CallsView.SetCalls(m.callStore.GetFilteredCalls())
			} else {
				m.uiState.CallsView.SetCalls(m.callStore.GetCallsInOrder())
			}

			return m, toastCmd
		}
	}
	return m, nil
}

// handleClearAllCallFilters clears all active call filters
func (m Model) handleClearAllCallFilters() (Model, tea.Cmd) {
	if m.callStore.HasFilter() {
		filterCount := m.callStore.FilterChain.Count()
		m.callStore.ClearFilter()

		// Refresh calls view
		m.uiState.CallsView.SetCalls(m.callStore.GetCallsInOrder())

		// Show toast notification with count
		msg := fmt.Sprintf("All call filters cleared (%d removed)", filterCount)
		if filterCount == 1 {
			msg = "Call filter cleared"
		}
		return m, m.uiState.Toast.Show(
			msg,
			components.ToastInfo,
			components.ToastDurationShort,
		)
	}
	return m, nil
}

// parseAndApplyCallFilter parses and applies a filter expression to the call list
func (m *Model) parseAndApplyCallFilter(filterStr string) tea.Cmd {
	if filterStr == "" {
		return nil
	}

	// Try to parse as boolean expression first
	filter, err := filters.ParseBooleanExpression(filterStr, func(s string) filters.Filter {
		f, _ := parseCallFilter(s)
		return f
	})
	if err == nil && filter != nil {
		m.callStore.AddFilter(filter)
	} else if err != nil {
		// Try simple filter parse
		simpleFilter, parseErr := parseCallFilter(filterStr)
		if parseErr != nil {
			// Show error toast for invalid filter
			return m.uiState.Toast.Show(
				fmt.Sprintf("Invalid call filter: %s", parseErr.Error()),
				components.ToastError,
				components.ToastDurationLong,
			)
		}
		if simpleFilter != nil {
			m.callStore.AddFilter(simpleFilter)
		}
	}

	// Refresh calls view with filtered calls
	m.uiState.CallsView.SetCalls(m.callStore.GetFilteredCalls())

	// Show toast with filter count
	filterCount := m.callStore.FilterChain.Count()
	if filterCount > 1 {
		return m.uiState.Toast.Show(
			fmt.Sprintf("Call filter added (%d filters active)", filterCount),
			components.ToastSuccess,
			components.ToastDurationShort,
		)
	}

	return nil
}

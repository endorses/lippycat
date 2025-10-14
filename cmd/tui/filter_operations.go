//go:build tui || all
// +build tui all

package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
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
			m.packetStore.MatchedPackets = m.packetStore.PacketsCount
			m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
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
				HunterID:   h.ID,
				Hostname:   h.Hostname,
				Interfaces: h.Interfaces,
				Status:     h.Status,
				RemoteAddr: h.RemoteAddr,
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
				HunterID:   h.ID,
				Hostname:   h.Hostname,
				Interfaces: h.Interfaces,
				Status:     h.Status,
				RemoteAddr: h.RemoteAddr,
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

		// Call GetFilters RPC
		mgmtClient := management.NewManagementServiceClient(client.GetConn())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := mgmtClient.GetFilters(ctx, &management.FilterRequest{
			HunterId: hunterID, // Empty string means all filters
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

		switch msg.Operation {
		case "create", "update", "toggle":
			// UpdateFilter handles both create and update
			if msg.Filter == nil {
				return components.FilterOperationResultMsg{
					Success:       false,
					Operation:     msg.Operation,
					FilterPattern: "",
					Error:         "filter is nil",
				}
			}
			filterPattern = msg.Filter.Pattern
			result, err = mgmtClient.UpdateFilter(ctx, msg.Filter)

		case "delete":
			// DeleteFilter
			if msg.FilterID == "" {
				return components.FilterOperationResultMsg{
					Success:       false,
					Operation:     msg.Operation,
					FilterPattern: "",
					Error:         "filter ID is empty",
				}
			}
			filterPattern = msg.FilterID
			result, err = mgmtClient.DeleteFilter(ctx, &management.FilterDeleteRequest{
				FilterId: msg.FilterID,
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

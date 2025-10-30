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
	"github.com/endorses/lippycat/cmd/tui/config"
	"github.com/endorses/lippycat/cmd/tui/store"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
)

// NodesLoadedMsg is sent when nodes are loaded successfully from YAML
type NodesLoadedMsg struct {
	NodeCount int
	FilePath  string
}

// NodesLoadFailedMsg is sent when loading nodes from YAML fails
type NodesLoadFailedMsg struct {
	Error    error
	FilePath string
}

// NodeDeletionData holds information about a node pending deletion
type NodeDeletionData struct {
	ProcessorAddr string // Non-empty if deleting a processor
	HunterID      string // Non-empty if unsubscribing from a hunter
	ProcessorID   string // For display purposes
}

// getConnectedProcessors returns a list of connected processor addresses
func (m *Model) getConnectedProcessors() []string {
	processors := make([]string, 0, len(m.connectionMgr.Processors))
	for addr := range m.connectionMgr.Processors {
		processors = append(processors, addr)
	}
	return processors
}

// getProcessorInfoList returns ProcessorInfo for all configured processors
func (m *Model) getProcessorInfoList() []components.ProcessorInfo {
	procInfos := make([]components.ProcessorInfo, 0, len(m.connectionMgr.Processors))
	for addr, proc := range m.connectionMgr.Processors {
		// Convert model store.ProcessorState to components.ProcessorConnectionState
		var connState components.ProcessorConnectionState
		switch proc.State {
		case store.ProcessorStateUnknown:
			connState = components.ProcessorConnectionStateUnknown
		case store.ProcessorStateDisconnected:
			connState = components.ProcessorConnectionStateDisconnected
		case store.ProcessorStateConnecting:
			connState = components.ProcessorConnectionStateConnecting
		case store.ProcessorStateConnected:
			connState = components.ProcessorConnectionStateConnected
		case store.ProcessorStateFailed:
			connState = components.ProcessorConnectionStateFailed
		default:
			connState = components.ProcessorConnectionStateDisconnected
		}

		// Filter hunters based on subscription list
		// - nil = never configured, show all hunters (default)
		// - empty slice [] = explicitly subscribed to none, show no hunters
		// - non-empty slice = show only subscribed hunters
		allHunters := m.connectionMgr.HuntersByProcessor[addr]
		var displayHunters []components.HunterInfo

		if proc.SubscribedHunters == nil {
			// Never configured - show all hunters (default behavior)
			displayHunters = allHunters
		} else if len(proc.SubscribedHunters) == 0 {
			// Explicitly subscribed to no hunters - show nothing
			displayHunters = []components.HunterInfo{}
		} else {
			// Filter to show only subscribed hunters
			subscribedSet := make(map[string]bool)
			for _, hunterID := range proc.SubscribedHunters {
				subscribedSet[hunterID] = true
			}

			displayHunters = make([]components.HunterInfo, 0)
			for _, hunter := range allHunters {
				if subscribedSet[hunter.ID] {
					displayHunters = append(displayHunters, hunter)
				}
			}
		}

		// Calculate hierarchy information
		depth := m.connectionMgr.GetHierarchyDepth(addr)
		path := m.connectionMgr.GetProcessorPath(addr)
		latency := m.connectionMgr.EstimateOperationLatency(addr)

		procInfos = append(procInfos, components.ProcessorInfo{
			Address:          addr,
			ProcessorID:      proc.ProcessorID,
			Status:           proc.Status,
			ConnectionState:  connState,
			TLSInsecure:      proc.TLSInsecure,
			UpstreamAddr:     proc.UpstreamAddr, // Upstream processor (for hierarchy display)
			Hunters:          displayHunters,
			TotalHunters:     len(allHunters), // Total hunters connected to processor
			HierarchyDepth:   depth,           // Hierarchy depth (0 = root, -1 = unknown)
			ProcessorPath:    path,            // Full path from root to this processor
			EstimatedLatency: latency,         // Estimated operation latency in ms
		})
	}
	return procInfos
}

// loadNodesFile loads processors from a YAML file and adds them for connection
func loadNodesFile(filePath string) tea.Cmd {
	return func() tea.Msg {
		// Load nodes in background
		nodes, err := config.LoadNodesFromYAML(filePath)
		if err != nil {
			return NodesLoadFailedMsg{
				Error:    err,
				FilePath: filePath,
			}
		}

		// Create AddNodeMsg commands for each node
		cmds := make([]tea.Cmd, len(nodes)+1) // +1 for success message
		for i, node := range nodes {
			addr := node.Address
			cmds[i] = func() tea.Msg {
				return components.AddNodeMsg{Address: addr}
			}
		}
		// Add success message
		cmds[len(nodes)] = func() tea.Msg {
			return NodesLoadedMsg{
				NodeCount: len(nodes),
				FilePath:  filePath,
			}
		}

		return tea.Batch(cmds...)()
	}
}

// handleDeleteNode handles deletion/unsubscription of a selected node
// Shows a confirmation dialog before performing the action
func (m *Model) handleDeleteNode() tea.Cmd {
	// Check what's selected in the nodes view
	selectedHunter := m.uiState.NodesView.GetSelectedHunter()
	selectedProcessorAddr := m.uiState.NodesView.GetSelectedProcessorAddr()

	if selectedProcessorAddr != "" {
		// Processor is selected - show confirmation dialog
		proc, exists := m.connectionMgr.Processors[selectedProcessorAddr]
		if !exists {
			return nil
		}

		details := []string{
			"Address: " + selectedProcessorAddr,
		}
		if proc.ProcessorID != "" {
			details = append(details, "ID: "+proc.ProcessorID)
		}

		// Show confirmation dialog with processor info
		return m.uiState.ConfirmDialog.Show(components.ConfirmDialogOptions{
			Type:        components.ConfirmDialogDanger,
			Title:       "Remove Processor",
			Message:     "Are you sure you want to remove this processor?",
			Details:     details,
			ConfirmText: "y",
			CancelText:  "n",
			UserData: NodeDeletionData{
				ProcessorAddr: selectedProcessorAddr,
				ProcessorID:   proc.ProcessorID,
			},
		})
	} else if selectedHunter != nil {
		// Hunter is selected - show confirmation dialog for unsubscription
		details := []string{
			"Hunter ID: " + selectedHunter.ID,
			"Hostname: " + selectedHunter.Hostname,
		}

		// Show confirmation dialog with hunter info
		return m.uiState.ConfirmDialog.Show(components.ConfirmDialogOptions{
			Type:        components.ConfirmDialogWarning,
			Title:       "Unsubscribe from Hunter",
			Message:     "Are you sure you want to unsubscribe from this hunter?",
			Details:     details,
			ConfirmText: "y",
			CancelText:  "n",
			UserData: NodeDeletionData{
				ProcessorAddr: selectedHunter.ProcessorAddr,
				HunterID:      selectedHunter.ID,
			},
		})
	}
	return nil
}

// performNodeDeletion performs the actual deletion/unsubscription after confirmation
func (m *Model) performNodeDeletion(data NodeDeletionData) tea.Cmd {
	if data.ProcessorAddr != "" && data.HunterID == "" {
		// Delete processor
		if proc, exists := m.connectionMgr.Processors[data.ProcessorAddr]; exists {
			// Close client connection
			if proc.Client != nil {
				proc.Client.Close()
			}
			// Remove from connection manager (also removes hunters)
			m.connectionMgr.RemoveProcessor(data.ProcessorAddr)

			// Update NodesView to reflect removal
			procInfos := m.getProcessorInfoList()
			m.uiState.NodesView.SetProcessors(procInfos)

			// Show success toast
			return m.uiState.Toast.Show(
				fmt.Sprintf("Removed %s", data.ProcessorAddr),
				components.ToastSuccess,
				components.ToastDurationShort,
			)
		}
	} else if data.HunterID != "" {
		// Unsubscribe from hunter
		processorAddr := data.ProcessorAddr

		proc, exists := m.connectionMgr.Processors[processorAddr]
		if !exists {
			return nil
		}

		// Get current subscription list (not all available hunters!)
		var currentSubscription []string
		if proc.SubscribedHunters == nil {
			// Never configured - currently subscribed to all hunters
			// Get list of all hunters and remove the selected one
			allHunters := m.connectionMgr.GetHunters(processorAddr)
			currentSubscription = make([]string, 0, len(allHunters))
			for _, h := range allHunters {
				currentSubscription = append(currentSubscription, h.ID)
			}
		} else {
			// Already configured - use existing subscription list
			currentSubscription = proc.SubscribedHunters
		}

		// Build new list excluding the hunter to remove
		newHunterIDs := make([]string, 0)
		for _, hunterID := range currentSubscription {
			if hunterID != data.HunterID {
				newHunterIDs = append(newHunterIDs, hunterID)
			}
		}

		// Show toast notification
		toastCmd := m.uiState.Toast.Show(
			fmt.Sprintf("Unsubscribed from %s", data.HunterID),
			components.ToastInfo,
			components.ToastDurationShort,
		)

		// Reconnect with new subscription list
		reconnectCmd := m.reconnectWithHunterFilter(processorAddr, newHunterIDs)
		return tea.Batch(toastCmd, reconnectCmd)
	}
	return nil
}

// handleOpenHunterSelector opens the hunter selector modal for the selected processor
func (m *Model) handleOpenHunterSelector() tea.Cmd {
	// Get selected processor from nodes view
	selectedProcessorAddr := m.uiState.NodesView.GetSelectedProcessorAddr()

	if selectedProcessorAddr == "" {
		// Check if a hunter is selected, and get its processor
		if hunter := m.uiState.NodesView.GetSelectedHunter(); hunter != nil {
			selectedProcessorAddr = hunter.ProcessorAddr
		}
	}

	if selectedProcessorAddr != "" {
		// Open hunter selector and load hunters
		m.uiState.HunterSelector.Activate(selectedProcessorAddr)
		m.uiState.HunterSelector.SetSize(m.uiState.Width, m.uiState.Height)

		// Trigger loading hunters from processor
		return func() tea.Msg {
			return components.LoadHuntersFromProcessorMsg{ProcessorAddr: selectedProcessorAddr}
		}
	}
	return nil
}

// handleHunterSelectionConfirmed handles when user confirms hunter selection in modal
func (m *Model) handleHunterSelectionConfirmed(msg components.HunterSelectionConfirmedMsg) tea.Cmd {
	// Show toast notification
	var toastMsg string
	if len(msg.SelectedHunterIDs) == 0 {
		toastMsg = "Subscribed to all hunters"
	} else if len(msg.SelectedHunterIDs) == 1 {
		toastMsg = "Subscribed to 1 hunter"
	} else {
		toastMsg = fmt.Sprintf("Subscribed to %d hunters", len(msg.SelectedHunterIDs))
	}
	toastCmd := m.uiState.Toast.Show(
		toastMsg,
		components.ToastSuccess,
		components.ToastDurationShort,
	)

	// Reconnect with new hunter filter
	reconnectCmd := m.reconnectWithHunterFilter(msg.ProcessorAddr, msg.SelectedHunterIDs)
	return tea.Batch(toastCmd, reconnectCmd)
}

// reconnectWithHunterFilter hot-swaps the hunter subscription without reconnecting
// This works across the hierarchy by finding the root processor connection
func (m *Model) reconnectWithHunterFilter(processorAddr string, hunterIDs []string) tea.Cmd {
	proc, exists := m.connectionMgr.Processors[processorAddr]
	if !exists {
		return nil
	}

	// Store the new subscription list for this processor
	proc.SubscribedHunters = hunterIDs

	// Find the root processor (the one we're directly connected to)
	// This handles hierarchical subscriptions where hunters may be on downstream processors
	var client *remotecapture.Client
	var rootAddr string

	if proc.Client != nil {
		// This processor is directly connected (it's the root)
		rootAddr = processorAddr
		client, _ = proc.Client.(*remotecapture.Client)
	} else {
		// This processor is downstream - find the root processor
		rootProcAddr, rootClient, err := m.connectionMgr.GetRootProcessorForAddress(processorAddr)
		if err != nil {
			logger.Error("Failed to find root processor for subscription update",
				"processor", processorAddr,
				"error", err)
			return nil
		}
		rootAddr = rootProcAddr
		client, _ = rootClient.(*remotecapture.Client)
	}

	if client == nil {
		logger.Error("No client available for subscription update",
			"processor", processorAddr,
			"root_processor", rootAddr)
		return nil
	}

	// Update subscription on the root processor connection
	// The root processor will filter packets by hunter_id, which works across the hierarchy
	return func() tea.Msg {
		err := client.UpdateSubscription(hunterIDs)
		if err != nil {
			// Hot-swap failed, fall back to reconnection
			logger.Error("Hot-swap subscription failed on root processor",
				"processor", processorAddr,
				"root_processor", rootAddr,
				"error", err)
			return ProcessorReconnectMsg{
				Address:   rootAddr, // Reconnect to root processor
				HunterIDs: hunterIDs,
			}
		}
		// Success - subscription updated seamlessly across hierarchy
		logger.Info("Subscription updated successfully",
			"processor", processorAddr,
			"root_processor", rootAddr,
			"hunters", hunterIDs)
		return nil
	}
}

// loadHuntersFromProcessor loads the list of hunters from a processor
// For hierarchical mode, uses cached topology data from the connection manager
// For direct connections, queries via gRPC if needed
func (m *Model) loadHuntersFromProcessor(processorAddr string) tea.Cmd {
	return func() tea.Msg {
		proc, exists := m.connectionMgr.Processors[processorAddr]
		if !exists {
			return components.HuntersLoadedMsg{
				ProcessorAddr: processorAddr,
				Hunters:       []components.HunterSelectorItem{},
			}
		}

		// Get hunters from cached topology (updated via SubscribeTopology)
		// This works for both direct connections and hierarchical downstream processors
		cachedHunters := m.connectionMgr.GetHunters(processorAddr)

		// If we have cached hunters, use them (most common case)
		if len(cachedHunters) > 0 {
			// Convert to HunterSelectorItem and mark currently subscribed hunters as selected
			subscribedIDs := make(map[string]bool)
			if proc.SubscribedHunters == nil {
				// Never configured - pre-select all hunters (default)
				for _, h := range cachedHunters {
					subscribedIDs[h.ID] = true
				}
			} else if len(proc.SubscribedHunters) == 0 {
				// Explicitly subscribed to no hunters - select none
			} else {
				// We have a specific subscription list - only these are selected
				for _, hunterID := range proc.SubscribedHunters {
					subscribedIDs[hunterID] = true
				}
			}

			// Build hunter items from cached data
			hunterItems := make([]components.HunterSelectorItem, 0, len(cachedHunters))
			for _, h := range cachedHunters {
				hunterItems = append(hunterItems, components.HunterSelectorItem{
					HunterID:     h.ID,
					Hostname:     h.Hostname,
					Interfaces:   h.Interfaces,
					Status:       h.Status,
					RemoteAddr:   h.RemoteAddr,
					Selected:     subscribedIDs[h.ID],
					Capabilities: h.Capabilities,
				})
			}

			return components.HuntersLoadedMsg{
				ProcessorAddr: processorAddr,
				Hunters:       hunterItems,
			}
		}

		// No cached hunters - try to query directly if we have a client
		// This handles the case where topology hasn't been received yet
		if proc.Client == nil {
			// For downstream processors without direct connection, return empty
			// (topology will populate this later)
			return components.HuntersLoadedMsg{
				ProcessorAddr: processorAddr,
				Hunters:       []components.HunterSelectorItem{},
			}
		}

		// Cast client to remotecapture.Client
		client, ok := proc.Client.(*remotecapture.Client)
		if !ok {
			return components.HuntersLoadedMsg{
				ProcessorAddr: processorAddr,
				Hunters:       []components.HunterSelectorItem{},
			}
		}

		// Call ListAvailableHunters RPC (fallback for direct connections)
		mgmtClient := management.NewManagementServiceClient(client.GetConn())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := mgmtClient.ListAvailableHunters(ctx, &management.ListHuntersRequest{})
		if err != nil {
			logger.Error("Failed to load hunters from processor",
				"error", err,
				"processor", processorAddr,
				"error_type", fmt.Sprintf("%T", err))
			return components.HuntersLoadedMsg{
				ProcessorAddr: processorAddr,
				Hunters:       []components.HunterSelectorItem{},
			}
		}

		// Convert to HunterSelectorItem and mark currently subscribed hunters as selected
		subscribedIDs := make(map[string]bool)
		if proc.SubscribedHunters == nil {
			// Never configured - pre-select all hunters (default)
			for _, h := range resp.Hunters {
				subscribedIDs[h.HunterId] = true
			}
		} else if len(proc.SubscribedHunters) == 0 {
			// Explicitly subscribed to no hunters - select none
		} else {
			// We have a specific subscription list - only these are selected
			for _, hunterID := range proc.SubscribedHunters {
				subscribedIDs[hunterID] = true
			}
		}

		// Build hunter items from RPC response
		hunterItems := make([]components.HunterSelectorItem, 0, len(resp.Hunters))
		for _, h := range resp.Hunters {
			hunterItems = append(hunterItems, components.HunterSelectorItem{
				HunterID:     h.HunterId,
				Hostname:     h.Hostname,
				Interfaces:   h.Interfaces,
				Status:       h.Status,
				RemoteAddr:   h.RemoteAddr,
				Selected:     subscribedIDs[h.HunterId],
				Capabilities: h.Capabilities,
			})
		}

		return components.HuntersLoadedMsg{
			ProcessorAddr: processorAddr,
			Hunters:       hunterItems,
		}
	}
}

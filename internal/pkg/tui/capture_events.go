//go:build tui || all
// +build tui all

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

// handlePacketBatchMsg processes a batch of packets
func (m Model) handlePacketBatchMsg(msg PacketBatchMsg) (Model, tea.Cmd) {
	// Handle batch of packets more efficiently
	if !m.uiState.Paused {
		for _, packet := range msg.Packets {
			// Set NodeID to "Local" if not already set (for local/offline capture)
			if packet.NodeID == "" {
				packet.NodeID = "Local"
			}

			// Only process packets that match current capture mode
			// Live/Offline mode: only accept local packets
			// Remote mode: only accept remote packets
			if m.captureMode == components.CaptureModeRemote {
				// In remote mode, skip local packets
				if packet.NodeID == "Local" {
					continue
				}
			} else {
				// In live/offline mode, skip remote packets
				if packet.NodeID != "Local" {
					continue
				}
			}

			// Add packet using PacketStore method
			m.packetStore.AddPacket(packet)

			// Process packet through call aggregator (live and offline modes)
			if m.captureMode == components.CaptureModeOffline && m.offlineCallAggregator != nil {
				// Convert components.PacketDisplay to types.PacketDisplay (they're aliased, so direct cast)
				typesPacket := types.PacketDisplay(packet)
				m.offlineCallAggregator.ProcessPacket(&typesPacket)
			} else if m.captureMode == components.CaptureModeLive && m.liveCallAggregator != nil {
				// Convert components.PacketDisplay to types.PacketDisplay (they're aliased, so direct cast)
				typesPacket := types.PacketDisplay(packet)
				m.liveCallAggregator.ProcessPacket(&typesPacket)
			}

			// Update DNS queries view if this is a DNS packet
			// Parse DNS from raw data if not already parsed
			if packet.DNSData == nil && packet.Protocol == "DNS" && len(packet.RawData) > 0 {
				packet.DNSData = parseDNSFromRawData(packet.RawData, packet.LinkType)
			}
			if packet.DNSData != nil {
				typesPacket := types.PacketDisplay(packet)
				m.uiState.DNSQueriesView.UpdateFromPacket(&typesPacket)
			}

			// Update Email sessions view if this is an email packet
			if packet.EmailData != nil {
				typesPacket := types.PacketDisplay(packet)
				m.uiState.EmailView.UpdateFromPacket(&typesPacket)
			}

			// Write to streaming save if active
			if m.activeWriter != nil {
				// WritePacket will apply filter internally if configured (best-effort)
				_ = m.activeWriter.WritePacket(packet)
			}

			// Update statistics (lightweight)
			m.updateStatistics(packet)
		}

		// Update packet list with moderate throttling for smooth display
		// Throttle to 10 Hz (100ms) to balance responsiveness with performance
		now := time.Now()
		if now.Sub(m.lastPacketListUpdate) >= m.packetListUpdateInterval {
			if !m.packetStore.HasFilter() {
				m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
			} else {
				m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
			}
			m.lastPacketListUpdate = now
		}

		// Update details panel if showing details (throttled to reduce CPU usage)
		// Only update at configured interval (default 20 Hz) to avoid rendering
		// expensive hex dumps on every packet during high packet rate
		if m.uiState.ShowDetails {
			if now.Sub(m.lastDetailsPanelUpdate) >= m.detailsPanelUpdateInterval {
				m.updateDetailsPanel()
				m.lastDetailsPanelUpdate = now
			}
		}
	}
	return m, nil
}

// handlePacketMsg processes a single packet
func (m Model) handlePacketMsg(msg PacketMsg) (Model, tea.Cmd) {
	if !m.uiState.Paused {
		// Set NodeID to "Local" if not already set (for local/offline capture)
		packet := msg.Packet
		if packet.NodeID == "" {
			packet.NodeID = "Local"
		}

		// Only process packets that match current capture mode
		// Live/Offline mode: only accept local packets
		// Remote mode: only accept remote packets
		if m.captureMode == components.CaptureModeRemote {
			// In remote mode, skip local packets
			if packet.NodeID == "Local" {
				return m, nil
			}
		} else {
			// In live/offline mode, skip remote packets
			if packet.NodeID != "Local" {
				return m, nil
			}
		}

		// Add packet using PacketStore method
		m.packetStore.AddPacket(packet)

		// Process packet through call aggregator (live and offline modes)
		if m.captureMode == components.CaptureModeOffline && m.offlineCallAggregator != nil {
			// Convert components.PacketDisplay to types.PacketDisplay (they're aliased, so direct cast)
			typesPacket := types.PacketDisplay(packet)
			m.offlineCallAggregator.ProcessPacket(&typesPacket)
		} else if m.captureMode == components.CaptureModeLive && m.liveCallAggregator != nil {
			// Convert components.PacketDisplay to types.PacketDisplay (they're aliased, so direct cast)
			typesPacket := types.PacketDisplay(packet)
			m.liveCallAggregator.ProcessPacket(&typesPacket)
		}

		// Write to streaming save if active
		if m.activeWriter != nil {
			// WritePacket will apply filter internally if configured (best-effort)
			_ = m.activeWriter.WritePacket(packet)
		}

		// Update statistics (lightweight)
		m.updateStatistics(packet)

		// Update packet list with moderate throttling for smooth display
		// Throttle to 10 Hz (100ms) to balance responsiveness with performance
		now := time.Now()
		if now.Sub(m.lastPacketListUpdate) >= m.packetListUpdateInterval {
			if !m.packetStore.HasFilter() {
				m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
			} else {
				m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
			}
			m.lastPacketListUpdate = now
		}

		// Update details panel if showing details (throttled to reduce CPU usage)
		// Only update at configured interval (default 20 Hz) to avoid rendering
		// expensive hex dumps on every packet during high packet rate
		if m.uiState.ShowDetails {
			if now.Sub(m.lastDetailsPanelUpdate) >= m.detailsPanelUpdateInterval {
				m.updateDetailsPanel()
				m.lastDetailsPanelUpdate = now
			}
		}
	}
	return m, nil
}

// handleCallUpdateMsg processes VoIP call state updates
func (m Model) handleCallUpdateMsg(msg CallUpdateMsg) (Model, tea.Cmd) {
	// Add or update calls in the call store (maintains history across processor restarts)
	tuiCalls := make([]components.Call, len(msg.Calls))
	for i, call := range msg.Calls {
		// Debug logging to see what data we're receiving
		logger.Debug("Processing call update",
			"call_id", call.CallID,
			"node_id", call.NodeID,
			"hunters", call.Hunters,
			"hunters_count", len(call.Hunters))

		// Use hunter IDs as the node identifier (comma-separated if multiple hunters)
		nodeID := call.NodeID // Default to processor ID if no hunters
		if len(call.Hunters) > 0 {
			nodeID = strings.Join(call.Hunters, ",")
		} else {
			logger.Warn("Call has no hunter IDs", "call_id", call.CallID, "node_id", call.NodeID)
		}

		tuiCalls[i] = components.Call{
			CallID:      call.CallID,
			From:        call.From,
			To:          call.To,
			State:       mapCallState(call.State),
			StartTime:   call.StartTime,
			EndTime:     call.EndTime,
			Duration:    call.Duration,
			Codec:       call.Codec,
			PacketCount: call.PacketCount,
			PacketLoss:  call.PacketLoss,
			Jitter:      call.Jitter,
			MOS:         call.MOS,
			NodeID:      nodeID,
		}
	}

	// Add/update calls in the store (doesn't replace entire list)
	m.callStore.AddOrUpdateCalls(tuiCalls)

	// Update the CallsView with all calls from the store
	allCalls := m.callStore.GetCallsInOrder()
	m.uiState.CallsView.SetCalls(allCalls)

	return m, nil
}

// handleCorrelatedCallUpdateMsg processes correlated call updates from processor
func (m Model) handleCorrelatedCallUpdateMsg(msg CorrelatedCallUpdateMsg) (Model, tea.Cmd) {
	// Pass correlated calls to CallsView for display in detail panel
	m.uiState.CallsView.SetCorrelatedCalls(msg.CorrelatedCalls)

	logger.Debug("Received correlated call updates",
		"count", len(msg.CorrelatedCalls))

	return m, nil
}

// handleHunterStatusMsg processes hunter status updates from remote capture
func (m Model) handleHunterStatusMsg(msg HunterStatusMsg) (Model, tea.Cmd) {
	// Handle hunter status from remote capture client
	// Now we have the processor address directly from the message
	processorAddr := msg.ProcessorAddr

	// Update processor info if we have this processor in our connection manager
	if processorAddr != "" {
		if proc, exists := m.connectionMgr.Processors[processorAddr]; exists {
			// Update processor ID and status if provided
			if msg.ProcessorID != "" {
				proc.ProcessorID = msg.ProcessorID
			}
			proc.Status = msg.ProcessorStatus

			// Store upstream processor address for hierarchy display
			// If this processor has an upstream, create/update it in the processor list
			if msg.UpstreamProcessor != "" {
				// Ensure upstream processor exists in our processor map
				if _, exists := m.connectionMgr.Processors[msg.UpstreamProcessor]; !exists {
					// Create upstream processor entry (will be populated by its own status updates)
					// Inherit TLS security status from the processor that reported this upstream
					m.connectionMgr.Processors[msg.UpstreamProcessor] = &store.ProcessorConnection{
						Address:     msg.UpstreamProcessor,
						State:       store.ProcessorStateUnknown,
						ProcessorID: "", // Will be populated when we connect or it reports
						Status:      management.ProcessorStatus_PROCESSOR_HEALTHY,
						TLSInsecure: proc.TLSInsecure, // Inherit TLS security status
					}
				}

				// Mark that this processor forwards to upstream
				proc.UpstreamAddr = msg.UpstreamProcessor
				// Invalidate cache when hierarchy changes
				m.connectionMgr.InvalidateRootProcessorCache("")
			}
		}
	}

	// Update hunters for this processor
	m.connectionMgr.HuntersByProcessor[processorAddr] = msg.Hunters

	// Update NodesView with processor info (includes processor IDs, status, and hierarchy)
	m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
	return m, nil
}

// handleProcessorReconnectMsg attempts to connect or reconnect to a processor
func (m Model) handleProcessorReconnectMsg(msg ProcessorReconnectMsg) (Model, tea.Cmd) {
	// Attempt to connect/reconnect to a processor
	proc, exists := m.connectionMgr.Processors[msg.Address]
	if !exists {
		return m, nil
	}

	// Don't reconnect if already connecting or connected
	if proc.State == store.ProcessorStateConnecting || proc.State == store.ProcessorStateConnected {
		return m, nil
	}

	// Update state to connecting
	proc.State = store.ProcessorStateConnecting
	proc.LastAttempt = time.Now()

	// Show connecting toast (distinguish reconnection from initial connection)
	var toastMsg string
	if proc.FailureCount > 0 {
		toastMsg = fmt.Sprintf("Reconnecting to %s...", msg.Address)
	} else {
		toastMsg = fmt.Sprintf("Connecting to %s...", msg.Address)
	}
	toastCmd := m.uiState.Toast.Show(
		toastMsg,
		components.ToastInfo,
		components.ToastDurationShort,
	)

	// Capture insecure flag for use in goroutine
	insecure := m.insecure

	// Attempt connection in background
	go func() {
		// Get program reference via synchronized CaptureState
		program := globalCaptureState.GetProgram()
		if program == nil {
			logger.Error("Cannot connect to processor: no TUI program set", "address", msg.Address)
			return
		}

		// Create TUI event handler adapter
		handler := NewTUIEventHandler(program)

		// Build client config with TLS settings from viper
		// If --insecure flag is set, disable TLS entirely
		tlsEnabled := viper.GetBool("tui.tls.enabled")
		if insecure {
			tlsEnabled = false
		}

		clientConfig := &remotecapture.ClientConfig{
			Address:               msg.Address,
			TLSEnabled:            tlsEnabled,
			TLSCAFile:             viper.GetString("tui.tls.ca_file"),
			TLSCertFile:           viper.GetString("tui.tls.cert_file"),
			TLSKeyFile:            viper.GetString("tui.tls.key_file"),
			TLSSkipVerify:         viper.GetBool("tui.tls.skip_verify"),
			TLSServerNameOverride: viper.GetString("tui.tls.server_name_override"),
		}

		client, err := remotecapture.NewClientWithConfig(clientConfig, handler)
		if err != nil {
			// Connection failed
			logger.Error("Failed to connect to processor", "address", msg.Address, "error", err)
			globalCaptureState.SendMessage(ProcessorDisconnectedMsg{
				Address: msg.Address,
				Error:   err,
			})
			return
		}

		// Start packet stream with hunter filter (if specified)
		if err := client.StreamPacketsWithFilter(msg.HunterIDs); err != nil {
			client.Close()
			globalCaptureState.SendMessage(ProcessorDisconnectedMsg{
				Address: msg.Address,
				Error:   err,
			})
			return
		}

		// Subscribe to topology updates to discover downstream processors and hunters
		if err := client.SubscribeTopology(); err != nil {
			logger.Warn("Failed to subscribe to topology from processor",
				"address", msg.Address,
				"error", err)
			// Non-fatal - continue with regular hunter status
		}

		// Start hunter status subscription
		if err := client.SubscribeHunterStatus(); err != nil {
			// Non-fatal - continue anyway
		}

		// Start correlated calls subscription (for SIP call correlation across B2BUA)
		if err := client.SubscribeCorrelatedCalls(); err != nil {
			// Non-fatal - continue anyway (feature may not be available)
		}

		// Connection successful
		globalCaptureState.SendMessage(ProcessorConnectedMsg{
			Address:     msg.Address,
			Client:      client,
			TLSInsecure: !tlsEnabled, // Record if connection is insecure
		})
	}()

	return m, toastCmd
}

// handleProcessorConnectedMsg processes successful processor connection
func (m Model) handleProcessorConnectedMsg(msg ProcessorConnectedMsg) (Model, tea.Cmd) {
	// Processor connection established successfully
	if proc, exists := m.connectionMgr.Processors[msg.Address]; exists {
		proc.State = store.ProcessorStateConnected
		proc.Client = msg.Client
		proc.FailureCount = 0
		proc.TLSInsecure = msg.TLSInsecure

		// Also store in deprecated map for compatibility
		m.connectionMgr.RemoteClients[msg.Address] = msg.Client

		// Update NodesView to reflect connection state change
		procInfos := m.getProcessorInfoList()
		m.uiState.NodesView.SetProcessors(procInfos)

		// If in remote mode, mark capturing as active when we have at least one connected processor
		if m.captureMode == components.CaptureModeRemote {
			m.uiState.SetCapturing(true)
		}

		// Show success toast (with warning for insecure connections)
		var toastMsg string
		var toastType components.ToastType
		if msg.TLSInsecure {
			toastMsg = fmt.Sprintf("⚠ Connected to %s (INSECURE - no TLS)", msg.Address)
			toastType = components.ToastWarning
		} else {
			toastMsg = fmt.Sprintf("Connected to %s", msg.Address)
			toastType = components.ToastSuccess
		}

		return m, m.uiState.Toast.Show(
			toastMsg,
			toastType,
			components.ToastDurationShort,
		)
	}
	return m, nil
}

// handleProcessorDisconnectedMsg processes processor disconnection or failure
func (m Model) handleProcessorDisconnectedMsg(msg ProcessorDisconnectedMsg) (Model, tea.Cmd) {
	// Processor connection lost or failed
	if proc, exists := m.connectionMgr.Processors[msg.Address]; exists {
		proc.State = store.ProcessorStateFailed
		proc.FailureCount++
		proc.LastDisconnectedAt = time.Now() // Track when disconnected for cleanup

		// Clean up old client
		if proc.Client != nil {
			proc.Client.Close()
			proc.Client = nil
		}
		delete(m.connectionMgr.RemoteClients, msg.Address)

		// Update NodesView to reflect disconnection
		procInfos := m.getProcessorInfoList()
		m.uiState.NodesView.SetProcessors(procInfos)

		// If in remote mode, check if all processors are now disconnected
		var allDisconnectedToast tea.Cmd
		if m.captureMode == components.CaptureModeRemote {
			allDisconnected := true
			for _, p := range m.connectionMgr.Processors {
				if p.State == store.ProcessorStateConnected {
					allDisconnected = false
					break
				}
			}
			// If all processors are disconnected, mark capturing as inactive
			if allDisconnected {
				m.uiState.SetCapturing(false)
				// Show warning toast for all processors disconnected
				allDisconnectedToast = m.uiState.Toast.Show(
					"All processors disconnected",
					components.ToastWarning,
					components.ToastDurationNormal,
				)
			}
		}

		// Show error toast
		toastCmd := m.uiState.Toast.Show(
			fmt.Sprintf("Disconnected from %s", msg.Address),
			components.ToastError,
			components.ToastDurationNormal,
		)

		// Schedule reconnection with exponential backoff
		// Cap at 10 minutes to handle long network interruptions (e.g., laptop standby)
		// Exponential backoff: 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 512s, 600s (10 min max)
		backoff := time.Duration(1<<uint(min(proc.FailureCount-1, 9))) * time.Second
		const maxBackoff = 10 * time.Minute
		if backoff > maxBackoff {
			backoff = maxBackoff
		}

		// Don't retry indefinitely - stop after 10 attempts (roughly 17 minutes total)
		// User can manually reconnect from the Nodes view if needed
		const maxAttempts = 10
		var reconnectCmd tea.Cmd
		if proc.FailureCount < maxAttempts {
			reconnectCmd = tea.Tick(backoff, func(t time.Time) tea.Msg {
				return ProcessorReconnectMsg{Address: msg.Address}
			})
		} else {
			// Max retries reached - show warning and stop auto-reconnect
			toastCmd = m.uiState.Toast.Show(
				fmt.Sprintf("Max reconnection attempts reached for %s - use Nodes view to manually reconnect", msg.Address),
				components.ToastWarning,
				components.ToastDurationLong,
			)
		}

		// Batch commands (including allDisconnectedToast if set)
		if allDisconnectedToast != nil && reconnectCmd != nil {
			return m, tea.Batch(toastCmd, allDisconnectedToast, reconnectCmd)
		} else if allDisconnectedToast != nil {
			return m, tea.Batch(toastCmd, allDisconnectedToast)
		} else if reconnectCmd != nil {
			return m, tea.Batch(toastCmd, reconnectCmd)
		}
		return m, toastCmd
	}
	return m, nil
}

// handleCleanupOldProcessorsMsg cleans up disconnected processors
func (m Model) handleCleanupOldProcessorsMsg(msg CleanupOldProcessorsMsg) (Model, tea.Cmd) {
	// Clean up disconnected processors that have been offline for > 30 minutes
	const cleanupTimeout = 30 * time.Minute
	now := time.Now()

	for addr, proc := range m.connectionMgr.Processors {
		// Only clean up processors that are:
		// 1. In failed/disconnected state
		// 2. Have been disconnected for > 30 minutes
		// 3. Have a non-zero LastDisconnectedAt time
		if (proc.State == store.ProcessorStateFailed || proc.State == store.ProcessorStateDisconnected) &&
			!proc.LastDisconnectedAt.IsZero() &&
			now.Sub(proc.LastDisconnectedAt) > cleanupTimeout {

			// Clean up any remaining client
			if proc.Client != nil {
				proc.Client.Close()
			}

			// Remove from maps
			delete(m.connectionMgr.Processors, addr)
			delete(m.connectionMgr.RemoteClients, addr)
			delete(m.connectionMgr.HuntersByProcessor, addr)
		}
	}

	// Schedule next cleanup
	return m, cleanupProcessorsCmd()
}

// handleTopologyReceivedMsg processes topology information from a processor
func (m Model) handleTopologyReceivedMsg(msg TopologyReceivedMsg) (Model, tea.Cmd) {
	logger.Info("Received topology from processor",
		"address", msg.Address,
		"processor_id", msg.Topology.ProcessorId)

	// Recursively process the topology tree to discover all processors and hunters
	m.processTopologyNode(msg.Topology, msg.Address, "")

	// Update NodesView with the discovered topology
	procInfos := m.getProcessorInfoList()
	m.uiState.NodesView.SetProcessors(procInfos)

	return m, nil
}

// handleTopologyUpdateMsg processes streaming topology updates from a processor
func (m Model) handleTopologyUpdateMsg(msg TopologyUpdateMsg) (Model, tea.Cmd) {
	logger.Debug("Received topology update",
		"address", msg.ProcessorAddr,
		"type", msg.Update.UpdateType)

	// Process the update based on its type
	switch msg.Update.UpdateType {
	case management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED:
		if event := msg.Update.GetHunterConnected(); event != nil {
			logger.Info("Hunter connected via topology update",
				"hunter_id", event.Hunter.HunterId,
				"processor", msg.ProcessorAddr)
			// Add hunter to the processor's hunter list
			m.addHunterFromTopologyUpdate(msg.ProcessorAddr, event.Hunter)
		}

	case management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED:
		if event := msg.Update.GetHunterDisconnected(); event != nil {
			logger.Info("Hunter disconnected via topology update",
				"hunter_id", event.HunterId,
				"processor", msg.ProcessorAddr)
			// Remove hunter from the processor's hunter list
			m.removeHunterFromTopologyUpdate(msg.ProcessorAddr, event.HunterId)
		}

	case management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED:
		if event := msg.Update.GetProcessorConnected(); event != nil {
			logger.Info("Processor connected via topology update",
				"processor_id", event.Processor.ProcessorId,
				"address", event.Processor.Address)
			// Add downstream processor to topology
			m.addProcessorFromTopologyUpdate(event.Processor, msg.ProcessorAddr)
		}

	case management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED:
		if event := msg.Update.GetProcessorDisconnected(); event != nil {
			logger.Info("Processor disconnected via topology update",
				"processor_id", event.ProcessorId)
			// Remove downstream processor from topology
			m.removeProcessorFromTopologyUpdate(event.ProcessorId)
		}

	case management.TopologyUpdateType_TOPOLOGY_HUNTER_STATUS_CHANGED:
		if event := msg.Update.GetHunterStatusChanged(); event != nil {
			logger.Info("Hunter status changed via topology update",
				"hunter_id", event.HunterId,
				"status", event.NewStatus,
				"processor", msg.ProcessorAddr)
			// Update hunter status in the processor's hunter list
			m.updateHunterStatusFromTopologyUpdate(msg.ProcessorAddr, event.HunterId, event.NewStatus)
		}
	}

	// Update NodesView with the updated topology
	procInfos := m.getProcessorInfoList()
	m.uiState.NodesView.SetProcessors(procInfos)

	return m, nil
}

// addHunterFromTopologyUpdate adds a hunter discovered via topology update
func (m *Model) addHunterFromTopologyUpdate(processorAddr string, hunter *management.ConnectedHunter) {
	// Convert to components.HunterInfo
	hunterInfo := components.HunterInfo{
		ID:               hunter.HunterId,
		Hostname:         hunter.Hostname,
		RemoteAddr:       hunter.RemoteAddr,
		Status:           hunter.Status,
		ConnectedAt:      time.Now().UnixNano() - int64(hunter.ConnectedDurationSec*1e9),
		LastHeartbeat:    hunter.LastHeartbeatNs,
		PacketsCaptured:  hunter.Stats.PacketsCaptured,
		PacketsForwarded: hunter.Stats.PacketsForwarded,
		ActiveFilters:    hunter.Stats.ActiveFilters,
		Interfaces:       hunter.Interfaces,
		ProcessorAddr:    processorAddr,
		Capabilities:     hunter.Capabilities,
	}

	// Add or update in the hunter list for this processor
	hunters := m.connectionMgr.HuntersByProcessor[processorAddr]
	found := false
	for i, h := range hunters {
		if h.ID == hunter.HunterId {
			hunters[i] = hunterInfo
			found = true
			break
		}
	}
	if !found {
		hunters = append(hunters, hunterInfo)
	}
	m.connectionMgr.HuntersByProcessor[processorAddr] = hunters
}

// removeHunterFromTopologyUpdate removes a hunter based on topology update
func (m *Model) removeHunterFromTopologyUpdate(processorAddr string, hunterID string) {
	hunters := m.connectionMgr.HuntersByProcessor[processorAddr]
	filtered := make([]components.HunterInfo, 0, len(hunters))
	for _, h := range hunters {
		if h.ID != hunterID {
			filtered = append(filtered, h)
		}
	}
	m.connectionMgr.HuntersByProcessor[processorAddr] = filtered
}

// updateHunterStatusFromTopologyUpdate updates a hunter's status based on topology update
func (m *Model) updateHunterStatusFromTopologyUpdate(processorAddr string, hunterID string, newStatus management.HunterStatus) {
	hunters := m.connectionMgr.HuntersByProcessor[processorAddr]
	for i, h := range hunters {
		if h.ID == hunterID {
			hunters[i].Status = newStatus
			logger.Debug("Updated hunter status",
				"hunter_id", hunterID,
				"processor", processorAddr,
				"new_status", newStatus)
			break
		}
	}
}

// addProcessorFromTopologyUpdate adds a processor discovered via topology update
func (m *Model) addProcessorFromTopologyUpdate(processor *management.ProcessorNode, parentAddr string) {
	// Use the address from the processor node
	nodeAddr := processor.Address

	// Determine TLS security from parent processor
	var tlsInsecure bool
	if connectedProc, exists := m.connectionMgr.Processors[parentAddr]; exists {
		tlsInsecure = connectedProc.TLSInsecure
	}

	// Create or update processor entry
	if _, exists := m.connectionMgr.Processors[nodeAddr]; !exists {
		m.connectionMgr.Processors[nodeAddr] = &store.ProcessorConnection{
			Address:           nodeAddr,
			State:             store.ProcessorStateUnknown,
			ProcessorID:       processor.ProcessorId,
			Status:            processor.Status,
			TLSInsecure:       tlsInsecure,
			UpstreamAddr:      parentAddr,
			Reachable:         processor.Reachable,
			UnreachableReason: processor.UnreachableReason,
		}
		logger.Debug("Discovered processor from topology update",
			"address", nodeAddr,
			"processor_id", processor.ProcessorId,
			"parent", parentAddr,
			"reachable", processor.Reachable)
	} else {
		// Update existing entry
		proc := m.connectionMgr.Processors[nodeAddr]
		proc.ProcessorID = processor.ProcessorId
		proc.Status = processor.Status
		proc.UpstreamAddr = parentAddr
		proc.Reachable = processor.Reachable
		proc.UnreachableReason = processor.UnreachableReason
		// Invalidate cache when hierarchy changes
		m.connectionMgr.InvalidateRootProcessorCache("")
	}
}

// removeProcessorFromTopologyUpdate removes a processor based on topology update
func (m *Model) removeProcessorFromTopologyUpdate(processorID string) {
	// Find and remove processor by ID
	for addr, proc := range m.connectionMgr.Processors {
		if proc.ProcessorID == processorID {
			// Clean up any remaining client
			if proc.Client != nil {
				proc.Client.Close()
			}
			// Remove from maps
			delete(m.connectionMgr.Processors, addr)
			delete(m.connectionMgr.RemoteClients, addr)
			delete(m.connectionMgr.HuntersByProcessor, addr)
			logger.Debug("Removed processor from topology",
				"processor_id", processorID,
				"address", addr)
			break
		}
	}
}

// processTopologyNode recursively processes a topology node and its children
// The address parameter is the address of the processor we're directly connected to (for inheriting TLS settings)
func (m Model) processTopologyNode(node *management.ProcessorNode, address string, parentAddr string) {
	if node == nil {
		return
	}

	// Use the address from the node if available, otherwise use provided address
	nodeAddr := node.Address
	if nodeAddr == "" {
		nodeAddr = address
	}

	// Determine TLS security for this processor
	// If we're directly connected to this processor, use its TLS settings
	// Otherwise, inherit from the root processor we're connected to
	var tlsInsecure bool
	if connectedProc, exists := m.connectionMgr.Processors[address]; exists {
		// Use the TLS setting from the processor we're connected to
		tlsInsecure = connectedProc.TLSInsecure
	}

	// Create or update processor entry
	if _, exists := m.connectionMgr.Processors[nodeAddr]; !exists {
		// Discover this processor
		m.connectionMgr.Processors[nodeAddr] = &store.ProcessorConnection{
			Address:      nodeAddr,
			State:        store.ProcessorStateUnknown,
			ProcessorID:  node.ProcessorId,
			Status:       node.Status,
			TLSInsecure:  tlsInsecure, // Inherit TLS setting from connected processor
			UpstreamAddr: parentAddr,  // Use parent from topology tree, not node.UpstreamProcessor
		}
		logger.Debug("Discovered processor from topology",
			"address", nodeAddr,
			"processor_id", node.ProcessorId,
			"parent_in_tree", parentAddr,
			"tls_insecure", tlsInsecure)
	} else {
		// Update existing entry
		proc := m.connectionMgr.Processors[nodeAddr]
		proc.ProcessorID = node.ProcessorId
		proc.Status = node.Status
		// Update UpstreamAddr based on topology tree structure
		proc.UpstreamAddr = parentAddr
		// Invalidate cache when hierarchy changes
		m.connectionMgr.InvalidateRootProcessorCache("")
		// Update TLS setting if this is a discovered processor
		if proc.State == store.ProcessorStateUnknown {
			proc.TLSInsecure = tlsInsecure
		}
	}

	// Convert and store hunters for this processor
	hunters := make([]components.HunterInfo, 0, len(node.Hunters))
	for _, h := range node.Hunters {
		hunters = append(hunters, components.HunterInfo{
			ID:               h.HunterId,
			Hostname:         h.Hostname,
			RemoteAddr:       h.RemoteAddr,
			Status:           h.Status,
			ConnectedAt:      time.Now().UnixNano() - int64(h.ConnectedDurationSec*1e9),
			LastHeartbeat:    h.LastHeartbeatNs,
			PacketsCaptured:  h.Stats.PacketsCaptured,
			PacketsMatched:   0, // Not provided in topology
			PacketsForwarded: h.Stats.PacketsForwarded,
			PacketsDropped:   0, // Not provided in topology
			ActiveFilters:    h.Stats.ActiveFilters,
			Interfaces:       h.Interfaces,
			ProcessorAddr:    nodeAddr,
			Capabilities:     h.Capabilities,
		})
	}
	m.connectionMgr.HuntersByProcessor[nodeAddr] = hunters

	logger.Debug("Discovered hunters from topology",
		"processor", nodeAddr,
		"hunter_count", len(hunters))

	// Recursively process downstream processors
	// Pass the same 'address' (our connected processor) to inherit TLS settings
	for _, downstream := range node.DownstreamProcessors {
		m.processTopologyNode(downstream, address, nodeAddr)
	}
}

// parseDNSFromRawData parses DNS metadata from raw packet bytes.
// This is used when packets arrive via remote capture without pre-parsed DNS data.
func parseDNSFromRawData(rawData []byte, linkType layers.LinkType) *types.DNSMetadata {
	if len(rawData) == 0 {
		return nil
	}

	// Create a gopacket from the raw data
	packet := gopacket.NewPacket(rawData, linkType, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})

	// Extract DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil
	}

	metadata := &types.DNSMetadata{
		TransactionID:      dns.ID,
		IsResponse:         dns.QR,
		ResponseCode:       rcodeToString(dns.ResponseCode),
		Authoritative:      dns.AA,
		Truncated:          dns.TC,
		RecursionDesired:   dns.RD,
		RecursionAvailable: dns.RA,
		QuestionCount:      dns.QDCount,
		AnswerCount:        dns.ANCount,
		AuthorityCount:     dns.NSCount,
		AdditionalCount:    dns.ARCount,
	}

	// Extract query information
	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		metadata.QueryName = string(q.Name)
		metadata.QueryType = q.Type.String()
		metadata.QueryClass = q.Class.String()
	}

	// Extract answers
	for _, answer := range dns.Answers {
		a := types.DNSAnswer{
			Name:  string(answer.Name),
			Type:  answer.Type.String(),
			Class: answer.Class.String(),
			TTL:   answer.TTL,
		}

		// Extract answer data based on type
		switch answer.Type {
		case layers.DNSTypeA:
			if len(answer.IP) == 4 {
				a.Data = answer.IP.String()
			}
		case layers.DNSTypeAAAA:
			if len(answer.IP) == 16 {
				a.Data = answer.IP.String()
			}
		case layers.DNSTypeCNAME, layers.DNSTypeNS, layers.DNSTypePTR:
			a.Data = string(answer.CNAME)
		case layers.DNSTypeMX:
			a.Data = string(answer.MX.Name)
		case layers.DNSTypeTXT:
			for _, txt := range answer.TXTs {
				a.Data += string(txt) + " "
			}
		default:
			a.Data = fmt.Sprintf("<%s data>", answer.Type.String())
		}

		metadata.Answers = append(metadata.Answers, a)
	}

	return metadata
}

// rcodeToString converts DNS response code to string
func rcodeToString(rcode layers.DNSResponseCode) string {
	switch rcode {
	case layers.DNSResponseCodeNoErr:
		return "NOERROR"
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeNotImp:
		return "NOTIMP"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

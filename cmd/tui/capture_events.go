//go:build tui || all
// +build tui all

package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/store"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/remotecapture"
	"github.com/endorses/lippycat/internal/pkg/types"
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

			// Write to streaming save if active
			if m.activeWriter != nil {
				// WritePacket will apply filter internally if configured (best-effort)
				_ = m.activeWriter.WritePacket(packet)
			}

			// Update statistics (lightweight)
			m.updateStatistics(packet)
		}

		// Update packet list immediately for smooth streaming
		if !m.packetStore.HasFilter() {
			m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		} else {
			m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
		}

		// Update details panel if showing details (throttled to reduce CPU usage)
		// Only update at configured interval (default 20 Hz) to avoid rendering
		// expensive hex dumps on every packet during high packet rate
		if m.uiState.ShowDetails {
			now := time.Now()
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

		// Update packet list immediately for smooth streaming
		if !m.packetStore.HasFilter() {
			m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		} else {
			m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
		}

		// Update details panel if showing details (throttled to reduce CPU usage)
		// Only update at configured interval (default 20 Hz) to avoid rendering
		// expensive hex dumps on every packet during high packet rate
		if m.uiState.ShowDetails {
			now := time.Now()
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
		// Create TUI event handler adapter
		handler := NewTUIEventHandler(currentProgram)

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
			currentProgram.Send(ProcessorDisconnectedMsg{
				Address: msg.Address,
				Error:   err,
			})
			return
		}

		// Start packet stream with hunter filter (if specified)
		if err := client.StreamPacketsWithFilter(msg.HunterIDs); err != nil {
			client.Close()
			currentProgram.Send(ProcessorDisconnectedMsg{
				Address: msg.Address,
				Error:   err,
			})
			return
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
		currentProgram.Send(ProcessorConnectedMsg{
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

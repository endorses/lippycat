//go:build tui || all
// +build tui all

package tui

import (
	"context"
	"fmt"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/cmd/tui/store"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// handleRestartCaptureMsg handles restarting capture with new settings
func (m Model) handleRestartCaptureMsg(msg components.RestartCaptureMsg) (Model, tea.Cmd) {
	// Stop any active streaming save before switching modes
	if m.activeWriter != nil {
		// Close writer synchronously (must complete before mode switch)
		if err := m.activeWriter.Close(); err != nil {
			// Log error but continue with mode switch
			logger.Warn("Failed to close streaming writer during mode switch",
				"error", err,
				"path", m.savePath)
		}
		// Clear streaming save state
		m.activeWriter = nil
		m.savePath = ""
		m.uiState.StreamingSave = false
		m.uiState.Footer.SetStreamingSave(false) // Update footer hint
	}

	// Stop current capture and wait for it to finish
	if currentCaptureHandle != nil {
		// Cancel the old capture and wait for completion
		// This ensures old and new captures don't run simultaneously
		handle := currentCaptureHandle
		currentCaptureHandle = nil // Clear immediately to prevent double-cancellation

		handle.cancel()
		// Wait for capture goroutine to finish (deterministic, no race conditions)
		<-handle.done
	}

	// Keep all remote clients connected regardless of mode
	// Users can switch between modes without losing node connections

	// Update settings based on mode and show toast
	var toastCmd tea.Cmd
	switch msg.Mode {
	case components.CaptureModeLive:
		m.interfaceName = msg.Interface
		m.uiState.Tabs.UpdateTab(0, "Live Capture", "📡")
		toastCmd = m.uiState.Toast.Show(
			fmt.Sprintf("Switched to live capture on %s", msg.Interface),
			components.ToastInfo,
			components.ToastDurationShort,
		)
	case components.CaptureModeOffline:
		m.interfaceName = msg.PCAPFile
		m.uiState.Tabs.UpdateTab(0, "Offline Capture", "📄")
		toastCmd = m.uiState.Toast.Show(
			fmt.Sprintf("Opening %s...", filepath.Base(msg.PCAPFile)),
			components.ToastInfo,
			components.ToastDurationShort,
		)
	case components.CaptureModeRemote:
		m.interfaceName = msg.NodesFile
		m.uiState.Tabs.UpdateTab(0, "Remote Capture", "🌐")
		toastCmd = m.uiState.Toast.Show(
			"Switched to remote capture mode",
			components.ToastInfo,
			components.ToastDurationShort,
		)
	}
	m.bpfFilter = msg.Filter

	// Update mode BEFORE starting new capture so packet handlers check the right mode
	m.captureMode = msg.Mode
	m.packetStore.MaxPackets = msg.BufferSize // Apply the new buffer size
	m.uiState.Paused = false                  // Unpause when restarting capture

	// Clear old packets with new buffer size
	m.packetStore.Packets = make([]components.PacketDisplay, m.packetStore.MaxPackets)
	m.packetStore.PacketsHead = 0
	m.packetStore.PacketsCount = 0
	m.packetStore.FilteredPackets = make([]components.PacketDisplay, 0)
	m.packetStore.TotalPackets = 0
	m.packetStore.MatchedPackets = 0
	m.uiState.PacketList.Reset() // Reset packet list including autoscroll state

	// Reset statistics (bounded counters)
	m.statistics.ProtocolCounts.Clear()
	m.statistics.SourceCounts.Clear()
	m.statistics.DestCounts.Clear()
	m.statistics.TotalBytes = 0
	m.statistics.TotalPackets = 0
	m.statistics.MinPacketSize = 999999
	m.statistics.MaxPacketSize = 0
	m.uiState.StatisticsView.SetStatistics(m.statistics)

	// Start new capture in background using global program reference
	if currentProgram != nil {
		// Only create new capture context for live/offline modes
		// Remote mode doesn't need a capture context since it uses gRPC clients
		if msg.Mode == components.CaptureModeLive || msg.Mode == components.CaptureModeOffline {
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			currentCaptureHandle = &captureHandle{cancel: cancel, done: done}

			switch msg.Mode {
			case components.CaptureModeLive:
				go startLiveCapture(ctx, msg.Interface, m.bpfFilter, currentProgram, done)
			case components.CaptureModeOffline:
				go startOfflineCapture(ctx, msg.PCAPFile, m.bpfFilter, currentProgram, done)
			}

			// Mark capture as active for live/offline modes
			m.uiState.SetCapturing(true)
		} else if msg.Mode == components.CaptureModeRemote {
			// Remote mode: set capture handle to nil since we're not running local capture
			currentCaptureHandle = nil

			// Load and connect to nodes from YAML file (if provided)
			if msg.NodesFile != "" {
				m.nodesFilePath = msg.NodesFile
				return m, tea.Batch(toastCmd, loadNodesFile(msg.NodesFile))
			}
			// If no nodes file, check if we have connected processors already
			// (user may have added nodes via Nodes tab before switching to remote mode)
			hasConnectedProcessor := false
			for _, proc := range m.connectionMgr.Processors {
				if proc.State == store.ProcessorStateConnected {
					hasConnectedProcessor = true
					break
				}
			}
			// Mark capturing as active if we have at least one connected processor
			if hasConnectedProcessor {
				m.uiState.SetCapturing(true)
			}
			// If no nodes connected yet, capturing will be marked active when nodes connect successfully
		}
	}

	return m, toastCmd
}

// startLiveCapture starts live packet capture on a network interface
func startLiveCapture(ctx context.Context, interfaceName string, filter string, program *tea.Program, done chan struct{}) {
	defer close(done) // Signal completion when capture goroutine exits
	capture.StartLiveSniffer(interfaceName, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startTUISniffer(ctx, devices, filter, program)
	})
}

// startOfflineCapture starts packet capture from a PCAP file
func startOfflineCapture(ctx context.Context, pcapFile string, filter string, program *tea.Program, done chan struct{}) {
	defer close(done) // Signal completion when capture goroutine exits
	capture.StartOfflineSniffer(pcapFile, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startTUISniffer(ctx, devices, filter, program)
	})
}

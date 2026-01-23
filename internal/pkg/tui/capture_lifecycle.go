//go:build tui || all

package tui

import (
	"context"
	"fmt"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/google/gopacket/tcpassembly"
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
	// Uses synchronized CaptureState to safely cancel and wait
	globalCaptureState.StopCapture()

	// Stop call aggregators if switching modes
	if m.offlineCallAggregator != nil {
		m.offlineCallAggregator.Stop()
		m.offlineCallAggregator = nil
	}
	if m.liveCallAggregator != nil {
		m.liveCallAggregator.Stop()
		m.liveCallAggregator = nil
	}

	// Clear call aggregator from background processor
	if m.backgroundProcessor != nil {
		m.backgroundProcessor.SetCallAggregator(nil, components.CaptureModeLive)
	}

	// Clear call tracker (used by both live and offline modes)
	ClearCallTracker()

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
		m.interfaceName = formatPCAPFilesDisplay(msg.PCAPFiles)
		m.pcapFiles = msg.PCAPFiles
		m.uiState.Tabs.UpdateTab(0, "Offline Capture", "📄")
		toastMsg := "Opening PCAP file..."
		if len(msg.PCAPFiles) == 1 {
			toastMsg = fmt.Sprintf("Opening %s...", filepath.Base(msg.PCAPFiles[0]))
		} else if len(msg.PCAPFiles) > 1 {
			toastMsg = fmt.Sprintf("Opening %d PCAP files...", len(msg.PCAPFiles))
		}
		toastCmd = m.uiState.Toast.Show(
			toastMsg,
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

	// Reset incremental sync tracking
	m.lastSyncedTotal = 0
	m.lastSyncedFilteredCount = 0
	m.lastFilterState = false

	// Reset statistics (bounded counters)
	m.statistics.ProtocolCounts.Clear()
	m.statistics.SourceCounts.Clear()
	m.statistics.DestCounts.Clear()
	m.statistics.TotalBytes = 0
	m.statistics.TotalPackets = 0
	m.statistics.MinPacketSize = 999999
	m.statistics.MaxPacketSize = 0
	m.uiState.StatisticsView.SetStatistics(m.statistics)

	// Start new capture in background using synchronized program reference
	program := globalCaptureState.GetProgram()
	if program != nil {
		// Only create new capture context for live/offline modes
		// Remote mode doesn't need a capture context since it uses gRPC clients
		if msg.Mode == components.CaptureModeLive || msg.Mode == components.CaptureModeOffline {
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			globalCaptureState.SetHandle(cancel, done)

			switch msg.Mode {
			case components.CaptureModeLive:
				// Initialize live call aggregator for VoIP analysis
				m.liveCallAggregator = NewLocalCallAggregator(program)
				m.liveCallAggregator.Start()

				// Update background processor with the new call aggregator
				if m.backgroundProcessor != nil {
					m.backgroundProcessor.SetCallAggregator(m.liveCallAggregator, components.CaptureModeLive)
				}

				// Initialize call tracker for RTP-to-CallID mapping (shared with offline mode)
				liveTracker := NewCallTracker()
				SetCallTracker(liveTracker)

				go startLiveCapture(ctx, msg.Interface, m.bpfFilter, program, done)
			case components.CaptureModeOffline:
				// Initialize offline call aggregator for VoIP analysis
				m.offlineCallAggregator = NewLocalCallAggregator(program)
				m.offlineCallAggregator.Start()

				// Update background processor with the new call aggregator
				if m.backgroundProcessor != nil {
					m.backgroundProcessor.SetCallAggregator(m.offlineCallAggregator, components.CaptureModeOffline)
				}

				// Initialize offline call tracker for RTP-to-CallID mapping
				offlineTracker := NewCallTracker()
				SetCallTracker(offlineTracker)

				go startOfflineCapture(ctx, msg.PCAPFiles, m.bpfFilter, program, done)
			}

			// Mark capture as active for live/offline modes
			m.uiState.SetCapturing(true)
		} else if msg.Mode == components.CaptureModeRemote {
			// Remote mode: clear capture handle since we're not running local capture
			globalCaptureState.ClearHandle()

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

// startOfflineCapture starts packet capture from PCAP files
// Uses timestamp-ordered processing to ensure SIP packets register media ports
// before their corresponding RTP packets are processed (critical for VoIP analysis)
func startOfflineCapture(ctx context.Context, pcapFiles []string, filter string, program *tea.Program, done chan struct{}) {
	defer close(done) // Signal completion when capture goroutine exits
	capture.StartOfflineSnifferOrdered(pcapFiles, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startTUISnifferOrdered(ctx, devices, filter, program)
	})
}

// startTUISniffer initializes packet capture and bridges packets to the TUI
func startTUISniffer(ctx context.Context, devices []pcaptypes.PcapInterface, filter string, program *tea.Program) {
	// Create a simple processor that forwards packets to TUI
	processor := func(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
		StartPacketBridge(ch, program)
	}

	// Run capture - InitWithContext handles both live and offline modes
	// For offline: blocks until file is read (StartOfflineSniffer keeps file open)
	// For live: caller uses goroutine for non-blocking behavior
	capture.InitWithContext(ctx, devices, filter, processor, nil)
}

// startTUISnifferOrdered initializes timestamp-ordered packet capture for offline VoIP analysis.
// This ensures SIP packets are processed before their corresponding RTP packets,
// which is essential for proper call tracking and RTP-to-CallID mapping.
func startTUISnifferOrdered(ctx context.Context, devices []pcaptypes.PcapInterface, filter string, program *tea.Program) {
	// Create a simple processor that forwards packets to TUI
	processor := func(ch <-chan capture.PacketInfo, assembler *tcpassembly.Assembler) {
		StartPacketBridge(ch, program)
	}

	// Run capture with timestamp ordering - reads all packets, sorts by timestamp, then processes
	capture.RunOfflineOrdered(devices, filter, processor, nil)
}

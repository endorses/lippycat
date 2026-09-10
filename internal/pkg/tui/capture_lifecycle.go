//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/voip"
)

// handleRestartCaptureMsg handles restarting capture with new settings
func (m Model) handleRestartCaptureMsg(msg components.RestartCaptureMsg) (Model, tea.Cmd) {
	if msg.Mode == components.CaptureModeOffline {
		return m.openOffline(FreezeOfflineOpen(msg.PCAPFiles, msg.Filter, msg.BufferSize))
	}
	if m.offlineOpening || m.offlineSession != nil {
		return m.leaveOffline(&msg, false)
	}
	configureLiveTLSDetails(&m.uiState.DetailsPanel)
	m.uiState.DetailsPanel.SetPacket(nil)

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
		m.uiState.Header.SetStreamingSave(false) // Update header status
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
		m.backgroundProcessor.BeginGeneration()
	}

	// Clear call tracker (used by both live and offline modes)
	if m.callTracker != nil {
		m.callTracker.Clear()
	}

	// Keep all remote clients connected regardless of mode
	// Users can switch between modes without losing node connections
	// Every capture restart begins a new normalized-event analysis session.
	// Clear retained events before the new runtime starts so identities and
	// partial flows from different inputs cannot be presented as one timeline.
	m.eventStore.Reset()
	m.eventStore.ClearUserFilters()
	m.eventStore.SetPaused(false)

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
	if m.uiState != nil {
		m.uiState.StatisticsView.SetL3L4ProtocolClassification(msg.Mode == components.CaptureModeLive)
	}
	m.uiState.Paused = false                     // Unpause when restarting capture
	globalCaptureState.GetPauseSignal().Resume() // Reset pause state for new capture

	// Clear old packets with new buffer size
	m.packetStore.ClearAndResize(msg.BufferSize)
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
	m.uiState.StatisticsView.ClearOfflineStatistics()
	m.uiState.StatisticsView.GetDropStats().Reset()

	// Reset bridge state (clears stale data from previous capture mode)
	ResetBridgeStats()
	voip.ResetTCPStreamMetrics()
	ClearPendingPackets()
	pendingLocalEvents.clear()
	m.pendingRemoteEvents.clear()
	m.syncEventsView()

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
				m.callTracker = NewCallTracker()
				m.liveCallAggregator = NewLocalCallAggregator(program, m.callTracker)
				m.liveCallAggregator.Start()

				// Update background processor with the new call aggregator
				if m.backgroundProcessor != nil {
					m.backgroundProcessor.BeginGeneration()
				}

				// Initialize call tracker for RTP-to-CallID mapping (shared with offline mode)
				go startLiveCapture(ctx, msg.Interface, m.bpfFilter, program, done, m.callTracker, m.liveCallAggregator)
			case components.CaptureModeOffline:
				// Initialize offline call aggregator for VoIP analysis
				m.callTracker = NewCallTracker()
				m.offlineCallAggregator = NewLocalCallAggregator(program, m.callTracker)
				m.offlineCallAggregator.Start()

				// Update background processor with the new call aggregator
				if m.backgroundProcessor != nil {
					m.backgroundProcessor.BeginGeneration()
				}

				// Initialize offline call tracker for RTP-to-CallID mapping
				go startOfflineCapture(ctx, msg.PCAPFiles, m.bpfFilter, program, done, m.callTracker, m.offlineCallAggregator)
			}

			// Mark capture as active for live/offline modes
			m.uiState.SetCapturing(true)
		} else if msg.Mode == components.CaptureModeRemote {
			// Remote mode: clear capture handle since we're not running local capture
			globalCaptureState.ClearHandle()

			// Check whether processors are already connected
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
			// Load and connect to nodes from YAML file (if provided).
			if msg.NodesFile != "" {
				m.nodesFilePath = msg.NodesFile
				return m, tea.Batch(toastCmd, loadNodesFile(msg.NodesFile))
			}
			// If no nodes connected yet, capturing will be marked active when nodes connect successfully
		}
	}

	return m, toastCmd
}

// startLiveCapture starts live packet capture on a network interface
func startLiveCapture(ctx context.Context, interfaceName string, filter string, program *tea.Program, done chan struct{}, tracker *CallTracker, aggregator *LocalCallAggregator) {
	defer close(done) // Signal completion when capture goroutine exits
	capture.StartLiveSniffer(interfaceName, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		startTUISniffer(ctx, devices, filter, program, tracker, aggregator)
	})
}

// startOfflineCapture starts packet capture from PCAP files
// Uses timestamp-ordered processing so earlier SIP signaling can register media
// ports before later RTP is analyzed, without prioritizing later SIP packets.
func startOfflineCapture(ctx context.Context, pcapFiles []string, filter string, program *tea.Program, done chan struct{}, tracker *CallTracker, aggregator *LocalCallAggregator) {
	defer close(done) // Signal completion when capture goroutine exits
	inputIdentity, err := events.OfflineInputIdentity(pcapFiles)
	if err != nil {
		logger.Error("Failed to identify offline event inputs", "error", err)
	}
	var replayErr error
	openErr := capture.StartOfflineSnifferOrdered(pcapFiles, filter, func(devices []pcaptypes.PcapInterface, filter string) {
		replayErr = startTUISnifferOrdered(ctx, devices, filter, inputIdentity, program, tracker, aggregator)
	})
	if ctx.Err() != nil {
		return
	}

	// Notify TUI that capture is complete so it can drain remaining packets
	// This is critical for offline capture where files are read quickly
	stats := GetBridgeStats()
	if program != nil {
		program.Send(CaptureCompleteMsg{
			PacketsReceived: stats.PacketsReceived,
			Err:             errors.Join(openErr, replayErr),
		})
	}
}

// startTUISniffer initializes packet capture and bridges packets to the TUI
func startTUISniffer(ctx context.Context, devices []pcaptypes.PcapInterface, filter string, program *tea.Program, tracker *CallTracker, aggregator *LocalCallAggregator) {
	// Get pause signal for bridge to respect pause/resume
	pauseSignal := globalCaptureState.GetPauseSignal()

	// Create a simple processor that forwards packets to TUI
	processor := func(ch <-chan capture.PacketInfo) {
		StartEnvelopeBridge(NormalizeCaptureStream(ctx, ch, pipeline.SourceLiveCapture), program, pauseSignal, tracker, false, aggregator,
			localCaptureEventOptions(filter))
	}

	// Run capture - InitWithContext handles both live and offline modes
	// For offline: blocks until the caller-managed PCAP replay completes.
	// For live: caller uses goroutine for non-blocking behavior
	// Pass pause function to drop packets at source when paused (reduces CPU)
	capture.InitWithContextAndTelemetry(ctx, devices, filter, func(ch <-chan capture.PacketInfo, _ *capture.TCPAssembler) {
		processor(ch)
	}, nil, pauseSignal.IsPaused, func(stats capture.Telemetry) {
		if program != nil {
			program.Send(CaptureTelemetryMsg(stats))
		}
	}, capture.CaptureOptions{ReassembleIPFragmentsWhen: IsVoIPModeEnabled})
}

// startTUISnifferOrdered initializes timestamp-ordered packet capture for offline VoIP analysis.
// Earlier SIP signaling registers media ports before later RTP is analyzed.
// SIP packets are never prioritized ahead of earlier traffic.
func startTUISnifferOrdered(ctx context.Context, devices []pcaptypes.PcapInterface, filter, inputIdentity string, program *tea.Program, tracker *CallTracker, aggregator *LocalCallAggregator) error {
	// Get pause signal for bridge to respect pause/resume
	pauseSignal := globalCaptureState.GetPauseSignal()

	// Create a simple processor that forwards packets to TUI
	processor := func(ch <-chan capture.PacketInfo) {
		options := localCaptureEventOptions(filter)
		options.InputIdentity = inputIdentity
		options.AnalysisProfile = localFileAnalysisProfile(filter)
		options.SourceOrdering = pcapInterfaceNames(devices)
		StartEnvelopeBridge(NormalizeCaptureStream(ctx, ch, pipeline.SourcePCAPReplay), program, pauseSignal, tracker, true, aggregator, options)
	}

	// Merge sequential sources in timestamp order with bounded reader state.
	return capture.RunOfflineOrderedContext(ctx, devices, filter, processor)
}

func localCaptureEventOptions(filter string) LocalEventAnalysisOptions {
	options := LocalEventAnalysisOptions{NodeID: "watch-local"}
	if strings.TrimSpace(filter) != "" {
		options.CaptureScope = events.CaptureScopeFiltered
		options.Partial = true
	}
	return options
}

func localFileAnalysisProfile(filter string) string {
	return fmt.Sprintf("watch-eventanalysis-v1|filter=%s", filter)
}

func pcapInterfaceNames(devices []pcaptypes.PcapInterface) []string {
	names := make([]string, 0, len(devices))
	for _, device := range devices {
		names = append(names, device.Name())
	}
	return names
}

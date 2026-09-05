//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
)

// OpenOfflineDatasetMsg is the only entry point for offline input replacement.
// Config is frozen before dispatch; indexing never reads mutable settings.
type OpenOfflineDatasetMsg struct {
	Config OfflineAnalysisConfig
	Limits offline.ResourceLimits
}
type offlineOpenCompleteMsg struct {
	generation offline.DatasetGeneration
	session    *offlineIndexedSession
	err        error
}
type offlineProgressMsg struct{ generation offline.DatasetGeneration }
type offlineCleanupMsg struct {
	generation offline.DatasetGeneration
	restart    *components.RestartCaptureMsg
	quit       bool
	cancelled  bool
	err        error
	reportErr  error
}

// Shared by Bubble Tea's model copies and the program owner, including when
// Run returns without a final Update. Workers remain owned until joined.
type offlineController struct {
	mu         sync.Mutex
	cleanupMu  sync.Mutex
	generation offline.DatasetGeneration
	cancel     context.CancelFunc
	done       chan struct{}
	storage    *offline.Storage
	limits     offline.ResourceLimits
	sessions   map[*offlineIndexedSession]struct{}
	installed  *offlineIndexedSession
	progress   offline.Progress
	closed     bool
	index      func(context.Context, *offline.Storage, offline.DatasetGeneration, OfflineAnalysisConfig, func(offline.Progress)) (*offlineIndexedSession, error)
}

func newOfflineController() *offlineController {
	return &offlineController{sessions: make(map[*offlineIndexedSession]struct{})}
}
func (c *offlineController) dispose(s *offlineIndexedSession) error {
	if s == nil {
		return nil
	}
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()
	c.mu.Lock()
	_, owned := c.sessions[s]
	c.mu.Unlock()
	if !owned {
		return nil
	}
	if err := s.Close(); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.sessions, s)
	c.mu.Unlock()
	return nil
}
func (c *offlineController) close() error {
	c.mu.Lock()
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	done := c.done
	c.mu.Unlock()
	if done != nil {
		<-done
	}
	c.cleanupMu.Lock()
	defer c.cleanupMu.Unlock()
	c.mu.Lock()
	sessions := make([]*offlineIndexedSession, 0, len(c.sessions))
	for s := range c.sessions {
		sessions = append(sessions, s)
	}
	storage := c.storage
	c.mu.Unlock()
	var err error
	for _, s := range sessions {
		if e := s.Close(); e != nil {
			err = errors.Join(err, e)
		} else {
			c.mu.Lock()
			delete(c.sessions, s)
			c.mu.Unlock()
		}
	}
	if storage != nil {
		err = errors.Join(err, storage.Close())
	}
	return err
}

// CloseOffline joins indexing and releases all dataset resources. Call outside Update.
func (m Model) CloseOffline() error {
	if m.offlineController == nil {
		return nil
	}
	return m.offlineController.close()
}
func offlineProgressCmd(g offline.DatasetGeneration) tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return offlineProgressMsg{g} })
}
func (m Model) openOffline(msg OpenOfflineDatasetMsg) (Model, tea.Cmd) {
	if !m.offlineLeaving && (m.offlineCleanupFailed || m.offlineCancelledSession != nil) {
		copy := msg
		copy.Config.Inputs = append([]string(nil), msg.Config.Inputs...)
		copy.Config.Analysis.SourceOrdering = append([]string(nil), msg.Config.Analysis.SourceOrdering...)
		m.offlineQueued = &copy
		if m.offlineCleanupFailed {
			return m.retryOfflineCancellation()
		}
		return m, nil
	}
	if m.offlineLeaving {
		copy := msg
		copy.Config.Inputs = append([]string(nil), msg.Config.Inputs...)
		copy.Config.Analysis.SourceOrdering = append([]string(nil), msg.Config.Analysis.SourceOrdering...)
		m.offlineQueued = &copy
		if m.offlineCleanupFailed {
			return m.leaveOffline(nil, false)
		}
		return m, nil
	}
	if m.offlineController == nil {
		m.offlineController = newOfflineController()
	}
	c := m.offlineController
	msg.Config.Inputs = append([]string(nil), msg.Config.Inputs...)
	msg.Config.Analysis.SourceOrdering = append([]string(nil), msg.Config.Analysis.SourceOrdering...)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return m, nil
	}
	if c.cancel != nil {
		c.cancel()
	}
	prior := c.done
	c.generation++
	g := c.generation
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	done := make(chan struct{})
	c.done = done
	c.progress = offline.Progress{Token: offline.Token{Dataset: g}, State: offline.Opening, Sources: uint32(len(msg.Config.Inputs))}
	c.mu.Unlock()
	m.offlineOpening = true
	m.offlineStarted = time.Now()
	m.uiState.SetCapturing(false)
	m.offlineGeneration = g
	m.offlineProgress = offline.Progress{State: offline.Opening, Sources: uint32(len(msg.Config.Inputs))}
	m.offlinePending = msg
	if m.offlineSession != nil {
		m.installOfflineSettings(m.offlineInstalled)
	}
	writer := m.activeWriter
	liveAggregator, oldAggregator := m.liveCallAggregator, m.offlineCallAggregator
	m.activeWriter = nil
	m.liveCallAggregator = nil
	m.offlineCallAggregator = nil
	m.savePath = ""
	m.uiState.StreamingSave = false
	m.uiState.Footer.SetStreamingSave(false)
	m.uiState.Header.SetStreamingSave(false)
	worker := func() tea.Msg {
		defer close(done)
		if prior != nil {
			<-prior
		}
		// Reclaim completed obsolete generations even when their Bubble Tea
		// completion commands have not yet been consumed.
		c.mu.Lock()
		var obsolete []*offlineIndexedSession
		for session := range c.sessions {
			if session != c.installed {
				obsolete = append(obsolete, session)
			}
		}
		c.mu.Unlock()
		for _, session := range obsolete {
			if err := c.dispose(session); err != nil {
				return offlineOpenCompleteMsg{generation: g, session: session, err: err}
			}
		}
		// A previous live reader must stop before another analyzer is created.
		globalCaptureState.StopCapture()
		if liveAggregator != nil {
			liveAggregator.Stop()
		}
		if oldAggregator != nil {
			oldAggregator.Stop()
		}
		if writer != nil {
			if err := writer.Close(); err != nil {
				return offlineOpenCompleteMsg{generation: g, err: fmt.Errorf("close streaming capture: %w", err)}
			}
		}
		if err := ctx.Err(); err != nil {
			return offlineOpenCompleteMsg{generation: g, err: err}
		}
		c.mu.Lock()
		storage, limits := c.storage, c.limits
		c.mu.Unlock()
		if storage == nil {
			var err error
			storage, err = offline.NewStorage(msg.Limits)
			if err != nil {
				return offlineOpenCompleteMsg{generation: g, err: err}
			}
			limits = msg.Limits
			c.mu.Lock()
			c.storage = storage
			c.limits = limits
			c.mu.Unlock()
		}
		if limits != msg.Limits {
			return offlineOpenCompleteMsg{generation: g, err: errors.New("offline resource limits cannot change while a session is installed")}
		}
		index := c.index
		if index == nil {
			index = indexOfflineDataset
		}
		s, err := index(ctx, storage, g, msg.Config, func(p offline.Progress) {
			c.mu.Lock()
			if c.generation == g {
				c.progress = p
			}
			c.mu.Unlock()
		})
		if s != nil && err == nil {
			base := s.Dataset.Resources().PinnedBytes
			for id := uint64(0); id < min(s.Dataset.Count(), uint64(min(32, max(1, msg.Config.EventCapacity)))); id++ {
				pin, e := s.Dataset.PinDetail(ctx, offline.Token{Dataset: g}, offline.PacketID(id))
				if e != nil {
					err = e
					break
				}
				if s.Dataset.Resources().PinnedBytes-base > msg.Limits.CacheBytes/4 {
					err = pin.Close()
					break
				}
				s.previewPins = append(s.previewPins, pin)
				s.Preview = append(s.Preview, pin.Value.Packet)
			}
		}
		if s != nil {
			c.mu.Lock()
			c.sessions[s] = struct{}{}
			c.mu.Unlock()
		}
		return offlineOpenCompleteMsg{g, s, err}
	}
	result := make(chan tea.Msg, 1)
	go func() { result <- worker() }()
	return m, tea.Batch(func() tea.Msg { return <-result }, offlineProgressCmd(g))
}
func (m Model) cancelOffline() (Model, tea.Cmd) {
	c := m.offlineController
	if c == nil {
		return m, nil
	}
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	m.offlineProgress.State = offline.Cancelling
	return m, nil
}
func (m Model) completeOffline(msg offlineOpenCompleteMsg) (Model, tea.Cmd) {
	c := m.offlineController
	if msg.session != nil && msg.session == m.offlineSession {
		return m, nil
	}
	if msg.generation != m.offlineGeneration || !m.offlineOpening || m.offlineProgress.State == offline.Cancelling {
		cancelled := msg.generation == m.offlineGeneration && m.offlineOpening
		if cancelled {
			m.offlineCancelledSession = msg.session
		}
		return m, func() tea.Msg {
			return offlineCleanupMsg{generation: msg.generation, cancelled: cancelled, err: c.dispose(msg.session), reportErr: offlineCancellationError(msg.err)}
		}
	}
	m.offlineOpening = false

	if msg.err != nil {
		toast := m.uiState.Toast.Show("Could not open offline dataset: "+msg.err.Error(), components.ToastError, components.ToastDurationLong)
		if msg.session != nil {
			// Failed finalization can leave a cleanup-only candidate. Keep
			// the same retryable cleanup workflow used by cancellation until
			// its resources are released, without touching the ready session.
			m.offlineOpening = true
			m.offlineProgress.State = offline.Cancelling
			m.offlineCancelledSession = msg.session
			return m, tea.Batch(toast, func() tea.Msg {
				return offlineCleanupMsg{generation: msg.generation, cancelled: true, err: c.dispose(msg.session)}
			})
		}
		return m, tea.Batch(toast, func() tea.Msg { return offlineCleanupMsg{err: c.dispose(msg.session)} })
	}
	old := m.offlineSession
	m.offlineSession = msg.session
	c.mu.Lock()
	c.installed = msg.session
	c.mu.Unlock()
	m.offlineInstalled = m.offlinePending
	m.installOfflineSettings(m.offlineInstalled)
	m.uiState.SettingsView.SaveBufferSize()
	m.captureMode = components.CaptureModeOffline
	m.pcapFiles = append([]string(nil), m.offlinePending.Config.Inputs...)
	m.bpfFilter = m.offlinePending.Config.BPFFilter
	m.interfaceName = formatPCAPFilesDisplay(m.pcapFiles)
	m.uiState.Tabs.UpdateTab(0, "Offline Capture", "📄")
	m.uiState.SetCapturing(false)
	m.uiState.Paused = false
	m.packetStore.ClearAndResize(m.offlinePending.Config.EventCapacity)
	m.uiState.PacketList.Reset()
	m.packetStore.AddPacketBatch(msg.session.Preview)
	m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
	m.lastSyncedTotal = 0
	m.lastSyncedFilteredCount = 0
	m.lastFilterState = false
	m.eventStore = msg.session.EventStore
	m.callTracker = msg.session.Tracker
	m.callStore = store.NewCallStore(m.maxOfflineCalls)
	m.uiState.CallsView.ClearCorrelatedCalls()
	m, _ = m.handleCallUpdateMsg(CallUpdateMsg{Calls: msg.session.Calls})
	if m.backgroundProcessor != nil {
		m.backgroundProcessor.BeginGeneration()
	}
	ClearPendingPackets()
	pendingLocalEvents.clear()
	m.pendingRemoteEvents.clear()
	m.eventViewStore = nil
	m.syncEventsView()
	stats := msg.session.Dataset.Statistics()
	convert := func(in map[string]uint64) map[string]int64 {
		out := make(map[string]int64, len(in))
		for k, v := range in {
			out[k] = int64(v)
		}
		return out
	}
	m.statistics.ProtocolCounts.Replace(convert(stats.Protocols))
	m.statistics.SourceCounts.Replace(convert(stats.SourceCounts))
	m.statistics.DestCounts.Replace(convert(stats.DestinationCounts))
	m.statistics.TotalPackets = int64(stats.Packets)
	m.statistics.TotalBytes = int64(stats.Bytes)
	m.statistics.MinPacketSize = int(stats.MinPacketSize)
	m.statistics.MaxPacketSize = int(stats.MaxPacketSize)
	m.uiState.StatisticsView.SetStatistics(m.statistics)
	// The dataset bypasses the live bridge. Publish its statistics without
	// carrying capture loss or bridge health from the previous session.
	m.uiState.StatisticsView.GetDropStats().Reset()
	m.uiState.StatisticsView.SetBridgeStats(nil)
	m.uiState.StatisticsView.SetL3L4ProtocolClassification(false)
	decryptor := msg.session.TLSDecryptor
	m.uiState.DetailsPanel.SetDecryptedDataGetter(func(a, b, c, d string) ([]byte, []byte) {
		if decryptor == nil {
			return nil, nil
		}
		return decryptor.GetDecryptedData(a, b, c, d)
	})
	m.updateDetailsPanel()
	return m, func() tea.Msg { return offlineCleanupMsg{err: c.dispose(old)} }
}

// Cancellation is expected, but joined analyzer/cleanup failures still need to
// reach the user even when disposal succeeds on its next attempt.
func offlineCancellationError(err error) error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var result error
		for _, cause := range joined.Unwrap() {
			result = errors.Join(result, offlineCancellationError(cause))
		}
		return result
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if offlineCancellationError(wrapped.Unwrap()) == nil {
			return nil
		}
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return nil
	}
	return err
}

func (m Model) retryOfflineCancellation() (Model, tea.Cmd) {
	m.offlineCleanupFailed = false
	m.offlineCleanupError = ""
	c, session, generation := m.offlineController, m.offlineCancelledSession, m.offlineGeneration
	return m, func() tea.Msg {
		return offlineCleanupMsg{generation: generation, cancelled: true, err: c.dispose(session)}
	}
}
func (m Model) offlineModal() string {
	p := m.offlineProgress
	content := fmt.Sprintf("Phase: %s\nSources: %d\nLogical packets: %d\nBytes scanned: %d\nTemporary disk: %d bytes\nElapsed: %s", p.State, p.Sources, p.LogicalPackets, p.ScannedBytes, p.DiskBytes, p.Elapsed.Round(time.Millisecond))
	footer := "Esc: Cancel   Ctrl+C: Quit"
	if m.offlineCleanupFailed {
		content += "\n\nCleanup failed: " + m.offlineCleanupError
		footer = "Enter: Retry cleanup   Ctrl+C: Retry and quit"
	}
	return components.RenderModal(components.ModalRenderOptions{Title: "Opening offline dataset", Content: content, Footer: footer, Width: m.uiState.Width, Height: m.uiState.Height, Theme: m.uiState.Theme})
}

// Mode changes and quit join workers and release sessions in a command, keeping
// Update responsive throughout cleanup. The restart re-enters only after join.
func (m Model) leaveOffline(restart *components.RestartCaptureMsg, quit bool) (Model, tea.Cmd) {
	if quit {
		m.offlineQuitRequested = true
	}
	if m.offlineLeaving && !m.offlineCleanupFailed {
		return m, nil
	}
	if restart != nil {
		copy := *restart
		copy.PCAPFiles = append([]string(nil), restart.PCAPFiles...)
		m.offlineRestart = &copy
	}
	restart = m.offlineRestart
	quit = m.offlineQuitRequested
	m.offlineCleanupFailed = false
	m.offlineCleanupError = ""
	m.offlineLeaving = true
	m.offlineStarted = time.Now()
	m, _ = m.cancelOffline()
	m.offlineOpening = true
	m.offlineProgress.State = offline.Cancelling
	c := m.offlineController
	c.mu.Lock()
	c.generation++
	m.offlineGeneration = c.generation
	c.mu.Unlock()
	g := m.offlineGeneration
	return m, func() tea.Msg {
		err := c.close()
		return offlineCleanupMsg{generation: g, restart: restart, quit: quit, err: err}
	}
}

func (m Model) requestQuit() (Model, tea.Cmd) {
	if m.offlineOpening || m.offlineSession != nil {
		return m.leaveOffline(nil, true)
	}
	m.Shutdown()
	m.uiState.Quitting = true
	return m, tea.Quit
}

func (m *Model) installOfflineSettings(msg OpenOfflineDatasetMsg) {
	m.uiState.SettingsView.InstallCaptureConfiguration(components.RestartCaptureMsg{Mode: components.CaptureModeOffline, PCAPFiles: msg.Config.Inputs, BufferSize: msg.Config.EventCapacity, Filter: msg.Config.BPFFilter})
}

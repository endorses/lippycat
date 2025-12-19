package processor

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
)

// CallCompletionMonitorConfig configures the call completion monitor
type CallCompletionMonitorConfig struct {
	GracePeriod   time.Duration // Time to wait after call ends before closing PCAP (default: 5s)
	CheckInterval time.Duration // How often to check for ended calls (default: 1s)
}

// DefaultCallCompletionMonitorConfig returns default configuration
func DefaultCallCompletionMonitorConfig() *CallCompletionMonitorConfig {
	return &CallCompletionMonitorConfig{
		GracePeriod:   5 * time.Second,
		CheckInterval: 1 * time.Second,
	}
}

// CallCompletionMonitor monitors call state and closes PCAP files after grace period
type CallCompletionMonitor struct {
	config       *CallCompletionMonitorConfig
	aggregator   *voip.CallAggregator
	pcapManager  *PcapWriterManager
	pendingClose map[string]time.Time // callID -> time when grace period expires
	closedCalls  map[string]struct{}  // callIDs that have already been closed (avoid re-scheduling)
	mu           sync.Mutex
	checkTicker  *time.Ticker
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// NewCallCompletionMonitor creates a new call completion monitor
func NewCallCompletionMonitor(
	config *CallCompletionMonitorConfig,
	aggregator *voip.CallAggregator,
	pcapManager *PcapWriterManager,
) *CallCompletionMonitor {
	if config == nil {
		config = DefaultCallCompletionMonitorConfig()
	}

	// Ensure reasonable defaults
	if config.GracePeriod <= 0 {
		config.GracePeriod = 5 * time.Second
	}
	if config.CheckInterval <= 0 {
		config.CheckInterval = 1 * time.Second
	}

	return &CallCompletionMonitor{
		config:       config,
		aggregator:   aggregator,
		pcapManager:  pcapManager,
		pendingClose: make(map[string]time.Time),
		closedCalls:  make(map[string]struct{}),
		stopChan:     make(chan struct{}),
	}
}

// Start begins monitoring call completions
func (m *CallCompletionMonitor) Start() {
	if m == nil || m.aggregator == nil || m.pcapManager == nil {
		return
	}

	m.checkTicker = time.NewTicker(m.config.CheckInterval)

	m.wg.Add(1)
	go m.monitorLoop()

	logger.Info("Call completion monitor started",
		"grace_period", m.config.GracePeriod,
		"check_interval", m.config.CheckInterval)
}

// Stop stops the monitor
func (m *CallCompletionMonitor) Stop() {
	if m == nil {
		return
	}

	close(m.stopChan)

	if m.checkTicker != nil {
		m.checkTicker.Stop()
	}

	m.wg.Wait()

	logger.Info("Call completion monitor stopped")
}

// monitorLoop periodically checks for ended calls and closes PCAP files
func (m *CallCompletionMonitor) monitorLoop() {
	defer m.wg.Done()

	for {
		select {
		case <-m.checkTicker.C:
			m.checkEndedCalls()
			m.processPendingClose()
		case <-m.stopChan:
			// Close any remaining pending calls on shutdown
			m.closeAllPending()
			return
		}
	}
}

// checkEndedCalls looks for calls that have ended and schedules them for closure
func (m *CallCompletionMonitor) checkEndedCalls() {
	calls := m.aggregator.GetCalls()
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, call := range calls {
		// Skip if already closed
		if _, closed := m.closedCalls[call.CallID]; closed {
			continue
		}

		// Skip if already pending close
		if _, pending := m.pendingClose[call.CallID]; pending {
			continue
		}

		// Check if call has ended
		if call.State == voip.CallStateEnded || call.State == voip.CallStateFailed {
			// Schedule for closure after grace period
			closeTime := now.Add(m.config.GracePeriod)
			m.pendingClose[call.CallID] = closeTime

			logger.Debug("Scheduled call PCAP closure",
				"call_id", call.CallID,
				"state", call.State.String(),
				"close_time", closeTime.Format(time.RFC3339))
		}
	}
}

// processPendingClose closes PCAP files for calls whose grace period has expired
func (m *CallCompletionMonitor) processPendingClose() {
	now := time.Now()

	m.mu.Lock()
	toClose := make([]string, 0)
	for callID, closeTime := range m.pendingClose {
		if now.After(closeTime) {
			toClose = append(toClose, callID)
		}
	}
	// Remove from pending before releasing lock
	for _, callID := range toClose {
		delete(m.pendingClose, callID)
	}
	m.mu.Unlock()

	// Close PCAP files outside the lock
	for _, callID := range toClose {
		m.closeCallPcap(callID)
	}
}

// closeCallPcap closes the PCAP files for a call and fires the voipcommand callback
func (m *CallCompletionMonitor) closeCallPcap(callID string) {
	if m.pcapManager == nil {
		// Even without PCAP manager, mark as closed to prevent re-scheduling
		m.mu.Lock()
		m.closedCalls[callID] = struct{}{}
		m.mu.Unlock()
		return
	}

	if err := m.pcapManager.CloseCallWriter(callID); err != nil {
		logger.Error("Failed to close call PCAP writer",
			"call_id", callID,
			"error", err)
		// Still mark as closed to prevent infinite retry
		m.mu.Lock()
		m.closedCalls[callID] = struct{}{}
		m.mu.Unlock()
		return
	}

	// Mark as closed
	m.mu.Lock()
	m.closedCalls[callID] = struct{}{}
	m.mu.Unlock()

	logger.Info("Closed PCAP files for completed call", "call_id", callID)
}

// closeAllPending closes all pending calls immediately (used during shutdown)
func (m *CallCompletionMonitor) closeAllPending() {
	m.mu.Lock()
	toClose := make([]string, 0, len(m.pendingClose))
	for callID := range m.pendingClose {
		toClose = append(toClose, callID)
	}
	m.pendingClose = make(map[string]time.Time)
	m.mu.Unlock()

	for _, callID := range toClose {
		m.closeCallPcap(callID)
	}

	logger.Info("Closed all pending call PCAP files on shutdown", "count", len(toClose))
}

// GetPendingCount returns the number of calls pending closure
func (m *CallCompletionMonitor) GetPendingCount() int {
	if m == nil {
		return 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pendingClose)
}

// CancelPendingClose cancels a scheduled closure (used if call receives more packets)
func (m *CallCompletionMonitor) CancelPendingClose(callID string) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.pendingClose[callID]; exists {
		delete(m.pendingClose, callID)
		logger.Debug("Cancelled pending PCAP closure", "call_id", callID)
	}
}

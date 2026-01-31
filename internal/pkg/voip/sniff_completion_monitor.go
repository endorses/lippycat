package voip

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Package-level monitor for sniff mode PCAP completion
var (
	globalSniffCompletionMonitor *SniffCompletionMonitor
	sniffMonitorMu               sync.RWMutex
)

// SetSniffCompletionMonitor sets the global sniff completion monitor.
// Called by StartVoipSniffer when PCAP writing is enabled.
func SetSniffCompletionMonitor(m *SniffCompletionMonitor) {
	sniffMonitorMu.Lock()
	defer sniffMonitorMu.Unlock()
	globalSniffCompletionMonitor = m
}

// getSniffCompletionMonitor returns the global sniff completion monitor (may be nil).
func getSniffCompletionMonitor() *SniffCompletionMonitor {
	sniffMonitorMu.RLock()
	defer sniffMonitorMu.RUnlock()
	return globalSniffCompletionMonitor
}

// SniffCompletionMonitorConfig configures the sniff completion monitor
type SniffCompletionMonitorConfig struct {
	GracePeriod   time.Duration // Time to wait after call ends before closing PCAP (default: 5s)
	CheckInterval time.Duration // How often to check for ended calls (default: 1s)
}

// DefaultSniffCompletionMonitorConfig returns default configuration
func DefaultSniffCompletionMonitorConfig() *SniffCompletionMonitorConfig {
	return &SniffCompletionMonitorConfig{
		GracePeriod:   5 * time.Second,
		CheckInterval: 1 * time.Second,
	}
}

// sniffPendingCallInfo tracks timing for a call pending closure
type sniffPendingCallInfo struct {
	scheduledAt time.Time // When the call was first scheduled for closure
	callID      string
}

// SniffCompletionMonitor monitors call state and closes PCAP files after grace period.
// This is the sniff mode equivalent of processor's CallCompletionMonitor.
// It integrates with CallTracker to monitor call state changes and close PCAP files.
type SniffCompletionMonitor struct {
	config       *SniffCompletionMonitorConfig
	pendingClose map[string]*sniffPendingCallInfo // callID -> pending closure info
	closedCalls  map[string]struct{}              // callIDs that have already been closed
	mu           sync.Mutex
	checkTicker  *time.Ticker
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// NewSniffCompletionMonitor creates a new sniff completion monitor
func NewSniffCompletionMonitor(config *SniffCompletionMonitorConfig) *SniffCompletionMonitor {
	if config == nil {
		config = DefaultSniffCompletionMonitorConfig()
	}

	// Ensure reasonable defaults
	if config.GracePeriod <= 0 {
		config.GracePeriod = 5 * time.Second
	}
	if config.CheckInterval <= 0 {
		config.CheckInterval = 1 * time.Second
	}

	return &SniffCompletionMonitor{
		config:       config,
		pendingClose: make(map[string]*sniffPendingCallInfo),
		closedCalls:  make(map[string]struct{}),
		stopChan:     make(chan struct{}),
	}
}

// Start begins monitoring call completions
func (m *SniffCompletionMonitor) Start() {
	if m == nil {
		return
	}

	m.checkTicker = time.NewTicker(m.config.CheckInterval)

	m.wg.Add(1)
	go m.monitorLoop()

	logger.Info("Sniff completion monitor started",
		"grace_period", m.config.GracePeriod,
		"check_interval", m.config.CheckInterval)
}

// Stop stops the monitor
func (m *SniffCompletionMonitor) Stop() {
	if m == nil {
		return
	}

	close(m.stopChan)

	if m.checkTicker != nil {
		m.checkTicker.Stop()
	}

	m.wg.Wait()

	logger.Info("Sniff completion monitor stopped")
}

// ScheduleClose schedules a call for PCAP closure after the grace period.
// This should be called when a call reaches BYE/CANCEL state.
func (m *SniffCompletionMonitor) ScheduleClose(callID string) {
	if m == nil || callID == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Skip if already closed
	if _, closed := m.closedCalls[callID]; closed {
		return
	}

	// Skip if already pending close
	if _, pending := m.pendingClose[callID]; pending {
		return
	}

	m.pendingClose[callID] = &sniffPendingCallInfo{
		scheduledAt: time.Now(),
		callID:      callID,
	}

	logger.Debug("Scheduled call PCAP closure",
		"call_id", SanitizeCallIDForLogging(callID),
		"grace_period", m.config.GracePeriod)
}

// monitorLoop periodically checks for ended calls and closes PCAP files
func (m *SniffCompletionMonitor) monitorLoop() {
	defer m.wg.Done()

	for {
		select {
		case <-m.checkTicker.C:
			m.processPendingClose()
		case <-m.stopChan:
			// Close any remaining pending calls on shutdown
			m.closeAllPending()
			return
		}
	}
}

// processPendingClose closes PCAP files for calls whose grace period has expired
func (m *SniffCompletionMonitor) processPendingClose() {
	now := time.Now()

	m.mu.Lock()
	toClose := make([]string, 0)
	for callID, info := range m.pendingClose {
		gracePeriodExpired := now.After(info.scheduledAt.Add(m.config.GracePeriod))
		if gracePeriodExpired {
			toClose = append(toClose, callID)
			logger.Debug("Call grace period expired",
				"call_id", SanitizeCallIDForLogging(callID),
				"waited", now.Sub(info.scheduledAt))
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

// closeCallPcap closes the PCAP files for a call
func (m *SniffCompletionMonitor) closeCallPcap(callID string) {
	// Clean up RTP port mappings for this call
	CleanupPortMappings(callID)

	// Get the call from the tracker
	call, err := getCall(callID)
	if err != nil {
		// Call may have already been evicted from LRU, just mark as closed
		m.mu.Lock()
		m.closedCalls[callID] = struct{}{}
		m.mu.Unlock()
		logger.Debug("Call not found for PCAP closure (may have been evicted)",
			"call_id", SanitizeCallIDForLogging(callID))
		return
	}

	// Close the PCAP files
	if err := call.Close(); err != nil {
		logger.Error("Failed to close call PCAP files",
			"call_id", SanitizeCallIDForLogging(callID),
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

	logger.Info("Closed PCAP files for completed call",
		"call_id", SanitizeCallIDForLogging(callID))
}

// closeAllPending closes all pending calls immediately (used during shutdown)
func (m *SniffCompletionMonitor) closeAllPending() {
	m.mu.Lock()
	toClose := make([]string, 0, len(m.pendingClose))
	for callID := range m.pendingClose {
		toClose = append(toClose, callID)
	}
	m.pendingClose = make(map[string]*sniffPendingCallInfo)
	m.mu.Unlock()

	for _, callID := range toClose {
		m.closeCallPcap(callID)
	}

	logger.Info("Closed all pending call PCAP files on shutdown", "count", len(toClose))
}

// GetPendingCount returns the number of calls pending closure
func (m *SniffCompletionMonitor) GetPendingCount() int {
	if m == nil {
		return 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pendingClose)
}

// CancelPendingClose cancels a scheduled closure (used if call receives more packets)
func (m *SniffCompletionMonitor) CancelPendingClose(callID string) {
	if m == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.pendingClose[callID]; exists {
		delete(m.pendingClose, callID)
		logger.Debug("Cancelled pending PCAP closure",
			"call_id", SanitizeCallIDForLogging(callID))
	}
}

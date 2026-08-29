package voip

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// SetCompletionMonitor binds lifecycle output handling to this tracker instance.
func (ct *CallTracker) SetCompletionMonitor(m *SniffCompletionMonitor) {
	ct.mu.Lock()
	ct.stateObservers = ct.stateObservers[:0]
	if m != nil {
		ct.stateObservers = append(ct.stateObservers, m)
	}
	ct.mu.Unlock()
}

func (m *SniffCompletionMonitor) OnCallStateChanged(callID, state string) {
	if state == "BYE" || state == "CANCEL" {
		m.ScheduleClose(callID)
	}
}

func (m *SniffCompletionMonitor) OnCallAdmitted(callID string) { m.CallStarted(callID) }

// SniffCompletionMonitorConfig configures the sniff completion monitor
type SniffCompletionMonitorConfig struct {
	GracePeriod   time.Duration // Time to wait after call ends before closing PCAP (default: 5s)
	CheckInterval time.Duration // How often to check for ended calls (default: 1s)
	ClosedCallTTL time.Duration // Time to retain completed call IDs for suppression (default: 1h)
}

// DefaultSniffCompletionMonitorConfig returns default configuration
func DefaultSniffCompletionMonitorConfig() *SniffCompletionMonitorConfig {
	return &SniffCompletionMonitorConfig{
		GracePeriod:   5 * time.Second,
		CheckInterval: 1 * time.Second,
		ClosedCallTTL: 1 * time.Hour,
	}
}

// sniffPendingCallInfo tracks timing for a call pending closure
type sniffPendingCallInfo struct {
	scheduledAt time.Time // When the call was first scheduled for closure
	callID      string
	call        *CallInfo // Exact admitted generation scheduled for closure
}

// SniffCompletionMonitor monitors call state and closes PCAP files after grace period.
// This is the sniff mode equivalent of processor's CallCompletionMonitor.
// It integrates with CallTracker to monitor call state changes and close PCAP files.
type SniffCompletionMonitor struct {
	tracker      *CallTracker
	config       *SniffCompletionMonitorConfig
	pendingClose map[string]*sniffPendingCallInfo // callID -> pending closure info
	closedCalls  map[string]time.Time             // callIDs that have already been closed
	mu           sync.Mutex
	checkTicker  *time.Ticker
	stopChan     chan struct{}
	wg           sync.WaitGroup
}

// NewSniffCompletionMonitor creates a new sniff completion monitor
func NewSniffCompletionMonitor(tracker *CallTracker, config *SniffCompletionMonitorConfig) *SniffCompletionMonitor {
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
	if config.ClosedCallTTL <= 0 {
		config.ClosedCallTTL = 1 * time.Hour
	}

	return &SniffCompletionMonitor{
		tracker:      tracker,
		config:       config,
		pendingClose: make(map[string]*sniffPendingCallInfo),
		closedCalls:  make(map[string]time.Time),
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

	call, _ := m.tracker.GetCall(callID)
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
		call:        call,
	}

	logger.Debug("Scheduled call PCAP closure",
		"call_id", SanitizeCallIDForLogging(callID),
		"grace_period", m.config.GracePeriod)
}

// CallStarted removes closure suppression left by an earlier dialog which used
// the same Call-ID. SIP Call-IDs are identifiers, not globally unique session
// generations, and may be reused after a call has been fully removed.
func (m *SniffCompletionMonitor) CallStarted(callID string) {
	if m == nil || callID == "" {
		return
	}
	m.mu.Lock()
	delete(m.closedCalls, callID)
	delete(m.pendingClose, callID)
	m.mu.Unlock()
}

// monitorLoop periodically checks for ended calls and closes PCAP files
func (m *SniffCompletionMonitor) monitorLoop() {
	defer m.wg.Done()

	for {
		select {
		case <-m.checkTicker.C:
			m.processPendingClose()
			m.pruneClosedCalls(time.Now())
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
	toClose := make([]*sniffPendingCallInfo, 0)
	for callID, info := range m.pendingClose {
		gracePeriodExpired := now.After(info.scheduledAt.Add(m.config.GracePeriod))
		if gracePeriodExpired {
			toClose = append(toClose, info)
			logger.Debug("Call grace period expired",
				"call_id", SanitizeCallIDForLogging(callID),
				"waited", now.Sub(info.scheduledAt))
		}
	}

	// Remove from pending before releasing lock
	for _, info := range toClose {
		delete(m.pendingClose, info.callID)
	}
	m.mu.Unlock()

	// Close PCAP files outside the lock
	for _, info := range toClose {
		m.closeCallPcapGeneration(info.callID, info.call)
	}
}

// closeCallPcap closes the PCAP files for a call
func (m *SniffCompletionMonitor) closeCallPcap(callID string) {
	m.closeCallPcapGeneration(callID, nil)
}

func (m *SniffCompletionMonitor) closeCallPcapGeneration(callID string, expected *CallInfo) {
	// Serialize the old generation's detach/closed marker with CallStarted.
	// A reused Call-ID may already be admitted while CallStarted waits here; once
	// this lock is released, CallStarted removes the old suppression marker.
	m.mu.Lock()
	defer m.mu.Unlock()

	// Detaching atomically removes tracker state and RTP endpoint mappings before
	// taking writer locks. The identity check protects a reused Call-ID.
	found, err := m.tracker.removeCallIf(callID, expected)
	if !found {
		if expected != nil {
			if current, getErr := m.tracker.GetCall(callID); getErr == nil && current != expected {
				return
			}
		}
		// Call may have already been evicted from LRU, just mark as closed
		m.closedCalls[callID] = time.Now()
		logger.Debug("Call not found for PCAP closure (may have been evicted)",
			"call_id", SanitizeCallIDForLogging(callID))
		return
	}

	if err != nil {
		logger.Error("Failed to close call PCAP files",
			"call_id", SanitizeCallIDForLogging(callID),
			"error", err)
		// Still mark as closed to prevent infinite retry
		m.closedCalls[callID] = time.Now()
		return
	}

	// Mark as closed
	m.closedCalls[callID] = time.Now()

	logger.Info("Closed PCAP files for completed call",
		"call_id", SanitizeCallIDForLogging(callID))
}

func (m *SniffCompletionMonitor) pruneClosedCalls(now time.Time) int {
	if m == nil || m.config == nil || m.config.ClosedCallTTL <= 0 {
		return 0
	}

	cutoff := now.Add(-m.config.ClosedCallTTL)
	pruned := 0

	m.mu.Lock()
	for callID, closedAt := range m.closedCalls {
		if closedAt.Before(cutoff) {
			delete(m.closedCalls, callID)
			pruned++
		}
	}
	m.mu.Unlock()

	return pruned
}

// closeAllPending closes all pending calls immediately (used during shutdown)
func (m *SniffCompletionMonitor) closeAllPending() {
	m.mu.Lock()
	toClose := make([]*sniffPendingCallInfo, 0, len(m.pendingClose))
	for _, info := range m.pendingClose {
		toClose = append(toClose, info)
	}
	m.pendingClose = make(map[string]*sniffPendingCallInfo)
	m.mu.Unlock()

	for _, info := range toClose {
		m.closeCallPcapGeneration(info.callID, info.call)
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

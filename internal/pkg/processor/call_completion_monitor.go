//go:build processor || tap || all

package processor

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
)

// CallCompletionMonitorConfig configures the call completion monitor
type CallCompletionMonitorConfig struct {
	GracePeriod    time.Duration // Time to wait after call ends before closing PCAP (default: 5s)
	CheckInterval  time.Duration // How often to check for ended calls (default: 1s)
	RTPWaitTimeout time.Duration // Max time to wait for RTP after grace period (default: 60s)
	ClosedCallTTL  time.Duration // Time to retain completed call IDs for suppression (default: 1h)
}

// DefaultCallCompletionMonitorConfig returns default configuration
func DefaultCallCompletionMonitorConfig() *CallCompletionMonitorConfig {
	return &CallCompletionMonitorConfig{
		GracePeriod:    5 * time.Second,
		CheckInterval:  1 * time.Second,
		RTPWaitTimeout: 60 * time.Second,
		ClosedCallTTL:  1 * time.Hour,
	}
}

// pendingCallInfo tracks timing for a call pending closure
type pendingCallInfo struct {
	scheduledAt time.Time // When the call was first scheduled for closure
	rtpExpected bool      // Whether RTP is expected (call was ACTIVE)
	reason      CallFinalizationReason
}

// VoIPPortCleaner is an interface for cleaning up VoIP port-to-call mappings.
// This is implemented by the voip processor to clean up RTP port associations
// when calls end.
type VoIPPortCleaner interface {
	CleanupCallPorts(callID string)
}

// CallCompletionMonitor monitors call state and closes PCAP files after grace period
type CallCompletionMonitor struct {
	config       *CallCompletionMonitorConfig
	aggregator   *voip.CallAggregator
	pcapManager  *PcapWriterManager
	lifecycle    *CallLifecycleRegistry
	voipCleaner  VoIPPortCleaner             // Optional voip processor for port cleanup
	pendingClose map[string]*pendingCallInfo // callID -> pending closure info
	mu           sync.Mutex
	checkTicker  *time.Ticker
	stopChan     chan struct{}
	wg           sync.WaitGroup
	startOnce    sync.Once
	stopOnce     sync.Once
	cleanerOnce  sync.Once
}

// NewCallCompletionMonitor creates a new call completion monitor
func NewCallCompletionMonitor(
	config *CallCompletionMonitorConfig,
	aggregator *voip.CallAggregator,
	pcapManager *PcapWriterManager,
) *CallCompletionMonitor {
	return NewCallCompletionMonitorWithLifecycle(config, aggregator, pcapManager, nil)
}

// NewCallCompletionMonitorWithLifecycle creates a monitor whose terminal call
// decisions are owned by lifecycle, independently of whether PCAP output exists.
func NewCallCompletionMonitorWithLifecycle(
	config *CallCompletionMonitorConfig,
	aggregator *voip.CallAggregator,
	pcapManager *PcapWriterManager,
	lifecycle *CallLifecycleRegistry,
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
	if config.RTPWaitTimeout <= 0 {
		config.RTPWaitTimeout = 60 * time.Second
	}
	if config.ClosedCallTTL <= 0 {
		config.ClosedCallTTL = 1 * time.Hour
	}
	if lifecycle == nil && pcapManager != nil {
		lifecycle = pcapManager.Lifecycle()
	}
	if lifecycle == nil {
		lifecycle = NewCallLifecycleRegistry(CallLifecycleConfig{TombstoneTTL: config.ClosedCallTTL})
	}
	// Preserve the monitor's retention knob on the shared terminal authority,
	// including the compatibility path where the PCAP manager supplied it.
	lifecycle.mu.Lock()
	lifecycle.tombstoneTTL = config.ClosedCallTTL
	lifecycle.mu.Unlock()

	return &CallCompletionMonitor{
		config:       config,
		aggregator:   aggregator,
		pcapManager:  pcapManager,
		lifecycle:    lifecycle,
		pendingClose: make(map[string]*pendingCallInfo),
		stopChan:     make(chan struct{}),
	}
}

// Start begins monitoring call completions
func (m *CallCompletionMonitor) Start() {
	if m == nil || m.aggregator == nil || m.lifecycle == nil {
		return
	}

	m.startOnce.Do(func() {
		m.checkTicker = time.NewTicker(m.config.CheckInterval)
		m.wg.Add(1)
		go m.monitorLoop()
		logger.Info("Call completion monitor started",
			"grace_period", m.config.GracePeriod,
			"check_interval", m.config.CheckInterval,
			"rtp_wait_timeout", m.config.RTPWaitTimeout)
	})
}

// Stop stops the monitor
func (m *CallCompletionMonitor) Stop() {
	if m == nil {
		return
	}

	m.stopOnce.Do(func() {
		close(m.stopChan)
		if m.checkTicker != nil {
			m.checkTicker.Stop()
		}
		m.wg.Wait()
		logger.Info("Call completion monitor stopped")
	})
}

// SetVoIPPortCleaner sets an optional VoIP port cleaner for cleanup when calls end.
// This is used in tap mode where the voip processor maintains its own port mappings.
func (m *CallCompletionMonitor) SetVoIPPortCleaner(cleaner VoIPPortCleaner) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.voipCleaner = cleaner
	m.mu.Unlock()
	if m.lifecycle != nil {
		m.cleanerOnce.Do(func() {
			m.lifecycle.Subscribe(func(event CallFinalizationEvent) {
				m.mu.Lock()
				currentCleaner := m.voipCleaner
				m.mu.Unlock()
				if currentCleaner != nil {
					currentCleaner.CleanupCallPorts(event.CallID)
				}
			})
		})
	}
}

// monitorLoop periodically checks for ended calls and closes PCAP files
func (m *CallCompletionMonitor) monitorLoop() {
	defer m.wg.Done()

	for {
		select {
		case <-m.checkTicker.C:
			m.checkEndedCalls()
			m.processPendingClose()
			m.sweepIdleWriters()
		case <-m.stopChan:
			// Shutdown is not protocol completion. The owning output manager
			// flushes live writers without firing completion hooks.
			m.discardAllPending()
			return
		}
	}
}

// checkEndedCalls looks for calls that have ended and schedules them for closure
func (m *CallCompletionMonitor) checkEndedCalls() {
	// First, process timewait expiry to transition ENDING calls to ENDED
	// This is necessary because BYE puts calls in ENDING state with a timewait
	// period before transitioning to ENDED state.
	m.aggregator.ProcessTimewaitExpiry()

	calls := m.aggregator.GetCalls()
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, call := range calls {
		// Skip if already closed
		if m.lifecycle.IsFinalized(call.CallID) {
			continue
		}

		// Skip if already pending close
		if _, pending := m.pendingClose[call.CallID]; pending {
			continue
		}

		// Check if call has ended (any terminal state)
		if call.State == voip.CallStateEnded || call.State == voip.CallStateFailed ||
			call.State == voip.CallStateCancelled || call.State == voip.CallStateBusy {
			// RTP is expected for successful calls (ENDED state).
			// Failed/cancelled/busy calls typically don't have RTP.
			// For ENDED calls, we wait for RTP even if we haven't seen any yet,
			// because RTP packets may arrive after the SIP BYE.
			rtpExpected := call.State == voip.CallStateEnded

			m.pendingClose[call.CallID] = &pendingCallInfo{
				scheduledAt: now,
				rtpExpected: rtpExpected,
				reason:      CallFinalizationProtocolComplete,
			}

			logger.Debug("Scheduled call PCAP closure",
				"call_id", call.CallID,
				"state", call.State.String(),
				"rtp_expected", rtpExpected,
				"rtp_packets_seen", call.RTPStats != nil && call.RTPStats.TotalPackets > 0,
				"grace_period", m.config.GracePeriod)
		}
	}
}

// ScheduleClose records an explicit lifecycle completion. This is the observer
// path used by instance-owned registries; polling remains temporarily for the
// processor aggregator until its Phase 5 orchestration migration.
func (m *CallCompletionMonitor) ScheduleClose(callID string, rtpExpected bool) {
	m.ScheduleCloseReason(callID, rtpExpected, CallFinalizationProtocolComplete)
}

// ScheduleCloseReason records completion while preserving its lifecycle cause.
func (m *CallCompletionMonitor) ScheduleCloseReason(callID string, rtpExpected bool, reason CallFinalizationReason) {
	if m == nil || callID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lifecycle != nil && m.lifecycle.IsFinalized(callID) {
		return
	}
	if _, pending := m.pendingClose[callID]; pending {
		return
	}
	m.pendingClose[callID] = &pendingCallInfo{scheduledAt: time.Now(), rtpExpected: rtpExpected, reason: reason}
}

// processPendingClose closes PCAP files for calls whose grace period has expired
func (m *CallCompletionMonitor) processPendingClose() {
	now := time.Now()

	m.mu.Lock()
	type pendingFinalization struct {
		callID string
		reason CallFinalizationReason
	}
	toClose := make([]pendingFinalization, 0)
	for callID, info := range m.pendingClose {
		gracePeriodExpired := now.After(info.scheduledAt.Add(m.config.GracePeriod))
		if !gracePeriodExpired {
			continue
		}

		// Check if we should close this call
		shouldClose := false
		reason := ""

		if !info.rtpExpected {
			// No RTP expected (failed call), close immediately after grace period
			shouldClose = true
			reason = "no RTP expected"
		} else if m.hasRTPPackets(callID) {
			// RTP expected and received, safe to close
			shouldClose = true
			reason = "RTP received"
		} else {
			// RTP expected but not yet received, check timeout
			timeoutExpired := now.After(info.scheduledAt.Add(m.config.RTPWaitTimeout))
			if timeoutExpired {
				shouldClose = true
				reason = "RTP wait timeout"
				logger.Warn("Closing call without RTP (timeout expired)",
					"call_id", callID,
					"waited", now.Sub(info.scheduledAt))
			}
			// Otherwise keep waiting
		}

		if shouldClose {
			toClose = append(toClose, pendingFinalization{callID: callID, reason: info.reason})
			logger.Debug("Call ready to close",
				"call_id", callID,
				"reason", reason,
				"rtp_expected", info.rtpExpected)
		}
	}

	// Remove from pending before releasing lock
	for _, pending := range toClose {
		delete(m.pendingClose, pending.callID)
	}
	m.mu.Unlock()

	// Close PCAP files outside the lock
	for _, pending := range toClose {
		m.finalizeCall(pending.callID, pending.reason)
	}
}

// closeCallPcap closes the PCAP files for a call and fires the voipcommand callback
func (m *CallCompletionMonitor) finalizeCall(callID string, reason CallFinalizationReason) {
	if m.lifecycle == nil {
		return
	}
	result := m.lifecycle.Finalize(callID, reason)
	if result.Finalized {
		logger.Info("Finalized completed call", "call_id", callID, "reason", reason)
	}
}

func (m *CallCompletionMonitor) hasRTPPackets(callID string) bool {
	if m.aggregator != nil {
		for _, call := range m.aggregator.GetCalls() {
			if call.CallID == callID {
				return call.RTPStats != nil && call.RTPStats.TotalPackets > 0
			}
		}
	}
	return m.pcapManager != nil && m.pcapManager.HasRTPPackets(callID)
}

func (m *CallCompletionMonitor) sweepIdleWriters() {
	if m == nil || m.pcapManager == nil || m.pcapManager.config == nil {
		return
	}

	maxIdle := m.pcapManager.config.MaxIdle
	if maxIdle <= 0 {
		return
	}

	closed := m.pcapManager.SweepIdle(maxIdle)
	if closed > 0 {
		logger.Warn("Closed idle per-call PCAP writers",
			"count", closed,
			"max_idle", maxIdle)
	}
}

// discardAllPending abandons completion scheduling during shutdown. Live
// writers are flushed by PcapWriterManager.Close with the shutdown reason.
func (m *CallCompletionMonitor) discardAllPending() {
	m.mu.Lock()
	toClose := make([]string, 0, len(m.pendingClose))
	for callID := range m.pendingClose {
		toClose = append(toClose, callID)
	}
	m.pendingClose = make(map[string]*pendingCallInfo)
	m.mu.Unlock()

	logger.Info("Discarded pending call PCAP completions on shutdown", "count", len(toClose))
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

//go:build tui || all
// +build tui all

package tui

import (
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
)

// OfflineCallAggregator wraps voip.CallAggregator for TUI offline mode
type OfflineCallAggregator struct {
	aggregator      *voip.CallAggregator
	program         *tea.Program
	lastNotifyTime  time.Time
	notifyThrottle  time.Duration
	mu              sync.Mutex
	knownCalls      map[string]bool // Track which calls we've already notified about
	callUpdateTimer *time.Timer
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// NewOfflineCallAggregator creates a new offline call aggregator
func NewOfflineCallAggregator(program *tea.Program) *OfflineCallAggregator {
	return &OfflineCallAggregator{
		aggregator:     voip.NewCallAggregator(),
		program:        program,
		notifyThrottle: 500 * time.Millisecond, // Throttle call updates
		knownCalls:     make(map[string]bool),
		stopCh:         make(chan struct{}),
	}
}

// ProcessPacket processes a packet and updates call state
func (oca *OfflineCallAggregator) ProcessPacket(pkt *types.PacketDisplay) {
	if pkt.VoIPData == nil {
		return
	}

	// Process the packet through the aggregator
	oca.aggregator.ProcessPacketDisplay(pkt, "offline")

	// Schedule a call update notification
	oca.scheduleCallUpdate()
}

// scheduleCallUpdate schedules a throttled call update notification
func (oca *OfflineCallAggregator) scheduleCallUpdate() {
	oca.mu.Lock()
	defer oca.mu.Unlock()

	// Cancel existing timer if any
	if oca.callUpdateTimer != nil {
		oca.callUpdateTimer.Stop()
	}

	// Schedule new notification after throttle period
	oca.callUpdateTimer = time.AfterFunc(oca.notifyThrottle, func() {
		oca.notifyCallUpdates()
	})
}

// notifyCallUpdates sends call updates to the TUI
func (oca *OfflineCallAggregator) notifyCallUpdates() {
	calls := oca.aggregator.GetCalls()

	// Convert all calls to types.CallInfo and send in a single batch
	callInfos := make([]types.CallInfo, 0, len(calls))
	for _, call := range calls {
		oca.mu.Lock()
		// Track known calls
		if !oca.knownCalls[call.CallID] {
			oca.knownCalls[call.CallID] = true
		}
		oca.mu.Unlock()

		// Convert voip.AggregatedCall to types.CallInfo
		callInfo := oca.convertToTUICall(call)
		callInfos = append(callInfos, callInfo)
	}

	// Send all call updates in a single message
	if oca.program != nil && len(callInfos) > 0 {
		oca.program.Send(CallUpdateMsg{
			Calls: callInfos,
		})
	}
}

// convertToTUICall converts voip.AggregatedCall to types.CallInfo
func (oca *OfflineCallAggregator) convertToTUICall(call voip.AggregatedCall) types.CallInfo {
	// Calculate duration using actual packet timestamps
	duration := time.Duration(0)
	if !call.EndTime.IsZero() {
		// Call ended - use EndTime
		duration = call.EndTime.Sub(call.StartTime)
	} else if !call.LastPacketTime.IsZero() {
		// Call didn't complete - use last packet seen
		duration = call.LastPacketTime.Sub(call.StartTime)
	}

	// Get codec
	codec := "Unknown"
	if call.RTPStats != nil && call.RTPStats.Codec != "" {
		codec = call.RTPStats.Codec
	}

	// Get quality metrics
	mos := 0.0
	packetLoss := 0.0
	jitter := 0.0
	if call.RTPStats != nil {
		mos = call.RTPStats.MOS
		packetLoss = call.RTPStats.PacketLoss
		jitter = call.RTPStats.Jitter
	}

	// Build NodeID from hunters list
	nodeID := "offline"
	if len(call.Hunters) > 0 {
		nodeID = call.Hunters[0] // Use first hunter as node ID
	}

	return types.CallInfo{
		CallID:      call.CallID,
		From:        call.From,
		To:          call.To,
		State:       call.State.String(), // Convert to string
		StartTime:   call.StartTime,
		EndTime:     call.EndTime,
		Duration:    duration,
		Codec:       codec,
		PacketCount: call.PacketCount,
		PacketLoss:  packetLoss,
		Jitter:      jitter,
		MOS:         mos,
		NodeID:      nodeID,
		Hunters:     call.Hunters,
	}
}

// Start starts the background call update notifier
func (oca *OfflineCallAggregator) Start() {
	oca.wg.Add(1)
	go func() {
		defer oca.wg.Done()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Periodically check for call updates
				oca.notifyCallUpdates()
			case <-oca.stopCh:
				return
			}
		}
	}()

	logger.Debug("Offline call aggregator started")
}

// Stop stops the background call update notifier
func (oca *OfflineCallAggregator) Stop() {
	close(oca.stopCh)
	oca.wg.Wait()

	oca.mu.Lock()
	if oca.callUpdateTimer != nil {
		oca.callUpdateTimer.Stop()
	}
	oca.mu.Unlock()

	logger.Debug("Offline call aggregator stopped")
}

// GetCalls returns all tracked calls
func (oca *OfflineCallAggregator) GetCalls() []voip.AggregatedCall {
	return oca.aggregator.GetCalls()
}

// GetCallCount returns the number of tracked calls
func (oca *OfflineCallAggregator) GetCallCount() int {
	return oca.aggregator.GetCallCount()
}

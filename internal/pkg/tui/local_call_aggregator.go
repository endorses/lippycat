//go:build tui || all

package tui

import (
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
)

// LocalCallAggregator wraps voip.CallAggregator for TUI local capture modes (live and offline)
type LocalCallAggregator struct {
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

// NewLocalCallAggregator creates a new local call aggregator for live or offline mode
func NewLocalCallAggregator(program *tea.Program) *LocalCallAggregator {
	return &LocalCallAggregator{
		aggregator:     voip.NewCallAggregator(),
		program:        program,
		notifyThrottle: 500 * time.Millisecond, // Throttle call updates
		knownCalls:     make(map[string]bool),
		stopCh:         make(chan struct{}),
	}
}

// ProcessPacket processes a packet and updates call state
func (lca *LocalCallAggregator) ProcessPacket(pkt *types.PacketDisplay) {
	if pkt.VoIPData == nil {
		return
	}

	// Use the packet's interface name as the source identifier
	// This shows which interface captured the packet in local modes
	sourceID := pkt.Interface
	if sourceID == "" {
		sourceID = "local"
	}

	// Process the packet through the aggregator
	lca.aggregator.ProcessPacketDisplay(pkt, sourceID)

	// Schedule a call update notification
	lca.scheduleCallUpdate()
}

// scheduleCallUpdate schedules a throttled call update notification
func (lca *LocalCallAggregator) scheduleCallUpdate() {
	lca.mu.Lock()
	defer lca.mu.Unlock()

	// Cancel existing timer if any
	if lca.callUpdateTimer != nil {
		lca.callUpdateTimer.Stop()
	}

	// Schedule new notification after throttle period
	lca.callUpdateTimer = time.AfterFunc(lca.notifyThrottle, func() {
		lca.notifyCallUpdates()
	})
}

// notifyCallUpdates sends call updates to the TUI
func (lca *LocalCallAggregator) notifyCallUpdates() {
	calls := lca.aggregator.GetCalls()

	// Convert all calls to types.CallInfo and send in a single batch
	callInfos := make([]types.CallInfo, 0, len(calls))
	for _, call := range calls {
		lca.mu.Lock()
		// Track known calls
		if !lca.knownCalls[call.CallID] {
			lca.knownCalls[call.CallID] = true
		}
		lca.mu.Unlock()

		// Convert voip.AggregatedCall to types.CallInfo
		callInfo := lca.convertToTUICall(call)
		callInfos = append(callInfos, callInfo)
	}

	// Send all call updates in a single message
	if lca.program != nil && len(callInfos) > 0 {
		lca.program.Send(CallUpdateMsg{
			Calls: callInfos,
		})
	}
}

// convertToTUICall converts voip.AggregatedCall to types.CallInfo
func (lca *LocalCallAggregator) convertToTUICall(call voip.AggregatedCall) types.CallInfo {
	// Calculate duration using actual packet timestamps
	duration := time.Duration(0)
	if !call.EndTime.IsZero() {
		// Call ended - use EndTime
		duration = call.EndTime.Sub(call.StartTime)
	} else if !call.LastPacketTime.IsZero() {
		// Call didn't complete - use last packet seen
		duration = call.LastPacketTime.Sub(call.StartTime)
	}

	// Get From/To from call, or fall back to tracker's party info
	// This handles RTP-created calls where SIP hasn't updated the call aggregator yet
	from := call.From
	to := call.To
	if (from == "" || to == "") && call.CallID != "" {
		if tracker := GetCallTracker(); tracker != nil {
			trackerFrom, trackerTo := tracker.GetCallPartyInfo(call.CallID)
			if from == "" && trackerFrom != "" {
				from = trackerFrom
			}
			if to == "" && trackerTo != "" {
				to = trackerTo
			}
		}
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

	// Build NodeID from hunters list (contains interface names for local capture)
	nodeID := "local"
	if len(call.Hunters) > 0 {
		nodeID = call.Hunters[0] // Use first interface/hunter as node ID
	}

	return types.CallInfo{
		CallID:      call.CallID,
		From:        from,
		To:          to,
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
func (lca *LocalCallAggregator) Start() {
	lca.wg.Add(1)
	go func() {
		defer lca.wg.Done()

		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Periodically check for call updates
				lca.notifyCallUpdates()
			case <-lca.stopCh:
				return
			}
		}
	}()

	logger.Debug("Local call aggregator started")
}

// Stop stops the background call update notifier
func (lca *LocalCallAggregator) Stop() {
	close(lca.stopCh)
	lca.wg.Wait()

	lca.mu.Lock()
	if lca.callUpdateTimer != nil {
		lca.callUpdateTimer.Stop()
	}
	lca.mu.Unlock()

	logger.Debug("Local call aggregator stopped")
}

// GetCalls returns all tracked calls
func (lca *LocalCallAggregator) GetCalls() []voip.AggregatedCall {
	return lca.aggregator.GetCalls()
}

// GetCallCount returns the number of tracked calls
func (lca *LocalCallAggregator) GetCallCount() int {
	return lca.aggregator.GetCallCount()
}

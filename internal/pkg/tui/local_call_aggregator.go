//go:build tui || all

package tui

import (
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/pkg/voip"
)

// CallTracker fallback counters for diagnostics
var (
	trackerFallbackAttempts int64 // Calls with empty From/To that tried CallTracker
	trackerFallbackFromHit  int64 // Times CallTracker provided From
	trackerFallbackToHit    int64 // Times CallTracker provided To
	trackerFallbackMiss     int64 // Times CallTracker had no party info
)

// GetTrackerFallbackStats returns CallTracker fallback statistics
func GetTrackerFallbackStats() (attempts, fromHit, toHit, miss int64) {
	return atomic.LoadInt64(&trackerFallbackAttempts),
		atomic.LoadInt64(&trackerFallbackFromHit),
		atomic.LoadInt64(&trackerFallbackToHit),
		atomic.LoadInt64(&trackerFallbackMiss)
}

// rtpStalenessThreshold is the duration after which an RTP-only call
// with no recent packets is considered ended/stale.
const rtpStalenessThreshold = 10 * time.Second

// LocalCallAggregator wraps voip.CallAggregator for TUI local capture modes (live and offline)
type LocalCallAggregator struct {
	aggregator      *voip.CallAggregator
	program         *tea.Program
	lastNotifyTime  time.Time
	notifyThrottle  time.Duration
	mu              sync.Mutex
	callUpdateTimer *time.Timer
	stopCh          chan struct{}
	wg              sync.WaitGroup
	// Double-buffer for call updates to reduce allocations
	// We alternate between buffers so one can be processed by TUI while we fill the other
	callInfoBuffers [2][]types.CallInfo
	activeBuffer    int // Index of buffer currently being used for building (0 or 1)
}

// NewLocalCallAggregator creates a new local call aggregator for live or offline mode
func NewLocalCallAggregator(program *tea.Program) *LocalCallAggregator {
	return &LocalCallAggregator{
		aggregator:     voip.NewCallAggregator(),
		program:        program,
		notifyThrottle: 500 * time.Millisecond, // Throttle call updates
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

	lca.mu.Lock()
	// Use double-buffer pattern to reduce allocations:
	// - One buffer is being processed by TUI
	// - We fill the other buffer with new data
	// - Swap buffers after sending
	// This eliminates per-cycle allocations once buffers reach steady-state size

	bufIdx := lca.activeBuffer
	buf := &lca.callInfoBuffers[bufIdx]

	// Ensure buffer has sufficient capacity, grow if needed
	needed := len(calls)
	if cap(*buf) < needed {
		// Grow with headroom to reduce future reallocations
		newCap := needed
		if newCap < 64 {
			newCap = 64
		} else {
			newCap = newCap * 3 / 2 // 50% growth factor
		}
		*buf = make([]types.CallInfo, 0, newCap)
	}
	// Reset length but keep capacity
	*buf = (*buf)[:0]

	// Convert all calls to types.CallInfo
	for _, call := range calls {
		callInfo := lca.convertToTUICall(call)
		*buf = append(*buf, callInfo)
	}

	// Get the slice to send (references the buffer we just filled)
	callInfos := *buf

	// Swap to the other buffer for next cycle
	// This ensures the TUI can safely process callInfos while we fill the other buffer
	lca.activeBuffer = 1 - bufIdx
	lca.mu.Unlock()

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

	// Determine call state, with special handling for RTP-only calls
	// RTP-only calls don't have SIP signaling, so we detect activity based on
	// whether we've received RTP packets recently
	state := call.State.String()
	if call.State == voip.CallStateRTPOnly {
		// RTP-only call - determine state based on packet activity
		if !call.LastPacketTime.IsZero() && time.Since(call.LastPacketTime) < rtpStalenessThreshold {
			// Recent RTP activity - show as RTP-only (distinct from SIP-based Active)
			state = "RTP-ONLY"
		} else {
			// No recent RTP - show as ended
			state = "ENDED"
			// Set end time if not already set
			if call.EndTime.IsZero() && !call.LastPacketTime.IsZero() {
				call.EndTime = call.LastPacketTime
			}
		}
	}

	// Get From/To from call, or fall back to tracker's party info
	// This handles RTP-created calls where SIP hasn't updated the call aggregator yet
	from := call.From
	to := call.To
	if (from == "" || to == "") && call.CallID != "" {
		atomic.AddInt64(&trackerFallbackAttempts, 1)
		if tracker := GetCallTracker(); tracker != nil {
			trackerFrom, trackerTo := tracker.GetCallPartyInfo(call.CallID)
			foundAny := false
			if from == "" && trackerFrom != "" {
				from = trackerFrom
				atomic.AddInt64(&trackerFallbackFromHit, 1)
				foundAny = true
			}
			if to == "" && trackerTo != "" {
				to = trackerTo
				atomic.AddInt64(&trackerFallbackToHit, 1)
				foundAny = true
			}
			if !foundAny && (from == "" || to == "") {
				atomic.AddInt64(&trackerFallbackMiss, 1)
				// Log missed fallback for debugging
				logger.Debug("CallTracker fallback miss - no party info found",
					"call_id", voip.SanitizeCallIDForLogging(call.CallID),
					"call_from", call.From,
					"call_to", call.To,
					"tracker_from", trackerFrom,
					"tracker_to", trackerTo)
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

	// Get SDP endpoints from CallTracker for debugging correlation
	var sdpEndpoints []string
	if tracker := GetCallTracker(); tracker != nil {
		sdpEndpoints = tracker.GetEndpointsForCall(call.CallID)
	}

	return types.CallInfo{
		CallID:           call.CallID,
		From:             from,
		To:               to,
		State:            state,
		LastResponseCode: call.LastResponseCode,
		StartTime:        call.StartTime,
		EndTime:          call.EndTime,
		Duration:         duration,
		Codec:            codec,
		PacketCount:      call.PacketCount,
		PacketLoss:       packetLoss,
		Jitter:           jitter,
		MOS:              mos,
		NodeID:           nodeID,
		Hunters:          call.Hunters,
		SDPEndpoints:     sdpEndpoints,
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

// TriggerMerge triggers a merge from an RTP-only (synthetic) call to a real SIP call.
// This is called by HandleSIPMessage when TCP reassembly detects a SIP message
// with SDP that matches an existing RTP-only call.
func (lca *LocalCallAggregator) TriggerMerge(syntheticCallID, realCallID string) {
	if syntheticCallID == "" || realCallID == "" {
		return
	}
	lca.aggregator.TriggerMerge(syntheticCallID, realCallID)
}

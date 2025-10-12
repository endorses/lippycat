package voip

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

// LockFreeCallTracker provides lock-free operations for hot paths
// Falls back to standard locking for complex operations
type LockFreeCallTracker struct {
	// Lock-free maps using sync.Map for concurrent access
	callMap      sync.Map // map[string]*CallInfo
	portToCallID sync.Map // map[string]string

	// Atomic counters for statistics
	totalCalls   atomic.Int64
	activeCalls  atomic.Int64
	droppedCalls atomic.Int64
	lastCleanup  atomic.Int64 // Unix timestamp

	// Traditional locking for complex operations
	complexOpsMu sync.RWMutex

	// Lifecycle management
	janitorCtx    context.Context
	janitorCancel context.CancelFunc
	janitorDone   chan struct{} // Closed when janitor goroutine exits
	shutdownOnce  sync.Once

	// Configuration
	config *Config
}

// NewLockFreeCallTracker creates a new lock-free call tracker
func NewLockFreeCallTracker() *LockFreeCallTracker {
	ctx, cancel := context.WithCancel(context.Background())
	tracker := &LockFreeCallTracker{
		janitorCtx:    ctx,
		janitorCancel: cancel,
		janitorDone:   make(chan struct{}),
		config:        GetConfig(),
	}

	tracker.lastCleanup.Store(time.Now().Unix())
	tracker.startJanitor()

	return tracker
}

// GetCall retrieves a call by ID (lock-free read)
func (lf *LockFreeCallTracker) GetCall(callID string) (*CallInfo, error) {
	if value, ok := lf.callMap.Load(callID); ok {
		lockFreeCall := value.(*LockFreeCallInfo)
		// Return a snapshot copy to avoid data races
		return lockFreeCall.getSnapshot(), nil
	}
	return nil, errors.New("the CallID does not exist")
}

// GetOrCreateCall gets or creates a call (optimized for the common read case)
func (lf *LockFreeCallTracker) GetOrCreateCall(callID string, linkType layers.LinkType) *CallInfo {
	// Fast path: try to load existing call (lock-free)
	if value, ok := lf.callMap.Load(callID); ok {
		lockFreeCall := value.(*LockFreeCallInfo)
		// Return a snapshot copy to avoid data races
		return lockFreeCall.getSnapshot()
	}

	// Slow path: need to create new call
	return lf.createCallSafely(callID, linkType)
}

// createCallSafely handles call creation with proper synchronization
func (lf *LockFreeCallTracker) createCallSafely(callID string, linkType layers.LinkType) *CallInfo {
	// Use LoadOrStore to handle race conditions
	call := &CallInfo{
		CallID:      callID,
		State:       "NEW",
		Created:     time.Now(),
		LastUpdated: time.Now(),
		LinkType:    linkType,
	}

	// Initialize writers if needed
	if viper.GetViper().GetBool("writeVoip") {
		if err := call.initWriters(); err != nil {
			logger.Error("Failed to initialize writers for call",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			lf.droppedCalls.Add(1)
			return nil
		}
	}

	// Wrap in lock-free wrapper
	lockFreeCall := newLockFreeCallInfo(call)

	// Atomic store - if another goroutine stored first, use theirs
	if actual, loaded := lf.callMap.LoadOrStore(callID, lockFreeCall); loaded {
		// Close our writers since we're using the existing call
		if call.sipFile != nil {
			_ = call.sipFile.Close()
		}
		if call.rtpFile != nil {
			_ = call.rtpFile.Close()
		}
		return actual.(*LockFreeCallInfo).CallInfo
	}

	// We successfully stored our call
	lf.totalCalls.Add(1)
	lf.activeCalls.Add(1)
	return call
}

// SetCallState updates call state (lock-free for the call lookup)
func (lf *LockFreeCallTracker) SetCallState(callID, newState string) {
	if value, ok := lf.callMap.Load(callID); ok {
		lockFreeCall := value.(*LockFreeCallInfo)
		// Use atomic operations for the state update
		lockFreeCall.setStateLockFree(newState)
	}
}

// AddPortMapping adds a port to call ID mapping (lock-free)
func (lf *LockFreeCallTracker) AddPortMapping(port, callID string) {
	lf.portToCallID.Store(port, callID)
}

// GetCallIDByPort retrieves call ID by port (lock-free)
func (lf *LockFreeCallTracker) GetCallIDByPort(port string) (string, bool) {
	if value, ok := lf.portToCallID.Load(port); ok {
		return value.(string), true
	}
	return "", false
}

// RemovePortMapping removes a port mapping (lock-free)
func (lf *LockFreeCallTracker) RemovePortMapping(port string) {
	lf.portToCallID.Delete(port)
}

// GetStats returns statistics (lock-free)
func (lf *LockFreeCallTracker) GetStats() CallTrackerStats {
	return CallTrackerStats{
		TotalCalls:    lf.totalCalls.Load(),
		ActiveCalls:   lf.activeCalls.Load(),
		DroppedCalls:  lf.droppedCalls.Load(),
		LastCleanupAt: time.Unix(lf.lastCleanup.Load(), 0),
	}
}

// CleanupExpiredCalls removes expired calls (uses locking for safety)
func (lf *LockFreeCallTracker) CleanupExpiredCalls() int {
	lf.complexOpsMu.Lock()
	defer lf.complexOpsMu.Unlock()

	var expiredCalls []string
	cutoff := time.Now().Add(-lf.config.CallExpirationTime)

	// Collect expired calls
	lf.callMap.Range(func(key, value interface{}) bool {
		lockFreeCall := value.(*LockFreeCallInfo)
		if lockFreeCall.CallInfo.LastUpdated.Before(cutoff) {
			expiredCalls = append(expiredCalls, key.(string))
		}
		return true
	})

	// Remove expired calls
	cleanedCount := 0
	for _, callID := range expiredCalls {
		if lf.removeCall(callID) {
			cleanedCount++
		}
	}

	lf.lastCleanup.Store(time.Now().Unix())
	return cleanedCount
}

// removeCall removes a call and associated port mappings
func (lf *LockFreeCallTracker) removeCall(callID string) bool {
	if value, ok := lf.callMap.LoadAndDelete(callID); ok {
		lockFreeCall := value.(*LockFreeCallInfo)
		call := lockFreeCall.CallInfo

		// Close writers
		if call.sipFile != nil {
			_ = call.sipFile.Close()
		}
		if call.rtpFile != nil {
			_ = call.rtpFile.Close()
		}

		// Remove associated port mappings
		lf.removePortMappingsForCall(callID)

		lf.activeCalls.Add(-1)
		return true
	}
	return false
}

// removePortMappingsForCall removes all port mappings for a call
func (lf *LockFreeCallTracker) removePortMappingsForCall(callID string) {
	var portsToDelete []string

	lf.portToCallID.Range(func(key, value interface{}) bool {
		if value.(string) == callID {
			portsToDelete = append(portsToDelete, key.(string))
		}
		return true
	})

	for _, port := range portsToDelete {
		lf.portToCallID.Delete(port)
	}
}

// startJanitor starts the background cleanup goroutine
func (lf *LockFreeCallTracker) startJanitor() {
	go func() {
		defer close(lf.janitorDone) // Signal completion when goroutine exits
		ticker := time.NewTicker(lf.config.JanitorCleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-lf.janitorCtx.Done():
				return
			case <-ticker.C:
				cleaned := lf.CleanupExpiredCalls()
				if cleaned > 0 {
					logger.Debug("Cleaned up expired calls",
						"count", cleaned,
						"active_calls", lf.activeCalls.Load())
				}
			}
		}
	}()
}

// Shutdown gracefully shuts down the tracker
func (lf *LockFreeCallTracker) Shutdown() {
	lf.shutdownOnce.Do(func() {
		logger.Info("Shutting down lock-free call tracker")

		lf.janitorCancel()

		// Wait for janitor goroutine to exit
		<-lf.janitorDone

		// Close all calls
		lf.callMap.Range(func(key, value interface{}) bool {
			lockFreeCall := value.(*LockFreeCallInfo)
			call := lockFreeCall.CallInfo
			if call.sipFile != nil {
				_ = call.sipFile.Close()
			}
			if call.rtpFile != nil {
				_ = call.rtpFile.Close()
			}
			return true
		})

		logger.Info("Lock-free call tracker shutdown complete")
	})
}

// CallTrackerStats holds statistics for the call tracker
type CallTrackerStats struct {
	TotalCalls    int64
	ActiveCalls   int64
	DroppedCalls  int64
	LastCleanupAt time.Time
}

// LockFreeCallInfo extends CallInfo with lock-free state management
type LockFreeCallInfo struct {
	*CallInfo
	stateAtomic atomic.Value // stores string
	lastUpdated atomic.Int64 // stores Unix nanoseconds
}

// newLockFreeCallInfo creates a new lock-free call info wrapper
func newLockFreeCallInfo(callInfo *CallInfo) *LockFreeCallInfo {
	lf := &LockFreeCallInfo{
		CallInfo: callInfo,
	}
	lf.stateAtomic.Store(callInfo.State)
	lf.lastUpdated.Store(callInfo.LastUpdated.UnixNano())
	return lf
}

// setStateLockFree updates call state using atomic operations
func (lf *LockFreeCallInfo) setStateLockFree(newState string) {
	lf.stateAtomic.Store(newState)
	lf.lastUpdated.Store(time.Now().UnixNano())

	// Note: We do NOT update lf.CallInfo.State and lf.CallInfo.LastUpdated here
	// because that would cause data races. Use getStateLockFree() instead to read state.
	// The underlying CallInfo fields are only synchronized when accessed through lock-free methods.
}

// getStateLockFree gets the current state atomically
func (lf *LockFreeCallInfo) getStateLockFree() string {
	return lf.stateAtomic.Load().(string)
}

// getLastUpdatedLockFree gets the last updated time atomically
func (lf *LockFreeCallInfo) getLastUpdatedLockFree() time.Time {
	nanos := lf.lastUpdated.Load()
	return time.Unix(0, nanos)
}

// getSnapshot returns a copy of the CallInfo with current atomic values
// This prevents data races when multiple readers access the same call
func (lf *LockFreeCallInfo) getSnapshot() *CallInfo {
	// Create a new CallInfo with safe-to-copy fields only (no mutexes)
	snapshot := &CallInfo{
		CallID:      lf.CallInfo.CallID,
		State:       lf.getStateLockFree(),
		Created:     lf.CallInfo.Created,
		LastUpdated: lf.getLastUpdatedLockFree(),
		LinkType:    lf.CallInfo.LinkType,
		SIPWriter:   lf.CallInfo.SIPWriter,
		RTPWriter:   lf.CallInfo.RTPWriter,
		sipFile:     lf.CallInfo.sipFile,
		rtpFile:     lf.CallInfo.rtpFile,
		// Note: We intentionally don't copy sipWriterMu and rtpWriterMu
		// as mutexes should never be copied. These fields will be zero-valued.
	}
	return snapshot
}

// Lock-free metric operations
type LockFreeMetrics struct {
	reads         atomic.Int64
	writes        atomic.Int64
	lookupMisses  atomic.Int64
	creations     atomic.Int64
	cleanups      atomic.Int64
	avgLookupTime atomic.Int64 // nanoseconds
}

var globalLockFreeMetrics LockFreeMetrics

// IncrementReads atomically increments read counter
func (m *LockFreeMetrics) IncrementReads() {
	m.reads.Add(1)
}

// IncrementWrites atomically increments write counter
func (m *LockFreeMetrics) IncrementWrites() {
	m.writes.Add(1)
}

// IncrementLookupMisses atomically increments lookup miss counter
func (m *LockFreeMetrics) IncrementLookupMisses() {
	m.lookupMisses.Add(1)
}

// IncrementCreations atomically increments creation counter
func (m *LockFreeMetrics) IncrementCreations() {
	m.creations.Add(1)
}

// IncrementCleanups atomically increments cleanup counter
func (m *LockFreeMetrics) IncrementCleanups() {
	m.cleanups.Add(1)
}

// UpdateAverageLookupTime updates the average lookup time using exponential moving average
func (m *LockFreeMetrics) UpdateAverageLookupTime(newTime int64) {
	for {
		current := m.avgLookupTime.Load()
		// Exponential moving average (α = 0.1)
		newAvg := current*9/10 + newTime/10
		if m.avgLookupTime.CompareAndSwap(current, newAvg) {
			break
		}
	}
}

// GetMetrics returns current metrics
func (m *LockFreeMetrics) GetMetrics() map[string]int64 {
	return map[string]int64{
		"reads":           m.reads.Load(),
		"writes":          m.writes.Load(),
		"lookup_misses":   m.lookupMisses.Load(),
		"creations":       m.creations.Load(),
		"cleanups":        m.cleanups.Load(),
		"avg_lookup_time": m.avgLookupTime.Load(),
	}
}

// Global lock-free tracker instance
var (
	globalLockFreeTracker    *LockFreeCallTracker
	lockFreeTrackerOnce      sync.Once
	lockFreeModeEnabled      atomic.Bool
	lockFreePerformanceGains atomic.Int64
)

// GetLockFreeTracker returns the global lock-free tracker instance
func GetLockFreeTracker() *LockFreeCallTracker {
	lockFreeTrackerOnce.Do(func() {
		globalLockFreeTracker = NewLockFreeCallTracker()
	})
	return globalLockFreeTracker
}

// EnableLockFreeMode enables lock-free optimizations globally
func EnableLockFreeMode() {
	lockFreeModeEnabled.Store(true)
	logger.Info("Lock-free optimizations enabled")
}

// DisableLockFreeMode disables lock-free optimizations globally
func DisableLockFreeMode() {
	lockFreeModeEnabled.Store(false)
	logger.Info("Lock-free optimizations disabled")
}

// IsLockFreeModeEnabled returns whether lock-free mode is enabled
func IsLockFreeModeEnabled() bool {
	return lockFreeModeEnabled.Load()
}

// GetLockFreeMetrics returns current lock-free metrics
func GetLockFreeMetrics() map[string]int64 {
	return globalLockFreeMetrics.GetMetrics()
}

// GetPerformanceGains returns the performance improvement factor
func GetPerformanceGains() int64 {
	return lockFreePerformanceGains.Load()
}

// SetPerformanceGains sets the performance improvement factor
func SetPerformanceGains(factor int64) {
	lockFreePerformanceGains.Store(factor)
}

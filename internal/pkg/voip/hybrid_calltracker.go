package voip

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// HybridCallTracker provides an interface that can switch between
// traditional locking and lock-free implementations at runtime
type HybridCallTracker struct {
	traditional *CallTracker
	lockFree    *LockFreeCallTracker
	enabled     atomic.Bool
}

// NewHybridCallTracker creates a new hybrid call tracker
func NewHybridCallTracker() *HybridCallTracker {
	return &HybridCallTracker{
		traditional: NewCallTracker(),
		lockFree:    NewLockFreeCallTracker(),
	}
}

// EnableLockFree switches to lock-free mode
func (h *HybridCallTracker) EnableLockFree() {
	h.enabled.Store(true)
	EnableLockFreeMode()
}

// DisableLockFree switches to traditional locking mode
func (h *HybridCallTracker) DisableLockFree() {
	h.enabled.Store(false)
	DisableLockFreeMode()
}

// IsLockFreeEnabled returns whether lock-free mode is active
func (h *HybridCallTracker) IsLockFreeEnabled() bool {
	return h.enabled.Load()
}

// GetCall retrieves a call by ID
func (h *HybridCallTracker) GetCall(callID string) (*CallInfo, error) {
	if h.enabled.Load() {
		start := time.Now()
		result, err := h.lockFree.GetCall(callID)
		globalLockFreeMetrics.UpdateAverageLookupTime(time.Since(start).Nanoseconds())
		globalLockFreeMetrics.IncrementReads()
		if err != nil {
			globalLockFreeMetrics.IncrementLookupMisses()
		}
		return result, err
	}
	return getCall(callID)
}

// GetOrCreateCall gets or creates a call
func (h *HybridCallTracker) GetOrCreateCall(callID string, linkType layers.LinkType) *CallInfo {
	if h.enabled.Load() {
		start := time.Now()
		result := h.lockFree.GetOrCreateCall(callID, linkType)
		globalLockFreeMetrics.UpdateAverageLookupTime(time.Since(start).Nanoseconds())
		if result != nil {
			globalLockFreeMetrics.IncrementWrites()
		}
		return result
	}
	return GetOrCreateCall(callID, linkType)
}

// SetCallState updates call state
func (h *HybridCallTracker) SetCallState(callID, newState string) {
	if h.enabled.Load() {
		h.lockFree.SetCallState(callID, newState)
		globalLockFreeMetrics.IncrementWrites()
		return
	}

	// Traditional method
	if call, err := getCall(callID); err == nil {
		call.SetCallInfoState(newState)
	}
}

// AddPortMapping adds a port to call ID mapping
func (h *HybridCallTracker) AddPortMapping(port, callID string) {
	if h.enabled.Load() {
		h.lockFree.AddPortMapping(port, callID)
		return
	}

	// Traditional method - direct access to tracker
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID[port] = callID
	tracker.mu.Unlock()
}

// GetCallIDByPort retrieves call ID by port
func (h *HybridCallTracker) GetCallIDByPort(port string) (string, bool) {
	if h.enabled.Load() {
		globalLockFreeMetrics.IncrementReads()
		return h.lockFree.GetCallIDByPort(port)
	}

	// Traditional method
	tracker := getTracker()
	tracker.mu.RLock()
	callID, exists := tracker.portToCallID[port]
	tracker.mu.RUnlock()
	return callID, exists
}

// RemovePortMapping removes a port mapping
func (h *HybridCallTracker) RemovePortMapping(port string) {
	if h.enabled.Load() {
		h.lockFree.RemovePortMapping(port)
		return
	}

	// Traditional method
	tracker := getTracker()
	tracker.mu.Lock()
	delete(tracker.portToCallID, port)
	tracker.mu.Unlock()
}

// CleanupExpiredCalls removes expired calls
func (h *HybridCallTracker) CleanupExpiredCalls() int {
	if h.enabled.Load() {
		count := h.lockFree.CleanupExpiredCalls()
		globalLockFreeMetrics.IncrementCleanups()
		return count
	}

	// Traditional cleanup - would need to implement in traditional tracker
	return 0
}

// GetStats returns tracker statistics
func (h *HybridCallTracker) GetStats() interface{} {
	if h.enabled.Load() {
		return h.lockFree.GetStats()
	}

	// Traditional stats would need to be implemented
	return map[string]interface{}{
		"mode": "traditional",
	}
}

// Shutdown gracefully shuts down both trackers
func (h *HybridCallTracker) Shutdown() {
	h.traditional.Shutdown()
	h.lockFree.Shutdown()
}

// Global hybrid tracker instance
var (
	globalHybridTracker *HybridCallTracker
	hybridTrackerOnce   sync.Once
)

// GetHybridTracker returns the global hybrid tracker
func GetHybridTracker() *HybridCallTracker {
	hybridTrackerOnce.Do(func() {
		globalHybridTracker = NewHybridCallTracker()
	})
	return globalHybridTracker
}

// Lock-free optimized versions of commonly used functions

// GetCallLockFree is a lock-free version of getCall
func GetCallLockFree(callID string) (*CallInfo, error) {
	if IsLockFreeModeEnabled() {
		return GetLockFreeTracker().GetCall(callID)
	}
	return getCall(callID)
}

// GetOrCreateCallLockFree is a lock-free version of GetOrCreateCall
func GetOrCreateCallLockFree(callID string, linkType layers.LinkType) *CallInfo {
	if IsLockFreeModeEnabled() {
		return GetLockFreeTracker().GetOrCreateCall(callID, linkType)
	}
	return GetOrCreateCall(callID, linkType)
}

// GetCallIDForPacketLockFree is a lock-free version of GetCallIDForPacket
func GetCallIDForPacketLockFree(packet gopacket.Packet) string {
	// Extract port information
	var srcPort, dstPort string

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort = udp.SrcPort.String()
		dstPort = udp.DstPort.String()
	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		srcPort = tcp.SrcPort.String()
		dstPort = tcp.DstPort.String()
	}

	if IsLockFreeModeEnabled() {
		tracker := GetLockFreeTracker()

		// Try source port first
		if callID, found := tracker.GetCallIDByPort(srcPort); found {
			return callID
		}

		// Try destination port
		if callID, found := tracker.GetCallIDByPort(dstPort); found {
			return callID
		}

		return ""
	}

	// Fall back to traditional method
	return GetCallIDForPacket(packet)
}

// AddPortMappingLockFree is a lock-free version of port mapping
func AddPortMappingLockFree(port, callID string) {
	if IsLockFreeModeEnabled() {
		GetLockFreeTracker().AddPortMapping(port, callID)
		return
	}

	// Traditional method
	tracker := getTracker()
	tracker.mu.Lock()
	tracker.portToCallID[port] = callID
	tracker.mu.Unlock()
}
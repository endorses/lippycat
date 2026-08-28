package voip

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	// maxSanitizationIterations limits the number of sanitization passes to prevent
	// infinite loops from adversarial inputs with recursive dangerous patterns
	maxSanitizationIterations = 10
)

var (
	// ErrShuttingDown is returned when attempting to write during shutdown
	ErrShuttingDown = errors.New("call tracker is shutting down")
)

// CallInfo contains registry state for a VoIP call. Output resources are owned
// by the CallOutput service injected into its tracker.
type CallInfo struct {
	CallID      string
	State       string
	Created     time.Time
	LastUpdated time.Time
	EndTime     *time.Time // Set when BYE/CANCEL is detected
	LinkType    layers.LinkType
	tracker     *CallTracker
}

func (c *CallInfo) writeSIP(packet gopacket.Packet) error {
	if c.tracker == nil {
		return ErrWriterNotInitialized
	}
	return c.tracker.output.WritePacket(c.CallID, packet, PacketTypeSIP)
}
func (c *CallInfo) writeRTP(packet gopacket.Packet) error {
	if c.tracker == nil {
		return ErrWriterNotInitialized
	}
	return c.tracker.output.WritePacket(c.CallID, packet, PacketTypeRTP)
}

// Close emits a lifecycle callback; CallInfo itself owns no resources.
func (c *CallInfo) Close() error {
	if c.tracker == nil {
		return nil
	}
	return c.tracker.output.CloseSession(c.CallID)
}

// removeCall detaches a call and all tracker-owned indexes before closing it.
// Closing after releasing ct.mu is required by CallInfo's lock ordering rule.
func (ct *CallTracker) removeCall(callID string) (bool, error) {
	ct.mu.Lock()
	call, exists := ct.callMap[callID]
	if exists {
		delete(ct.callMap, callID)
		delete(ct.pins, callID)
		if elem := ct.lruIndex[callID]; elem != nil {
			ct.lruList.Remove(elem)
			delete(ct.lruIndex, callID)
		}
		for port, callIDs := range ct.portToCallID {
			kept := callIDs[:0]
			for _, id := range callIDs {
				if id != callID {
					kept = append(kept, id)
				}
			}
			if len(kept) == 0 {
				delete(ct.portToCallID, port)
			} else {
				ct.portToCallID[port] = kept
			}
		}
		ct.recency.Delete(callID)
	}
	ct.mu.Unlock()
	if !exists || call == nil {
		return exists, nil
	}
	return true, ct.output.CloseSession(callID)
}

type CallTracker struct {
	callMap           map[string]*CallInfo
	portToCallID      map[string][]string      // key = port, value = []CallID (multi-value for B2BUA)
	lruList           *list.List               // LRU list (front = most recently used)
	lruIndex          map[string]*list.Element // callID -> list element for O(1) lookup
	pins              map[string]int           // callID -> active retention leases
	recency           sync.Map                 // callID -> *atomic.Int64 Unix nanoseconds; RTP fast path
	maxCalls          int                      // Maximum calls to keep
	lastPinnedWarning time.Time
	mu                sync.RWMutex
	janitorCtx        context.Context
	janitorCancel     context.CancelFunc
	janitorStarted    bool
	janitorWG         sync.WaitGroup
	shutdownOnce      sync.Once
	config            *Config
	output            CallOutput
	completionMonitor *SniffCompletionMonitor
	asyncWriterMu     sync.Mutex
	asyncWriter       interface{ Stop() error }
	shuttingDown      atomic.Int32   // Atomic flag: 1 if shutting down, 0 otherwise
	activeWrites      sync.WaitGroup // Tracks active write operations
}

func (ct *CallTracker) registerEndpoint(endpoint, callID string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	for _, existing := range ct.portToCallID[endpoint] {
		if existing == callID {
			return
		}
	}
	ct.portToCallID[endpoint] = append(ct.portToCallID[endpoint], callID)
}

func NewCallTracker() *CallTracker {
	return NewCallTrackerWithConfig(GetConfig())
}

// NewCallTrackerWithConfig creates a tracker with an immutable configuration
// snapshot. Subsequent SetConfig calls do not affect the tracker.
func NewCallTrackerWithConfig(config *Config) *CallTracker {
	return NewCallTrackerWithOutput(config, nil)
}

// NewCallTrackerWithOutput injects the output lifecycle service used by the
// registry. A nil service selects the configured session output or a no-op.
func NewCallTrackerWithOutput(config *Config, output CallOutput) *CallTracker {
	if config == nil {
		config = DefaultConfig()
	}
	clone := *config
	clone.PluginPaths = append([]string(nil), config.PluginPaths...)
	if output == nil {
		if clone.WriteVoIP {
			output = NewSessionOutputManager(&clone)
		} else {
			output = NoopCallOutput{}
		}
	}
	return newCallTracker(&clone, clone.MaxCalls, output)
}

// NewCallTrackerWithCapacity creates a tracker with the configured hard cap.
func NewCallTrackerWithCapacity(maxCalls int) *CallTracker {
	return newCallTracker(GetConfig(), maxCalls, NoopCallOutput{})
}

func newCallTracker(config *Config, maxCalls int, output CallOutput) *CallTracker {
	ctx, cancel := context.WithCancel(context.Background())
	if maxCalls <= 0 {
		maxCalls = DefaultMaxCalls
	}
	tracker := &CallTracker{
		callMap:        make(map[string]*CallInfo),
		portToCallID:   make(map[string][]string),
		lruList:        list.New(),
		lruIndex:       make(map[string]*list.Element),
		pins:           make(map[string]int),
		maxCalls:       maxCalls,
		janitorCtx:     ctx,
		janitorCancel:  cancel,
		janitorStarted: false,
		config:         config,
		output:         output,
	}

	tracker.startJanitor()

	return tracker
}

// PinCall acquires a generic retention lease. It is safe to pin before the call
// is observed; the lease protects it as soon as it enters the tracker.
func (ct *CallTracker) PinCall(callID string) {
	if callID == "" {
		return
	}
	ct.mu.Lock()
	ct.pins[callID]++
	ct.mu.Unlock()
}

// UnpinCall releases one retention lease.
func (ct *CallTracker) UnpinCall(callID string) {
	if callID == "" {
		return
	}
	ct.mu.Lock()
	if ct.pins[callID] <= 1 {
		delete(ct.pins, callID)
	} else {
		ct.pins[callID]--
	}
	ct.mu.Unlock()
}
func (ct *CallTracker) IsPinned(callID string) bool {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.pins[callID] > 0
}

func (ct *CallTracker) startJanitor() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if !ct.janitorStarted {
		ct.janitorWG.Add(1)
		go ct.janitorLoop()
		ct.janitorStarted = true
	}
}

// Shutdown gracefully shuts down the call tracker
func (ct *CallTracker) Shutdown() {
	ct.shutdownOnce.Do(func() {
		// Signal shutdown to prevent new writes
		ct.shuttingDown.Store(1)
		logger.Info("Call tracker shutdown initiated, waiting for active writes to complete")

		// Cancel janitor goroutine
		if ct.janitorCancel != nil {
			ct.janitorCancel()
		}
		ct.janitorWG.Wait()

		ct.closeAsyncWriter()

		// Wait for all active writes to complete
		ct.activeWrites.Wait()
		logger.Info("All active writes completed, closing call files")

		// Now safe to close all files
		ct.mu.Lock()
		callIDs := make([]string, 0, len(ct.callMap))
		for id, call := range ct.callMap {
			_ = call
			callIDs = append(callIDs, id)
			delete(ct.callMap, id)
			ct.recency.Delete(id)
		}
		ct.mu.Unlock()
		for _, id := range callIDs {
			if err := ct.output.CloseSession(id); err != nil {
				logger.Error("Failed to close call output", "call_id", SanitizeCallIDForLogging(id), "error", err)
			}
		}
		if err := ct.output.Shutdown(); err != nil {
			logger.Error("Failed to shut down call output", "error", err)
		}
		logger.Info("Call tracker shutdown complete")
	})
}

func (c *CallInfo) SetCallInfoState(newState string) {
	tracker := c.tracker
	if tracker == nil {
		return
	}
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	c.State = newState
	c.LastUpdated = time.Now()

	// If this is a call termination message (BYE or CANCEL), set EndTime
	if newState == "BYE" || newState == "CANCEL" {
		if c.EndTime == nil {
			now := time.Now()
			c.EndTime = &now
			logger.Debug("Call terminated",
				"call_id", SanitizeCallIDForLogging(c.CallID),
				"method", newState,
				"duration", now.Sub(c.Created))

			// Schedule PCAP closure via this tracker's completion monitor.
			if monitor := tracker.completionMonitor; monitor != nil {
				monitor.ScheduleClose(c.CallID)
			}
		}
	}
}

// GetCall retrieves a call owned by this tracker.
func (tracker *CallTracker) GetCall(callID string) (*CallInfo, error) {
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	result, exists := tracker.callMap[callID]
	if !exists {
		return nil, errors.New("the CallID does not exist")
	}

	return result, nil
}

// IsCallActive checks if a call with the given Call-ID is currently active.
// A call is considered active if it exists and has not received a BYE or CANCEL.
// This is used by call-aware TCP timeouts to keep connections open for active calls.
// IsCallActive reports whether this tracker owns a call which has not ended.
func (tracker *CallTracker) IsCallActive(callID string) bool {
	if callID == "" {
		return false
	}

	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	call, exists := tracker.callMap[callID]
	if !exists {
		return false
	}

	// Call is active if EndTime is not set (no BYE/CANCEL received)
	return call.EndTime == nil
}

// GetOrCreateCall returns the existing call or creates one owned by this tracker.
func (tracker *CallTracker) GetOrCreateCall(callID string, linkType layers.LinkType) *CallInfo {
	return tracker.getOrCreateCall(callID, linkType)
}

func (tracker *CallTracker) getOrCreateCall(callID string, linkType layers.LinkType) *CallInfo {
	// Existing calls dominate the RTP packet path. Refresh their eviction
	// recency atomically so every media packet does not take the tracker-wide
	// write lock merely to promote an LRU element.
	tracker.mu.RLock()
	call, exists := tracker.callMap[callID]
	if exists {
		tracker.touchCall(callID)
		tracker.mu.RUnlock()
		return call
	}
	tracker.mu.RUnlock()

	tracker.mu.Lock()
	var evicted *CallInfo

	call, exists = tracker.callMap[callID]
	if !exists {
		// Enforce the capacity before allocating output resources. Pinned calls
		// cannot be evicted, so admission fails when every resident is pinned.
		if tracker.lruList.Len() >= tracker.maxCalls && tracker.leastRecentUnpinnedLocked() == nil {
			if time.Since(tracker.lastPinnedWarning) > time.Minute {
				tracker.lastPinnedWarning = time.Now()
				logger.Warn("call tracker capacity reached; rejecting call because all calls are pinned", "max_calls", tracker.maxCalls)
			}
			tracker.mu.Unlock()
			return nil
		}
		call = &CallInfo{
			CallID:      callID,
			State:       "NEW",
			Created:     time.Now(),
			LastUpdated: time.Now(),
			LinkType:    linkType,
			tracker:     tracker,
		}
		if tracker.config.WriteVoIP {
			if err := tracker.output.OpenSession(callID, linkType); err != nil {
				logger.Error("Failed to initialize writers for call",
					"call_id", SanitizeCallIDForLogging(callID),
					"error", err)
				// Don't track call if we can't write it - prevents silent data loss
				tracker.mu.Unlock()
				return nil
			}
		}

		// Evict LRU (least recently used) if at capacity
		if tracker.lruList.Len() >= tracker.maxCalls {
			// Prefer an unpinned inactive call, then any unpinned LRU call.
			var oldest *list.Element
			for e := tracker.lruList.Back(); e != nil; e = e.Prev() {
				id := e.Value.(string)
				if tracker.pins[id] == 0 && tracker.callMap[id] != nil && tracker.callMap[id].EndTime != nil {
					oldest = e
					break
				}
			}
			if oldest == nil {
				oldest = tracker.leastRecentUnpinnedLocked()
			}
			if oldest != nil {
				oldestCallID := oldest.Value.(string)
				oldCall := tracker.callMap[oldestCallID]

				// Detach the old call while holding the tracker lock. It is closed
				// only after releasing that lock, per the documented lock order.
				if oldCall != nil {
					evicted = oldCall
					// Remove from port mapping
					for port, callIDs := range tracker.portToCallID {
						for i, cid := range callIDs {
							if cid == oldestCallID {
								// Remove this call ID from the slice
								tracker.portToCallID[port] = append(callIDs[:i], callIDs[i+1:]...)
								break
							}
						}
						// Clean up empty slices
						if len(tracker.portToCallID[port]) == 0 {
							delete(tracker.portToCallID, port)
						}
					}
					delete(tracker.callMap, oldestCallID)
					tracker.recency.Delete(oldestCallID)
				}
				tracker.lruList.Remove(oldest)
				delete(tracker.lruIndex, oldestCallID)
				logger.Debug("Evicted LRU call (buffer full)",
					"call_id", SanitizeCallIDForLogging(oldestCallID))
			}
		}

		// Add new call to front (most recently used)
		elem := tracker.lruList.PushFront(callID)
		tracker.lruIndex[callID] = elem
		tracker.callMap[callID] = call
		tracker.touchCall(callID)
	} else {
		tracker.touchCall(callID)
	}
	tracker.mu.Unlock()
	if evicted != nil {
		if err := tracker.output.CloseSession(evicted.CallID); err != nil {
			logger.Error("Error closing call files", "call_id", SanitizeCallIDForLogging(evicted.CallID), "error", err)
		}
	}
	return call
}

func (ct *CallTracker) touchCall(callID string) {
	value, _ := ct.recency.LoadOrStore(callID, &atomic.Int64{})
	value.(*atomic.Int64).Store(time.Now().UnixNano())
}

// leastRecentUnpinnedLocked chooses using atomic packet recency while retaining
// list order as a deterministic fallback for calls created by older/test paths.
func (ct *CallTracker) leastRecentUnpinnedLocked() *list.Element {
	var selected *list.Element
	var selectedAt int64
	for e := ct.lruList.Back(); e != nil; e = e.Prev() {
		id := e.Value.(string)
		if ct.pins[id] != 0 {
			continue
		}
		at := int64(0)
		if value, ok := ct.recency.Load(id); ok {
			at = value.(*atomic.Int64).Load()
		}
		if selected == nil || at < selectedAt {
			selected, selectedAt = e, at
		}
	}
	return selected
}

func sanitize(id string) string {
	return sanitizeWithMaxLength(id, GetConfig().MaxFilenameLength)
}

func sanitizeWithMaxLength(id string, maxLen int) string {
	// Handle empty string case
	if id == "" {
		return "safe_filename"
	}

	// Normalize Unicode to prevent normalization attacks
	cleaned := normalizeUnicode(id)

	// Iteratively clean dangerous patterns until no more changes occur
	for i := 0; i < maxSanitizationIterations; i++ {
		previous := cleaned

		// Replace ".." sequences first (before individual dots)
		cleaned = strings.ReplaceAll(cleaned, "..", "__")

		// Replace potentially dangerous characters
		cleaned = strings.ReplaceAll(cleaned, "\\", "_")
		cleaned = strings.ReplaceAll(cleaned, "/", "_")
		cleaned = strings.ReplaceAll(cleaned, "@", "_")
		cleaned = strings.ReplaceAll(cleaned, ":", "_")
		cleaned = strings.ReplaceAll(cleaned, "*", "_")
		cleaned = strings.ReplaceAll(cleaned, "?", "_")
		cleaned = strings.ReplaceAll(cleaned, "<", "_")
		cleaned = strings.ReplaceAll(cleaned, ">", "_")
		cleaned = strings.ReplaceAll(cleaned, "|", "_")
		cleaned = strings.ReplaceAll(cleaned, "\"", "_")

		// If no changes were made, we're done
		if cleaned == previous {
			break
		}
	}

	// Remove null bytes and other control characters
	cleaned = removeControlCharacters(cleaned)

	// Limit length to prevent filesystem issues (configurable)
	if maxLen > 0 && len(cleaned) > maxLen {
		cleaned = cleaned[:maxLen]
	}

	// Apply filepath.Clean for additional security
	cleaned = filepath.Clean(cleaned)

	// If cleaning resulted in empty string or dangerous paths, use safe default
	if cleaned == "" || cleaned == "." || cleaned == ".." || strings.Contains(cleaned, "..") {
		return "safe_filename"
	}

	return cleaned
}

// normalizeUnicode normalizes unicode strings to prevent normalization attacks
func normalizeUnicode(s string) string {
	if !utf8.ValidString(s) {
		// Replace invalid UTF-8 sequences
		return strings.ToValidUTF8(s, "_")
	}

	// Normalize to NFC (Canonical Decomposition, followed by Canonical Composition)
	// This prevents attacks using different unicode representations of the same string
	var normalized strings.Builder
	for _, r := range s {
		// Skip non-printable characters except common whitespace
		if unicode.IsPrint(r) || r == ' ' || r == '\t' {
			normalized.WriteRune(r)
		} else {
			normalized.WriteString("_")
		}
	}

	return normalized.String()
}

// removeControlCharacters removes control characters that could be dangerous in filenames
func removeControlCharacters(s string) string {
	var cleaned strings.Builder
	for _, r := range s {
		// Keep printable characters and safe whitespace
		if unicode.IsPrint(r) || r == ' ' {
			cleaned.WriteRune(r)
		} else {
			cleaned.WriteString("_")
		}
	}
	return cleaned.String()
}

func (ct *CallTracker) janitorLoop() {
	defer ct.janitorWG.Done()
	ticker := time.NewTicker(ct.config.JanitorCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ct.janitorCtx.Done():
			logger.Info("Call tracker janitor shutting down")
			return
		case <-ticker.C:
			ct.cleanupOldCalls()
		}
	}
}

func (ct *CallTracker) cleanupOldCalls() {
	// Ring buffer now handles call cleanup (FIFO when buffer is full)
	// This function is kept for potential future maintenance tasks
	// but does not expire calls based on time anymore
}

// getCapturesDir returns a safe absolute path for the captures directory
func getCapturesDir() (string, error) {
	// Try XDG data directory first (Linux standard)
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "lippycat", "captures"), nil
	}

	// Fall back to user's home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}

	return filepath.Join(homeDir, ".local", "share", "lippycat", "captures"), nil
}

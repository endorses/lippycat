package voip

import (
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

	"github.com/endorses/lippycat/internal/pkg/callregistry"
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

// CallLifecycleObserver owns side effects caused by registry admission and
// removal. The registry itself owns only call/index state.
type CallLifecycleObserver interface {
	OnCallStarted(*CallInfo) error
	OnCallEnded(*CallInfo) error
}

type callOutputLifecycleAdapter struct{ output CallOutput }

func (a callOutputLifecycleAdapter) OnCallStarted(call *CallInfo) error {
	return a.output.OpenSession(call.CallID, call.LinkType)
}
func (a callOutputLifecycleAdapter) OnCallEnded(call *CallInfo) error {
	return a.output.CloseSession(call.CallID)
}

func (c *CallInfo) writeSIP(packet gopacket.Packet) error {
	if c.tracker == nil {
		return ErrWriterNotInitialized
	}
	return c.tracker.writePacket(c.CallID, packet, PacketTypeSIP)
}
func (c *CallInfo) writeRTP(packet gopacket.Packet) error {
	if c.tracker == nil {
		return ErrWriterNotInitialized
	}
	return c.tracker.writePacket(c.CallID, packet, PacketTypeRTP)
}

// Close emits a lifecycle callback; CallInfo itself owns no resources.
func (c *CallInfo) Close() error {
	if c.tracker == nil {
		return nil
	}
	_, err := c.tracker.removeCall(c.CallID)
	return err
}

// removeCall detaches a call and all tracker-owned indexes before closing it.
// Closing after releasing ct.mu is required by CallInfo's lock ordering rule.
func (ct *CallTracker) removeCall(callID string) (bool, error) {
	ct.lifecycleMu.Lock()
	defer ct.lifecycleMu.Unlock()
	ct.mu.Lock()
	call := ct.detachCallLocked(callID)
	ct.mu.Unlock()
	if call == nil {
		return false, nil
	}
	return true, ct.notifyCallEnded(call)
}

func (ct *CallTracker) removeCallIf(callID string, expected *CallInfo) (bool, error) {
	ct.lifecycleMu.Lock()
	defer ct.lifecycleMu.Unlock()
	ct.mu.Lock()
	if expected != nil && ct.callMap[callID] != expected {
		ct.mu.Unlock()
		return false, nil
	}
	call := ct.detachCallLocked(callID)
	ct.mu.Unlock()
	if call == nil {
		return false, nil
	}
	return true, ct.notifyCallEnded(call)
}

func (ct *CallTracker) detachCallLocked(callID string) *CallInfo {
	call := ct.callMap[callID]
	if call == nil {
		return nil
	}
	delete(ct.callMap, callID)
	if timer := ct.completionTimers[callID]; timer != nil {
		timer.Stop()
		delete(ct.completionTimers, callID)
	}
	ct.registry.Remove(callID, callregistry.EndCompleted)
	return call
}

type CallTracker struct {
	callMap            map[string]*CallInfo
	registry           *callregistry.Core
	maxCalls           int // Maximum calls to keep
	lastPinnedWarning  time.Time
	mu                 sync.RWMutex
	lifecycleMu        sync.Mutex // Serializes registry mutations with lifecycle callbacks.
	janitorCtx         context.Context
	janitorCancel      context.CancelFunc
	janitorStarted     bool
	janitorWG          sync.WaitGroup
	shutdownOnce       sync.Once
	config             *Config
	writePacket        func(string, gopacket.Packet, PacketType) error
	lifecycleObservers []CallLifecycleObserver
	completionTimers   map[string]*time.Timer // callID -> exact-generation completion timer
	asyncWriterMu      sync.Mutex
	asyncWriter        interface{ Stop() error }
	shuttingDown       atomic.Int32   // Atomic flag: 1 if shutting down, 0 otherwise
	writeGateMu        sync.Mutex     // Serializes write admission with closing activeWrites
	writesClosed       bool           // Protected by writeGateMu
	activeWrites       sync.WaitGroup // Tracks active write operations
}

func (ct *CallTracker) registerEndpoint(endpoint, callID string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.registerEndpointLocked(endpoint, callID)
}

func (ct *CallTracker) registerEndpointLocked(endpoint, callID string) bool {
	if endpoint == "" || callID == "" || ct.callMap[callID] == nil {
		return false
	}
	for _, existing := range ct.registry.CallIDsForEndpoint(endpoint) {
		if existing == callID {
			return true
		}
	}
	if _, ok := ct.registry.Call(callID); !ok {
		call := ct.callMap[callID]
		ct.registry.Upsert(callregistry.Call{CallID: call.CallID, State: call.State, Created: call.Created, LastUpdated: call.LastUpdated})
	}
	if !ct.registry.TryAssociateEndpoint(callID, endpoint) {
		return false
	}
	return true
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
	if output == nil {
		output = NoopCallOutput{}
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
	if config.MaxEndpointsPerCall <= 0 {
		config.MaxEndpointsPerCall = 64
	}
	if config.MaxEndpointAssociations <= 0 {
		config.MaxEndpointAssociations = maxCalls * 8
	}
	tracker := &CallTracker{
		callMap: make(map[string]*CallInfo),
		registry: callregistry.New(callregistry.Config{
			MaxCalls: maxCalls, MaxEndpointsPerCall: config.MaxEndpointsPerCall,
			MaxEndpointAssociations: config.MaxEndpointAssociations,
			EvictionPriority: func(call callregistry.Call) int {
				if call.State == "BYE" || call.State == "CANCEL" {
					return 1
				}
				return 0
			},
		}),
		maxCalls:         maxCalls,
		janitorCtx:       ctx,
		janitorCancel:    cancel,
		janitorStarted:   false,
		config:           config,
		writePacket:      output.WritePacket,
		completionTimers: make(map[string]*time.Timer),
	}
	if observer, ok := output.(CallLifecycleObserver); ok {
		tracker.lifecycleObservers = append(tracker.lifecycleObservers, observer)
	} else {
		tracker.lifecycleObservers = append(tracker.lifecycleObservers, callOutputLifecycleAdapter{output: output})
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
	ct.registry.Pin(callID)
}

// UnpinCall releases one retention lease.
func (ct *CallTracker) UnpinCall(callID string) {
	if callID == "" {
		return
	}
	ct.registry.Unpin(callID)
}
func (ct *CallTracker) IsPinned(callID string) bool {
	return ct.registry.IsPinned(callID)
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

		// No async worker can start another accepted write after Stop returns.
		// Close the synchronous admission gate before waiting, so Add can never
		// race with Wait.
		ct.writeGateMu.Lock()
		ct.writesClosed = true
		ct.writeGateMu.Unlock()

		// Wait for all active writes to complete
		ct.activeWrites.Wait()
		logger.Info("All active writes completed, closing call files")

		// Now safe to close all files
		ct.lifecycleMu.Lock()
		ct.mu.Lock()
		for id, timer := range ct.completionTimers {
			timer.Stop()
			delete(ct.completionTimers, id)
		}
		calls := make([]*CallInfo, 0, len(ct.callMap))
		for id, call := range ct.callMap {
			calls = append(calls, call)
			delete(ct.callMap, id)
		}
		ct.mu.Unlock()
		ct.registry.Close()
		for _, call := range calls {
			if err := ct.notifyCallEnded(call); err != nil {
				logger.Error("Failed to close call output", "call_id", SanitizeCallIDForLogging(call.CallID), "error", err)
			}
		}
		ct.lifecycleMu.Unlock()
		logger.Info("Call tracker shutdown complete")
	})
}

func (c *CallInfo) SetCallInfoState(newState string) {
	tracker := c.tracker
	if tracker == nil {
		return
	}
	tracker.mu.Lock()

	c.State = newState
	c.LastUpdated = time.Now()
	tracker.registry.Upsert(callregistry.Call{CallID: c.CallID, State: c.State, Created: c.Created, LastUpdated: c.LastUpdated})
	notifyEnded := false

	// If this is a call termination message (BYE or CANCEL), set EndTime
	if newState == "BYE" || newState == "CANCEL" {
		if c.EndTime == nil {
			now := time.Now()
			c.EndTime = &now
			logger.Debug("Call terminated",
				"call_id", SanitizeCallIDForLogging(c.CallID),
				"method", newState,
				"duration", now.Sub(c.Created))

			notifyEnded = true
		}
	}
	tracker.mu.Unlock()
	if notifyEnded {
		tracker.scheduleCallCompletion(c)
	}
}

// scheduleCallCompletion keeps the call admitted for a short trailing-media
// grace period, then removes that exact registry generation. A reused Call-ID
// can therefore never be closed by an older dialog's completion callback.
func (ct *CallTracker) scheduleCallCompletion(call *CallInfo) {
	gracePeriod := ct.config.PCAPGracePeriod
	if gracePeriod <= 0 {
		gracePeriod = 5 * time.Second
	}
	ct.mu.Lock()
	if ct.shuttingDown.Load() != 0 || ct.callMap[call.CallID] != call {
		ct.mu.Unlock()
		return
	}
	if timer := ct.completionTimers[call.CallID]; timer != nil {
		timer.Stop()
	}
	ct.completionTimers[call.CallID] = time.AfterFunc(gracePeriod, func() {
		found, err := ct.removeCallIf(call.CallID, call)
		if err != nil {
			logger.Error("Failed to complete call lifecycle", "call_id", SanitizeCallIDForLogging(call.CallID), "error", err)
		} else if found {
			logger.Debug("Completed call lifecycle", "call_id", SanitizeCallIDForLogging(call.CallID))
		}
	})
	ct.mu.Unlock()
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
	if tracker.shuttingDown.Load() != 0 {
		return nil
	}
	tracker.mu.RLock()
	call, exists := tracker.callMap[callID]
	if exists {
		tracker.mu.RUnlock()
		tracker.registry.Touch(callID, time.Now())
		return call
	}
	tracker.mu.RUnlock()

	tracker.lifecycleMu.Lock()
	defer tracker.lifecycleMu.Unlock()
	tracker.mu.Lock()
	if tracker.shuttingDown.Load() != 0 {
		tracker.mu.Unlock()
		return nil
	}

	call, exists = tracker.callMap[callID]
	if !exists {
		call = &CallInfo{
			CallID:      callID,
			State:       "NEW",
			Created:     time.Now(),
			LastUpdated: time.Now(),
			LinkType:    linkType,
			tracker:     tracker,
		}
		before := tracker.registry.ActiveCalls()
		if !tracker.registry.Upsert(callregistry.Call{
			CallID: call.CallID, State: call.State, Created: call.Created, LastUpdated: call.LastUpdated,
		}) {
			tracker.mu.Unlock()
			return nil
		}
		for _, prior := range before {
			if _, retained := tracker.registry.Call(prior.CallID); !retained {
				if old := tracker.callMap[prior.CallID]; old != nil {
					delete(tracker.callMap, prior.CallID)
					tracker.mu.Unlock()
					_ = tracker.notifyCallEnded(old)
					tracker.mu.Lock()
				}
			}
		}
		tracker.callMap[callID] = call
	}
	tracker.mu.Unlock()
	if !exists {
		// Lifecycle observers describe registry admission, independently of whether
		// packet output is enabled. Invoke them only after publishing the call and
		// releasing the registry lock so observers may safely query the registry.
		if err := tracker.notifyCallStarted(call); err != nil {
			logger.Error("Failed to initialize call lifecycle",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
			// Roll back the exact generation that failed to initialize. End
			// notification lets observers which started successfully release any
			// resources they allocated before a later observer returned an error.
			tracker.mu.Lock()
			var failedCall *CallInfo
			if tracker.callMap[callID] == call {
				failedCall = tracker.detachCallLocked(callID)
			}
			tracker.mu.Unlock()
			if failedCall != nil {
				if removeErr := tracker.notifyCallEnded(failedCall); removeErr != nil {
					logger.Error("Failed to roll back call lifecycle",
						"call_id", SanitizeCallIDForLogging(callID),
						"error", removeErr)
				}
			}
			return nil
		}
	}
	return call
}

func (ct *CallTracker) notifyCallStarted(call *CallInfo) error {
	for _, observer := range ct.lifecycleObservers {
		if err := observer.OnCallStarted(call); err != nil {
			return err
		}
	}
	return nil
}

func (ct *CallTracker) replaceOutputForTest(output CallOutput) {
	ct.writePacket = output.WritePacket
	ct.lifecycleObservers = ct.lifecycleObservers[:0]
	if observer, ok := output.(CallLifecycleObserver); ok {
		ct.lifecycleObservers = append(ct.lifecycleObservers, observer)
	} else {
		ct.lifecycleObservers = append(ct.lifecycleObservers, callOutputLifecycleAdapter{output: output})
	}
}

func (ct *CallTracker) notifyCallEnded(call *CallInfo) error {
	for _, observer := range ct.lifecycleObservers {
		if err := observer.OnCallEnded(call); err != nil {
			return err
		}
	}
	return nil
}

func (ct *CallTracker) touchCall(callID string) {
	ct.registry.Touch(callID, time.Now())
}

// beginWrite admits a synchronous write only while shutdown has not begun.
// Holding writeGateMu across Add makes the transition to WaitGroup.Wait safe.
func (ct *CallTracker) beginWrite() bool {
	ct.writeGateMu.Lock()
	defer ct.writeGateMu.Unlock()
	if ct.writesClosed || ct.shuttingDown.Load() != 0 {
		return false
	}
	ct.activeWrites.Add(1)
	return true
}

// beginAcceptedWrite accounts for work already accepted by the async queue.
// Shutdown stops and drains that queue before closing the admission gate.
func (ct *CallTracker) beginAcceptedWrite() bool {
	ct.writeGateMu.Lock()
	defer ct.writeGateMu.Unlock()
	if ct.writesClosed {
		return false
	}
	ct.activeWrites.Add(1)
	return true
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
	if ct.config.CallExpirationTime <= 0 {
		return
	}
	cutoff := time.Now().Add(-ct.config.CallExpirationTime)
	ct.lifecycleMu.Lock()
	defer ct.lifecycleMu.Unlock()
	ct.mu.Lock()
	expired := make([]*CallInfo, 0)
	for _, registryCall := range ct.registry.ExpiredUnpinned(cutoff) {
		if call := ct.callMap[registryCall.CallID]; call != nil {
			expired = append(expired, ct.detachCallLocked(registryCall.CallID))
		}
	}
	ct.mu.Unlock()
	for _, call := range expired {
		if call == nil {
			continue
		}
		err := ct.notifyCallEnded(call)
		if err != nil {
			logger.Error("Failed to close expired call output", "call_id", SanitizeCallIDForLogging(call.CallID), "error", err)
		} else {
			logger.Debug("Expired inactive call", "call_id", SanitizeCallIDForLogging(call.CallID))
		}
	}
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

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

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/signals"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
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

// CallInfo contains information about a VoIP call and manages PCAP file writing.
//
// Thread Safety:
// - SIPWriter and sipFile must be accessed only while holding sipWriterMu
// - RTPWriter and rtpFile must be accessed only while holding rtpWriterMu
// - All other fields (CallID, State, etc.) are protected by CallTracker.mu
//
// Mutex Usage Pattern:
// Always lock the appropriate writer mutex before accessing the writer or file:
//
//	call.sipWriterMu.Lock()
//	err := call.SIPWriter.WritePacket(...)
//	call.sipWriterMu.Unlock()
//
// The Close() method handles all locking internally and is safe to call
// concurrently and multiple times (idempotent).
type CallInfo struct {
	CallID      string
	State       string
	Created     time.Time
	LastUpdated time.Time
	EndTime     *time.Time // Set when BYE/CANCEL is detected
	LinkType    layers.LinkType
	SIPWriter   *pcapgo.Writer
	RTPWriter   *pcapgo.Writer
	sipFile     *os.File
	rtpFile     *os.File
	sipWriterMu sync.Mutex // Protects SIPWriter and sipFile access
	rtpWriterMu sync.Mutex // Protects RTPWriter and rtpFile access
}

// Close safely closes all PCAP writers and files for this call with proper locking.
// This method is safe to call concurrently and idempotent.
func (c *CallInfo) Close() error {
	var firstErr error

	// Close SIP file (with mutex protection)
	c.sipWriterMu.Lock()
	if c.sipFile != nil {
		if err := c.sipFile.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close SIP file: %w", err)
		}
		c.sipFile = nil
		c.SIPWriter = nil
	}
	c.sipWriterMu.Unlock()

	// Close RTP file (with mutex protection)
	c.rtpWriterMu.Lock()
	if c.rtpFile != nil {
		if err := c.rtpFile.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to close RTP file: %w", err)
		}
		c.rtpFile = nil
		c.RTPWriter = nil
	}
	c.rtpWriterMu.Unlock()

	return firstErr
}

type CallTracker struct {
	callMap           map[string]*CallInfo
	portToCallID      map[string]string        // key = port, value = CallID
	lruList           *list.List               // LRU list (front = most recently used)
	lruIndex          map[string]*list.Element // callID -> list element for O(1) lookup
	maxCalls          int                      // Maximum calls to keep
	mu                sync.RWMutex
	janitorCtx        context.Context
	janitorCancel     context.CancelFunc
	janitorStarted    bool
	shutdownOnce      sync.Once
	signalHandlerOnce sync.Once
	config            *Config
	shuttingDown      atomic.Int32   // Atomic flag: 1 if shutting down, 0 otherwise
	activeWrites      sync.WaitGroup // Tracks active write operations
}

var (
	defaultTracker *CallTracker
	trackerOnce    sync.Once
)

func getTracker() *CallTracker {
	trackerOnce.Do(func() {
		defaultTracker = NewCallTracker()
	})
	return defaultTracker
}

func NewCallTracker() *CallTracker {
	ctx, cancel := context.WithCancel(context.Background())
	maxCalls := DefaultMaxCalls
	tracker := &CallTracker{
		callMap:        make(map[string]*CallInfo),
		portToCallID:   make(map[string]string),
		lruList:        list.New(),
		lruIndex:       make(map[string]*list.Element),
		maxCalls:       maxCalls,
		janitorCtx:     ctx,
		janitorCancel:  cancel,
		janitorStarted: false,
		config:         GetConfig(),
	}

	tracker.startJanitor()

	// Set up automatic cleanup on process termination
	go tracker.setupSignalHandler()

	return tracker
}

func (ct *CallTracker) startJanitor() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if !ct.janitorStarted {
		go ct.janitorLoop()
		ct.janitorStarted = true
	}
}

// setupSignalHandler handles cleanup on process termination
func (ct *CallTracker) setupSignalHandler() {
	ct.signalHandlerOnce.Do(func() {
		_ = signals.SetupHandlerWithCallback(ct.janitorCtx, ct.Shutdown)
	})
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

		// Wait for all active writes to complete
		ct.activeWrites.Wait()
		logger.Info("All active writes completed, closing call files")

		// Now safe to close all files
		ct.mu.Lock()
		defer ct.mu.Unlock()

		for id, call := range ct.callMap {
			if err := call.Close(); err != nil {
				logger.Error("Failed to close call files",
					"call_id", SanitizeCallIDForLogging(id),
					"error", err)
			}
			delete(ct.callMap, id)
		}
		logger.Info("Call tracker shutdown complete")
	})
}

// ShutdownCallTracker gracefully shuts down the default call tracker
func ShutdownCallTracker() {
	getTracker().Shutdown()
}

func (c *CallInfo) SetCallInfoState(newState string) {
	tracker := getTracker()
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
		}
	}
}

func getCall(callID string) (*CallInfo, error) {
	tracker := getTracker()
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	result, exists := tracker.callMap[callID]
	if !exists {
		return nil, errors.New("the CallID does not exist")
	}

	return result, nil
}

func GetOrCreateCall(callID string, linkType layers.LinkType) *CallInfo {
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	call, exists := tracker.callMap[callID]
	if !exists {
		call = &CallInfo{
			CallID:      callID,
			State:       "NEW",
			Created:     time.Now(),
			LastUpdated: time.Now(),
			LinkType:    linkType,
		}
		if viper.GetViper().GetBool("writeVoip") {
			if err := call.initWriters(); err != nil {
				logger.Error("Failed to initialize writers for call",
					"call_id", SanitizeCallIDForLogging(callID),
					"error", err)
				// Don't track call if we can't write it - prevents silent data loss
				return nil
			}
		}

		// Evict LRU (least recently used) if at capacity
		if tracker.lruList.Len() >= tracker.maxCalls {
			// Remove from back (least recently used)
			oldest := tracker.lruList.Back()
			if oldest != nil {
				oldestCallID := oldest.Value.(string)
				oldCall := tracker.callMap[oldestCallID]

				// Clean up the old call's resources
				if oldCall != nil {
					if err := oldCall.Close(); err != nil {
						logger.Error("Error closing call files",
							"call_id", SanitizeCallIDForLogging(oldestCallID),
							"error", err)
					}
					// Remove from port mapping
					for port, cid := range tracker.portToCallID {
						if cid == oldestCallID {
							delete(tracker.portToCallID, port)
						}
					}
					delete(tracker.callMap, oldestCallID)
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
	} else {
		// Move existing call to front (most recently used)
		if elem, ok := tracker.lruIndex[callID]; ok {
			tracker.lruList.MoveToFront(elem)
		}
	}
	return call
}

func (c *CallInfo) initWriters() error {
	// Check if user specified an output file
	outputFile := viper.GetString("voip.output_file")

	var sipPath, rtpPath string

	if outputFile != "" {
		// User specified output file - use it as base name
		// Generate: <file>_sip_<callid>.pcap and <file>_rtp_<callid>.pcap
		base := strings.TrimSuffix(outputFile, filepath.Ext(outputFile))
		sipPath = fmt.Sprintf("%s_sip_%s.pcap", base, sanitize(c.CallID))
		rtpPath = fmt.Sprintf("%s_rtp_%s.pcap", base, sanitize(c.CallID))
	} else {
		// No output file specified - use default directory
		capturesDir, err := getCapturesDir()
		if err != nil {
			return fmt.Errorf("failed to get captures directory: %w", err)
		}

		// Create directory if it doesn't exist
		if err := os.MkdirAll(capturesDir, 0o750); err != nil {
			return fmt.Errorf("failed to create captures directory: %w", err)
		}

		// Verify directory is not a symlink to prevent symlink attacks
		dirInfo, err := os.Lstat(capturesDir)
		if err != nil {
			return fmt.Errorf("failed to stat captures directory: %w", err)
		}
		if dirInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("captures directory is a symlink, refusing to use it for security")
		}

		sipPath = filepath.Join(capturesDir, fmt.Sprintf("sip_%s.pcap", sanitize(c.CallID)))
		rtpPath = filepath.Join(capturesDir, fmt.Sprintf("rtp_%s.pcap", sanitize(c.CallID)))
	}

	var err error

	// Create SIP file with restrictive permissions (owner read/write only)
	// #nosec G304 -- Path is safe: uses getCapturesDir() + sanitized CallID, symlink-checked or user-specified
	c.sipFile, err = os.OpenFile(sipPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create SIP file %s: %w", sipPath, err)
	}

	// Create RTP file with restrictive permissions (owner read/write only)
	// #nosec G304 -- Path is safe: uses getCapturesDir() + sanitized CallID, symlink-checked or user-specified
	c.rtpFile, err = os.OpenFile(rtpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		if c.sipFile != nil {
			if closeErr := c.sipFile.Close(); closeErr != nil {
				logger.Error("Failed to close SIP file during error cleanup", "error", closeErr, "file", sipPath)
			}
		}
		return fmt.Errorf("failed to create RTP file %s: %w", rtpPath, err)
	}

	c.SIPWriter = pcapgo.NewWriter(c.sipFile)
	c.RTPWriter = pcapgo.NewWriter(c.rtpFile)

	if err := c.SIPWriter.WriteFileHeader(pcaptypes.MaxPcapSnapshotLen, c.LinkType); err != nil {
		if closeErr := c.sipFile.Close(); closeErr != nil {
			logger.Error("Failed to close SIP file during error cleanup", "error", closeErr, "file", sipPath)
		}
		if closeErr := c.rtpFile.Close(); closeErr != nil {
			logger.Error("Failed to close RTP file during error cleanup", "error", closeErr, "file", rtpPath)
		}
		return fmt.Errorf("failed to write SIP file header: %w", err)
	}

	if err := c.RTPWriter.WriteFileHeader(pcaptypes.MaxPcapSnapshotLen, c.LinkType); err != nil {
		if closeErr := c.sipFile.Close(); closeErr != nil {
			logger.Error("Failed to close SIP file during error cleanup", "error", closeErr, "file", sipPath)
		}
		if closeErr := c.rtpFile.Close(); closeErr != nil {
			logger.Error("Failed to close RTP file during error cleanup", "error", closeErr, "file", rtpPath)
		}
		return fmt.Errorf("failed to write RTP file header: %w", err)
	}

	return nil
}

func sanitize(id string) string {
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
	maxLen := GetConfig().MaxFilenameLength
	if len(cleaned) > maxLen {
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

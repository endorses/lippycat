package voip

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
)

type CallInfo struct {
	CallID      string
	State       string
	Created     time.Time
	LastUpdated time.Time
	LinkType    layers.LinkType
	SIPWriter   *pcapgo.Writer
	RTPWriter   *pcapgo.Writer
	sipFile     *os.File
	rtpFile     *os.File
}

type CallTracker struct {
	callMap           map[string]*CallInfo
	portToCallID      map[string]string // key = port, value = CallID
	mu                sync.RWMutex
	janitorCtx        context.Context
	janitorCancel     context.CancelFunc
	janitorStarted    bool
	shutdownOnce      sync.Once
	signalHandlerOnce sync.Once
	config            *Config
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
	tracker := &CallTracker{
		callMap:        make(map[string]*CallInfo),
		portToCallID:   make(map[string]string),
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
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

		go func() {
			<-sigCh // Block until we receive a signal
			ct.Shutdown()
		}()
	})
}

// Shutdown gracefully shuts down the call tracker
func (ct *CallTracker) Shutdown() {
	ct.shutdownOnce.Do(func() {
		if ct.janitorCancel != nil {
			ct.janitorCancel()
		}
		// Close all open call files
		ct.mu.Lock()
		for id, call := range ct.callMap {
			if call.sipFile != nil {
				call.sipFile.Close()
			}
			if call.rtpFile != nil {
				call.rtpFile.Close()
			}
			delete(ct.callMap, id)
		}
		ct.mu.Unlock()
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
					"call_id", callID,
					"error", err)
				// Don't track call if we can't write it - prevents silent data loss
				return nil
			}
		}
		tracker.callMap[callID] = call
	}
	return call
}

func (c *CallInfo) initWriters() error {
	if err := os.MkdirAll("captures", 0o755); err != nil {
		return fmt.Errorf("failed to create captures directory: %w", err)
	}

	sipPath := filepath.Join("captures", fmt.Sprintf("sip_%s.pcap", sanitize(c.CallID)))
	rtpPath := filepath.Join("captures", fmt.Sprintf("rtp_%s.pcap", sanitize(c.CallID)))

	var err error
	c.sipFile, err = os.Create(sipPath)
	if err != nil {
		return fmt.Errorf("failed to create SIP file %s: %w", sipPath, err)
	}

	c.rtpFile, err = os.Create(rtpPath)
	if err != nil {
		if c.sipFile != nil {
			c.sipFile.Close()
		}
		return fmt.Errorf("failed to create RTP file %s: %w", rtpPath, err)
	}

	c.SIPWriter = pcapgo.NewWriter(c.sipFile)
	c.RTPWriter = pcapgo.NewWriter(c.rtpFile)

	if err := c.SIPWriter.WriteFileHeader(pcaptypes.MaxPcapSnapshotLen, c.LinkType); err != nil {
		c.sipFile.Close()
		c.rtpFile.Close()
		return fmt.Errorf("failed to write SIP file header: %w", err)
	}

	if err := c.RTPWriter.WriteFileHeader(pcaptypes.MaxPcapSnapshotLen, c.LinkType); err != nil {
		c.sipFile.Close()
		c.rtpFile.Close()
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
	maxIterations := 10 // Prevent infinite loops
	for i := 0; i < maxIterations; i++ {
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
	ct.mu.Lock()
	defer ct.mu.Unlock()

	expireAfter := ct.config.CallExpirationTime
	now := time.Now()

	for id, call := range ct.callMap {
		if now.Sub(call.LastUpdated) > expireAfter {
			logger.Info("Cleaning up expired call",
				"call_id", id,
				"last_updated", call.LastUpdated,
				"age_seconds", int(now.Sub(call.LastUpdated).Seconds()))
			if call.sipFile != nil {
				if err := call.sipFile.Close(); err != nil {
					logger.Error("Error closing SIP file for call",
						"call_id", id,
						"error", err)
				}
			}
			if call.rtpFile != nil {
				if err := call.rtpFile.Close(); err != nil {
					logger.Error("Error closing RTP file for call",
						"call_id", id,
						"error", err)
				}
			}
			delete(ct.callMap, id)
		}
	}
}

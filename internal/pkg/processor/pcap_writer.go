//go:build processor || tap || all

package processor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	// completedCallTombstoneTTL preserves the historical one-hour closed-call
	// retention window. After expiry a Call-ID may represent a new generation.
	completedCallTombstoneTTL = time.Hour
	// completedCallTombstoneLimit bounds terminal lifecycle memory. At pressure,
	// the oldest tombstones are discarded; collision-safe file creation still
	// protects finalized artifacts if such a Call-ID is subsequently reused.
	completedCallTombstoneLimit = 100_000
	latePacketWarningInterval   = time.Minute
)

// FinalizedCallError is the expected, non-fatal result when a late packet
// attempts to recreate a writer for a call that has reached terminal state.
type FinalizedCallError struct {
	CallID      string
	FinalizedAt time.Time
}

func (e *FinalizedCallError) Error() string {
	return fmt.Sprintf("call %q was finalized at %s", e.CallID, e.FinalizedAt.Format(time.RFC3339Nano))
}

// IsCallFinalized reports whether err represents intentional late-packet suppression.
func IsCallFinalized(err error) bool {
	var finalizedErr *FinalizedCallError
	return errors.As(err, &finalizedErr)
}

// PcapWriterConfig configures per-call PCAP writing
type PcapWriterConfig struct {
	Enabled         bool          // Enable per-call PCAP writing
	OutputDir       string        // Directory for PCAP files
	FilePattern     string        // File naming pattern (supports {callid}, {from}, {to}, {timestamp})
	MaxFileSize     int64         // Max PCAP file size in bytes (0 = unlimited)
	MaxFilesPerCall int           // Max number of PCAP files per call (for rotation)
	MaxIdle         time.Duration // Max idle time before a call writer is reclaimed (0 = disabled)
	MaxWriters      int           // Max active call writers (0 = unlimited)
	BufferSize      int           // Write buffer size
	SyncInterval    time.Duration // How often to sync to disk

	// Callbacks for command hooks
	OnFileClose    func(filePath string)   // Called when any PCAP file is closed
	OnCallComplete func(meta CallMetadata) // Called when a VoIP call is complete
}

// DefaultPcapWriterConfig returns default configuration
func DefaultPcapWriterConfig() *PcapWriterConfig {
	return &PcapWriterConfig{
		Enabled:         false,
		OutputDir:       "./pcaps",
		FilePattern:     "{timestamp}_{callid}.pcap",
		MaxFileSize:     constants.DefaultPCAPMaxFileSize,
		MaxFilesPerCall: constants.DefaultMaxFilesPerCall,
		MaxIdle:         10 * time.Minute,
		MaxWriters:      0,
		BufferSize:      constants.DefaultPCAPBufferSize,
		SyncInterval:    constants.DefaultPCAPSyncInterval,
	}
}

// CallPcapWriter writes packets for a specific call to separate SIP and RTP PCAP files
type CallPcapWriter struct {
	config    *PcapWriterConfig
	callID    string
	from      string
	to        string
	startTime time.Time
	lastWrite time.Time
	linkType  layers.LinkType // Link type for PCAP files (set from first packet)
	// SIP file
	sipFile        *os.File
	sipWriter      *pcapgo.Writer
	sipFilePath    string
	sipSize        int64
	sipFileIndex   int
	sipPacketCount int
	// RTP file
	rtpFile        *os.File
	rtpWriter      *pcapgo.Writer
	rtpFilePath    string
	rtpSize        int64
	rtpFileIndex   int
	rtpPacketCount int
	// Synchronization
	mu         sync.Mutex
	syncTicker *time.Ticker
	stopSync   chan struct{}
	syncErrors int // Count of sync errors during periodic sync
}

// PcapWriterManager manages PCAP writers for multiple calls
type PcapWriterManager struct {
	config         *PcapWriterConfig
	writers        map[string]*CallPcapWriter
	tombstones     map[string]time.Time
	tombstoneTTL   time.Duration
	tombstoneLimit int
	shutdown       bool
	mu             sync.RWMutex

	suppressedLatePackets atomic.Uint64
	lastLateWarning       atomic.Int64
}

// NewPcapWriterManager creates a new PCAP writer manager
func NewPcapWriterManager(config *PcapWriterConfig) (*PcapWriterManager, error) {
	if config == nil {
		config = DefaultPcapWriterConfig()
	}

	// Create output directory if it doesn't exist
	if config.Enabled {
		if err := os.MkdirAll(config.OutputDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	return &PcapWriterManager{
		config:         config,
		writers:        make(map[string]*CallPcapWriter),
		tombstones:     make(map[string]time.Time),
		tombstoneTTL:   completedCallTombstoneTTL,
		tombstoneLimit: completedCallTombstoneLimit,
	}, nil
}

// Writer lifecycle is manager-owned: absent -> live -> finalizing -> tombstoned.
// The live-to-tombstone transition is atomic under mu; finalizing work (file
// sync/close and callbacks) occurs after mu is released. Tombstones suppress
// late packets. Expired/pruned tombstones admit a new generation, whose files
// are collision-safe. Manager shutdown rejects creation and closes live writers
// without treating process shutdown as protocol completion. Late output is not
// retained; adding it requires a distinct, standalone artifact lifecycle.

// GetOrCreateWriter gets or creates a writer for a call
func (pwm *PcapWriterManager) GetOrCreateWriter(callID, from, to string) (*CallPcapWriter, error) {
	if !pwm.config.Enabled {
		return nil, nil
	}

	for {
		now := time.Now()
		pwm.mu.Lock()
		if pwm.shutdown {
			pwm.mu.Unlock()
			return nil, fmt.Errorf("per-call PCAP writer manager is shut down")
		}
		if writer, exists := pwm.writers[callID]; exists {
			pwm.mu.Unlock()
			return writer, nil
		}
		if finalizedAt, finalized := pwm.tombstones[callID]; finalized {
			if pwm.tombstoneTTL > 0 && now.Sub(finalizedAt) < pwm.tombstoneTTL {
				pwm.mu.Unlock()
				pwm.recordSuppressedLatePacket(callID, finalizedAt)
				return nil, &FinalizedCallError{CallID: callID, FinalizedAt: finalizedAt}
			}
			delete(pwm.tombstones, callID)
		}

		if pwm.config.MaxWriters > 0 && len(pwm.writers) >= pwm.config.MaxWriters {
			evictCallID, evictWriter := pwm.leastRecentlyWrittenLocked()
			if evictWriter != nil {
				// Removal and tombstone installation are one manager-locked
				// transition. Slow finalization is deliberately outside mu.
				delete(pwm.writers, evictCallID)
				pwm.addTombstoneLocked(evictCallID, now)
				pwm.mu.Unlock()
				logger.Warn("Closing per-call PCAP writer due to max writer limit",
					"call_id", evictCallID, "max_writers", pwm.config.MaxWriters)
				if err := evictWriter.CloseCall(); err != nil {
					return nil, fmt.Errorf("failed to close overflow PCAP writer %q: %w", evictCallID, err)
				}
				continue
			}
		}

		writer, err := pwm.createWriter(callID, from, to)
		if err == nil {
			pwm.writers[callID] = writer
		}
		pwm.mu.Unlock()
		return writer, err
	}
}

// SuppressedLatePackets returns the process-lifetime count of packets rejected
// because their Call-ID remained tombstoned. The counter is monotonic.
func (pwm *PcapWriterManager) SuppressedLatePackets() uint64 {
	if pwm == nil {
		return 0
	}
	return pwm.suppressedLatePackets.Load()
}

func (pwm *PcapWriterManager) recordSuppressedLatePacket(callID string, finalizedAt time.Time) {
	total := pwm.suppressedLatePackets.Add(1)
	now := time.Now().UnixNano()
	last := pwm.lastLateWarning.Load()
	if now-last < latePacketWarningInterval.Nanoseconds() ||
		!pwm.lastLateWarning.CompareAndSwap(last, now) {
		return
	}
	logger.Warn("Suppressing late packet for finalized call",
		"call_id", callID, "finalized_at", finalizedAt, "suppressed_total", total)
}

func (pwm *PcapWriterManager) pruneTombstonesLocked(now time.Time) {
	for callID, finalizedAt := range pwm.tombstones {
		if pwm.tombstoneTTL <= 0 || now.Sub(finalizedAt) >= pwm.tombstoneTTL {
			delete(pwm.tombstones, callID)
		}
	}
}

func (pwm *PcapWriterManager) addTombstoneLocked(callID string, finalizedAt time.Time) {
	if pwm.tombstoneLimit <= 0 {
		return
	}
	pwm.pruneTombstonesLocked(finalizedAt)
	if _, exists := pwm.tombstones[callID]; !exists && len(pwm.tombstones) >= pwm.tombstoneLimit {
		var oldestID string
		var oldestAt time.Time
		for existingID, existingAt := range pwm.tombstones {
			if oldestID == "" || existingAt.Before(oldestAt) {
				oldestID, oldestAt = existingID, existingAt
			}
		}
		delete(pwm.tombstones, oldestID)
	}
	pwm.tombstones[callID] = finalizedAt
}

// createWriter creates a new PCAP writer for a call with separate SIP and RTP files
func (pwm *PcapWriterManager) createWriter(callID, from, to string) (*CallPcapWriter, error) {
	now := time.Now()
	writer := &CallPcapWriter{
		config:    pwm.config,
		callID:    callID,
		from:      from,
		to:        to,
		startTime: now,
		lastWrite: now,
		stopSync:  make(chan struct{}),
	}

	// Create initial SIP and RTP PCAP files
	if err := writer.createInitialFiles(); err != nil {
		return nil, err
	}

	// Start sync ticker
	writer.syncTicker = time.NewTicker(pwm.config.SyncInterval)
	go writer.syncLoop()

	logger.Info("Created PCAP writers for call", "call_id", callID, "from", from, "to", to)

	return writer, nil
}

// createInitialFiles is a no-op; files are created lazily on first packet
// to ensure we have the correct link type from the actual captured packets.
// This prevents the bug where PCAP files were hardcoded to LinkTypeEthernet
// regardless of the actual capture interface type (e.g., Linux cooked, raw IP).
func (writer *CallPcapWriter) createInitialFiles() error {
	// Files are created in WriteSIPPacket/WriteRTPPacket on first packet
	return nil
}

// WriteSIPPacket writes a SIP packet to the SIP PCAP file
func (writer *CallPcapWriter) WriteSIPPacket(timestamp time.Time, data []byte, linkType layers.LinkType) error {
	if writer == nil {
		return nil
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Store link type from first packet (used for all files in this call)
	if writer.linkType == 0 {
		writer.linkType = linkType
		logger.Debug("Set PCAP link type for call", "call_id", writer.callID, "link_type", linkType)
	}

	// Create SIP file on first SIP packet (deferred from createInitialFiles)
	if writer.sipWriter == nil {
		if err := writer.rotateSIPFile(); err != nil {
			return fmt.Errorf("failed to create SIP PCAP file: %w", err)
		}
	}

	// Check if we need to rotate SIP file
	if writer.config.MaxFileSize > 0 && writer.sipSize >= writer.config.MaxFileSize {
		if err := writer.rotateSIPFile(); err != nil {
			return fmt.Errorf("failed to rotate SIP PCAP file: %w", err)
		}
	}

	// Create CaptureInfo for raw packet
	ci := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(data),
		Length:        len(data),
	}

	// Write packet to SIP file
	if err := writer.sipWriter.WritePacket(ci, data); err != nil {
		return fmt.Errorf("failed to write SIP packet: %w", err)
	}

	writer.sipSize += int64(len(data))
	writer.sipPacketCount++
	writer.lastWrite = time.Now()

	return nil
}

// WriteRTPPacket writes an RTP packet to the RTP PCAP file
func (writer *CallPcapWriter) WriteRTPPacket(timestamp time.Time, data []byte, linkType layers.LinkType) error {
	if writer == nil {
		return nil
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Store link type from first packet (used for all files in this call)
	if writer.linkType == 0 {
		writer.linkType = linkType
		logger.Debug("Set PCAP link type for call", "call_id", writer.callID, "link_type", linkType)
	}

	// Create RTP file on first RTP packet (deferred from createInitialFiles)
	if writer.rtpWriter == nil {
		if err := writer.rotateRTPFile(); err != nil {
			return fmt.Errorf("failed to create RTP PCAP file: %w", err)
		}
	}

	// Check if we need to rotate RTP file
	if writer.config.MaxFileSize > 0 && writer.rtpSize >= writer.config.MaxFileSize {
		if err := writer.rotateRTPFile(); err != nil {
			return fmt.Errorf("failed to rotate RTP PCAP file: %w", err)
		}
	}

	// Create CaptureInfo for raw packet
	ci := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(data),
		Length:        len(data),
	}

	// Write packet to RTP file
	if err := writer.rtpWriter.WritePacket(ci, data); err != nil {
		return fmt.Errorf("failed to write RTP packet: %w", err)
	}

	writer.rtpSize += int64(len(data))
	writer.rtpPacketCount++
	writer.lastWrite = time.Now()

	return nil
}

func (pwm *PcapWriterManager) leastRecentlyWrittenLocked() (string, *CallPcapWriter) {
	var (
		oldestCallID string
		oldestWriter *CallPcapWriter
		oldestWrite  time.Time
	)

	for callID, writer := range pwm.writers {
		writer.mu.Lock()
		lastWrite := writer.lastWrite
		writer.mu.Unlock()

		if oldestWriter == nil || lastWrite.Before(oldestWrite) {
			oldestCallID = callID
			oldestWriter = writer
			oldestWrite = lastWrite
		}
	}

	return oldestCallID, oldestWriter
}

// SweepIdle closes writers that have not received SIP or RTP packets within maxIdle.
func (pwm *PcapWriterManager) SweepIdle(maxIdle time.Duration) int {
	if pwm == nil || maxIdle <= 0 {
		return 0
	}

	now := time.Now()
	toClose := make([]string, 0)

	pwm.mu.RLock()
	for callID, writer := range pwm.writers {
		writer.mu.Lock()
		idleFor := now.Sub(writer.lastWrite)
		writer.mu.Unlock()

		if idleFor >= maxIdle {
			toClose = append(toClose, callID)
		}
	}
	pwm.mu.RUnlock()

	closed := 0
	for _, callID := range toClose {
		logger.Warn("Closing idle per-call PCAP writer",
			"call_id", callID,
			"max_idle", maxIdle)
		if err := pwm.CloseCallWriter(callID); err != nil {
			logger.Warn("Failed to close idle per-call PCAP writer",
				"call_id", callID,
				"error", err)
			continue
		}
		closed++
	}

	return closed
}

// openCallPcapFile creates a new standalone PCAP without replacing or appending
// to an existing artifact. Manager-owned live state, never filesystem mtime,
// is the authority for continuation. A collision receives a generation suffix
// so Call-ID reuse after tombstone expiry cannot mutate finalized output.
func (writer *CallPcapWriter) openCallPcapFile(filePath string) (*os.File, *pcapgo.Writer, string, error) {
	linkType := writer.linkType
	if linkType == 0 {
		linkType = layers.LinkTypeEthernet
	}

	actualPath := filePath
	var file *os.File
	for attempt := 0; ; attempt++ {
		// #nosec G304 -- Path is safe: config OutputDir + generateFilename() with sanitization
		created, err := os.OpenFile(actualPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			file = created
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, nil, "", err
		}
		actualPath = generationFilePath(filePath, time.Now().UnixNano(), attempt)
	}

	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(constants.DefaultPCAPSnapLen, linkType); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("Failed to close file during error cleanup", "error", closeErr, "file", actualPath)
		}
		return nil, nil, "", err
	}

	return file, pcapWriter, actualPath, nil
}

func generationFilePath(filePath string, generation int64, attempt int) string {
	ext := filepath.Ext(filePath)
	base := strings.TrimSuffix(filePath, ext)
	if attempt == 0 {
		return fmt.Sprintf("%s_gen_%d%s", base, generation, ext)
	}
	return fmt.Sprintf("%s_gen_%d_%d%s", base, generation, attempt, ext)
}

// rotateSIPFile creates a new SIP PCAP file (called when size limit reached)
func (writer *CallPcapWriter) rotateSIPFile() error {
	// Close existing file and fire callback
	if writer.sipFile != nil {
		closedPath := writer.sipFilePath
		if err := writer.sipFile.Close(); err != nil {
			logger.Error("Failed to close SIP file during rotation", "error", err, "call_id", writer.callID)
		}
		// Fire callback after successful close
		if closedPath != "" && writer.config.OnFileClose != nil {
			writer.config.OnFileClose(closedPath)
		}
	}

	// Check file limit
	if writer.config.MaxFilesPerCall > 0 && writer.sipFileIndex >= writer.config.MaxFilesPerCall {
		return fmt.Errorf("max SIP files per call reached: %d", writer.config.MaxFilesPerCall)
	}

	// Generate filename
	filename := writer.generateFilename("sip", writer.sipFileIndex)
	filePath := filepath.Join(writer.config.OutputDir, filename)

	file, pcapWriter, actualPath, err := writer.openCallPcapFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to create SIP PCAP file: %w", err)
	}

	writer.sipFile = file
	writer.sipWriter = pcapWriter
	writer.sipFilePath = actualPath
	writer.sipSize = 0
	writer.sipFileIndex++

	logger.Info("Opened SIP PCAP file for call", "call_id", writer.callID, "file", actualPath)

	return nil
}

// rotateRTPFile creates a new RTP PCAP file (called when size limit reached)
func (writer *CallPcapWriter) rotateRTPFile() error {
	// Close existing file and fire callback
	if writer.rtpFile != nil {
		closedPath := writer.rtpFilePath
		if err := writer.rtpFile.Close(); err != nil {
			logger.Error("Failed to close RTP file during rotation", "error", err, "call_id", writer.callID)
		}
		// Fire callback after successful close
		if closedPath != "" && writer.config.OnFileClose != nil {
			writer.config.OnFileClose(closedPath)
		}
	}

	// Check file limit
	if writer.config.MaxFilesPerCall > 0 && writer.rtpFileIndex >= writer.config.MaxFilesPerCall {
		return fmt.Errorf("max RTP files per call reached: %d", writer.config.MaxFilesPerCall)
	}

	// Generate filename
	filename := writer.generateFilename("rtp", writer.rtpFileIndex)
	filePath := filepath.Join(writer.config.OutputDir, filename)

	file, pcapWriter, actualPath, err := writer.openCallPcapFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to create RTP PCAP file: %w", err)
	}

	writer.rtpFile = file
	writer.rtpWriter = pcapWriter
	writer.rtpFilePath = actualPath
	writer.rtpSize = 0
	writer.rtpFileIndex++

	logger.Info("Opened RTP PCAP file for call", "call_id", writer.callID, "file", actualPath)

	return nil
}

// generateFilename generates a filename for the PCAP file (SIP or RTP)
func (writer *CallPcapWriter) generateFilename(packetType string, fileIndex int) string {
	pattern := writer.config.FilePattern

	// Replace placeholders
	pattern = strings.ReplaceAll(pattern, "{callid}", sanitizeFilename(writer.callID))
	pattern = strings.ReplaceAll(pattern, "{from}", sanitizeFilename(writer.from))
	pattern = strings.ReplaceAll(pattern, "{to}", sanitizeFilename(writer.to))
	pattern = strings.ReplaceAll(pattern, "{timestamp}", writer.startTime.Format("20060102_150405"))

	// Add packet type (sip or rtp) before extension
	ext := filepath.Ext(pattern)
	base := pattern[:len(pattern)-len(ext)]
	pattern = fmt.Sprintf("%s_%s%s", base, packetType, ext)

	// Add index suffix if rotating
	if fileIndex > 0 {
		ext = filepath.Ext(pattern)
		base = pattern[:len(pattern)-len(ext)]
		pattern = fmt.Sprintf("%s_%d%s", base, fileIndex, ext)
	}

	return pattern
}

// syncLoop periodically syncs files to disk
func (writer *CallPcapWriter) syncLoop() {
	for {
		select {
		case <-writer.syncTicker.C:
			writer.mu.Lock()
			if writer.sipFile != nil {
				if err := writer.sipFile.Sync(); err != nil {
					writer.syncErrors++
					logger.Warn("Failed to sync SIP PCAP", "error", err, "call_id", writer.callID)
				}
			}
			if writer.rtpFile != nil {
				if err := writer.rtpFile.Sync(); err != nil {
					writer.syncErrors++
					logger.Warn("Failed to sync RTP PCAP", "error", err, "call_id", writer.callID)
				}
			}
			writer.mu.Unlock()
		case <-writer.stopSync:
			return
		}
	}
}

// Close closes the writer and flushes data for both SIP and RTP files
func (writer *CallPcapWriter) Close() error {
	if writer == nil {
		return nil
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Stop sync loop
	close(writer.stopSync)
	writer.syncTicker.Stop()

	// Close SIP file
	var sipClosedPath string
	if writer.sipFile != nil {
		sipClosedPath = writer.sipFilePath
		if err := writer.sipFile.Sync(); err != nil {
			logger.Warn("Failed to sync SIP PCAP file", "error", err)
		}
		if err := writer.sipFile.Close(); err != nil {
			logger.Warn("Failed to close SIP PCAP file", "error", err)
		}
		writer.sipFile = nil
	}

	// Close RTP file
	var rtpClosedPath string
	if writer.rtpFile != nil {
		rtpClosedPath = writer.rtpFilePath
		if err := writer.rtpFile.Sync(); err != nil {
			logger.Warn("Failed to sync RTP PCAP file", "error", err)
		}
		if err := writer.rtpFile.Close(); err != nil {
			logger.Warn("Failed to close RTP PCAP file", "error", err)
		}
		writer.rtpFile = nil
	}

	logger.Info("Closed PCAP writers for call",
		"call_id", writer.callID,
		"sip_packets", writer.sipPacketCount,
		"rtp_packets", writer.rtpPacketCount,
		"sip_files", writer.sipFileIndex,
		"rtp_files", writer.rtpFileIndex,
		"sync_errors", writer.syncErrors)

	// Fire OnFileClose callbacks after files are closed
	if writer.config.OnFileClose != nil {
		if sipClosedPath != "" {
			writer.config.OnFileClose(sipClosedPath)
		}
		if rtpClosedPath != "" {
			writer.config.OnFileClose(rtpClosedPath)
		}
	}

	return nil
}

// CloseCall closes both PCAP files and fires the OnCallComplete callback
// This should be called when a VoIP call is complete
func (writer *CallPcapWriter) CloseCall() error {
	if writer == nil {
		return nil
	}

	// Close files first
	if err := writer.Close(); err != nil {
		return err
	}

	// Fire OnCallComplete callback with call metadata
	if writer.config.OnCallComplete != nil {
		meta := CallMetadata{
			CallID:   writer.callID,
			DirName:  writer.config.OutputDir,
			Caller:   writer.from,
			Called:   writer.to,
			CallDate: writer.startTime,
		}
		writer.config.OnCallComplete(meta)
	}

	return nil
}

// CloseWriter closes a specific call's writer (without firing OnCallComplete)
func (pwm *PcapWriterManager) CloseWriter(callID string) error {
	pwm.mu.Lock()
	writer, exists := pwm.writers[callID]
	if !exists {
		pwm.mu.Unlock()
		return nil
	}
	delete(pwm.writers, callID)
	pwm.addTombstoneLocked(callID, time.Now())
	pwm.mu.Unlock()

	return writer.Close()
}

// CloseCallWriter closes a specific call's writer and fires OnCallComplete callback.
// Use this method when a VoIP call completes to trigger the voipcommand hook.
func (pwm *PcapWriterManager) CloseCallWriter(callID string) error {
	pwm.mu.Lock()
	writer, exists := pwm.writers[callID]
	finalizedAt := time.Now()
	// A completion observed before the first captured packet is still terminal.
	// Record it so a delayed packet cannot create the first writer afterward.
	pwm.addTombstoneLocked(callID, finalizedAt)
	if !exists {
		pwm.mu.Unlock()
		return nil
	}
	delete(pwm.writers, callID)
	pwm.mu.Unlock()

	return writer.CloseCall()
}

// HasRTPPackets returns true if the call has received any RTP packets.
// Used by CallCompletionMonitor to wait for RTP before firing voipcommand.
func (pwm *PcapWriterManager) HasRTPPackets(callID string) bool {
	pwm.mu.RLock()
	defer pwm.mu.RUnlock()

	writer, exists := pwm.writers[callID]
	if !exists {
		return false
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.rtpPacketCount > 0
}

// HasSIPPackets returns true if the call has received any SIP packets.
func (pwm *PcapWriterManager) HasSIPPackets(callID string) bool {
	pwm.mu.RLock()
	defer pwm.mu.RUnlock()

	writer, exists := pwm.writers[callID]
	if !exists {
		return false
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.sipPacketCount > 0
}

// Close closes all writers
func (pwm *PcapWriterManager) Close() error {
	pwm.mu.Lock()
	if pwm.shutdown {
		pwm.mu.Unlock()
		return nil
	}
	pwm.shutdown = true
	writers := pwm.writers
	pwm.writers = make(map[string]*CallPcapWriter)
	pwm.mu.Unlock()

	var lastErr error
	for callID, writer := range writers {
		if err := writer.Close(); err != nil {
			logger.Warn("Failed to close PCAP writer", "call_id", callID, "error", err)
			lastErr = err
		}
	}
	return lastErr
}

// Helper functions

func sanitizeFilename(s string) string {
	// Replace unsafe characters
	replacements := map[rune]rune{
		'/':  '_',
		'\\': '_',
		':':  '_',
		'*':  '_',
		'?':  '_',
		'"':  '_',
		'<':  '_',
		'>':  '_',
		'|':  '_',
		'@':  '_',
		' ':  '_',
	}

	runes := []rune(s)
	for i, r := range runes {
		if replacement, ok := replacements[r]; ok {
			runes[i] = replacement
		}
	}

	return string(runes)
}

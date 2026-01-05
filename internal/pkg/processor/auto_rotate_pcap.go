package processor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// AutoRotateConfig configures auto-rotating PCAP writing for non-VoIP traffic
type AutoRotateConfig struct {
	Enabled      bool          // Enable auto-rotating PCAP writing
	OutputDir    string        // Directory for PCAP files
	FilePattern  string        // File naming pattern (supports {timestamp})
	MaxIdleTime  time.Duration // Close file after this much idle time
	MaxFileSize  int64         // Max PCAP file size in bytes (0 = unlimited)
	MaxDuration  time.Duration // Max time per file (0 = unlimited)
	MinDuration  time.Duration // Minimum time to keep file open before closing due to idle
	BufferSize   int           // Write buffer size
	SyncInterval time.Duration // How often to sync to disk

	// Callback for command hooks
	OnFileClose func(filePath string) // Called when a PCAP file is closed
}

// DefaultAutoRotateConfig returns default configuration
func DefaultAutoRotateConfig() *AutoRotateConfig {
	return &AutoRotateConfig{
		Enabled:      false,
		OutputDir:    "./auto-rotate-pcaps",
		FilePattern:  "{timestamp}.pcap",
		MaxIdleTime:  30 * time.Second,
		MaxFileSize:  constants.DefaultPCAPMaxFileSize,
		MaxDuration:  1 * time.Hour,
		MinDuration:  10 * time.Second,
		BufferSize:   constants.DefaultPCAPBufferSize,
		SyncInterval: constants.DefaultPCAPSyncInterval,
	}
}

// AutoRotatePcapWriter writes non-VoIP packets with auto-rotation based on idle time, size, and duration
type AutoRotatePcapWriter struct {
	config          *AutoRotateConfig
	currentFile     *os.File
	currentWriter   *pcapgo.Writer
	currentFilePath string
	lastPacketTime  time.Time
	fileStartTime   time.Time
	currentSize     int64
	packetCount     int
	fileIndex       int
	linkType        layers.LinkType // Link type for PCAP files (set from first packet)
	mu              sync.Mutex
	idleTimer       *time.Timer
	syncTicker      *time.Ticker
	stopSync        chan struct{}
}

// NewAutoRotatePcapWriter creates a new auto-rotating PCAP writer
func NewAutoRotatePcapWriter(config *AutoRotateConfig) (*AutoRotatePcapWriter, error) {
	if config == nil {
		config = DefaultAutoRotateConfig()
	}

	// Create output directory if it doesn't exist
	if config.Enabled {
		if err := os.MkdirAll(config.OutputDir, 0750); err != nil {
			return nil, fmt.Errorf("failed to create auto-rotate output directory: %w", err)
		}
	}

	writer := &AutoRotatePcapWriter{
		config:   config,
		stopSync: make(chan struct{}),
	}

	// Start sync ticker
	writer.syncTicker = time.NewTicker(config.SyncInterval)
	go writer.syncLoop()

	logger.Info("Auto-rotate PCAP writer initialized",
		"output_dir", config.OutputDir,
		"max_idle_time", config.MaxIdleTime,
		"max_file_size", config.MaxFileSize,
		"max_duration", config.MaxDuration)

	return writer, nil
}

// WritePacket writes a packet to the current auto-rotating PCAP file
func (w *AutoRotatePcapWriter) WritePacket(timestamp time.Time, data []byte, linkType layers.LinkType) error {
	if w == nil || !w.config.Enabled {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Store link type from first packet (used for all files)
	if w.linkType == 0 {
		w.linkType = linkType
		logger.Debug("Set auto-rotate PCAP link type", "link_type", linkType)
	}

	// Check if we need to rotate based on size or duration
	if w.shouldRotate() {
		if err := w.rotateFile(); err != nil {
			return fmt.Errorf("failed to rotate auto-rotate PCAP file: %w", err)
		}
	}

	// Create new file if needed
	if w.currentFile == nil {
		if err := w.createNewFile(timestamp); err != nil {
			return fmt.Errorf("failed to create new auto-rotate PCAP file: %w", err)
		}
	}

	// Create CaptureInfo for raw packet
	ci := gopacket.CaptureInfo{
		Timestamp:     timestamp,
		CaptureLength: len(data),
		Length:        len(data),
	}

	// Write packet
	if err := w.currentWriter.WritePacket(ci, data); err != nil {
		return fmt.Errorf("failed to write packet to auto-rotate PCAP: %w", err)
	}

	w.currentSize += int64(len(data))
	w.packetCount++
	w.lastPacketTime = time.Now()

	// Reset idle timer
	w.resetIdleTimer()

	return nil
}

// shouldRotate checks if the current file should be rotated based on size or duration
func (w *AutoRotatePcapWriter) shouldRotate() bool {
	if w.currentFile == nil {
		return false
	}

	now := time.Now()
	timeSinceStart := now.Sub(w.fileStartTime)

	// Rotate if file too large
	if w.config.MaxFileSize > 0 && w.currentSize >= w.config.MaxFileSize {
		logger.Debug("Auto-rotate PCAP: rotating due to file size",
			"current_size", w.currentSize,
			"max_size", w.config.MaxFileSize)
		return true
	}

	// Rotate if file too old
	if w.config.MaxDuration > 0 && timeSinceStart >= w.config.MaxDuration {
		logger.Debug("Auto-rotate PCAP: rotating due to file duration",
			"duration", timeSinceStart,
			"max_duration", w.config.MaxDuration)
		return true
	}

	return false
}

// rotateFile closes the current file (logs stats) and prepares for a new one
func (w *AutoRotatePcapWriter) rotateFile() error {
	if w.currentFile == nil {
		return nil
	}

	duration := time.Since(w.fileStartTime)
	closedPath := w.currentFilePath

	// Close current file
	if err := w.currentFile.Sync(); err != nil {
		logger.Warn("Failed to sync auto-rotate PCAP file before rotation", "error", err)
	}

	if err := w.currentFile.Close(); err != nil {
		logger.Warn("Failed to close auto-rotate PCAP file", "error", err)
	}

	logger.Info("Closed auto-rotate PCAP file",
		"packets", w.packetCount,
		"size_bytes", w.currentSize,
		"duration", duration)

	// Reset state
	w.currentFile = nil
	w.currentWriter = nil
	w.currentFilePath = ""
	w.currentSize = 0
	w.packetCount = 0
	w.fileIndex++

	// Fire callback after file is closed
	if closedPath != "" && w.config.OnFileClose != nil {
		w.config.OnFileClose(closedPath)
	}

	return nil
}

// createNewFile creates a new PCAP file
func (w *AutoRotatePcapWriter) createNewFile(timestamp time.Time) error {
	// Generate filename based on pattern
	filename := w.generateFilename(timestamp)
	filePath := filepath.Join(w.config.OutputDir, filename)

	// Create file with restrictive permissions (owner read/write only)
	// #nosec G304 -- Path is safe: config OutputDir + generateFilename() with sanitization
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create auto-rotate PCAP file: %w", err)
	}

	// Create PCAP writer with actual link type from captured packets
	// Default to Ethernet if no packets received yet (shouldn't happen in normal flow)
	linkType := w.linkType
	if linkType == 0 {
		linkType = layers.LinkTypeEthernet
	}
	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(constants.DefaultPCAPSnapLen, linkType); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("Failed to close file during error cleanup", "error", closeErr, "file", filePath)
		}
		return fmt.Errorf("failed to write auto-rotate PCAP header: %w", err)
	}

	w.currentFile = file
	w.currentWriter = pcapWriter
	w.currentFilePath = filePath
	w.currentSize = 0
	w.packetCount = 0
	w.fileStartTime = time.Now()
	w.lastPacketTime = time.Now()

	logger.Info("Created new auto-rotate PCAP file", "file", filePath, "link_type", linkType)

	return nil
}

// generateFilename generates a filename based on the pattern
func (w *AutoRotatePcapWriter) generateFilename(timestamp time.Time) string {
	pattern := w.config.FilePattern

	// Replace {timestamp} placeholder
	pattern = replaceAll(pattern, "{timestamp}", timestamp.Format("20060102_150405"))

	// Add index suffix if needed (for multiple files with same timestamp)
	if w.fileIndex > 0 {
		ext := filepath.Ext(pattern)
		base := pattern[:len(pattern)-len(ext)]
		pattern = fmt.Sprintf("%s_%d%s", base, w.fileIndex, ext)
	}

	return pattern
}

// resetIdleTimer resets the idle timer
func (w *AutoRotatePcapWriter) resetIdleTimer() {
	if w.idleTimer != nil {
		w.idleTimer.Stop()
	}

	w.idleTimer = time.AfterFunc(w.config.MaxIdleTime, func() {
		w.mu.Lock()
		defer w.mu.Unlock()

		if w.currentFile == nil {
			return
		}

		// Check if minimum duration has elapsed
		timeSinceStart := time.Since(w.fileStartTime)
		if timeSinceStart < w.config.MinDuration {
			logger.Debug("Auto-rotate PCAP: idle timeout but min duration not met, keeping file open",
				"time_since_start", timeSinceStart,
				"min_duration", w.config.MinDuration)
			// Re-arm timer for remaining min duration
			remaining := w.config.MinDuration - timeSinceStart
			w.idleTimer = time.AfterFunc(remaining, func() {
				w.mu.Lock()
				defer w.mu.Unlock()
				w.closeCurrentFile()
			})
			return
		}

		logger.Debug("Auto-rotate PCAP: closing file due to idle timeout",
			"idle_time", w.config.MaxIdleTime,
			"time_since_start", timeSinceStart)

		w.closeCurrentFile()
	})
}

// closeCurrentFile closes the current file (helper for idle timer)
func (w *AutoRotatePcapWriter) closeCurrentFile() {
	if w.currentFile == nil {
		return
	}

	duration := time.Since(w.fileStartTime)
	closedPath := w.currentFilePath

	if err := w.currentFile.Sync(); err != nil {
		logger.Warn("Failed to sync auto-rotate PCAP file", "error", err)
	}

	if err := w.currentFile.Close(); err != nil {
		logger.Warn("Failed to close auto-rotate PCAP file", "error", err)
	}

	logger.Info("Closed auto-rotate PCAP file due to idle timeout",
		"packets", w.packetCount,
		"size_bytes", w.currentSize,
		"duration", duration,
		"idle_time", w.config.MaxIdleTime)

	w.currentFile = nil
	w.currentWriter = nil
	w.currentFilePath = ""

	// Fire callback after file is closed
	if closedPath != "" && w.config.OnFileClose != nil {
		w.config.OnFileClose(closedPath)
	}
}

// syncLoop periodically syncs file to disk
func (w *AutoRotatePcapWriter) syncLoop() {
	for {
		select {
		case <-w.syncTicker.C:
			w.mu.Lock()
			if w.currentFile != nil {
				_ = w.currentFile.Sync()
			}
			w.mu.Unlock()
		case <-w.stopSync:
			return
		}
	}
}

// Close closes the writer and flushes data
func (w *AutoRotatePcapWriter) Close() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Stop sync loop
	close(w.stopSync)
	w.syncTicker.Stop()

	// Stop idle timer
	if w.idleTimer != nil {
		w.idleTimer.Stop()
	}

	// Close current file
	var closedPath string
	if w.currentFile != nil {
		duration := time.Since(w.fileStartTime)
		closedPath = w.currentFilePath

		if err := w.currentFile.Sync(); err != nil {
			logger.Warn("Failed to sync auto-rotate PCAP file", "error", err)
		}

		if err := w.currentFile.Close(); err != nil {
			logger.Warn("Failed to close auto-rotate PCAP file", "error", err)
		}

		logger.Info("Closed auto-rotate PCAP writer",
			"packets", w.packetCount,
			"size_bytes", w.currentSize,
			"duration", duration)

		w.currentFile = nil
		w.currentFilePath = ""
	}

	// Fire callback after file is closed
	if closedPath != "" && w.config.OnFileClose != nil {
		w.config.OnFileClose(closedPath)
	}

	return nil
}

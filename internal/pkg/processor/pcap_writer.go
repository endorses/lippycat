package processor

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PcapWriterConfig configures per-call PCAP writing
type PcapWriterConfig struct {
	Enabled         bool          // Enable per-call PCAP writing
	OutputDir       string        // Directory for PCAP files
	FilePattern     string        // File naming pattern (supports {callid}, {from}, {to}, {timestamp})
	MaxFileSize     int64         // Max PCAP file size in bytes (0 = unlimited)
	MaxFilesPerCall int           // Max number of PCAP files per call (for rotation)
	BufferSize      int           // Write buffer size
	SyncInterval    time.Duration // How often to sync to disk
}

// DefaultPcapWriterConfig returns default configuration
func DefaultPcapWriterConfig() *PcapWriterConfig {
	return &PcapWriterConfig{
		Enabled:         false,
		OutputDir:       "./pcaps",
		FilePattern:     "{timestamp}_{callid}.pcap",
		MaxFileSize:     100 * 1024 * 1024, // 100MB
		MaxFilesPerCall: 10,
		BufferSize:      4096,
		SyncInterval:    5 * time.Second,
	}
}

// CallPcapWriter writes packets for a specific call to separate SIP and RTP PCAP files
type CallPcapWriter struct {
	config    *PcapWriterConfig
	callID    string
	from      string
	to        string
	startTime time.Time
	// SIP file
	sipFile        *os.File
	sipWriter      *pcapgo.Writer
	sipSize        int64
	sipFileIndex   int
	sipPacketCount int
	// RTP file
	rtpFile        *os.File
	rtpWriter      *pcapgo.Writer
	rtpSize        int64
	rtpFileIndex   int
	rtpPacketCount int
	// Synchronization
	mu         sync.Mutex
	syncTicker *time.Ticker
	stopSync   chan struct{}
}

// PcapWriterManager manages PCAP writers for multiple calls
type PcapWriterManager struct {
	config  *PcapWriterConfig
	writers map[string]*CallPcapWriter
	mu      sync.RWMutex
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
		config:  config,
		writers: make(map[string]*CallPcapWriter),
	}, nil
}

// GetOrCreateWriter gets or creates a writer for a call
func (pwm *PcapWriterManager) GetOrCreateWriter(callID, from, to string) (*CallPcapWriter, error) {
	if !pwm.config.Enabled {
		return nil, nil
	}

	pwm.mu.Lock()
	defer pwm.mu.Unlock()

	// Check if writer already exists
	if writer, exists := pwm.writers[callID]; exists {
		return writer, nil
	}

	// Create new writer
	writer, err := pwm.createWriter(callID, from, to)
	if err != nil {
		return nil, err
	}

	pwm.writers[callID] = writer
	return writer, nil
}

// createWriter creates a new PCAP writer for a call with separate SIP and RTP files
func (pwm *PcapWriterManager) createWriter(callID, from, to string) (*CallPcapWriter, error) {
	writer := &CallPcapWriter{
		config:    pwm.config,
		callID:    callID,
		from:      from,
		to:        to,
		startTime: time.Now(),
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

// createInitialFiles creates both SIP and RTP PCAP files
func (writer *CallPcapWriter) createInitialFiles() error {
	if err := writer.rotateSIPFile(); err != nil {
		return fmt.Errorf("failed to create SIP file: %w", err)
	}
	if err := writer.rotateRTPFile(); err != nil {
		return fmt.Errorf("failed to create RTP file: %w", err)
	}
	return nil
}

// WriteSIPPacket writes a SIP packet to the SIP PCAP file
func (writer *CallPcapWriter) WriteSIPPacket(timestamp time.Time, data []byte) error {
	if writer == nil {
		return nil
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()

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

	return nil
}

// WriteRTPPacket writes an RTP packet to the RTP PCAP file
func (writer *CallPcapWriter) WriteRTPPacket(timestamp time.Time, data []byte) error {
	if writer == nil {
		return nil
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()

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

	return nil
}

// rotateSIPFile creates a new SIP PCAP file (called when size limit reached)
func (writer *CallPcapWriter) rotateSIPFile() error {
	// Close existing file
	if writer.sipFile != nil {
		_ = writer.sipFile.Close()
	}

	// Check file limit
	if writer.config.MaxFilesPerCall > 0 && writer.sipFileIndex >= writer.config.MaxFilesPerCall {
		return fmt.Errorf("max SIP files per call reached: %d", writer.config.MaxFilesPerCall)
	}

	// Generate filename
	filename := writer.generateFilename("sip", writer.sipFileIndex)
	filepath := filepath.Join(writer.config.OutputDir, filename)

	// Create file
	// #nosec G304 -- Path is safe: config OutputDir + generateFilename() with sanitization
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create SIP PCAP file: %w", err)
	}

	// Create PCAP writer
	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write SIP PCAP header: %w", err)
	}

	writer.sipFile = file
	writer.sipWriter = pcapWriter
	writer.sipSize = 0
	writer.sipFileIndex++

	logger.Info("Created SIP PCAP file for call", "call_id", writer.callID, "file", filepath)

	return nil
}

// rotateRTPFile creates a new RTP PCAP file (called when size limit reached)
func (writer *CallPcapWriter) rotateRTPFile() error {
	// Close existing file
	if writer.rtpFile != nil {
		_ = writer.rtpFile.Close()
	}

	// Check file limit
	if writer.config.MaxFilesPerCall > 0 && writer.rtpFileIndex >= writer.config.MaxFilesPerCall {
		return fmt.Errorf("max RTP files per call reached: %d", writer.config.MaxFilesPerCall)
	}

	// Generate filename
	filename := writer.generateFilename("rtp", writer.rtpFileIndex)
	filepath := filepath.Join(writer.config.OutputDir, filename)

	// Create file
	// #nosec G304 -- Path is safe: config OutputDir + generateFilename() with sanitization
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create RTP PCAP file: %w", err)
	}

	// Create PCAP writer
	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write RTP PCAP header: %w", err)
	}

	writer.rtpFile = file
	writer.rtpWriter = pcapWriter
	writer.rtpSize = 0
	writer.rtpFileIndex++

	logger.Info("Created RTP PCAP file for call", "call_id", writer.callID, "file", filepath)

	return nil
}

// generateFilename generates a filename for the PCAP file (SIP or RTP)
func (writer *CallPcapWriter) generateFilename(packetType string, fileIndex int) string {
	pattern := writer.config.FilePattern

	// Replace placeholders
	pattern = replaceAll(pattern, "{callid}", sanitizeFilename(writer.callID))
	pattern = replaceAll(pattern, "{from}", sanitizeFilename(writer.from))
	pattern = replaceAll(pattern, "{to}", sanitizeFilename(writer.to))
	pattern = replaceAll(pattern, "{timestamp}", writer.startTime.Format("20060102_150405"))

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
				_ = writer.sipFile.Sync()
			}
			if writer.rtpFile != nil {
				_ = writer.rtpFile.Sync()
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
	if writer.sipFile != nil {
		if err := writer.sipFile.Sync(); err != nil {
			logger.Warn("Failed to sync SIP PCAP file", "error", err)
		}
		if err := writer.sipFile.Close(); err != nil {
			logger.Warn("Failed to close SIP PCAP file", "error", err)
		}
		writer.sipFile = nil
	}

	// Close RTP file
	if writer.rtpFile != nil {
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
		"rtp_files", writer.rtpFileIndex)

	return nil
}

// CloseWriter closes a specific call's writer
func (pwm *PcapWriterManager) CloseWriter(callID string) error {
	pwm.mu.Lock()
	defer pwm.mu.Unlock()

	writer, exists := pwm.writers[callID]
	if !exists {
		return nil
	}

	if err := writer.Close(); err != nil {
		return err
	}

	delete(pwm.writers, callID)
	return nil
}

// Close closes all writers
func (pwm *PcapWriterManager) Close() error {
	pwm.mu.Lock()
	defer pwm.mu.Unlock()

	var lastErr error
	for callID, writer := range pwm.writers {
		if err := writer.Close(); err != nil {
			logger.Warn("Failed to close PCAP writer", "call_id", callID, "error", err)
			lastErr = err
		}
	}

	pwm.writers = make(map[string]*CallPcapWriter)
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

func replaceAll(s, old, new string) string {
	result := ""
	for {
		idx := indexSubstring(s, old)
		if idx == -1 {
			result += s
			break
		}
		result += s[:idx] + new
		s = s[idx+len(old):]
	}
	return result
}

func indexSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

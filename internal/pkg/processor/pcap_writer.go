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
	Enabled       bool   // Enable per-call PCAP writing
	OutputDir     string // Directory for PCAP files
	FilePattern   string // File naming pattern (supports {callid}, {from}, {to}, {timestamp})
	MaxFileSize   int64  // Max PCAP file size in bytes (0 = unlimited)
	MaxFilesPerCall int  // Max number of PCAP files per call (for rotation)
	BufferSize    int    // Write buffer size
	SyncInterval  time.Duration // How often to sync to disk
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

// CallPcapWriter writes packets for a specific call to PCAP file
type CallPcapWriter struct {
	config       *PcapWriterConfig
	callID       string
	from         string
	to           string
	startTime    time.Time
	file         *os.File
	writer       *pcapgo.Writer
	currentSize  int64
	fileIndex    int
	packetCount  int
	mu           sync.Mutex
	syncTicker   *time.Ticker
	stopSync     chan struct{}
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
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
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

// createWriter creates a new PCAP writer for a call
func (pwm *PcapWriterManager) createWriter(callID, from, to string) (*CallPcapWriter, error) {
	writer := &CallPcapWriter{
		config:    pwm.config,
		callID:    callID,
		from:      from,
		to:        to,
		startTime: time.Now(),
		fileIndex: 0,
		stopSync:  make(chan struct{}),
	}

	// Create initial PCAP file
	if err := writer.rotateFile(); err != nil {
		return nil, err
	}

	// Start sync ticker
	writer.syncTicker = time.NewTicker(pwm.config.SyncInterval)
	go writer.syncLoop()

	logger.Info("Created PCAP writer for call", "call_id", callID, "from", from, "to", to)

	return writer, nil
}

// WritePacket writes a packet to the call's PCAP file
func (writer *CallPcapWriter) WritePacket(packet gopacket.Packet) error {
	if writer == nil {
		return nil
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Check if we need to rotate file
	if writer.config.MaxFileSize > 0 && writer.currentSize >= writer.config.MaxFileSize {
		if err := writer.rotateFile(); err != nil {
			return fmt.Errorf("failed to rotate PCAP file: %w", err)
		}
	}

	// Write packet
	ci := packet.Metadata().CaptureInfo
	if err := writer.writer.WritePacket(ci, packet.Data()); err != nil {
		return fmt.Errorf("failed to write packet: %w", err)
	}

	writer.currentSize += int64(len(packet.Data()))
	writer.packetCount++

	return nil
}

// rotateFile creates a new PCAP file (called when size limit reached)
func (writer *CallPcapWriter) rotateFile() error {
	// Close existing file
	if writer.file != nil {
		writer.file.Close()
	}

	// Check file limit
	if writer.config.MaxFilesPerCall > 0 && writer.fileIndex >= writer.config.MaxFilesPerCall {
		return fmt.Errorf("max files per call reached: %d", writer.config.MaxFilesPerCall)
	}

	// Generate filename
	filename := writer.generateFilename()
	filepath := filepath.Join(writer.config.OutputDir, filename)

	// Create file
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create PCAP file: %w", err)
	}

	// Create PCAP writer
	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		file.Close()
		return fmt.Errorf("failed to write PCAP header: %w", err)
	}

	writer.file = file
	writer.writer = pcapWriter
	writer.currentSize = 0
	writer.fileIndex++

	logger.Info("Created PCAP file for call", "call_id", writer.callID, "file", filepath)

	return nil
}

// generateFilename generates a filename for the PCAP file
func (writer *CallPcapWriter) generateFilename() string {
	pattern := writer.config.FilePattern

	// Replace placeholders
	pattern = replaceAll(pattern, "{callid}", sanitizeFilename(writer.callID))
	pattern = replaceAll(pattern, "{from}", sanitizeFilename(writer.from))
	pattern = replaceAll(pattern, "{to}", sanitizeFilename(writer.to))
	pattern = replaceAll(pattern, "{timestamp}", writer.startTime.Format("20060102_150405"))

	// Add index suffix if rotating
	if writer.fileIndex > 0 {
		ext := filepath.Ext(pattern)
		base := pattern[:len(pattern)-len(ext)]
		pattern = fmt.Sprintf("%s_%d%s", base, writer.fileIndex, ext)
	}

	return pattern
}

// syncLoop periodically syncs file to disk
func (writer *CallPcapWriter) syncLoop() {
	for {
		select {
		case <-writer.syncTicker.C:
			writer.mu.Lock()
			if writer.file != nil {
				writer.file.Sync()
			}
			writer.mu.Unlock()
		case <-writer.stopSync:
			return
		}
	}
}

// Close closes the writer and flushes data
func (writer *CallPcapWriter) Close() error {
	if writer == nil {
		return nil
	}

	writer.mu.Lock()
	defer writer.mu.Unlock()

	// Stop sync loop
	close(writer.stopSync)
	writer.syncTicker.Stop()

	// Close file
	if writer.file != nil {
		if err := writer.file.Sync(); err != nil {
			logger.Warn("Failed to sync PCAP file", "error", err)
		}
		if err := writer.file.Close(); err != nil {
			return err
		}
		writer.file = nil
	}

	logger.Info("Closed PCAP writer for call",
		"call_id", writer.callID,
		"packets", writer.packetCount,
		"files", writer.fileIndex)

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

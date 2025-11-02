package pcap

import (
	"fmt"
	"os"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/pcapgo"
)

// OneShotWriter is a simple, synchronous PCAP writer for offline mode
// It writes all packets at once without background goroutines
// Best for: Offline PCAP reading, paused live capture
type OneShotWriter struct {
	config      Config
	file        *os.File
	writer      *pcapgo.Writer
	packetCount int
	mu          sync.Mutex
	closed      bool
}

// NewOneShotWriter creates a new one-shot PCAP writer
func NewOneShotWriter(config Config) (*OneShotWriter, error) {
	if config.FilePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Apply defaults
	if config.LinkType == 0 {
		config.LinkType = DefaultConfig().LinkType
	}
	if config.Snaplen == 0 {
		config.Snaplen = DefaultConfig().Snaplen
	}

	// Create file
	file, err := os.Create(config.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCAP file: %w", err)
	}

	// Create PCAP writer
	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(config.Snaplen, config.LinkType); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			logger.Error("Failed to close file during error cleanup", "error", closeErr, "file", config.FilePath)
		}
		return nil, fmt.Errorf("failed to write PCAP header: %w", err)
	}

	logger.Info("Created one-shot PCAP writer",
		"file", config.FilePath,
		"link_type", config.LinkType,
		"snaplen", config.Snaplen)

	return &OneShotWriter{
		config: config,
		file:   file,
		writer: pcapWriter,
	}, nil
}

// WritePacket writes a single packet to the PCAP file
// Synchronous - writes immediately and returns
func (w *OneShotWriter) WritePacket(pkt types.PacketDisplay) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return fmt.Errorf("writer is closed")
	}

	// Convert PacketDisplay to gopacket format
	ci, rawData, err := PacketDisplayToGopacket(pkt)
	if err != nil {
		// Skip packets without raw data
		logger.Debug("Skipping packet without raw data", "error", err)
		return nil
	}

	// Write packet
	if err := w.writer.WritePacket(ci, rawData); err != nil {
		return fmt.Errorf("failed to write packet: %w", err)
	}

	w.packetCount++
	return nil
}

// Close closes the writer and flushes data to disk
func (w *OneShotWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil // Already closed
	}

	w.closed = true

	// Sync and close file
	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			logger.Warn("Failed to sync PCAP file", "error", err, "file", w.config.FilePath)
		}
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("failed to close PCAP file: %w", err)
		}
		w.file = nil
	}

	logger.Info("Closed one-shot PCAP writer",
		"file", w.config.FilePath,
		"packets", w.packetCount)

	return nil
}

// PacketCount returns the number of packets written
func (w *OneShotWriter) PacketCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.packetCount
}

// FilePath returns the path to the PCAP file
func (w *OneShotWriter) FilePath() string {
	return w.config.FilePath
}

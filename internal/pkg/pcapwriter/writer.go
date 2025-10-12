package pcapwriter

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Writer provides a simple interface for writing packets to a PCAP file
type Writer struct {
	filePath    string
	file        *os.File
	writer      *pcapgo.Writer
	packetChan  chan capture.PacketInfo
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	closed      atomic.Bool
	syncTicker  *time.Ticker
	packetCount int64
	bytesWritten int64
}

// Config for PCAP writer
type Config struct {
	FilePath     string        // Path to PCAP file
	BufferSize   int           // Channel buffer size
	SyncInterval time.Duration // How often to sync to disk (0 = after each packet)
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		BufferSize:   1000,
		SyncInterval: 5 * time.Second,
	}
}

// New creates a new PCAP writer
func New(config *Config) (*Writer, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if config.FilePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}

	// Create file
	file, err := os.Create(config.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCAP file: %w", err)
	}

	// Create PCAP writer with standard Ethernet link type
	// Note: We'll use the actual link type from the first packet
	pcapWriter := pcapgo.NewWriter(file)

	ctx, cancel := context.WithCancel(context.Background())

	w := &Writer{
		filePath:   config.FilePath,
		file:       file,
		writer:     pcapWriter,
		packetChan: make(chan capture.PacketInfo, config.BufferSize),
		ctx:        ctx,
		cancel:     cancel,
		syncTicker: time.NewTicker(config.SyncInterval),
	}

	// Start write loop
	w.wg.Add(1)
	go w.writeLoop()

	logger.Info("Created PCAP writer", "file", config.FilePath, "buffer_size", config.BufferSize)

	return w, nil
}

// WritePacket writes a packet to the PCAP file (non-blocking)
func (w *Writer) WritePacket(pkt capture.PacketInfo) error {
	if w.closed.Load() {
		return fmt.Errorf("writer is closed")
	}

	select {
	case w.packetChan <- pkt:
		return nil
	case <-w.ctx.Done():
		return fmt.Errorf("writer context cancelled")
	default:
		// Channel full - drop packet
		logger.Warn("Packet dropped due to full write buffer", "file", w.filePath)
		return fmt.Errorf("write buffer full")
	}
}

// writeLoop is the main packet writing goroutine
func (w *Writer) writeLoop() {
	defer w.wg.Done()

	headerWritten := false
	var linkType layers.LinkType

	for {
		select {
		case pkt, ok := <-w.packetChan:
			if !ok {
				// Channel closed
				return
			}

			// Write file header on first packet (to get correct link type)
			if !headerWritten {
				linkType = pkt.LinkType
				if err := w.writer.WriteFileHeader(65536, linkType); err != nil {
					logger.Error("Failed to write PCAP header", "error", err, "file", w.filePath)
					return
				}
				headerWritten = true
				logger.Debug("Wrote PCAP header", "file", w.filePath, "link_type", linkType)
			}

			// Write packet
			if err := w.writePacketToFile(pkt); err != nil {
				logger.Error("Failed to write packet", "error", err, "file", w.filePath)
				// Continue writing despite errors
			}

		case <-w.syncTicker.C:
			// Periodic sync
			w.mu.Lock()
			if w.file != nil {
				w.file.Sync()
			}
			w.mu.Unlock()

		case <-w.ctx.Done():
			// Context cancelled - drain remaining packets
			w.drainPackets()
			return
		}
	}
}

// writePacketToFile writes a single packet to the file
func (w *Writer) writePacketToFile(pkt capture.PacketInfo) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ci := pkt.Packet.Metadata().CaptureInfo
	if err := w.writer.WritePacket(ci, pkt.Packet.Data()); err != nil {
		return fmt.Errorf("failed to write packet: %w", err)
	}

	atomic.AddInt64(&w.packetCount, 1)
	atomic.AddInt64(&w.bytesWritten, int64(len(pkt.Packet.Data())))

	return nil
}

// drainPackets drains any remaining packets in the channel
func (w *Writer) drainPackets() {
	for {
		select {
		case pkt, ok := <-w.packetChan:
			if !ok {
				return
			}
			if err := w.writePacketToFile(pkt); err != nil {
				logger.Warn("Failed to write packet during drain", "error", err)
			}
		default:
			// No more packets
			return
		}
	}
}

// Close closes the writer and flushes all pending packets
func (w *Writer) Close() error {
	if w.closed.Swap(true) {
		return nil // Already closed
	}

	logger.Info("Closing PCAP writer", "file", w.filePath)

	// Cancel context to stop write loop
	w.cancel()

	// Close packet channel
	close(w.packetChan)

	// Wait for write loop to finish
	w.wg.Wait()

	// Stop sync ticker
	w.syncTicker.Stop()

	// Close file
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			logger.Warn("Failed to sync PCAP file", "error", err, "file", w.filePath)
		}
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("failed to close PCAP file: %w", err)
		}
		w.file = nil
	}

	logger.Info("Closed PCAP writer",
		"file", w.filePath,
		"packets", w.packetCount,
		"bytes", w.bytesWritten)

	return nil
}

// Stats returns current writer statistics
func (w *Writer) Stats() (packetCount, bytesWritten int64) {
	return atomic.LoadInt64(&w.packetCount), atomic.LoadInt64(&w.bytesWritten)
}

// FilePath returns the file path being written to
func (w *Writer) FilePath() string {
	return w.filePath
}

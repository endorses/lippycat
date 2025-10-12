package pcap

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/pcapgo"
)

// FilterFunc defines a filter function for packets
// Return true to write the packet, false to skip
type FilterFunc func(types.PacketDisplay) bool

// StreamingWriter is an asynchronous PCAP writer for live capture
// Writes packets in background goroutine with periodic sync to disk
// Best for: Live capture, remote capture, long-running saves
type StreamingWriter struct {
	config       Config
	file         *os.File
	writer       *pcapgo.Writer
	packetChan   chan types.PacketDisplay
	filterFunc   FilterFunc
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	mu           sync.Mutex
	closed       atomic.Bool
	syncTicker   *time.Ticker
	packetCount  int64
	droppedCount int64
}

// NewStreamingWriter creates a new streaming PCAP writer
// filterFunc is optional - pass nil to write all packets
func NewStreamingWriter(config Config, filterFunc FilterFunc) (*StreamingWriter, error) {
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
	if config.SyncInterval == 0 {
		config.SyncInterval = DefaultConfig().SyncInterval
	}
	if config.BufferSize == 0 {
		config.BufferSize = DefaultConfig().BufferSize
	}

	// Create file
	file, err := os.Create(config.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCAP file: %w", err)
	}

	// Create PCAP writer
	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(config.Snaplen, config.LinkType); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write PCAP header: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &StreamingWriter{
		config:     config,
		file:       file,
		writer:     pcapWriter,
		packetChan: make(chan types.PacketDisplay, config.BufferSize),
		filterFunc: filterFunc,
		ctx:        ctx,
		cancel:     cancel,
		syncTicker: time.NewTicker(config.SyncInterval),
	}

	// Start write loop
	w.wg.Add(1)
	go w.writeLoop()

	logger.Info("Created streaming PCAP writer",
		"file", config.FilePath,
		"link_type", config.LinkType,
		"snaplen", config.Snaplen,
		"buffer_size", config.BufferSize,
		"sync_interval", config.SyncInterval,
		"has_filter", filterFunc != nil)

	return w, nil
}

// WritePacket writes a packet to the PCAP file (non-blocking)
// Packets are queued and written asynchronously by background goroutine
func (w *StreamingWriter) WritePacket(pkt types.PacketDisplay) error {
	if w.closed.Load() {
		return fmt.Errorf("writer is closed")
	}

	// Apply filter if set
	if w.filterFunc != nil && !w.filterFunc(pkt) {
		return nil // Packet filtered out
	}

	select {
	case w.packetChan <- pkt:
		return nil
	case <-w.ctx.Done():
		return fmt.Errorf("writer context cancelled")
	default:
		// Channel full - drop packet
		dropped := atomic.AddInt64(&w.droppedCount, 1)
		if dropped%100 == 0 {
			logger.Warn("Packets dropped due to full write buffer",
				"total_dropped", dropped,
				"file", w.config.FilePath)
		}
		return fmt.Errorf("write buffer full, packet dropped")
	}
}

// writeLoop is the main packet writing goroutine
func (w *StreamingWriter) writeLoop() {
	defer w.wg.Done()

	for {
		select {
		case pkt, ok := <-w.packetChan:
			if !ok {
				// Channel closed
				return
			}

			// Write packet
			if err := w.writePacketToFile(pkt); err != nil {
				logger.Error("Failed to write packet",
					"error", err,
					"file", w.config.FilePath)
				// Continue writing despite errors
			}

		case <-w.syncTicker.C:
			// Periodic sync
			w.mu.Lock()
			if w.file != nil {
				if err := w.file.Sync(); err != nil {
					logger.Warn("Failed to sync PCAP file",
						"error", err,
						"file", w.config.FilePath)
				}
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
func (w *StreamingWriter) writePacketToFile(pkt types.PacketDisplay) error {
	w.mu.Lock()
	defer w.mu.Unlock()

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

	atomic.AddInt64(&w.packetCount, 1)
	return nil
}

// drainPackets drains any remaining packets in the channel
func (w *StreamingWriter) drainPackets() {
	for {
		select {
		case pkt, ok := <-w.packetChan:
			if !ok {
				return
			}
			if err := w.writePacketToFile(pkt); err != nil {
				logger.Warn("Failed to write packet during drain",
					"error", err,
					"file", w.config.FilePath)
			}
		default:
			// No more packets
			return
		}
	}
}

// Close closes the writer and flushes all pending packets
func (w *StreamingWriter) Close() error {
	if w.closed.Swap(true) {
		return nil // Already closed
	}

	logger.Info("Closing streaming PCAP writer", "file", w.config.FilePath)

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
			logger.Warn("Failed to sync PCAP file",
				"error", err,
				"file", w.config.FilePath)
		}
		if err := w.file.Close(); err != nil {
			return fmt.Errorf("failed to close PCAP file: %w", err)
		}
		w.file = nil
	}

	logger.Info("Closed streaming PCAP writer",
		"file", w.config.FilePath,
		"packets", w.packetCount,
		"dropped", w.droppedCount)

	return nil
}

// PacketCount returns the number of packets written
func (w *StreamingWriter) PacketCount() int {
	return int(atomic.LoadInt64(&w.packetCount))
}

// FilePath returns the path to the PCAP file
func (w *StreamingWriter) FilePath() string {
	return w.config.FilePath
}

// DroppedCount returns the number of packets dropped due to full buffer
func (w *StreamingWriter) DroppedCount() int64 {
	return atomic.LoadInt64(&w.droppedCount)
}

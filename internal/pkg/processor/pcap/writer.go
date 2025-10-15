package pcap

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Writer manages asynchronous PCAP file writing
type Writer struct {
	file   *os.File
	writer *pcapgo.Writer

	writeQueue chan []*data.CapturedPacket
	writerWg   sync.WaitGroup

	writeErrors     atomic.Uint64 // Total write errors
	consecErrors    atomic.Uint64 // Consecutive write errors
	lastErrorLogged atomic.Int64  // Timestamp of last error log

	ctx    context.Context
	cancel context.CancelFunc
}

// NewWriter creates a new PCAP writer
func NewWriter(filePath string) (*Writer, error) {
	logger.Info("Initializing async PCAP writer", "file", filePath)

	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCAP file: %w", err)
	}

	pcapWriter := pcapgo.NewWriter(file)

	// Write PCAP header (Ethernet link type)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to write PCAP header: %w", err)
	}

	w := &Writer{
		file:       file,
		writer:     pcapWriter,
		writeQueue: make(chan []*data.CapturedPacket, constants.PCAPWriteQueueBuffer),
	}

	logger.Info("Async PCAP writer initialized", "file", filePath)
	return w, nil
}

// Start begins the async write worker
func (w *Writer) Start(ctx context.Context) {
	w.ctx, w.cancel = context.WithCancel(ctx)

	// Start single writer goroutine
	// Note: PCAP writes are inherently serial (file format requires sequential writes)
	// Multiple workers would just compete for mutex with no benefit
	w.writerWg.Add(1)
	go w.writeWorker()
}

// Stop stops the writer and closes the file
func (w *Writer) Stop() {
	// Close queue to signal worker
	if w.writeQueue != nil {
		close(w.writeQueue)
	}

	// Wait for worker to finish
	logger.Info("Waiting for PCAP writer to finish")
	w.writerWg.Wait()

	// Close file
	if w.file != nil {
		_ = w.file.Close()
		logger.Info("PCAP file closed")
	}
}

// QueuePackets queues packets for async writing
// Returns false if queue is full (non-blocking)
func (w *Writer) QueuePackets(packets []*data.CapturedPacket) bool {
	select {
	case w.writeQueue <- packets:
		return true
	default:
		logger.Warn("PCAP write queue full, dropping batch", "packets", len(packets))
		return false
	}
}

// QueueDepth returns the current queue depth
func (w *Writer) QueueDepth() int {
	return len(w.writeQueue)
}

// QueueCapacity returns the queue capacity
func (w *Writer) QueueCapacity() int {
	return cap(w.writeQueue)
}

// GetStats returns write error statistics
func (w *Writer) GetStats() (totalErrors, consecErrors uint64) {
	return w.writeErrors.Load(), w.consecErrors.Load()
}

// writeWorker processes PCAP write queue asynchronously (single writer)
func (w *Writer) writeWorker() {
	defer w.writerWg.Done()

	logger.Debug("PCAP write worker started")

	for {
		select {
		case <-w.ctx.Done():
			logger.Debug("PCAP write worker stopping")
			return

		case packets, ok := <-w.writeQueue:
			if !ok {
				logger.Debug("PCAP write queue closed")
				return
			}

			// Write batch to PCAP file (single writer - no mutex needed)
			w.writePacketBatch(packets)
		}
	}
}

// writePacketBatch writes a batch of packets to PCAP file (called by single writer)
func (w *Writer) writePacketBatch(packets []*data.CapturedPacket) {
	// No mutex needed - single writer goroutine ensures serial access

	batchErrors := 0
	for _, pkt := range packets {
		// Convert timestamp
		timestamp := time.Unix(0, pkt.TimestampNs)

		// Create capture info
		ci := gopacket.CaptureInfo{
			Timestamp:     timestamp,
			CaptureLength: int(pkt.CaptureLength),
			Length:        int(pkt.OriginalLength),
		}

		// Write packet
		if err := w.writer.WritePacket(ci, pkt.Data); err != nil {
			batchErrors++
			w.writeErrors.Add(1)
			consecErrors := w.consecErrors.Add(1)

			// Log errors with rate limiting (max once per 10 seconds)
			now := time.Now().Unix()
			lastLogged := w.lastErrorLogged.Load()
			if now-lastLogged >= 10 {
				if w.lastErrorLogged.CompareAndSwap(lastLogged, now) {
					logger.Error("Failed to write packet to PCAP",
						"error", err,
						"consecutive_errors", consecErrors,
						"total_errors", w.writeErrors.Load())

					// Emit critical warning if many consecutive failures
					if consecErrors >= 100 {
						logger.Warn("PCAP writing may be failing due to disk full or permissions",
							"consecutive_errors", consecErrors,
							"recommendation", "check disk space and file permissions")
					}
				}
			}
		} else {
			// Successful write - reset consecutive error counter
			if w.consecErrors.Load() > 0 {
				w.consecErrors.Store(0)
			}
		}
	}

	// Log batch summary if there were errors
	if batchErrors > 0 && len(packets) > 0 {
		logger.Warn("PCAP batch write completed with errors",
			"batch_size", len(packets),
			"errors", batchErrors,
			"success_rate", float64(len(packets)-batchErrors)/float64(len(packets))*100)
	}
}

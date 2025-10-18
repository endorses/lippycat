//go:build hunter || all

package buffer

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/protobuf/proto"
)

// DiskOverflowBuffer provides disk-based buffering when memory queue is full
// Layout: [4-byte length][protobuf batch][4-byte length][protobuf batch]...
type DiskOverflowBuffer struct {
	// Configuration
	dir              string // Directory for buffer files
	maxDiskBytes     uint64 // Maximum disk space to use
	compressionLevel int    // 0=none, 1-9=gzip level

	// State
	mu            sync.Mutex
	currentFile   *os.File
	currentSize   atomic.Uint64 // Current total bytes on disk
	writeSequence uint64        // Monotonic write counter
	readSequence  uint64        // Monotonic read counter (for cleanup)

	// Metrics
	totalWrites   atomic.Uint64 // Total batches written to disk
	totalReads    atomic.Uint64 // Total batches read from disk
	totalDropped  atomic.Uint64 // Total batches dropped (disk full)
	peakDiskBytes atomic.Uint64 // Peak disk usage
}

// Config contains disk buffer configuration
type Config struct {
	Dir              string // Directory for buffer files (default: /var/tmp/lippycat-buffer)
	MaxDiskBytes     uint64 // Maximum disk space (default: 1GB)
	CompressionLevel int    // Compression level 0-9 (default: 0 = disabled for speed)
}

// New creates a new disk overflow buffer
func New(config Config) (*DiskOverflowBuffer, error) {
	// Set defaults
	if config.Dir == "" {
		config.Dir = "/var/tmp/lippycat-buffer"
	}
	if config.MaxDiskBytes == 0 {
		config.MaxDiskBytes = 1024 * 1024 * 1024 // 1GB default
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(config.Dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create buffer directory: %w", err)
	}

	// Clean up any existing buffer files from previous runs
	pattern := filepath.Join(config.Dir, "batch-*.pb")
	matches, _ := filepath.Glob(pattern)
	for _, match := range matches {
		_ = os.Remove(match)
	}

	return &DiskOverflowBuffer{
		dir:              config.Dir,
		maxDiskBytes:     config.MaxDiskBytes,
		compressionLevel: config.CompressionLevel,
	}, nil
}

// Write writes a batch to disk (called when memory queue is full)
func (b *DiskOverflowBuffer) Write(batch *data.PacketBatch) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Serialize batch to protobuf
	pbData, err := proto.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to serialize batch: %w", err)
	}

	// Check disk space limit
	currentSize := b.currentSize.Load()
	neededSpace := uint64(4 + len(pbData)) // 4-byte length prefix + data
	if currentSize+neededSpace > b.maxDiskBytes {
		b.totalDropped.Add(1)
		logger.Warn("Disk buffer full, dropping batch",
			"sequence", batch.Sequence,
			"current_bytes", currentSize,
			"max_bytes", b.maxDiskBytes)
		return fmt.Errorf("disk buffer full")
	}

	// Create new file if needed
	if b.currentFile == nil {
		filename := filepath.Join(b.dir, fmt.Sprintf("batch-%010d.pb", b.writeSequence))
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to create buffer file: %w", err)
		}
		b.currentFile = f
	}

	// Write length prefix (4 bytes, big-endian)
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(pbData)))
	if _, err := b.currentFile.Write(lengthBuf[:]); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}

	// Write protobuf data
	if _, err := b.currentFile.Write(pbData); err != nil {
		return fmt.Errorf("failed to write batch data: %w", err)
	}

	// Sync and close file (one batch per file for simplicity)
	if err := b.currentFile.Sync(); err != nil {
		logger.Warn("Failed to sync buffer file", "error", err)
	}
	b.currentFile.Close()
	b.currentFile = nil

	// Update metrics
	b.writeSequence++
	newSize := b.currentSize.Add(neededSpace)
	b.totalWrites.Add(1)

	// Update peak metric
	for {
		currentPeak := b.peakDiskBytes.Load()
		if newSize <= currentPeak || b.peakDiskBytes.CompareAndSwap(currentPeak, newSize) {
			break
		}
	}

	logger.Debug("Wrote batch to disk buffer",
		"sequence", batch.Sequence,
		"bytes", neededSpace,
		"total_bytes", newSize)

	return nil
}

// Read reads the next available batch from disk (FIFO order)
// Returns nil, nil if no batches available
func (b *DiskOverflowBuffer) Read() (*data.PacketBatch, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Find oldest buffer file
	filename := filepath.Join(b.dir, fmt.Sprintf("batch-%010d.pb", b.readSequence))
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// No more batches
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open buffer file: %w", err)
	}
	defer f.Close()

	// Read length prefix
	var lengthBuf [4]byte
	if _, err := io.ReadFull(f, lengthBuf[:]); err != nil {
		if err == io.EOF {
			// Empty file - remove it and try next
			_ = os.Remove(filename)
			b.readSequence++
			return b.Read() // Recursive call to try next file
		}
		return nil, fmt.Errorf("failed to read length prefix: %w", err)
	}

	length := binary.BigEndian.Uint32(lengthBuf[:])
	if length > 10*1024*1024 { // Sanity check: max 10MB per batch
		logger.Error("Invalid batch length in buffer file", "length", length, "file", filename)
		_ = os.Remove(filename)
		b.readSequence++
		return nil, fmt.Errorf("invalid batch length: %d", length)
	}

	// Read protobuf data
	pbData := make([]byte, length)
	if _, err := io.ReadFull(f, pbData); err != nil {
		return nil, fmt.Errorf("failed to read batch data: %w", err)
	}

	// Deserialize batch
	var batch data.PacketBatch
	if err := proto.Unmarshal(pbData, &batch); err != nil {
		logger.Error("Failed to deserialize batch", "error", err, "file", filename)
		_ = os.Remove(filename)
		b.readSequence++
		return nil, fmt.Errorf("failed to deserialize batch: %w", err)
	}

	// Remove file and update metrics
	_ = os.Remove(filename)
	b.readSequence++
	b.currentSize.Add(^uint64(4 + length - 1)) // Subtract (length + 4)
	b.totalReads.Add(1)

	logger.Debug("Read batch from disk buffer",
		"sequence", batch.Sequence,
		"packets", len(batch.Packets),
		"file", filename)

	return &batch, nil
}

// Close closes the disk buffer and removes all files
func (b *DiskOverflowBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Close current file
	if b.currentFile != nil {
		b.currentFile.Close()
		b.currentFile = nil
	}

	// Remove all buffer files
	pattern := filepath.Join(b.dir, "batch-*.pb")
	matches, _ := filepath.Glob(pattern)
	for _, match := range matches {
		_ = os.Remove(match)
	}

	logger.Info("Disk buffer closed",
		"total_writes", b.totalWrites.Load(),
		"total_reads", b.totalReads.Load(),
		"total_dropped", b.totalDropped.Load(),
		"peak_bytes", b.peakDiskBytes.Load())

	return nil
}

// GetMetrics returns current buffer metrics
func (b *DiskOverflowBuffer) GetMetrics() DiskBufferMetrics {
	return DiskBufferMetrics{
		CurrentBytes:   b.currentSize.Load(),
		MaxBytes:       b.maxDiskBytes,
		TotalWrites:    b.totalWrites.Load(),
		TotalReads:     b.totalReads.Load(),
		TotalDropped:   b.totalDropped.Load(),
		PeakBytes:      b.peakDiskBytes.Load(),
		PendingBatches: b.writeSequence - b.readSequence,
	}
}

// DiskBufferMetrics contains disk buffer statistics
type DiskBufferMetrics struct {
	CurrentBytes   uint64 // Current bytes on disk
	MaxBytes       uint64 // Maximum allowed bytes
	TotalWrites    uint64 // Total batches written
	TotalReads     uint64 // Total batches read
	TotalDropped   uint64 // Total batches dropped (disk full)
	PeakBytes      uint64 // Peak disk usage
	PendingBatches uint64 // Number of batches waiting to be read
}

// Utilization returns disk buffer utilization as a percentage (0.0 to 1.0)
func (m DiskBufferMetrics) Utilization() float64 {
	if m.MaxBytes == 0 {
		return 0.0
	}
	return float64(m.CurrentBytes) / float64(m.MaxBytes)
}

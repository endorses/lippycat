//go:build cli || all
// +build cli all

package voip

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// MmapWriterV2 provides enhanced memory-mapped I/O with ring buffer and concurrent support
type MmapWriterV2 struct {
	file         *os.File
	writer       *pcapgo.Writer
	mmapData     []byte
	size         int64
	writePos     atomic.Int64 // Atomic write position for lock-free writes
	flushPos     atomic.Int64 // Position of last flush
	maxSize      int64
	enableMmap   bool
	fallbackMode atomic.Bool

	// Ring buffer support
	ringBuffer bool
	ringStart  int64
	ringEnd    int64

	// Concurrency control
	mu         sync.RWMutex // For structural changes only
	writerPool *BufferPool  // Reuse write buffers

	// Rotation support
	rotationSize int64
	rotationCb   func(oldPath, newPath string)
	rotationNum  atomic.Int32

	// Metrics
	packetsWritten atomic.Int64
	bytesWritten   atomic.Int64
	mmapErrors     atomic.Int64
	rotations      atomic.Int32
}

// MmapWriterV2Config configures enhanced memory-mapped writer
type MmapWriterV2Config struct {
	MaxFileSize   int64                         // Max file size before rotation
	EnableMmap    bool                          // Enable memory mapping
	PreallocSize  int64                         // Preallocate size
	FallbackOnErr bool                          // Fallback to regular I/O on errors
	RingBuffer    bool                          // Use ring buffer mode
	RotationSize  int64                         // Rotate at this size (0 = no rotation)
	RotationCb    func(oldPath, newPath string) // Callback on rotation
}

// DefaultMmapV2Config returns default configuration
func DefaultMmapV2Config() *MmapWriterV2Config {
	return &MmapWriterV2Config{
		MaxFileSize:   1024 * 1024 * 1024, // 1GB
		EnableMmap:    true,
		PreallocSize:  100 * 1024 * 1024, // 100MB
		FallbackOnErr: true,
		RingBuffer:    false,
		RotationSize:  0, // No rotation by default
	}
}

// NewMmapWriterV2 creates an enhanced memory-mapped writer
func NewMmapWriterV2(filename string, linkType layers.LinkType, config *MmapWriterV2Config) (*MmapWriterV2, error) {
	if config == nil {
		config = DefaultMmapV2Config()
	}

	// Create file with proper permissions
	// #nosec G304 -- filename from call tracker, sanitized path
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCAP file: %w", err)
	}

	writer := &MmapWriterV2{
		file:         file,
		maxSize:      config.MaxFileSize,
		enableMmap:   config.EnableMmap,
		ringBuffer:   config.RingBuffer,
		rotationSize: config.RotationSize,
		rotationCb:   config.RotationCb,
		writerPool:   GetBufferPool(),
	}
	writer.fallbackMode.Store(false)

	// Write PCAP header
	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(65536, linkType); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("failed to write PCAP header: %w", err)
	}
	writer.writer = pcapWriter
	writer.writePos.Store(24) // PCAP header size

	// Set up memory mapping if enabled
	if config.EnableMmap && config.PreallocSize > 0 {
		if err := writer.setupMmapV2(config.PreallocSize); err != nil {
			if config.FallbackOnErr {
				logger.Warn("Memory mapping failed, falling back to regular I/O",
					"error", err, "filename", filename)
				writer.fallbackMode.Store(true)
			} else {
				_ = file.Close()
				return nil, fmt.Errorf("failed to setup memory mapping: %w", err)
			}
		}
	} else {
		writer.fallbackMode.Store(true)
	}

	return writer, nil
}

// setupMmapV2 initializes memory mapping with proper permissions
func (w *MmapWriterV2) setupMmapV2(size int64) error {
	// Preallocate file space
	if err := w.file.Truncate(size); err != nil {
		return fmt.Errorf("failed to preallocate file space: %w", err)
	}

	// Memory map with READ+WRITE permissions (critical fix)
	mmapData, err := syscall.Mmap(int(w.file.Fd()), 0, int(size),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("failed to memory map file: %w", err)
	}

	w.mmapData = mmapData
	w.size = size

	if w.ringBuffer {
		w.ringStart = 24 // After PCAP header
		w.ringEnd = size
	}

	// #nosec G103 -- Audited: Getting mmap address for logging only, no pointer arithmetic
	logger.Info("Enhanced memory-mapped PCAP writer initialized",
		"filename", w.file.Name(),
		"size", size,
		"ring_buffer", w.ringBuffer,
		"mmap_addr", fmt.Sprintf("0x%x", uintptr(unsafe.Pointer(&mmapData[0]))))

	return nil
}

// WritePacket writes a packet with lock-free concurrent support
func (w *MmapWriterV2) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	if w.fallbackMode.Load() || w.mmapData == nil {
		// Use regular writer with lock
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.writer.WritePacket(ci, data)
	}

	// Calculate record size
	recordSize := int64(16 + len(data))

	// Check rotation
	if w.rotationSize > 0 {
		currentPos := w.writePos.Load()
		if currentPos+recordSize > w.rotationSize {
			if err := w.rotate(); err != nil {
				logger.Error("File rotation failed", "error", err)
			}
		}
	}

	// Lock-free atomic position reservation
	for {
		currentPos := w.writePos.Load()
		nextPos := currentPos + recordSize

		// Check bounds
		if !w.ringBuffer && nextPos > w.size {
			// Out of space, fall back
			logger.Warn("Memory-mapped region full, falling back",
				"current_pos", currentPos,
				"record_size", recordSize,
				"total_size", w.size)
			w.fallbackMode.Store(true)
			w.mu.Lock()
			defer w.mu.Unlock()
			return w.writer.WritePacket(ci, data)
		}

		// Ring buffer wrap
		if w.ringBuffer && nextPos > w.ringEnd {
			nextPos = w.ringStart + recordSize
		}

		// Try to claim this position
		if w.writePos.CompareAndSwap(currentPos, nextPos) {
			// Successfully claimed position, write packet
			return w.writePacketAt(currentPos, ci, data)
		}
		// CAS failed, retry
	}
}

// writePacketAt writes packet at specific position (lock-free)
func (w *MmapWriterV2) writePacketAt(pos int64, ci gopacket.CaptureInfo, data []byte) error {
	// Write PCAP record header (16 bytes) with proper endianness
	header := w.mmapData[pos : pos+16]

	// Use little-endian for PCAP format
	// Safe conversions: timestamp fits in uint32 until year 2106, packet lengths are bounded by MTU
	binary.LittleEndian.PutUint32(header[0:4], uint32(ci.Timestamp.Unix()))            // #nosec G115
	binary.LittleEndian.PutUint32(header[4:8], uint32(ci.Timestamp.Nanosecond()/1000)) // #nosec G115
	binary.LittleEndian.PutUint32(header[8:12], uint32(ci.CaptureLength))              // #nosec G115
	binary.LittleEndian.PutUint32(header[12:16], uint32(ci.Length))                    // #nosec G115

	// Copy packet data
	copy(w.mmapData[pos+16:pos+16+int64(len(data))], data)

	// Update metrics
	w.packetsWritten.Add(1)
	w.bytesWritten.Add(int64(16 + len(data)))

	return nil
}

// Flush syncs data to disk
func (w *MmapWriterV2) Flush() error {
	if w.mmapData != nil && !w.fallbackMode.Load() {
		currentPos := w.writePos.Load()

		// Only sync new data
		flushPos := w.flushPos.Load()
		if currentPos > flushPos {
			// Sync the delta
			syncSize := currentPos - flushPos
			if syncSize > 0 {
				// #nosec G103 -- Audited: Required for msync syscall, mmap region properly managed
				if _, _, errno := syscall.Syscall(syscall.SYS_MSYNC,
					uintptr(unsafe.Pointer(&w.mmapData[flushPos])),
					uintptr(syncSize),
					uintptr(syscall.MS_ASYNC)); errno != 0 {
					w.mmapErrors.Add(1)
					return fmt.Errorf("failed to sync mmap data: %v", errno)
				}
			}
			w.flushPos.Store(currentPos)
		}
	}
	return w.file.Sync()
}

// rotate handles file rotation
func (w *MmapWriterV2) rotate() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.fallbackMode.Load() {
		return fmt.Errorf("cannot rotate in fallback mode")
	}

	// Sync current file
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush before rotation failed: %w", err)
	}

	// Generate new filename
	rotNum := w.rotationNum.Add(1)
	oldPath := w.file.Name()
	newPath := fmt.Sprintf("%s.%d", oldPath, rotNum)

	// Unmap current file
	if w.mmapData != nil {
		if err := syscall.Munmap(w.mmapData); err != nil {
			return fmt.Errorf("failed to unmap: %w", err)
		}
		w.mmapData = nil
	}

	// Truncate to actual size
	currentPos := w.writePos.Load()
	if err := w.file.Truncate(currentPos); err != nil {
		return fmt.Errorf("truncate failed: %w", err)
	}

	// Close old file
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close old file failed: %w", err)
	}

	// Rename old file
	if err := os.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("rename failed: %w", err)
	}

	// Create new file
	// #nosec G304 -- oldPath is internal, from file rotation
	newFile, err := os.OpenFile(oldPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create new file failed: %w", err)
	}

	w.file = newFile

	// Write new PCAP header
	pcapWriter := pcapgo.NewWriter(newFile)
	if err := pcapWriter.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("write header failed: %w", err)
	}
	w.writer = pcapWriter

	// Remap new file
	if err := w.setupMmapV2(w.size); err != nil {
		return fmt.Errorf("remap failed: %w", err)
	}

	w.writePos.Store(24)
	w.flushPos.Store(0)
	w.rotations.Add(1)

	// Callback notification
	if w.rotationCb != nil {
		go w.rotationCb(newPath, oldPath)
	}

	logger.Info("File rotated successfully",
		"old_path", newPath,
		"new_path", oldPath,
		"rotation_num", rotNum)

	return nil
}

// Close closes the writer and cleans up
func (w *MmapWriterV2) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var firstErr error

	// Final flush
	if err := w.Flush(); err != nil {
		firstErr = err
	}

	// Unmap memory
	if w.mmapData != nil {
		if err := syscall.Munmap(w.mmapData); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to unmap: %w", err)
		}
		w.mmapData = nil
	}

	// Truncate to actual size
	currentPos := w.writePos.Load()
	if currentPos > 0 && currentPos < w.size {
		if err := w.file.Truncate(currentPos); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to truncate: %w", err)
		}
	}

	// Close file
	if err := w.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	logger.Info("Enhanced memory-mapped writer closed",
		"filename", w.file.Name(),
		"packets_written", w.packetsWritten.Load(),
		"bytes_written", w.bytesWritten.Load(),
		"rotations", w.rotations.Load(),
		"mmap_errors", w.mmapErrors.Load(),
		"fallback_used", w.fallbackMode.Load())

	return firstErr
}

// GetStats returns detailed statistics
func (w *MmapWriterV2) GetStats() map[string]interface{} {
	currentPos := w.writePos.Load()

	stats := map[string]interface{}{
		"filename":        w.file.Name(),
		"packets_written": w.packetsWritten.Load(),
		"bytes_written":   w.bytesWritten.Load(),
		"current_pos":     currentPos,
		"total_size":      w.size,
		"fallback_mode":   w.fallbackMode.Load(),
		"mmap_enabled":    w.mmapData != nil,
		"ring_buffer":     w.ringBuffer,
		"rotations":       w.rotations.Load(),
		"mmap_errors":     w.mmapErrors.Load(),
	}

	if w.mmapData != nil && w.size > 0 {
		stats["utilization"] = float64(currentPos) / float64(w.size) * 100.0
	}

	return stats
}

// GetMetrics returns metrics for monitoring
func (w *MmapWriterV2) GetMetrics() MmapMetrics {
	return MmapMetrics{
		PacketsWritten: w.packetsWritten.Load(),
		BytesWritten:   w.bytesWritten.Load(),
		CurrentPos:     w.writePos.Load(),
		TotalSize:      w.size,
		Utilization:    float64(w.writePos.Load()) / float64(w.size) * 100.0,
		FallbackMode:   w.fallbackMode.Load(),
		Rotations:      w.rotations.Load(),
		MmapErrors:     w.mmapErrors.Load(),
	}
}

// MmapMetrics holds performance metrics
type MmapMetrics struct {
	PacketsWritten int64
	BytesWritten   int64
	CurrentPos     int64
	TotalSize      int64
	Utilization    float64
	FallbackMode   bool
	Rotations      int32
	MmapErrors     int64
}

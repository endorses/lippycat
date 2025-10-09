package voip

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

// MmapWriter provides memory-mapped I/O for high-volume PCAP writing
type MmapWriter struct {
	file         *os.File
	writer       *pcapgo.Writer
	mmapData     []byte
	size         int64
	currentPos   int64
	maxSize      int64
	enableMmap   bool
	fallbackMode bool
}

// MmapWriterConfig configures memory-mapped writer behavior
type MmapWriterConfig struct {
	MaxFileSize   int64 // Maximum file size before rotating (default: 1GB)
	EnableMmap    bool  // Whether to use memory mapping (default: true for files > 100MB)
	PreallocSize  int64 // Size to preallocate (default: 100MB)
	FallbackOnErr bool  // Fall back to regular I/O on mmap errors (default: true)
}

// DefaultMmapConfig returns sensible defaults for memory-mapped writing
func DefaultMmapConfig() *MmapWriterConfig {
	return &MmapWriterConfig{
		MaxFileSize:   1024 * 1024 * 1024, // 1GB
		EnableMmap:    true,
		PreallocSize:  100 * 1024 * 1024, // 100MB
		FallbackOnErr: true,
	}
}

// NewMmapWriter creates a new memory-mapped PCAP writer
func NewMmapWriter(filename string, config *MmapWriterConfig) (*MmapWriter, error) {
	if config == nil {
		config = DefaultMmapConfig()
	}

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create PCAP file: %w", err)
	}

	writer := &MmapWriter{
		file:         file,
		maxSize:      config.MaxFileSize,
		enableMmap:   config.EnableMmap,
		fallbackMode: false,
	}

	// Initialize regular pcapgo writer first
	pcapWriter := pcapgo.NewWriter(file)
	if err := pcapWriter.WriteFileHeader(65536, 1 /* Ethernet */); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to write PCAP header: %w", err)
	}
	writer.writer = pcapWriter

	// Set up memory mapping if enabled and file is large enough
	if config.EnableMmap && config.PreallocSize > 0 {
		if err := writer.setupMmap(config.PreallocSize); err != nil {
			if config.FallbackOnErr {
				logger.Warn("Memory mapping failed, falling back to regular I/O",
					"error", err, "filename", filename)
				writer.fallbackMode = true
			} else {
				file.Close()
				return nil, fmt.Errorf("failed to setup memory mapping: %w", err)
			}
		}
	} else {
		writer.fallbackMode = true
	}

	return writer, nil
}

// setupMmap initializes memory mapping for the file
func (w *MmapWriter) setupMmap(size int64) error {
	// Preallocate file space
	if err := w.file.Truncate(size); err != nil {
		return fmt.Errorf("failed to preallocate file space: %w", err)
	}

	// Memory map the file
	mmapData, err := syscall.Mmap(int(w.file.Fd()), 0, int(size),
		syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("failed to memory map file: %w", err)
	}

	w.mmapData = mmapData
	w.size = size
	w.currentPos = 24 // Skip PCAP header that was already written

	logger.Info("Memory-mapped PCAP writer initialized",
		"filename", w.file.Name(),
		"size", size,
		"mmap_addr", fmt.Sprintf("0x%x", uintptr(unsafe.Pointer(&mmapData[0]))))

	return nil
}

// WritePacket writes a packet using memory-mapped I/O when available
func (w *MmapWriter) WritePacket(ci gopacket.CaptureInfo, data []byte) error {
	if w.fallbackMode || w.mmapData == nil {
		// Use regular writer
		return w.writer.WritePacket(ci, data)
	}

	// Calculate packet record size (16-byte header + data)
	recordSize := int64(16 + len(data))

	// Check if we have enough space
	if w.currentPos+recordSize > w.size {
		// File is getting full, consider rotation or fallback
		logger.Warn("Memory-mapped region full, falling back to regular I/O",
			"current_pos", w.currentPos,
			"record_size", recordSize,
			"total_size", w.size)
		w.fallbackMode = true
		return w.writer.WritePacket(ci, data)
	}

	// Write packet record directly to memory-mapped region
	pos := w.currentPos

	// Verify bounds before unsafe operations to prevent buffer overflow
	if pos < 0 || pos+16 > int64(len(w.mmapData)) {
		return fmt.Errorf("invalid header position: pos=%d, need 16 bytes, have %d",
			pos, len(w.mmapData))
	}
	if pos+16+int64(len(data)) > int64(len(w.mmapData)) {
		return fmt.Errorf("insufficient mmap space: need %d bytes at pos=%d, have %d",
			16+len(data), pos, len(w.mmapData))
	}

	// Write PCAP record header (16 bytes)
	// This is a simplified version - in production you'd want proper endianness handling
	header := (*[16]byte)(unsafe.Pointer(&w.mmapData[pos]))

	// Timestamp seconds
	*(*uint32)(unsafe.Pointer(&header[0])) = uint32(ci.Timestamp.Unix())
	// Timestamp microseconds
	*(*uint32)(unsafe.Pointer(&header[4])) = uint32(ci.Timestamp.Nanosecond() / 1000)
	// Captured length
	*(*uint32)(unsafe.Pointer(&header[8])) = uint32(ci.CaptureLength)
	// Original length
	*(*uint32)(unsafe.Pointer(&header[12])) = uint32(ci.Length)

	// Copy packet data (bounds already verified above)
	copy(w.mmapData[pos+16:pos+16+int64(len(data))], data)

	w.currentPos += recordSize

	return nil
}

// Sync flushes any pending writes to disk
func (w *MmapWriter) Sync() error {
	if w.mmapData != nil && !w.fallbackMode {
		// Sync memory-mapped data to disk using unix.Msync
		if _, _, errno := syscall.Syscall(syscall.SYS_MSYNC,
			uintptr(unsafe.Pointer(&w.mmapData[0])),
			uintptr(len(w.mmapData)),
			uintptr(syscall.MS_SYNC)); errno != 0 {
			return fmt.Errorf("failed to sync memory-mapped data: %v", errno)
		}
	}
	return w.file.Sync()
}

// Close closes the writer and cleans up resources
func (w *MmapWriter) Close() error {
	var firstErr error

	// Sync any pending data
	if err := w.Sync(); err != nil {
		firstErr = err
	}

	// Unmap memory if mapped
	if w.mmapData != nil {
		if err := syscall.Munmap(w.mmapData); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to unmap memory: %w", err)
		}
		w.mmapData = nil
	}

	// Truncate file to actual size used
	if w.currentPos > 0 && w.currentPos < w.size {
		if err := w.file.Truncate(w.currentPos); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("failed to truncate file: %w", err)
		}
	}

	// Close file
	if err := w.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}

	logger.Info("Memory-mapped PCAP writer closed",
		"filename", w.file.Name(),
		"bytes_written", w.currentPos,
		"fallback_used", w.fallbackMode)

	return firstErr
}

// GetStats returns statistics about the writer
func (w *MmapWriter) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"filename":      w.file.Name(),
		"bytes_written": w.currentPos,
		"total_size":    w.size,
		"fallback_mode": w.fallbackMode,
		"mmap_enabled":  w.mmapData != nil,
	}

	if w.mmapData != nil {
		stats["utilization"] = float64(w.currentPos) / float64(w.size) * 100
	}

	return stats
}
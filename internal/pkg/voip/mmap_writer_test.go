//go:build cli || all
// +build cli all

package voip

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMmapWriter_Creation(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test.pcap")

	config := DefaultMmapConfig()
	config.PreallocSize = 1024 * 1024 // 1MB for testing

	writer, err := NewMmapWriter(filename, config)
	require.NoError(t, err)
	defer writer.Close()

	// Verify file was created
	_, err = os.Stat(filename)
	assert.NoError(t, err)

	// Verify stats
	stats := writer.GetStats()
	assert.Equal(t, filename, stats["filename"])
	assert.Equal(t, int64(24), stats["bytes_written"]) // PCAP header size
}

func TestMmapWriter_WritePacket(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test.pcap")

	config := DefaultMmapConfig()
	config.PreallocSize = 1024 * 1024 // 1MB for testing

	writer, err := NewMmapWriter(filename, config)
	require.NoError(t, err)
	defer writer.Close()

	// Create test packet
	testData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	// Write packet
	err = writer.WritePacket(ci, testData)
	assert.NoError(t, err)

	// Verify stats updated
	stats := writer.GetStats()
	assert.Greater(t, stats["bytes_written"].(int64), int64(24)) // More than just header
}

func TestMmapWriter_FallbackMode(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test.pcap")

	config := DefaultMmapConfig()
	config.EnableMmap = false // Disable mmap to test fallback

	writer, err := NewMmapWriter(filename, config)
	require.NoError(t, err)
	defer writer.Close()

	// Should be in fallback mode
	stats := writer.GetStats()
	assert.True(t, stats["fallback_mode"].(bool))
	assert.False(t, stats["mmap_enabled"].(bool))

	// Writing should still work
	testData := []byte{0x00, 0x01, 0x02, 0x03}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	err = writer.WritePacket(ci, testData)
	assert.NoError(t, err)
}

func TestMmapWriter_LargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "large_test.pcap")

	config := DefaultMmapConfig()
	config.PreallocSize = 10 * 1024 * 1024 // 10MB

	writer, err := NewMmapWriter(filename, config)
	require.NoError(t, err)
	defer writer.Close()

	// Write many packets to test memory mapping efficiency
	testData := make([]byte, 1024) // 1KB packet
	for i := 0; i < 1000; i++ {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(testData),
			Length:        len(testData),
		}

		err = writer.WritePacket(ci, testData)
		assert.NoError(t, err)
	}

	// Verify utilization (if not in fallback mode)
	stats := writer.GetStats()
	if util, ok := stats["utilization"].(float64); ok {
		assert.Greater(t, util, 0.0)
		assert.Less(t, util, 100.0)
	}
}

func TestMmapWriter_Sync(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "sync_test.pcap")

	writer, err := NewMmapWriter(filename, DefaultMmapConfig())
	require.NoError(t, err)
	defer writer.Close()

	// Write a packet
	testData := []byte{0x00, 0x01, 0x02, 0x03}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	err = writer.WritePacket(ci, testData)
	require.NoError(t, err)

	// Sync should not error
	err = writer.Sync()
	assert.NoError(t, err)
}

// Benchmark comparing memory-mapped vs regular I/O
func BenchmarkMmapWriter_vs_Regular(b *testing.B) {
	tempDir := b.TempDir()

	// Test data
	testData := make([]byte, 1024) // 1KB packet
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	b.Run("MmapWriter", func(b *testing.B) {
		filename := filepath.Join(tempDir, "mmap_bench.pcap")
		config := DefaultMmapConfig()
		config.PreallocSize = 100 * 1024 * 1024 // 100MB

		writer, err := NewMmapWriter(filename, config)
		require.NoError(b, err)
		defer writer.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			writer.WritePacket(ci, testData)
		}
	})

	b.Run("RegularWriter", func(b *testing.B) {
		filename := filepath.Join(tempDir, "regular_bench.pcap")
		config := DefaultMmapConfig()
		config.EnableMmap = false // Disable mmap

		writer, err := NewMmapWriter(filename, config)
		require.NoError(b, err)
		defer writer.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			writer.WritePacket(ci, testData)
		}
	})
}

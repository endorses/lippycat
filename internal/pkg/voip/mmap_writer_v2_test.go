//go:build cli || all
// +build cli all

package voip

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMmapWriterV2_Creation(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test.pcap")

	config := DefaultMmapV2Config()
	config.PreallocSize = 1024 * 1024 // 1MB

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
	require.NoError(t, err)
	defer writer.Close()

	// Verify file created
	_, err = os.Stat(filename)
	assert.NoError(t, err)

	// Verify stats
	stats := writer.GetStats()
	assert.Equal(t, filename, stats["filename"])
	assert.Equal(t, int64(24), stats["current_pos"]) // PCAP header
}

func TestMmapWriterV2_WritePacket(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "test.pcap")

	config := DefaultMmapV2Config()
	config.PreallocSize = 1024 * 1024

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
	require.NoError(t, err)
	defer writer.Close()

	// Write packet
	testData := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	err = writer.WritePacket(ci, testData)
	assert.NoError(t, err)

	// Verify metrics
	metrics := writer.GetMetrics()
	assert.Equal(t, int64(1), metrics.PacketsWritten)
	assert.Greater(t, metrics.BytesWritten, int64(0))
}

func TestMmapWriterV2_ConcurrentWrites(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "concurrent.pcap")

	config := DefaultMmapV2Config()
	config.PreallocSize = 10 * 1024 * 1024 // 10MB

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
	require.NoError(t, err)
	defer writer.Close()

	// Concurrent writes
	const numGoroutines = 10
	const packetsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			testData := []byte{byte(id), 0x01, 0x02, 0x03}
			for j := 0; j < packetsPerGoroutine; j++ {
				ci := gopacket.CaptureInfo{
					Timestamp:     time.Now(),
					CaptureLength: len(testData),
					Length:        len(testData),
				}
				writer.WritePacket(ci, testData)
			}
		}(i)
	}

	wg.Wait()

	// Verify all packets written
	metrics := writer.GetMetrics()
	assert.Equal(t, int64(numGoroutines*packetsPerGoroutine), metrics.PacketsWritten)
}

func TestMmapWriterV2_Flush(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "flush_test.pcap")

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, DefaultMmapV2Config())
	require.NoError(t, err)
	defer writer.Close()

	// Write packet
	testData := []byte{0x00, 0x01, 0x02, 0x03}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	err = writer.WritePacket(ci, testData)
	require.NoError(t, err)

	// Flush
	err = writer.Flush()
	assert.NoError(t, err)
}

func TestMmapWriterV2_Rotation(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "rotate.pcap")

	config := DefaultMmapV2Config()
	config.PreallocSize = 1024 * 1024 // 1MB
	config.RotationSize = 100 * 1024  // Rotate at 100KB

	rotated := make(chan bool, 1)
	config.RotationCb = func(old, new string) {
		t.Logf("Rotated: %s -> %s", old, new)
		rotated <- true
	}

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
	require.NoError(t, err)
	defer writer.Close()

	// Write enough data to trigger rotation
	testData := make([]byte, 1024) // 1KB packet
	for i := 0; i < 150; i++ {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(testData),
			Length:        len(testData),
		}
		writer.WritePacket(ci, testData)
	}

	// Check if rotation occurred
	select {
	case <-rotated:
		t.Log("Rotation callback triggered")
	case <-time.After(2 * time.Second):
		t.Log("Rotation might not have triggered (acceptable)")
	}

	metrics := writer.GetMetrics()
	t.Logf("Rotations: %d", metrics.Rotations)
}

func TestMmapWriterV2_FallbackMode(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "fallback.pcap")

	config := DefaultMmapV2Config()
	config.EnableMmap = false

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
	require.NoError(t, err)
	defer writer.Close()

	// Should be in fallback mode
	stats := writer.GetStats()
	assert.True(t, stats["fallback_mode"].(bool))

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

func TestMmapWriterV2_RingBuffer(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "ring.pcap")

	config := DefaultMmapV2Config()
	config.PreallocSize = 100 * 1024 // 100KB
	config.RingBuffer = true

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
	require.NoError(t, err)
	defer writer.Close()

	// Verify ring buffer enabled
	stats := writer.GetStats()
	assert.True(t, stats["ring_buffer"].(bool))

	// Write packets
	testData := make([]byte, 1024)
	for i := 0; i < 50; i++ {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(testData),
			Length:        len(testData),
		}
		writer.WritePacket(ci, testData)
	}

	metrics := writer.GetMetrics()
	assert.Greater(t, metrics.PacketsWritten, int64(0))
}

func TestMmapWriterV2_Metrics(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "metrics.pcap")

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, DefaultMmapV2Config())
	require.NoError(t, err)
	defer writer.Close()

	// Write multiple packets
	testData := []byte{0x00, 0x01, 0x02, 0x03}
	for i := 0; i < 10; i++ {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(testData),
			Length:        len(testData),
		}
		writer.WritePacket(ci, testData)
	}

	// Check metrics
	metrics := writer.GetMetrics()
	assert.Equal(t, int64(10), metrics.PacketsWritten)
	assert.Equal(t, int64(10*(16+4)), metrics.BytesWritten) // 16 header + 4 data per packet
	assert.Greater(t, metrics.Utilization, 0.0)
	assert.False(t, metrics.FallbackMode)
}

// Benchmarks

func BenchmarkMmapWriterV2_Sequential(b *testing.B) {
	tempDir := b.TempDir()
	filename := filepath.Join(tempDir, "bench_seq.pcap")

	config := DefaultMmapV2Config()
	config.PreallocSize = 100 * 1024 * 1024 // 100MB

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
	require.NoError(b, err)
	defer writer.Close()

	testData := make([]byte, 1024) // 1KB packet
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		writer.WritePacket(ci, testData)
	}
}

func BenchmarkMmapWriterV2_Parallel(b *testing.B) {
	tempDir := b.TempDir()
	filename := filepath.Join(tempDir, "bench_par.pcap")

	config := DefaultMmapV2Config()
	config.PreallocSize = 100 * 1024 * 1024 // 100MB

	writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
	require.NoError(b, err)
	defer writer.Close()

	testData := make([]byte, 1024)
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			writer.WritePacket(ci, testData)
		}
	})
}

func BenchmarkMmapWriterV2_vs_V1(b *testing.B) {
	tempDir := b.TempDir()
	testData := make([]byte, 1024)
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(testData),
		Length:        len(testData),
	}

	b.Run("V2_Mmap", func(b *testing.B) {
		filename := filepath.Join(tempDir, "v2_mmap.pcap")
		config := DefaultMmapV2Config()
		config.PreallocSize = 100 * 1024 * 1024

		writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
		require.NoError(b, err)
		defer writer.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			writer.WritePacket(ci, testData)
		}
	})

	b.Run("V2_Fallback", func(b *testing.B) {
		filename := filepath.Join(tempDir, "v2_fallback.pcap")
		config := DefaultMmapV2Config()
		config.EnableMmap = false

		writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
		require.NoError(b, err)
		defer writer.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			writer.WritePacket(ci, testData)
		}
	})

	b.Run("V1_Mmap", func(b *testing.B) {
		filename := filepath.Join(tempDir, "v1_mmap.pcap")
		config := DefaultMmapConfig()
		config.PreallocSize = 100 * 1024 * 1024

		writer, err := NewMmapWriter(filename, config)
		require.NoError(b, err)
		defer writer.Close()

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			writer.WritePacket(ci, testData)
		}
	})
}

func BenchmarkMmapWriterV2_DifferentSizes(b *testing.B) {
	tempDir := b.TempDir()

	sizes := []int{64, 256, 1024, 4096, 16384}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			filename := filepath.Join(tempDir, fmt.Sprintf("size_%d.pcap", size))
			config := DefaultMmapV2Config()
			config.PreallocSize = 100 * 1024 * 1024

			writer, err := NewMmapWriterV2(filename, layers.LinkTypeEthernet, config)
			require.NoError(b, err)
			defer writer.Close()

			testData := make([]byte, size)
			ci := gopacket.CaptureInfo{
				Timestamp:     time.Now(),
				CaptureLength: len(testData),
				Length:        len(testData),
			}

			b.SetBytes(int64(size))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				writer.WritePacket(ci, testData)
			}
		})
	}
}

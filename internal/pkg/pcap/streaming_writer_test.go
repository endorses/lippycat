package pcap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamingWriter_New(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcap")

	config := Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 1 * time.Second,
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)
	require.NotNil(t, writer)
	defer writer.Close()

	assert.Equal(t, testFile, writer.FilePath())
	assert.Equal(t, 0, writer.PacketCount())

	// Check file was created
	_, err = os.Stat(testFile)
	assert.NoError(t, err)
}

func TestStreamingWriter_WritePacket(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcap")

	config := Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 100 * time.Millisecond,
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)
	defer writer.Close()

	// Write a packet
	pkt := createTestPacket(t)
	err = writer.WritePacket(pkt)
	assert.NoError(t, err)

	// Wait for async write
	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, 1, writer.PacketCount())

	// Close and verify
	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, 1)
}

func TestStreamingWriter_WriteMultiplePackets(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_multiple.pcap")

	config := Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 100 * time.Millisecond,
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)
	defer writer.Close()

	// Write multiple packets
	numPackets := 10
	for i := 0; i < numPackets; i++ {
		pkt := createTestPacket(t)
		err := writer.WritePacket(pkt)
		assert.NoError(t, err)
	}

	// Wait for async writes
	time.Sleep(300 * time.Millisecond)
	assert.Equal(t, numPackets, writer.PacketCount())

	// Close and verify
	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, numPackets)
}

func TestStreamingWriter_WithFilter(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_filter.pcap")

	config := Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 100 * time.Millisecond,
	}

	// Filter: only write packets with SrcPort == "5060"
	filterFunc := func(pkt types.PacketDisplay) bool {
		return pkt.SrcPort == "5060"
	}

	writer, err := NewStreamingWriter(config, filterFunc)
	require.NoError(t, err)
	defer writer.Close()

	// Write packets (all have SrcPort 5060, so all should pass)
	numPackets := 5
	for i := 0; i < numPackets; i++ {
		pkt := createTestPacket(t)
		err := writer.WritePacket(pkt)
		assert.NoError(t, err)
	}

	// Write a packet that should be filtered
	badPkt := createTestPacket(t)
	badPkt.SrcPort = "9999"
	err = writer.WritePacket(badPkt)
	assert.NoError(t, err) // No error, but packet filtered

	// Wait for async writes
	time.Sleep(300 * time.Millisecond)

	// Should only have 5 packets (badPkt filtered)
	assert.Equal(t, numPackets, writer.PacketCount())

	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, numPackets)
}

func TestStreamingWriter_WriteAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_after_close.pcap")

	config := Config{
		FilePath:   testFile,
		BufferSize: 10,
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)

	// Close writer
	err = writer.Close()
	assert.NoError(t, err)

	// Try to write after close
	pkt := createTestPacket(t)
	err = writer.WritePacket(pkt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestStreamingWriter_CloseIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_close.pcap")

	config := Config{
		FilePath:   testFile,
		BufferSize: 10,
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)

	// Close multiple times should not error
	err = writer.Close()
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)
}

func TestStreamingWriter_EmptyFilePath(t *testing.T) {
	config := Config{
		FilePath:   "",
		BufferSize: 10,
	}

	writer, err := NewStreamingWriter(config, nil)
	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "file path cannot be empty")
}

func TestStreamingWriter_FullBuffer(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_full_buffer.pcap")

	config := Config{
		FilePath:     testFile,
		BufferSize:   2,               // Very small buffer
		SyncInterval: 1 * time.Second, // Slow sync
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)
	defer writer.Close()

	// Try to write many packets quickly to fill buffer
	droppedCount := 0
	for i := 0; i < 100; i++ {
		pkt := createTestPacket(t)
		err := writer.WritePacket(pkt)
		if err != nil {
			droppedCount++
		}
	}

	// Some packets should have been dropped
	assert.Greater(t, droppedCount, 0)
	assert.Greater(t, writer.DroppedCount(), int64(0))

	// Wait for writes to complete
	time.Sleep(500 * time.Millisecond)

	err = writer.Close()
	assert.NoError(t, err)
}

func TestStreamingWriter_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_concurrent.pcap")

	config := Config{
		FilePath:     testFile,
		BufferSize:   1000,
		SyncInterval: 100 * time.Millisecond,
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)
	defer writer.Close()

	// Write packets concurrently
	numGoroutines := 10
	packetsPerGoroutine := 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < packetsPerGoroutine; j++ {
				pkt := createTestPacket(t)
				writer.WritePacket(pkt)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Wait for async writes
	time.Sleep(500 * time.Millisecond)

	expectedCount := numGoroutines * packetsPerGoroutine
	assert.Equal(t, expectedCount, writer.PacketCount())

	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, expectedCount)
}

func TestStreamingWriter_DrainOnClose(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_drain.pcap")

	config := Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 10 * time.Second, // Very long sync interval
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)

	// Write packets
	numPackets := 10
	for i := 0; i < numPackets; i++ {
		pkt := createTestPacket(t)
		err := writer.WritePacket(pkt)
		assert.NoError(t, err)
	}

	// Close immediately (should drain pending packets)
	err = writer.Close()
	assert.NoError(t, err)

	// All packets should have been written
	verifyPcapFile(t, testFile, numPackets)
}

func TestStreamingWriter_SkipPacketWithoutRawData(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_skip.pcap")

	config := Config{
		FilePath:     testFile,
		BufferSize:   100,
		SyncInterval: 100 * time.Millisecond,
	}

	writer, err := NewStreamingWriter(config, nil)
	require.NoError(t, err)
	defer writer.Close()

	// Write packet with raw data
	goodPkt := createTestPacket(t)
	err = writer.WritePacket(goodPkt)
	assert.NoError(t, err)

	// Write packet without raw data (should be skipped)
	badPkt := goodPkt
	badPkt.RawData = nil
	err = writer.WritePacket(badPkt)
	assert.NoError(t, err) // No error, but packet should be skipped

	// Wait for async writes
	time.Sleep(300 * time.Millisecond)

	// Should only count 1 packet
	assert.Equal(t, 1, writer.PacketCount())

	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, 1)
}

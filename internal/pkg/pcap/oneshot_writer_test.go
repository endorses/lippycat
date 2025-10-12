package pcap

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOneShotWriter_New(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcap")

	config := Config{
		FilePath: testFile,
	}

	writer, err := NewOneShotWriter(config)
	require.NoError(t, err)
	require.NotNil(t, writer)
	defer writer.Close()

	assert.Equal(t, testFile, writer.FilePath())
	assert.Equal(t, 0, writer.PacketCount())

	// Check file was created
	_, err = os.Stat(testFile)
	assert.NoError(t, err)
}

func TestOneShotWriter_WritePacket(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.pcap")

	config := Config{
		FilePath: testFile,
	}

	writer, err := NewOneShotWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Write a packet
	pkt := createTestPacket(t)
	err = writer.WritePacket(pkt)
	assert.NoError(t, err)
	assert.Equal(t, 1, writer.PacketCount())

	// Close and verify
	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, 1)
}

func TestOneShotWriter_WriteMultiplePackets(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_multiple.pcap")

	config := Config{
		FilePath: testFile,
	}

	writer, err := NewOneShotWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Write multiple packets
	numPackets := 10
	for i := 0; i < numPackets; i++ {
		pkt := createTestPacket(t)
		err := writer.WritePacket(pkt)
		assert.NoError(t, err)
	}

	assert.Equal(t, numPackets, writer.PacketCount())

	// Close and verify
	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, numPackets)
}

func TestOneShotWriter_WriteAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_after_close.pcap")

	config := Config{
		FilePath: testFile,
	}

	writer, err := NewOneShotWriter(config)
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

func TestOneShotWriter_CloseIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_close.pcap")

	config := Config{
		FilePath: testFile,
	}

	writer, err := NewOneShotWriter(config)
	require.NoError(t, err)

	// Close multiple times should not error
	err = writer.Close()
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)

	err = writer.Close()
	assert.NoError(t, err)
}

func TestOneShotWriter_EmptyFilePath(t *testing.T) {
	config := Config{
		FilePath: "",
	}

	writer, err := NewOneShotWriter(config)
	assert.Error(t, err)
	assert.Nil(t, writer)
	assert.Contains(t, err.Error(), "file path cannot be empty")
}

func TestOneShotWriter_SkipPacketWithoutRawData(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_skip.pcap")

	config := Config{
		FilePath: testFile,
	}

	writer, err := NewOneShotWriter(config)
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

	// Should only count 1 packet
	assert.Equal(t, 1, writer.PacketCount())

	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, 1)
}

func TestOneShotWriter_Concurrent(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_concurrent.pcap")

	config := Config{
		FilePath: testFile,
	}

	writer, err := NewOneShotWriter(config)
	require.NoError(t, err)
	defer writer.Close()

	// Write packets concurrently (mutex should protect)
	numGoroutines := 10
	packetsPerGoroutine := 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < packetsPerGoroutine; j++ {
				pkt := createTestPacket(t)
				writer.WritePacket(pkt)
				time.Sleep(time.Millisecond) // Small delay
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	expectedCount := numGoroutines * packetsPerGoroutine
	assert.Equal(t, expectedCount, writer.PacketCount())

	err = writer.Close()
	assert.NoError(t, err)

	verifyPcapFile(t, testFile, expectedCount)
}

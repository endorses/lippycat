package pcap

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPcapFilePermissions verifies that PCAP files are created with secure permissions (0600)
// This test addresses security concern from code review: Phase 1.4 - Fix PCAP File Permissions
func TestPcapFilePermissions(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "lippycat-pcap-permissions-test")
	defer os.RemoveAll(tempDir)

	err := os.MkdirAll(tempDir, 0755)
	require.NoError(t, err)

	testFile := filepath.Join(tempDir, "test.pcap")

	// Create a new PCAP writer
	writer, err := NewWriter(testFile)
	require.NoError(t, err)
	require.NotNil(t, writer)

	// Stop the writer (closes the file)
	writer.Stop()

	// Check file permissions
	info, err := os.Stat(testFile)
	require.NoError(t, err)

	// Verify permissions are 0600 (owner read/write only)
	mode := info.Mode().Perm()
	assert.Equal(t, os.FileMode(0600), mode,
		"PCAP file should have 0600 permissions (owner read/write only), got %04o", mode)
}

func TestWriterStopIsIdempotentAndRejectsEnqueue(t *testing.T) {
	writer, err := NewWriter(filepath.Join(t.TempDir(), "idempotent.pcap"))
	require.NoError(t, err)
	writer.Start(context.Background())

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writer.Stop()
		}()
	}
	wg.Wait()

	assert.False(t, writer.QueuePackets([]*data.CapturedPacket{{Data: []byte{1}}}))
}

func TestWriterStopDrainsAcceptedBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drained.pcap")
	writer, err := NewWriter(path)
	require.NoError(t, err)
	writer.Start(context.Background())

	const batches = 64
	for i := 0; i < batches; i++ {
		require.True(t, writer.QueuePackets([]*data.CapturedPacket{{
			TimestampNs:    time.Now().UnixNano(),
			CaptureLength:  4,
			OriginalLength: 4,
			LinkType:       1,
			Data:           []byte{0, 1, 2, byte(i)},
		}}))
	}
	writer.Stop()

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	count := 0
	for {
		_, _, err = reader.ReadPacketData()
		if err != nil {
			break
		}
		count++
	}
	assert.Equal(t, batches, count)
}

func TestWriterQueueRaceWithStopDoesNotPanic(t *testing.T) {
	writer, err := NewWriter(filepath.Join(t.TempDir(), "race.pcap"))
	require.NoError(t, err)
	writer.Start(context.Background())

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for writer.QueuePackets(nil) {
			}
		}()
	}
	close(start)
	writer.Stop()
	wg.Wait()
}

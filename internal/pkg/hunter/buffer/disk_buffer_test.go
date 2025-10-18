//go:build hunter || all

package buffer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiskOverflowBuffer_WriteRead(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()

	// Create buffer
	buf, err := New(Config{
		Dir:          tmpDir,
		MaxDiskBytes: 1024 * 1024, // 1MB
	})
	require.NoError(t, err)
	defer buf.Close()

	// Create test batch
	batch := &data.PacketBatch{
		HunterId: "test-hunter",
		Sequence: 1,
		Packets: []*data.CapturedPacket{
			{Data: []byte("test packet 1"), CaptureLength: 13},
			{Data: []byte("test packet 2"), CaptureLength: 13},
		},
	}

	// Write batch
	err = buf.Write(batch)
	require.NoError(t, err)

	// Read batch back
	readBatch, err := buf.Read()
	require.NoError(t, err)
	require.NotNil(t, readBatch)

	// Verify batch contents
	assert.Equal(t, batch.HunterId, readBatch.HunterId)
	assert.Equal(t, batch.Sequence, readBatch.Sequence)
	assert.Equal(t, len(batch.Packets), len(readBatch.Packets))

	// Verify metrics
	metrics := buf.GetMetrics()
	assert.Equal(t, uint64(1), metrics.TotalWrites)
	assert.Equal(t, uint64(1), metrics.TotalReads)
	assert.Equal(t, uint64(0), metrics.TotalDropped)
	assert.Equal(t, uint64(0), metrics.CurrentBytes) // All read, should be empty
}

func TestDiskOverflowBuffer_FIFO(t *testing.T) {
	tmpDir := t.TempDir()

	buf, err := New(Config{
		Dir:          tmpDir,
		MaxDiskBytes: 1024 * 1024,
	})
	require.NoError(t, err)
	defer buf.Close()

	// Write multiple batches
	for i := 1; i <= 5; i++ {
		batch := &data.PacketBatch{
			HunterId: "test-hunter",
			Sequence: uint64(i),
		}
		err = buf.Write(batch)
		require.NoError(t, err)
	}

	// Read batches back - should be in FIFO order
	for i := 1; i <= 5; i++ {
		readBatch, err := buf.Read()
		require.NoError(t, err)
		require.NotNil(t, readBatch)
		assert.Equal(t, uint64(i), readBatch.Sequence, "Batch %d should be read in order", i)
	}

	// Next read should return nil (empty)
	emptyBatch, err := buf.Read()
	require.NoError(t, err)
	assert.Nil(t, emptyBatch)
}

func TestDiskOverflowBuffer_MaxSize(t *testing.T) {
	tmpDir := t.TempDir()

	// Create buffer with small max size
	buf, err := New(Config{
		Dir:          tmpDir,
		MaxDiskBytes: 100, // Very small
	})
	require.NoError(t, err)
	defer buf.Close()

	// Create large batch
	largeBatch := &data.PacketBatch{
		HunterId: "test-hunter",
		Sequence: 1,
		Packets: []*data.CapturedPacket{
			{Data: make([]byte, 200), CaptureLength: 200}, // Larger than max
		},
	}

	// Write should fail (too large)
	err = buf.Write(largeBatch)
	assert.Error(t, err)

	// Metrics should show dropped batch
	metrics := buf.GetMetrics()
	assert.Equal(t, uint64(1), metrics.TotalDropped)
}

func TestDiskOverflowBuffer_Persistence(t *testing.T) {
	tmpDir := t.TempDir()

	// Create buffer and write batch
	buf1, err := New(Config{
		Dir:          tmpDir,
		MaxDiskBytes: 1024 * 1024,
	})
	require.NoError(t, err)

	batch := &data.PacketBatch{
		HunterId: "test-hunter",
		Sequence: 42,
	}
	err = buf1.Write(batch)
	require.NoError(t, err)

	// Close buffer (but don't delete files)
	buf1.Close()

	// Create new buffer with same directory
	// (In real usage, new buffer is created on reconnection)
	// Note: Current implementation cleans up files on New(), so this tests cleanup
	buf2, err := New(Config{
		Dir:          tmpDir,
		MaxDiskBytes: 1024 * 1024,
	})
	require.NoError(t, err)
	defer buf2.Close()

	// Read should return nil (files were cleaned)
	readBatch, err := buf2.Read()
	require.NoError(t, err)
	assert.Nil(t, readBatch)
}

func TestDiskOverflowBuffer_Utilization(t *testing.T) {
	tmpDir := t.TempDir()

	buf, err := New(Config{
		Dir:          tmpDir,
		MaxDiskBytes: 1000,
	})
	require.NoError(t, err)
	defer buf.Close()

	// Write small batch
	batch := &data.PacketBatch{
		HunterId: "test-hunter",
		Sequence: 1,
		Packets:  []*data.CapturedPacket{{Data: make([]byte, 100)}},
	}
	err = buf.Write(batch)
	require.NoError(t, err)

	// Check utilization
	metrics := buf.GetMetrics()
	assert.Greater(t, metrics.Utilization(), 0.0)
	assert.Less(t, metrics.Utilization(), 1.0)

	// Read batch
	_, err = buf.Read()
	require.NoError(t, err)

	// Utilization should be 0 after reading
	metrics = buf.GetMetrics()
	assert.Equal(t, 0.0, metrics.Utilization())
}

func TestDiskOverflowBuffer_CleanupOldFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some old buffer files manually
	oldFile := filepath.Join(tmpDir, "batch-0000000001.pb")
	err := os.WriteFile(oldFile, []byte("old data"), 0600)
	require.NoError(t, err)

	// Create new buffer - should clean up old files
	buf, err := New(Config{
		Dir:          tmpDir,
		MaxDiskBytes: 1024 * 1024,
	})
	require.NoError(t, err)
	defer buf.Close()

	// Old file should be gone
	_, err = os.Stat(oldFile)
	assert.True(t, os.IsNotExist(err), "Old buffer file should be cleaned up")
}

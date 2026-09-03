//go:build processor || tap || all

package processor

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPcapWriterManagerSuppressesTombstonedCall(t *testing.T) {
	manager := newFinalizationTestManager(t, "{callid}.pcap")

	writer, err := manager.GetOrCreateWriter("completed-call", "alice", "bob")
	require.NoError(t, err)
	require.NotNil(t, writer)
	require.NoError(t, manager.CloseCallWriter("completed-call"))

	resurrected, err := manager.GetOrCreateWriter("completed-call", "alice", "bob")
	assert.Nil(t, resurrected)
	require.Error(t, err)
	assert.True(t, IsCallFinalized(err))

	var finalizedErr *FinalizedCallError
	require.True(t, errors.As(err, &finalizedErr))
	assert.Equal(t, "completed-call", finalizedErr.CallID)
	assert.False(t, finalizedErr.FinalizedAt.IsZero())
	assert.Equal(t, uint64(1), manager.SuppressedLatePackets())

	_, err = manager.GetOrCreateWriter("completed-call", "alice", "bob")
	assert.True(t, IsCallFinalized(err))
	assert.Equal(t, uint64(2), manager.SuppressedLatePackets())
}

func TestPcapWriterManagerPrunesTombstonesToLimit(t *testing.T) {
	manager := newFinalizationTestManager(t, "{callid}.pcap")
	manager.lifecycle.mu.Lock()
	manager.lifecycle.tombstoneLimit = 2
	manager.lifecycle.mu.Unlock()

	for _, callID := range []string{"oldest", "middle", "newest"} {
		_, err := manager.GetOrCreateWriter(callID, "alice", "bob")
		require.NoError(t, err)
		require.NoError(t, manager.CloseCallWriter(callID))
		time.Sleep(time.Millisecond)
	}

	manager.lifecycle.mu.Lock()
	defer manager.lifecycle.mu.Unlock()
	assert.Len(t, manager.lifecycle.tombstones, 2)
	assert.NotContains(t, manager.lifecycle.tombstones, "oldest")
	assert.Contains(t, manager.lifecycle.tombstones, "middle")
	assert.Contains(t, manager.lifecycle.tombstones, "newest")
}

func TestPcapWriterManagerCapacityPrunedCallIDReuseDoesNotMutateArtifact(t *testing.T) {
	dir := t.TempDir()
	manager := newFinalizationTestManagerInDir(t, dir, "{callid}.pcap")
	manager.lifecycle.mu.Lock()
	manager.lifecycle.tombstoneLimit = 2
	manager.lifecycle.mu.Unlock()

	first, err := manager.GetOrCreateWriter("oldest", "alice", "bob")
	require.NoError(t, err)
	require.NoError(t, first.WriteSIPPacket(time.Now(), []byte("first-generation"), layers.LinkTypeEthernet))
	require.NoError(t, manager.CloseCallWriter("oldest"))
	originalPath := filepath.Join(dir, "oldest_sip.pcap")
	original, err := os.ReadFile(originalPath)
	require.NoError(t, err)

	for _, callID := range []string{"middle", "newest"} {
		_, err := manager.GetOrCreateWriter(callID, "alice", "bob")
		require.NoError(t, err)
		require.NoError(t, manager.CloseCallWriter(callID))
		time.Sleep(time.Millisecond)
	}
	assert.False(t, manager.IsFinalized("oldest"))

	second, err := manager.GetOrCreateWriter("oldest", "carol", "dave")
	require.NoError(t, err)
	require.NotSame(t, first, second)
	require.NoError(t, second.WriteSIPPacket(time.Now(), []byte("second-generation"), layers.LinkTypeEthernet))
	require.NoError(t, manager.CloseCallWriter("oldest"))

	after, err := os.ReadFile(originalPath)
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(original), sha256.Sum256(after))

	files, err := filepath.Glob(filepath.Join(dir, "oldest_sip*.pcap"))
	require.NoError(t, err)
	require.Len(t, files, 2)
	for _, path := range files {
		assertStandalonePCAP(t, path)
	}
}

func TestPcapWriterManagerExpiredCallIDReuseDoesNotMutateArtifact(t *testing.T) {
	dir := t.TempDir()
	manager := newFinalizationTestManagerInDir(t, dir, "{callid}.pcap")
	callID := "reused-call"

	first, err := manager.GetOrCreateWriter(callID, "alice", "bob")
	require.NoError(t, err)
	require.NoError(t, first.WriteSIPPacket(time.Now(), []byte("first-generation"), layers.LinkTypeEthernet))
	require.NoError(t, manager.CloseCallWriter(callID))

	originalPath := filepath.Join(dir, callID+"_sip.pcap")
	original, err := os.ReadFile(originalPath)
	require.NoError(t, err)

	manager.lifecycle.mu.Lock()
	manager.lifecycle.tombstoneTTL = time.Minute
	manager.lifecycle.tombstones[callID].finalizedAt = time.Now().Add(-2 * time.Minute)
	manager.lifecycle.mu.Unlock()

	second, err := manager.GetOrCreateWriter(callID, "alice", "bob")
	require.NoError(t, err)
	require.NotSame(t, first, second)
	require.NoError(t, second.WriteSIPPacket(time.Now(), []byte("second-generation"), layers.LinkTypeEthernet))
	require.NoError(t, manager.CloseCallWriter(callID))

	after, err := os.ReadFile(originalPath)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(original, after), "reusing an expired Call-ID must not modify its finalized artifact")

	files, err := filepath.Glob(filepath.Join(dir, callID+"_sip*.pcap"))
	require.NoError(t, err)
	require.Len(t, files, 2)
	for _, path := range files {
		assertStandalonePCAP(t, path)
	}
}

func TestRetainedWriterCannotFinalizeReusedCallID(t *testing.T) {
	tests := []struct {
		name  string
		close func(*CallPcapWriter) error
	}{
		{name: "close", close: (*CallPcapWriter).Close},
		{name: "close call", close: (*CallPcapWriter).CloseCall},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newFinalizationTestManager(t, "{callid}.pcap")
			const callID = "generation-safe-reuse"

			first, err := manager.GetOrCreateWriter(callID, "alice", "bob")
			require.NoError(t, err)
			require.NoError(t, manager.CloseCallWriter(callID))

			manager.lifecycle.mu.Lock()
			manager.lifecycle.tombstones[callID].finalizedAt = time.Now().Add(-2 * manager.lifecycle.tombstoneTTL)
			manager.lifecycle.mu.Unlock()

			second, err := manager.GetOrCreateWriter(callID, "carol", "dave")
			require.NoError(t, err)
			require.NotSame(t, first, second)

			require.NoError(t, tt.close(first))
			assert.False(t, manager.IsFinalized(callID), "stale writer handle finalized the reused Call-ID")
			require.NoError(t, second.WriteSIPPacket(time.Now(), []byte("new generation remains live"), layers.LinkTypeEthernet))
			require.NoError(t, manager.CloseCallWriter(callID))
		})
	}
}

func TestFinalizeReportsWriterCreatedByAdmittedConcurrentWork(t *testing.T) {
	manager := newFinalizationTestManager(t, "{callid}.pcap")
	const callID = "admitted-writer-race"

	admission, err := manager.lifecycle.Admit(callID)
	require.NoError(t, err)

	type finalizeResult struct {
		result CallFinalizationResult
		err    error
	}
	finalized := make(chan finalizeResult, 1)
	go func() {
		result, finalizeErr := manager.FinalizeCall(callID, CallFinalizationProtocolComplete)
		finalized <- finalizeResult{result: result, err: finalizeErr}
	}()
	require.Eventually(t, func() bool { return manager.lifecycle.IsFinalized(callID) }, time.Second, time.Millisecond)

	writer, err := manager.getOrCreateWriter(callID, "alice", "bob", admission.Generation())
	require.NoError(t, err)
	require.NotNil(t, writer)
	admission.Release()

	outcome := <-finalized
	require.NoError(t, outcome.err)
	assert.True(t, outcome.result.Finalized)
	assert.True(t, outcome.result.HadWriter)
}

func TestPcapWriterManagerExistingPathIsNeverTruncated(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "collision_sip.pcap")
	original := []byte("pre-existing artifact must remain byte-for-byte intact")
	require.NoError(t, os.WriteFile(originalPath, original, 0o600))

	manager := newFinalizationTestManagerInDir(t, dir, "{callid}.pcap")
	writer, err := manager.GetOrCreateWriter("collision", "alice", "bob")
	require.NoError(t, err)
	require.NoError(t, writer.WriteSIPPacket(time.Now(), []byte("new capture"), layers.LinkTypeEthernet))
	require.NoError(t, manager.CloseCallWriter("collision"))

	after, err := os.ReadFile(originalPath)
	require.NoError(t, err)
	assert.Equal(t, original, after)

	files, err := filepath.Glob(filepath.Join(dir, "collision_sip*.pcap"))
	require.NoError(t, err)
	require.Len(t, files, 2)
	for _, path := range files {
		if path != originalPath {
			assertStandalonePCAP(t, path)
		}
	}
}

func TestPcapWriterManagerRestartNeverTruncatesPreExistingPath(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, string, string)
	}{
		{
			name: "empty",
			prepare: func(t *testing.T, _ string, path string) {
				require.NoError(t, os.WriteFile(path, nil, 0o600))
			},
		},
		{
			name: "valid",
			prepare: func(t *testing.T, _ string, path string) {
				writeTestPCAP(t, path, []byte("valid-pre-existing-packet"))
			},
		},
		{
			name: "partial",
			prepare: func(t *testing.T, _ string, path string) {
				require.NoError(t, os.WriteFile(path, []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02}, 0o600))
			},
		},
		{
			name: "finalized",
			prepare: func(t *testing.T, dir, _ string) {
				prior := newFinalizationTestManagerInDir(t, dir, "{callid}.pcap")
				writer, err := prior.GetOrCreateWriter("restart", "alice", "bob")
				require.NoError(t, err)
				require.NoError(t, writer.WriteSIPPacket(time.Now(), []byte("finalized-packet"), layers.LinkTypeEthernet))
				require.NoError(t, prior.CloseCallWriter("restart"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			originalPath := filepath.Join(dir, "restart_sip.pcap")
			tt.prepare(t, dir, originalPath)
			original, err := os.ReadFile(originalPath)
			require.NoError(t, err)
			originalHash := sha256.Sum256(original)

			manager := newFinalizationTestManagerInDir(t, dir, "{callid}.pcap")
			writer, err := manager.GetOrCreateWriter("restart", "carol", "dave")
			require.NoError(t, err)
			// Creation is lazy: exercise the first-packet path where the collision
			// is actually discovered after a restart.
			require.NoError(t, writer.WriteSIPPacket(time.Now(), []byte("post-restart-packet"), layers.LinkTypeEthernet))
			require.NoError(t, manager.CloseCallWriter("restart"))

			after, err := os.ReadFile(originalPath)
			require.NoError(t, err)
			assert.Equal(t, int64(len(original)), fileSize(t, originalPath))
			assert.Equal(t, original, after)
			assert.Equal(t, originalHash, sha256.Sum256(after))

			files, err := filepath.Glob(filepath.Join(dir, "restart_sip*.pcap"))
			require.NoError(t, err)
			require.Len(t, files, 2)
			for _, path := range files {
				if path != originalPath {
					assertStandalonePCAP(t, path)
				}
			}
		})
	}
}

func newFinalizationTestManager(t *testing.T, pattern string) *PcapWriterManager {
	t.Helper()
	return newFinalizationTestManagerInDir(t, t.TempDir(), pattern)
}

func newFinalizationTestManagerInDir(t *testing.T, dir, pattern string) *PcapWriterManager {
	t.Helper()
	manager, err := NewPcapWriterManager(&PcapWriterConfig{
		Enabled:      true,
		OutputDir:    dir,
		FilePattern:  pattern,
		SyncInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })
	return manager
}

func assertStandalonePCAP(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, file.Close()) }()

	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err, "%s must begin with a valid PCAP header", path)
	_, _, err = reader.ReadPacketData()
	require.NoError(t, err)
	_, _, err = reader.ReadPacketData()
	assert.ErrorIs(t, err, io.EOF)
}

func writeTestPCAP(t *testing.T, path string, packet []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(packet),
		Length:        len(packet),
	}, packet))
	require.NoError(t, file.Close())
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Size()
}

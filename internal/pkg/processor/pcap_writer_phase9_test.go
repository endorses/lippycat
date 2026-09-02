//go:build processor || tap || all

package processor

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type artifactSnapshot struct {
	size int64
	data []byte
	hash [sha256.Size]byte
}

func snapshotArtifact(t *testing.T, path string) artifactSnapshot {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return artifactSnapshot{size: info.Size(), data: data, hash: sha256.Sum256(data)}
}

func assertArtifactUnchanged(t *testing.T, path string, before artifactSnapshot) {
	t.Helper()
	after := snapshotArtifact(t, path)
	assert.Equal(t, before.size, after.size, "finalized artifact size changed")
	assert.True(t, bytes.Equal(before.data, after.data), "finalized artifact bytes changed")
	assert.Equal(t, before.hash, after.hash, "finalized artifact hash changed")
}

func TestPhase9LatePacketCannotMutateFinalizedArtifactWithoutTimestamp(t *testing.T) {
	dir := t.TempDir()
	var completions atomic.Int32
	manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
		config.OutputDir = dir
		config.FilePattern = "{callid}.pcap"
		config.OnCallComplete = func(CallMetadata) { completions.Add(1) }
	})
	const callID = "incident-regression"

	writer, err := manager.GetOrCreateWriter(callID, "alice", "bob")
	require.NoError(t, err)
	for _, packet := range [][]byte{[]byte("invite"), []byte("trying"), []byte("bye")} {
		require.NoError(t, manager.WritePacket(callID, "alice", "bob", time.Now(), packet, layers.LinkTypeEthernet, false))
	}

	result, err := manager.FinalizeCall(callID, CallFinalizationProtocolComplete)
	require.NoError(t, err)
	require.True(t, result.Finalized)
	path := filepath.Join(dir, callID+"_sip.pcap")
	before := snapshotArtifact(t, path)

	err = manager.WritePacket(callID, "alice", "bob", time.Now(), []byte("late-manager-packet"), layers.LinkTypeEthernet, false)
	assert.True(t, IsCallFinalized(err))
	err = writer.WriteSIPPacket(time.Now(), []byte("late-retained-writer-packet"), layers.LinkTypeEthernet)
	assert.True(t, IsCallFinalized(err))
	duplicate, err := manager.FinalizeCall(callID, CallFinalizationProtocolComplete)
	require.NoError(t, err)
	assert.False(t, duplicate.Finalized)

	assertArtifactUnchanged(t, path, before)
	assert.Equal(t, int32(1), completions.Load())
	assert.Equal(t, uint64(2), manager.SuppressedLatePackets())
}

func TestPhase9CompletionHookPolicyIsStableAcrossTerminalPaths(t *testing.T) {
	tests := []struct {
		name            string
		finalize        func(*testing.T, *PcapWriterManager, *CallPcapWriter)
		wantReason      CallFinalizationReason
		wantCompletions int32
	}{
		{
			name: "explicit completion",
			finalize: func(t *testing.T, manager *PcapWriterManager, _ *CallPcapWriter) {
				_, err := manager.FinalizeCall("old", CallFinalizationProtocolComplete)
				require.NoError(t, err)
			},
			wantReason:      CallFinalizationProtocolComplete,
			wantCompletions: 1,
		},
		{
			name: "idle completion",
			finalize: func(t *testing.T, manager *PcapWriterManager, writer *CallPcapWriter) {
				writer.mu.Lock()
				writer.lastWrite = time.Now().Add(-time.Hour)
				writer.mu.Unlock()
				require.Equal(t, 1, manager.SweepIdle(time.Minute))
			},
			wantReason:      CallFinalizationIdleTimeout,
			wantCompletions: 1,
		},
		{
			name: "capacity pressure",
			finalize: func(t *testing.T, manager *PcapWriterManager, _ *CallPcapWriter) {
				_, err := manager.GetOrCreateWriter("new", "carol", "dave")
				require.NoError(t, err)
			},
			wantReason:      CallFinalizationCapacityEviction,
			wantCompletions: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var completions atomic.Int32
			manager := newPhase8Manager(t, func(config *PcapWriterConfig) {
				config.MaxWriters = 1
				config.OnCallComplete = func(CallMetadata) { completions.Add(1) }
			})
			reasons := make(chan CallFinalizationReason, 1)
			manager.SetBeforeFinalize(func(callID string, reason CallFinalizationReason) {
				if callID == "old" {
					reasons <- reason
				}
			})
			writer, err := manager.GetOrCreateWriter("old", "alice", "bob")
			require.NoError(t, err)
			require.NoError(t, manager.WritePacket("old", "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false))

			tt.finalize(t, manager, writer)
			assert.Equal(t, tt.wantReason, <-reasons)
			assert.True(t, manager.IsFinalized("old"))

			duplicate, err := manager.FinalizeCall("old", CallFinalizationProtocolComplete)
			require.NoError(t, err)
			assert.False(t, duplicate.Finalized)
			err = manager.WritePacket("old", "alice", "bob", time.Now(), []byte("late"), layers.LinkTypeEthernet, false)
			assert.True(t, IsCallFinalized(err))
			assert.Equal(t, tt.wantCompletions, completions.Load())
		})
	}
}

func TestPhase9FinalizationCallbacksCanInitiateShutdown(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*PcapWriterConfig, func())
	}{
		{
			name: "file close callback",
			configure: func(config *PcapWriterConfig, closeManager func()) {
				config.OnFileClose = func(string) { closeManager() }
			},
		},
		{
			name: "call completion callback",
			configure: func(config *PcapWriterConfig, closeManager func()) {
				config.OnCallComplete = func(CallMetadata) { closeManager() }
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var manager *PcapWriterManager
			shutdownErr := make(chan error, 1)
			manager = newPhase8Manager(t, func(config *PcapWriterConfig) {
				tt.configure(config, func() { shutdownErr <- manager.Close() })
			})
			require.NoError(t, manager.WritePacket("callback-shutdown", "alice", "bob", time.Now(), []byte("packet"), layers.LinkTypeEthernet, false))

			finalizeDone := make(chan error, 1)
			go func() {
				_, err := manager.FinalizeCall("callback-shutdown", CallFinalizationProtocolComplete)
				finalizeDone <- err
			}()

			select {
			case err := <-shutdownErr:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("finalization callback deadlocked while initiating shutdown")
			}
			require.NoError(t, <-finalizeDone)
		})
	}
}

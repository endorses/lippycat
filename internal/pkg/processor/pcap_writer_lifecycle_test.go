//go:build processor || tap || all

package processor

import (
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestPcapWriterManagerRotationCallbackRunsWithoutManagerLock(t *testing.T) {
	callbackDone := make(chan struct{}, 1)
	var manager *PcapWriterManager
	config := &PcapWriterConfig{
		Enabled:         true,
		OutputDir:       t.TempDir(),
		FilePattern:     "{callid}.pcap",
		MaxFileSize:     1,
		MaxFilesPerCall: 2,
		SyncInterval:    time.Hour,
		OnFileClose: func(string) {
			// IsFinalized takes the manager's exclusive lock. The callback would
			// deadlock here if WritePacket retained its read lifecycle lease.
			_ = manager.IsFinalized("rotating-call")
			callbackDone <- struct{}{}
		},
	}
	var err error
	manager, err = NewPcapWriterManager(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	require.NoError(t, manager.WritePacket("rotating-call", "alice", "bob", time.Now(), []byte{1}, layers.LinkTypeEthernet, false))
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- manager.WritePacket("rotating-call", "alice", "bob", time.Now(), []byte{2}, layers.LinkTypeEthernet, false)
	}()

	select {
	case err := <-writeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("rotation callback deadlocked acquiring manager lock")
	}
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("rotation callback was not invoked")
	}
}

func TestPcapWriterManagerIdleFinalizationRevalidatesLastWrite(t *testing.T) {
	manager, err := NewPcapWriterManager(&PcapWriterConfig{
		Enabled:      true,
		OutputDir:    t.TempDir(),
		FilePattern:  "{callid}.pcap",
		SyncInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	writer, err := manager.GetOrCreateWriter("refreshed-call", "alice", "bob")
	require.NoError(t, err)
	writer.mu.Lock()
	writer.lastWrite = time.Now().Add(-time.Hour)
	writer.mu.Unlock()

	// Model a packet arriving after SweepIdle selected the Call-ID but before
	// its terminal transition. The finalizer must use the refreshed timestamp.
	require.NoError(t, manager.WritePacket("refreshed-call", "alice", "bob", time.Now(), []byte{1}, layers.LinkTypeEthernet, false))
	result, err := manager.finalizeCallIfIdle("refreshed-call", time.Minute)
	require.NoError(t, err)
	require.False(t, result.Finalized)
	require.False(t, manager.IsFinalized("refreshed-call"))

	manager.mu.RLock()
	_, live := manager.writers["refreshed-call"]
	manager.mu.RUnlock()
	require.True(t, live)
}

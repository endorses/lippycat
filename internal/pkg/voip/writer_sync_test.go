//go:build cli || all

package voip

import (
	"path/filepath"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestAsyncWriterCannotRestartAfterTrackerShutdown(t *testing.T) {
	tracker := NewCallTrackerWithConfig(DefaultConfig())
	require.NotNil(t, GetAsyncWriter(tracker))
	tracker.Shutdown()
	require.Nil(t, GetAsyncWriter(tracker))
}

func newSyncWriterTracker(t *testing.T) *CallTracker {
	cfg := DefaultConfig()
	cfg.WriteVoIP = true
	cfg.OutputFile = filepath.Join(t.TempDir(), "capture.pcap")
	output := NewSessionOutputManager(cfg)
	tracker := NewCallTrackerWithOutput(cfg, output)
	t.Cleanup(func() { require.NoError(t, output.Shutdown()) })
	t.Cleanup(tracker.Shutdown)
	return tracker
}

func TestSynchronousSessionWrites(t *testing.T) {
	tracker := newSyncWriterTracker(t)
	call := tracker.GetOrCreateCall("sync", layers.LinkTypeEthernet)
	require.NotNil(t, call)
	require.NoError(t, tracker.writeSIPSync(call.CallID, testOutputPacket()))
	require.NoError(t, tracker.writeRTPSync(call.CallID, testOutputPacket()))
	require.False(t, call.LastUpdated.IsZero())
}

func TestSynchronousSessionWriteErrors(t *testing.T) {
	tracker := newSyncWriterTracker(t)
	require.ErrorIs(t, tracker.writeSIPSync("missing", testOutputPacket()), ErrCallNotFound)
	call := tracker.GetOrCreateCall("closed", layers.LinkTypeEthernet)
	require.NotNil(t, call)
	require.NoError(t, trackerOutput(t, tracker).CloseSession(call.CallID))
	require.ErrorIs(t, tracker.writeRTPSync(call.CallID, testOutputPacket()), ErrWriterNotInitialized)
}

func TestSynchronousSessionWriteRejectedDuringShutdown(t *testing.T) {
	tracker := newSyncWriterTracker(t)
	call := tracker.GetOrCreateCall("shutdown", layers.LinkTypeEthernet)
	require.NotNil(t, call)
	tracker.shuttingDown.Store(1)
	require.ErrorIs(t, tracker.writeSIPSync(call.CallID, testOutputPacket()), ErrShuttingDown)
}

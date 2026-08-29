//go:build cli || all

package voip

import (
	"path/filepath"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func createCallWithSIPOutput(t *testing.T, callID string) *CallInfo {
	return createCallWithTestOutput(t, callID)
}

func createCallWithRTPOutput(t *testing.T, callID string) *CallInfo {
	return createCallWithTestOutput(t, callID)
}

func createCallWithTestOutput(t *testing.T, callID string) *CallInfo {
	cfg := DefaultConfig()
	cfg.WriteVoIP = true
	cfg.OutputFile = filepath.Join(t.TempDir(), "capture.pcap")
	output := NewSessionOutputManager(cfg)
	tracker := NewCallTrackerWithOutput(cfg, output)
	t.Cleanup(func() { require.NoError(t, output.Shutdown()) })
	t.Cleanup(tracker.Shutdown)
	call := tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
	require.NotNil(t, call)
	return call
}

func trackerOutput(t testing.TB, tracker *CallTracker) CallOutput {
	t.Helper()
	for _, observer := range tracker.lifecycleObservers {
		switch value := observer.(type) {
		case *SessionOutputManager:
			return value
		case callOutputLifecycleAdapter:
			return value.output
		}
	}
	t.Fatal("tracker has no call output observer")
	return nil
}

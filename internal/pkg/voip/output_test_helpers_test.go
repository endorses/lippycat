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
	tracker := NewCallTrackerWithOutput(cfg, NewSessionOutputManager(cfg))
	t.Cleanup(tracker.Shutdown)
	call := tracker.GetOrCreateCall(callID, layers.LinkTypeEthernet)
	require.NotNil(t, call)
	return call
}

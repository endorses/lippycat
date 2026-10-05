//go:build hunter || all

package voip

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSDPDiagnosticsHunterTCPReportingOwner(t *testing.T) {
	logs := sdpDiagnosticsCapture(t)
	tracker := NewCallTrackerWithConfig(DefaultConfig())
	t.Cleanup(tracker.Shutdown)
	buffers := NewBufferManager(time.Minute, 100)
	t.Cleanup(buffers.Close)
	forwarder := &recordingHunterForwarder{}
	handler := NewHunterForwardHandler(tracker, forwarder, buffers)
	t.Cleanup(handler.Close)
	handler.SetApplicationFilter(&mutablePayloadFilter{needle: "selected"})
	netFlow, transportFlow := hunterFlow(t)
	body := "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\nm=invalid\r\n"
	require.True(t, handler.HandleSIPMessageAt(diagnosticSIPMessage("synthetic-hunter-tcp", body), "synthetic-hunter-tcp", "192.0.2.1:5060", "198.51.100.2:5060", netFlow, transportFlow, time.Now()))
	handler.Close()
	require.Equal(t, 1, forwarder.count(), "ordinary TCP output drains unchanged")
	require.Equal(t, []string{"synthetic-hunter-tcp"}, tracker.endpointCallIDs("192.0.2.1:10000"))
	buffers.Close()
	tracker.Shutdown()
	warnings := logs.warnings(t)
	require.Len(t, warnings, 1)
	require.Equal(t, "voip-buffer", warnings[0]["reporting_path"])
}

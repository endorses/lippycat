package voip

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/stretchr/testify/require"
)

type sdpDiagnosticLogs struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *sdpDiagnosticLogs) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *sdpDiagnosticLogs) warnings(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	raw := b.Buffer.String()
	b.mu.Unlock()
	var warnings []map[string]any
	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] == "SDP endpoint derivation incomplete" {
			warnings = append(warnings, record)
		}
	}
	return warnings
}

func sdpDiagnosticsCapture(t *testing.T) *sdpDiagnosticLogs {
	t.Helper()
	b := &sdpDiagnosticLogs{}
	logger.UseFile(b)
	t.Cleanup(logger.Enable)
	return b
}

func diagnosticSIPMessage(callID, body string) []byte {
	return []byte(fmt.Sprintf("INVITE sip:peer@example.invalid SIP/2.0\r\nFrom: <sip:selected@example.invalid>;tag=synthetic\r\nTo: <sip:peer@example.invalid>\r\nCall-ID: %s\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", callID, len(body), body))
}

func TestSDPDiagnosticsSniffOwnerAndOutputWithoutAdmissionOrLogs(t *testing.T) {
	logs := sdpDiagnosticsCapture(t)
	h := newUDPSelectionHarness(t, false)
	body := "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\nm=invalid\r\n"
	h.feed(h.packet(5060, 5060, diagnosticSIPMessage("synthetic-diagnostic", body)))
	require.Equal(t, 1, h.sink.count(), "successful selected SIP output is unchanged")
	require.Equal(t, []string{"synthetic-diagnostic"}, h.tracker.endpointCallIDs("192.0.2.1:10000"))
	h.feed(h.media())
	require.Equal(t, 2, h.sink.count(), "safe learned media still reaches ordinary output")
	h.buffer.Close()
	h.tracker.Shutdown()
	warnings := logs.warnings(t)
	require.Len(t, warnings, 1, "one parsing owner reports, despite tracker and buffer parses")
	require.Equal(t, "voip-buffer", warnings[0]["reporting_path"])
	require.Greater(t, warnings[0]["partial"].(float64), float64(0))
	encoded, err := json.Marshal(warnings)
	require.NoError(t, err)
	for _, private := range []string{"synthetic-diagnostic", "192.0.2.1", "selected@example.invalid", body} {
		require.NotContains(t, string(encoded), private)
	}
}

func TestSDPDiagnosticsStandaloneTrackerShutdown(t *testing.T) {
	logs := sdpDiagnosticsCapture(t)
	tracker := NewCallTrackerWithConfig(DefaultConfig())
	tracker.ExtractPortFromSDP("m=invalid", "synthetic-tracker")
	tracker.Shutdown()
	warnings := logs.warnings(t)
	require.Len(t, warnings, 1)
	require.Equal(t, "voip-tracker", warnings[0]["reporting_path"])
	require.Equal(t, float64(1), warnings[0]["failed"])
}

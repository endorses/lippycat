package processor

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

type diagnosticLogBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *diagnosticLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *diagnosticLogBuffer) snapshot() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}

func TestSDPDiagnosticsTapParserWithoutAdmissionOrLogs(t *testing.T) {
	var logs diagnosticLogBuffer
	logger.UseFile(&logs)
	t.Cleanup(logger.Enable)
	p := New(DefaultConfig())
	t.Cleanup(p.Close)
	body := "c=IN IP4 10.0.0.1\r\nm=audio 8000 RTP/AVP 0\r\nm=invalid\r\n"
	message := []byte(fmt.Sprintf("INVITE sip:peer@example.invalid SIP/2.0\r\nFrom: <sip:selected@example.invalid>\r\nTo: <sip:peer@example.invalid>\r\nCall-ID: synthetic-tap\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	result := p.Process(createUDPPacket(t, message, 5060, 5060))
	require.NotNil(t, result)
	require.True(t, result.IsVoIP)
	require.Equal(t, PacketTypeSIP, result.PacketType)
	require.Equal(t, []string{"synthetic-tap"}, p.CallIDsForEndpoint("10.0.0.1:8000"))
	p.Close()
	var warnings []map[string]any
	for _, line := range strings.Split(logs.snapshot(), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		if record["msg"] == "SDP endpoint derivation incomplete" {
			warnings = append(warnings, record)
		}
	}
	require.Len(t, warnings, 1)
	require.Equal(t, "voip-local-processor", warnings[0]["reporting_path"])
	require.Equal(t, float64(1), warnings[0]["partial"])
	encoded, err := json.Marshal(warnings)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "synthetic-tap")
	require.NotContains(t, string(encoded), "10.0.0.1")
}

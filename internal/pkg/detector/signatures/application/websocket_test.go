package application

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
)

func TestWebSocketSignature_DetectHandshake(t *testing.T) {
	sig := NewWebSocketSignature()

	tests := []struct {
		name      string
		payload   string
		wantProto string
		wantType  string
		minConf   float64
	}{
		{
			name:      "Upgrade request",
			payload:   "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
			wantProto: "WebSocket",
			wantType:  "upgrade_request",
			minConf:   0.8,
		},
		{
			name:      "Upgrade response",
			payload:   "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
			wantProto: "WebSocket",
			wantType:  "upgrade_response",
			minConf:   0.8,
		},
		{
			name:      "Invalid - no WebSocket upgrade",
			payload:   "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantProto: "",
		},
		{
			name:      "Invalid - missing Sec-WebSocket-Key",
			payload:   "GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
			wantProto: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &signatures.DetectionContext{
				Payload: []byte(tt.payload),
			}

			result := sig.Detect(ctx)

			if tt.wantProto == "" {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantProto, result.Protocol)
				assert.GreaterOrEqual(t, result.Confidence, tt.minConf)
				assert.Equal(t, tt.wantType, result.Metadata["type"])
			}
		})
	}
}

// Note: Frame detection tests removed because WebSocket frames are too ambiguous
// without flow context. The detector only validates WebSocket upgrade handshakes,
// which are definitive. Frames can only be reliably detected after seeing the handshake
// in a stateful flow tracker.

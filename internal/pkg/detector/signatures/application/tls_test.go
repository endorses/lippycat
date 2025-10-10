package application

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
)

func TestTLSSignature_Detect(t *testing.T) {
	sig := NewTLSSignature()

	tests := []struct {
		name      string
		payload   []byte
		wantProto string
		wantVer   string
		minConf   float64
	}{
		{
			name: "TLS 1.2 ClientHello",
			payload: []byte{
				0x16,       // Handshake
				0x03, 0x03, // TLS 1.2
				0x00, 0x05, // Length: 5 bytes
				0x01,             // ClientHello
				0x00, 0x00, 0x01, // Handshake length
				0x03, 0x03, // TLS 1.2 in handshake
			},
			wantProto: "TLS",
			wantVer:   "TLS 1.2",
			minConf:   0.7,
		},
		{
			name: "TLS 1.3 ServerHello",
			payload: []byte{
				0x16,       // Handshake
				0x03, 0x03, // TLS 1.2 (compatibility)
				0x00, 0x05, // Length: 5 bytes
				0x02, // ServerHello
				0x00, 0x00, 0x01,
				0x03, 0x04, // TLS 1.3
			},
			wantProto: "TLS",
			wantVer:   "TLS 1.2", // Outer version
			minConf:   0.7,
		},
		{
			name: "TLS 1.0 ApplicationData",
			payload: []byte{
				0x17,       // ApplicationData
				0x03, 0x01, // TLS 1.0
				0x00, 0x10, // Length: 16 bytes
				// ... encrypted data (16 bytes)
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			},
			wantProto: "TLS",
			wantVer:   "TLS 1.0",
			minConf:   0.7,
		},
		{
			name: "SSL 3.0",
			payload: []byte{
				0x16,       // Handshake
				0x03, 0x00, // SSL 3.0
				0x00, 0x05, // Length
				0x01, 0x00, 0x00, 0x01, 0x03,
			},
			wantProto: "TLS",
			wantVer:   "SSL 3.0",
			minConf:   0.7,
		},
		{
			name:      "Invalid - wrong content type",
			payload:   []byte{0x99, 0x03, 0x03, 0x00, 0x05},
			wantProto: "",
		},
		{
			name:      "Invalid - wrong version",
			payload:   []byte{0x16, 0x04, 0x00, 0x00, 0x05},
			wantProto: "",
		},
		{
			name:      "Invalid - too large length",
			payload:   []byte{0x16, 0x03, 0x03, 0xFF, 0xFF}, // 65KB > 16KB max
			wantProto: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &signatures.DetectionContext{
				Payload: tt.payload,
				DstPort: 443,
			}

			result := sig.Detect(ctx)

			if tt.wantProto == "" {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantProto, result.Protocol)
				assert.GreaterOrEqual(t, result.Confidence, tt.minConf)
				if tt.wantVer != "" {
					assert.Equal(t, tt.wantVer, result.Metadata["version"])
				}
			}
		})
	}
}

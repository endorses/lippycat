package application

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQUICSignature_Detect(t *testing.T) {
	sig := NewQUICSignature()

	tests := []struct {
		name       string
		payload    []byte
		transport  string
		srcPort    uint16
		dstPort    uint16
		wantResult bool
		wantMeta   map[string]any
	}{
		{
			name: "QUIC v1 Initial packet",
			// Long header: 0xc0 (form=1, fixed=1, type=0), version=0x00000001
			payload:    []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			transport:  "UDP",
			srcPort:    12345,
			dstPort:    443,
			wantResult: true,
			wantMeta: map[string]any{
				"header_type": "long",
				"version":     "QUIC v1",
				"packet_type": "Initial",
			},
		},
		{
			name: "QUIC v2 Handshake packet",
			// Long header: 0xe0 (form=1, fixed=1, type=2), version=0x6b3343cf
			payload:    []byte{0xe0, 0x6b, 0x33, 0x43, 0xcf, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			transport:  "UDP",
			srcPort:    443,
			dstPort:    54321,
			wantResult: true,
			wantMeta: map[string]any{
				"header_type": "long",
				"version":     "QUIC v2",
				"packet_type": "Handshake",
			},
		},
		{
			name: "QUIC draft-29",
			// Long header with draft version
			payload:    []byte{0xc0, 0xff, 0x00, 0x00, 0x1d, 0x04, 0x01, 0x02, 0x03, 0x04},
			transport:  "UDP",
			srcPort:    12345,
			dstPort:    443,
			wantResult: true,
			wantMeta: map[string]any{
				"header_type": "long",
				"version":     "draft-29",
			},
		},
		{
			name: "QUIC Short Header on port 443",
			// Short header: 0x40 (form=0, fixed=1)
			payload:    []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11},
			transport:  "UDP",
			srcPort:    443,
			dstPort:    54321,
			wantResult: true,
			wantMeta: map[string]any{
				"header_type": "short",
			},
		},
		{
			name:       "Not QUIC - TCP transport",
			payload:    []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			transport:  "TCP",
			srcPort:    12345,
			dstPort:    443,
			wantResult: false,
		},
		{
			name:       "Not QUIC - Short header without QUIC port",
			payload:    []byte{0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11},
			transport:  "UDP",
			srcPort:    12345,
			dstPort:    54321,
			wantResult: false,
		},
		{
			name:       "Not QUIC - Invalid fixed bit in short header",
			payload:    []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11},
			transport:  "UDP",
			srcPort:    443,
			dstPort:    54321,
			wantResult: false,
		},
		{
			name:       "Not QUIC - Too short payload",
			payload:    []byte{0xc0, 0x00, 0x00},
			transport:  "UDP",
			srcPort:    12345,
			dstPort:    443,
			wantResult: false,
		},
		{
			name:       "Not QUIC - Invalid DCID length (>20)",
			payload:    []byte{0xc0, 0x00, 0x00, 0x00, 0x01, 0x30}, // DCID len = 48
			transport:  "UDP",
			srcPort:    12345,
			dstPort:    443,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &signatures.DetectionContext{
				Payload:   tt.payload,
				Transport: tt.transport,
				SrcPort:   tt.srcPort,
				DstPort:   tt.dstPort,
			}

			result := sig.Detect(ctx)

			if tt.wantResult {
				require.NotNil(t, result, "Expected detection result")
				assert.Equal(t, "QUIC", result.Protocol)
				assert.Greater(t, result.Confidence, 0.0)

				for key, wantVal := range tt.wantMeta {
					gotVal, ok := result.Metadata[key]
					assert.True(t, ok, "Missing metadata key: %s", key)
					assert.Equal(t, wantVal, gotVal, "Metadata mismatch for key: %s", key)
				}
			} else {
				assert.Nil(t, result, "Expected no detection result")
			}
		})
	}
}

func TestQUICSignature_Properties(t *testing.T) {
	sig := NewQUICSignature()

	assert.Equal(t, "QUIC Detector", sig.Name())
	assert.Contains(t, sig.Protocols(), "QUIC")
	assert.Equal(t, 115, sig.Priority())
	assert.Equal(t, signatures.LayerApplication, sig.Layer())
}

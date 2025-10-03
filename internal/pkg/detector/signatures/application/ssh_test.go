package application

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
)

func TestSSHSignature_Detect(t *testing.T) {
	sig := NewSSHSignature()

	tests := []struct {
		name       string
		payload    string
		wantResult bool
		wantProto  string
		version    string
	}{
		{
			name:       "SSH-2.0 OpenSSH",
			payload:    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
			wantResult: true,
			wantProto:  "SSH",
			version:    "2.0",
		},
		{
			name:       "SSH-2.0 minimal",
			payload:    "SSH-2.0-Server\r\n",
			wantResult: true,
			wantProto:  "SSH",
			version:    "2.0",
		},
		{
			name:       "SSH-1.99",
			payload:    "SSH-1.99-OpenSSH_3.9p1\r\n",
			wantResult: true,
			wantProto:  "SSH",
			version:    "1.99",
		},
		{
			name:       "Invalid - too short",
			payload:    "SSH-",
			wantResult: false,
		},
		{
			name:       "Invalid - not SSH",
			payload:    "HTTP/1.1 200 OK\r\n",
			wantResult: false,
		},
		{
			name:       "Invalid - wrong prefix",
			payload:    "SSHH-2.0-Test\r\n",
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &signatures.DetectionContext{
				Payload:   []byte(tt.payload),
				Transport: "TCP",
				SrcPort:   22,
				DstPort:   54321,
			}

			result := sig.Detect(ctx)

			if tt.wantResult {
				assert.NotNil(t, result, "Expected SSH to be detected")
				assert.Equal(t, tt.wantProto, result.Protocol)
				if tt.version != "" {
					assert.Equal(t, tt.version, result.Metadata["proto_version"])
				}
			} else {
				assert.Nil(t, result, "Expected SSH not to be detected")
			}
		})
	}
}

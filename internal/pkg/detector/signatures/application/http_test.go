package application

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/stretchr/testify/assert"
)

func TestHTTPSignature_DetectRequest(t *testing.T) {
	sig := NewHTTPSignature()

	tests := []struct {
		name       string
		payload    []byte
		wantProto  string
		wantMethod string
		minConf    float64
	}{
		{
			name:       "GET request",
			payload:    []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantProto:  "HTTP",
			wantMethod: "GET",
			minConf:    0.7,
		},
		{
			name:       "POST request with body",
			payload:    []byte("POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}"),
			wantProto:  "HTTP",
			wantMethod: "POST",
			minConf:    0.7,
		},
		{
			name:       "PUT request",
			payload:    []byte("PUT /resource/123 HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
			wantProto:  "HTTP",
			wantMethod: "PUT",
			minConf:    0.7,
		},
		{
			name:      "Invalid - too short",
			payload:   []byte("GET /"),
			wantProto: "",
		},
		{
			name:      "Invalid - not HTTP",
			payload:   []byte("INVITE sip:user@example.com SIP/2.0\r\n"),
			wantProto: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &signatures.DetectionContext{
				Payload: tt.payload,
				DstPort: 80,
			}

			result := sig.Detect(ctx)

			if tt.wantProto == "" {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantProto, result.Protocol)
				assert.GreaterOrEqual(t, result.Confidence, tt.minConf)
				assert.Equal(t, tt.wantMethod, result.Metadata["method"])
				assert.Equal(t, "request", result.Metadata["type"])
			}
		})
	}
}

func TestHTTPSignature_DetectResponse(t *testing.T) {
	sig := NewHTTPSignature()

	tests := []struct {
		name       string
		payload    []byte
		wantProto  string
		wantStatus string
		minConf    float64
	}{
		{
			name:       "200 OK response",
			payload:    []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html></html>"),
			wantProto:  "HTTP",
			wantStatus: "200",
			minConf:    0.7,
		},
		{
			name:       "404 Not Found",
			payload:    []byte("HTTP/1.1 404 Not Found\r\nServer: Apache\r\n\r\n"),
			wantProto:  "HTTP",
			wantStatus: "404",
			minConf:    0.7,
		},
		{
			name:       "HTTP/1.0 response",
			payload:    []byte("HTTP/1.0 302 Found\r\nLocation: /redirect\r\n\r\n"),
			wantProto:  "HTTP",
			wantStatus: "302",
			minConf:    0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &signatures.DetectionContext{
				Payload: tt.payload,
				SrcPort: 80,
			}

			result := sig.Detect(ctx)

			assert.NotNil(t, result)
			assert.Equal(t, tt.wantProto, result.Protocol)
			assert.GreaterOrEqual(t, result.Confidence, tt.minConf)
			assert.Equal(t, tt.wantStatus, result.Metadata["status_code"])
			assert.Equal(t, "response", result.Metadata["type"])
		})
	}
}

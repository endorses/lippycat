package application

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/simd"
)

// WebSocketSignature detects WebSocket protocol
type WebSocketSignature struct{}

// NewWebSocketSignature creates a new WebSocket signature detector
func NewWebSocketSignature() *WebSocketSignature {
	return &WebSocketSignature{}
}

func (w *WebSocketSignature) Name() string {
	return "WebSocket Detector"
}

func (w *WebSocketSignature) Protocols() []string {
	return []string{"WebSocket"}
}

func (w *WebSocketSignature) Priority() int {
	return 90 // High priority, should be checked before generic HTTP
}

func (w *WebSocketSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (w *WebSocketSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// WebSocket handshake is HTTP Upgrade request/response
	// Check for upgrade handshake first - this is definitive
	if result := w.detectHandshake(ctx); result != nil {
		return result
	}

	// Don't try to detect frames - they're too ambiguous without flow context
	// WebSocket frames can only be reliably detected after seeing the handshake
	return nil
}

func (w *WebSocketSignature) detectHandshake(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if len(ctx.Payload) < 20 {
		return nil
	}

	// Quick SIMD check for GET or HTTP prefix (case-sensitive, fast path)
	getBytes := []byte("GET ")
	httpBytes := []byte("HTTP/")

	isGet := len(ctx.Payload) >= 4 && simd.BytesEqual(ctx.Payload[:4], getBytes)
	isHttp := len(ctx.Payload) >= 5 && simd.BytesEqual(ctx.Payload[:5], httpBytes)

	if !isGet && !isHttp {
		return nil // Not HTTP at all, can't be WebSocket
	}

	payloadStr := string(ctx.Payload[:min(1000, len(ctx.Payload))])
	lowerPayload := strings.ToLower(payloadStr)

	// Check for WebSocket upgrade request
	if isGet || strings.HasPrefix(lowerPayload, "get ") {
		if !simd.StringContains(lowerPayload, "upgrade: websocket") {
			return nil
		}

		lines := strings.Split(payloadStr, "\r\n")
		metadata := map[string]interface{}{
			"type": "upgrade_request",
		}

		headers := w.extractHeaders(lines[1:])

		// Required headers for WebSocket upgrade
		hasUpgrade := false
		hasConnection := false
		hasSecKey := false

		for key, value := range headers {
			keyLower := strings.ToLower(key)
			switch keyLower {
			case "upgrade":
				if strings.ToLower(value) == "websocket" {
					hasUpgrade = true
				}
			case "connection":
				if strings.Contains(strings.ToLower(value), "upgrade") {
					hasConnection = true
				}
			case "sec-websocket-key":
				hasSecKey = true
				metadata["sec_key"] = value
			case "sec-websocket-version":
				metadata["version"] = value
			case "sec-websocket-protocol":
				metadata["protocol"] = value
			case "origin":
				metadata["origin"] = value
			}
		}

		if !hasUpgrade || !hasConnection || !hasSecKey {
			return nil
		}

		// Calculate confidence
		indicators := []signatures.Indicator{
			{Name: "upgrade_header", Weight: 0.4, Confidence: 1.0},
			{Name: "connection_header", Weight: 0.3, Confidence: 1.0},
			{Name: "sec_key", Weight: 0.3, Confidence: 1.0},
		}

		confidence := signatures.ScoreDetection(indicators)

		return &signatures.DetectionResult{
			Protocol:    "WebSocket",
			Confidence:  confidence,
			Metadata:    metadata,
			ShouldCache: true,
		}
	}

	// Check for WebSocket upgrade response
	if isHttp || strings.HasPrefix(lowerPayload, "http/") {
		if !simd.StringContains(lowerPayload, "101 switching protocols") {
			return nil
		}
		if !simd.StringContains(lowerPayload, "upgrade: websocket") {
			return nil
		}

		lines := strings.Split(payloadStr, "\r\n")
		metadata := map[string]interface{}{
			"type": "upgrade_response",
		}

		headers := w.extractHeaders(lines[1:])

		hasUpgrade := false
		hasConnection := false

		for key, value := range headers {
			keyLower := strings.ToLower(key)
			switch keyLower {
			case "upgrade":
				if strings.ToLower(value) == "websocket" {
					hasUpgrade = true
				}
			case "connection":
				if strings.Contains(strings.ToLower(value), "upgrade") {
					hasConnection = true
				}
			case "sec-websocket-accept":
				metadata["sec_accept"] = value
			case "sec-websocket-protocol":
				metadata["protocol"] = value
			}
		}

		if !hasUpgrade || !hasConnection {
			return nil
		}

		// Calculate confidence
		indicators := []signatures.Indicator{
			{Name: "status_101", Weight: 0.4, Confidence: 1.0},
			{Name: "upgrade_header", Weight: 0.3, Confidence: 1.0},
			{Name: "connection_header", Weight: 0.3, Confidence: 1.0},
		}

		confidence := signatures.ScoreDetection(indicators)

		return &signatures.DetectionResult{
			Protocol:    "WebSocket",
			Confidence:  confidence,
			Metadata:    metadata,
			ShouldCache: true,
		}
	}

	return nil
}

func (w *WebSocketSignature) detectFrame(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if len(ctx.Payload) < 2 {
		return nil
	}

	// WebSocket frame format:
	// byte 0: FIN (1 bit) + RSV (3 bits) + opcode (4 bits)
	// byte 1: MASK (1 bit) + payload length (7 bits)
	// bytes 2-5: masking key (if MASK bit is set)
	// bytes N+: payload data

	firstByte := ctx.Payload[0]
	secondByte := ctx.Payload[1]

	fin := (firstByte >> 7) & 0x01
	rsv := (firstByte >> 4) & 0x07
	opcode := firstByte & 0x0F
	mask := (secondByte >> 7) & 0x01
	payloadLen := secondByte & 0x7F

	// Validate opcode (0x0-0xF, but only certain values are defined)
	opcodeNames := map[byte]string{
		0x0: "Continuation",
		0x1: "Text",
		0x2: "Binary",
		0x8: "Close",
		0x9: "Ping",
		0xA: "Pong",
	}

	// RSV bits should be 0 unless extensions are negotiated
	// For basic detection, we'll be lenient and just warn
	if rsv != 0 {
		// Might be using extensions, lower confidence slightly
	}

	// Validate opcode
	opcodeName, validOpcode := opcodeNames[opcode]
	if !validOpcode {
		// Check if it's a reserved opcode (could be extension)
		if opcode > 0xA {
			return nil
		}
	}

	// Calculate extended payload length if needed
	minFrameSize := 2
	if mask == 1 {
		minFrameSize += 4 // masking key
	}

	if payloadLen == 126 {
		minFrameSize += 2 // 16-bit extended length
		if len(ctx.Payload) < minFrameSize {
			return nil
		}
	} else if payloadLen == 127 {
		minFrameSize += 8 // 64-bit extended length
		if len(ctx.Payload) < minFrameSize {
			return nil
		}
	}

	if len(ctx.Payload) < minFrameSize {
		return nil
	}

	metadata := map[string]interface{}{
		"type":     "frame",
		"fin":      fin == 1,
		"opcode":   opcode,
		"masked":   mask == 1,
	}

	if opcodeName != "" {
		metadata["opcode_name"] = opcodeName
	}

	// Calculate confidence based on frame validity
	indicators := []signatures.Indicator{
		{Name: "valid_opcode", Weight: 0.6, Confidence: 0.8},
	}

	// Frames from client to server should be masked
	// Frames from server to client should not be masked
	// This is a strong indicator if we know the direction
	if mask == 1 {
		indicators = append(indicators, signatures.Indicator{
			Name: "masked_frame", Weight: 0.2, Confidence: 0.7,
		})
	}

	// FIN bit and control frames
	if opcode >= 0x8 && fin == 1 {
		// Control frames must not be fragmented (FIN must be 1)
		indicators = append(indicators, signatures.Indicator{
			Name: "control_frame_fin", Weight: 0.2, Confidence: 0.9,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	return &signatures.DetectionResult{
		Protocol:    "WebSocket",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: false, // Don't cache frames, only handshakes
	}
}

func (w *WebSocketSignature) extractHeaders(lines []string) map[string]string {
	headers := make(map[string]string)

	for _, line := range lines {
		if line == "" {
			break
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			headers[key] = value
		}
	}

	return headers
}

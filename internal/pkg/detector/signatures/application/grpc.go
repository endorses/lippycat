package application

import (
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// GRPCSignature detects gRPC/HTTP2 traffic
type GRPCSignature struct{}

// NewGRPCSignature creates a new gRPC signature detector
func NewGRPCSignature() *GRPCSignature {
	return &GRPCSignature{}
}

func (g *GRPCSignature) Name() string {
	return "gRPC/HTTP2 Detector"
}

func (g *GRPCSignature) Protocols() []string {
	return []string{"gRPC", "HTTP2"}
}

func (g *GRPCSignature) Priority() int {
	return 130 // Higher than DNS to prevent misclassification
}

func (g *GRPCSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (g *GRPCSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if len(ctx.Payload) < 9 {
		return nil
	}

	// HTTP/2 is always over TCP
	if ctx.Transport != "TCP" {
		return nil
	}

	payload := ctx.Payload

	// Check for HTTP/2 connection preface (24 bytes)
	if len(payload) >= 24 {
		preface := string(payload[:24])
		if preface == "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			return &signatures.DetectionResult{
				Protocol:    "gRPC",
				Confidence:  signatures.ConfidenceDefinite,
				Metadata: map[string]interface{}{
					"type": "connection_preface",
				},
				ShouldCache: true,
			}
		}
	}

	// Check for HTTP/2 frame header
	// Frame format: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream ID (with reserved bit)

	// Extract frame length (3 bytes, big-endian)
	frameLength := uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2])

	// Extract frame type
	frameType := payload[3]

	// Extract flags
	flags := payload[4]

	// Extract stream ID (4 bytes, big-endian, with reserved bit)
	streamID := uint32(payload[5])<<24 | uint32(payload[6])<<16 | uint32(payload[7])<<8 | uint32(payload[8])

	// Check reserved bit (first bit of stream ID, should be 0)
	reserved := (streamID >> 31) & 0x01
	if reserved != 0 {
		return nil
	}

	// Clear reserved bit to get actual stream ID
	streamID = streamID & 0x7FFFFFFF

	// Validate frame type (HTTP/2 frame types: 0x00-0x0A)
	validFrameTypes := map[uint8]string{
		0x00: "DATA",
		0x01: "HEADERS",
		0x02: "PRIORITY",
		0x03: "RST_STREAM",
		0x04: "SETTINGS",
		0x05: "PUSH_PROMISE",
		0x06: "PING",
		0x07: "GOAWAY",
		0x08: "WINDOW_UPDATE",
		0x09: "CONTINUATION",
		0x0A: "ALTSVC",
	}

	frameTypeName, validType := validFrameTypes[frameType]
	if !validType {
		return nil
	}

	// Validate frame length (should be reasonable, max 16MB default)
	if frameLength > 16*1024*1024 {
		return nil
	}

	// Validate frame length is reasonable for detection
	// TLS handshakes often get misinterpreted as HTTP/2 with huge frame lengths
	// Typical HTTP/2 initial frames:
	// - SETTINGS: usually 0-36 bytes
	// - PING: exactly 8 bytes
	// - HEADERS: typically < 8KB
	// - DATA: can be large, but first packet is usually smaller

	// If frame length is > 64KB, be very suspicious
	if frameLength > 64*1024 {
		// Only allow large DATA frames, and only if packet actually contains data
		if frameType != 0x00 || len(payload) < 9+min(int(frameLength), 1024) {
			return nil
		}
	}

	// For non-DATA frames, enforce stricter limits
	if frameType != 0x00 && frameLength > 16*1024 {
		return nil
	}

	// Sanity check: if claimed frame length is small, packet should contain it
	// This catches TLS ClientHello being misread as a massive DATA frame
	if frameLength < 100 {
		// Small frame should be fully present in packet
		if len(payload) < int(9+frameLength) {
			return nil
		}
	}

	// Additional validation based on frame type
	switch frameType {
	case 0x04: // SETTINGS frame
		// SETTINGS must have stream ID 0
		if streamID != 0 {
			return nil
		}
		// SETTINGS payload must be multiple of 6
		if frameLength%6 != 0 {
			return nil
		}
	case 0x06: // PING frame
		// PING must have stream ID 0
		if streamID != 0 {
			return nil
		}
		// PING payload must be exactly 8 bytes
		if frameLength != 8 {
			return nil
		}
	case 0x08: // WINDOW_UPDATE frame
		// WINDOW_UPDATE payload must be exactly 4 bytes
		if frameLength != 4 {
			return nil
		}
	}

	// Extract metadata
	metadata := map[string]interface{}{
		"frame_type":   frameTypeName,
		"frame_length": frameLength,
		"stream_id":    streamID,
		"flags":        flags,
	}

	// Calculate confidence
	confidence := g.calculateConfidence(ctx, metadata, frameType, streamID)

	// Determine protocol (gRPC or generic HTTP/2)
	protocol := "HTTP2"

	// gRPC typically uses specific ports or has specific patterns
	if ctx.DstPort == 50051 || ctx.SrcPort == 50051 {
		protocol = "gRPC"
		confidence = signatures.ConfidenceVeryHigh
	}

	return &signatures.DetectionResult{
		Protocol:    protocol,
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

// calculateConfidence determines confidence level for gRPC/HTTP2 detection
func (g *GRPCSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, frameType uint8, streamID uint32) float64 {
	indicators := []signatures.Indicator{}

	// Valid frame type and structure
	indicators = append(indicators, signatures.Indicator{
		Name:       "valid_frame",
		Weight:     0.5,
		Confidence: signatures.ConfidenceHigh,
	})

	// Stream ID validation (0 for connection-level frames, >0 for stream frames)
	if (frameType == 0x04 || frameType == 0x06 || frameType == 0x07) && streamID == 0 {
		// Connection-level frame with correct stream ID
		indicators = append(indicators, signatures.Indicator{
			Name:       "correct_stream_id",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	} else if streamID > 0 {
		// Stream-level frame
		indicators = append(indicators, signatures.Indicator{
			Name:       "stream_frame",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	// TCP transport (HTTP/2 is always over TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

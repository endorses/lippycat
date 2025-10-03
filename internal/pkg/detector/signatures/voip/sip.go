package voip

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// SIPSignature detects SIP (Session Initiation Protocol) traffic
type SIPSignature struct {
	methods []string
}

// NewSIPSignature creates a new SIP signature detector
func NewSIPSignature() *SIPSignature {
	return &SIPSignature{
		methods: []string{
			"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS",
			"PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER",
			"MESSAGE", "UPDATE", "SIP/2.0",
		},
	}
}

func (s *SIPSignature) Name() string {
	return "SIP Detector"
}

func (s *SIPSignature) Protocols() []string {
	return []string{"SIP"}
}

func (s *SIPSignature) Priority() int {
	return 150 // High priority for VoIP
}

func (s *SIPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (s *SIPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if len(ctx.Payload) < 8 {
		return nil
	}

	// Convert payload to string for pattern matching
	// TODO: Use SIMD byte matching to avoid allocation
	payloadStr := string(ctx.Payload[:min(len(ctx.Payload), 100)])

	// Check for SIP methods
	for _, method := range s.methods {
		if len(payloadStr) >= len(method) && payloadStr[:len(method)] == method {
			// Extract metadata
			metadata := s.extractMetadata(string(ctx.Payload))

			// Calculate confidence
			confidence := s.calculateConfidence(ctx, metadata)

			// Check if we're on standard SIP port for confidence boost
			portFactor := detector.PortBasedConfidence(ctx.SrcPort, []uint16{5060, 5061})
			if portFactor < 1.0 {
				portFactor = detector.PortBasedConfidence(ctx.DstPort, []uint16{5060, 5061})
			}
			confidence = detector.AdjustConfidenceByContext(confidence, map[string]float64{
				"port": portFactor,
			})

			return &signatures.DetectionResult{
				Protocol:    "SIP",
				Confidence:  confidence,
				Metadata:    metadata,
				ShouldCache: true,
			}
		}
	}

	return nil
}

// extractMetadata extracts SIP-specific metadata from the payload
func (s *SIPSignature) extractMetadata(payload string) map[string]interface{} {
	metadata := make(map[string]interface{})

	lines := splitLines(payload)
	if len(lines) == 0 {
		return metadata
	}

	// First line is the request/status line
	firstLine := lines[0]
	metadata["first_line"] = firstLine

	// Determine if request or response
	if strings.HasPrefix(firstLine, "SIP/2.0") {
		metadata["type"] = "response"
		// Extract status code
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			metadata["status_code"] = parts[1]
		}
		if len(parts) >= 3 {
			metadata["reason"] = parts[2]
		}
	} else {
		metadata["type"] = "request"
		// Extract method
		parts := strings.SplitN(firstLine, " ", 2)
		if len(parts) >= 1 {
			metadata["method"] = parts[0]
		}
	}

	// Parse headers
	headers := make(map[string]string)
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			break // End of headers
		}

		// Parse header
		colonIdx := strings.Index(line, ":")
		if colonIdx > 0 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			headers[key] = value

			// Extract important fields
			switch key {
			case "From", "f":
				metadata["from"] = value
				metadata["from_user"] = extractUserFromURI(value)
			case "To", "t":
				metadata["to"] = value
			case "Call-ID", "i":
				metadata["call_id"] = value
			case "CSeq":
				metadata["cseq"] = value
			case "Via", "v":
				if _, ok := metadata["via"]; !ok {
					metadata["via"] = value
				}
			case "Contact", "m":
				metadata["contact"] = value
			case "User-Agent":
				metadata["user_agent"] = value
			}
		}
	}

	metadata["headers"] = headers

	return metadata
}

// calculateConfidence determines confidence level based on SIP indicators
func (s *SIPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}) float64 {
	indicators := []detector.Indicator{}

	// Method/response indicator (very strong)
	indicators = append(indicators, detector.Indicator{
		Name:       "sip_method",
		Weight:     0.5,
		Confidence: signatures.ConfidenceVeryHigh,
	})

	// Has Call-ID header (strong indicator)
	if _, ok := metadata["call_id"]; ok {
		indicators = append(indicators, detector.Indicator{
			Name:       "has_call_id",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Has From/To headers (strong indicator)
	if _, ok := metadata["from"]; ok {
		indicators = append(indicators, detector.Indicator{
			Name:       "has_from",
			Weight:     0.2,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Has valid SIP structure
	if headers, ok := metadata["headers"].(map[string]string); ok && len(headers) > 0 {
		indicators = append(indicators, detector.Indicator{
			Name:       "has_headers",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return detector.ScoreDetection(indicators)
}

// Helper functions

func splitLines(s string) []string {
	var lines []string
	var line string
	for _, c := range s {
		if c == '\n' || c == '\r' {
			if line != "" {
				lines = append(lines, line)
				line = ""
			}
		} else {
			line += string(c)
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

func extractUserFromURI(uri string) string {
	// Extract username from SIP URI: "Alice <sip:alice@domain.com>"
	start := strings.Index(uri, "sip:")
	if start == -1 {
		return ""
	}
	start += 4

	end := strings.Index(uri[start:], "@")
	if end == -1 {
		return ""
	}

	return uri[start : start+end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

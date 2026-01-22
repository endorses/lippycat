package voip

import (
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/simd"
)

// SIPSignature detects SIP (Session Initiation Protocol) traffic
type SIPSignature struct {
	methods      []string
	methodsBytes [][]byte // Byte versions for SIMD matching
}

// NewSIPSignature creates a new SIP signature detector
func NewSIPSignature() *SIPSignature {
	methods := []string{
		"INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS",
		"PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER",
		"MESSAGE", "UPDATE", "SIP/2.0",
	}

	// Pre-convert methods to byte slices for SIMD matching
	methodsBytes := make([][]byte, len(methods))
	for i, m := range methods {
		methodsBytes[i] = []byte(m)
	}

	return &SIPSignature{
		methods:      methods,
		methodsBytes: methodsBytes,
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

	// Check for SIP methods using SIMD byte matching (zero allocation)
	for i, methodBytes := range s.methodsBytes {
		if len(ctx.Payload) >= len(methodBytes) &&
			simd.BytesEqual(ctx.Payload[:len(methodBytes)], methodBytes) {
			// Extract metadata (still needs string for parsing headers)
			payloadStr := string(ctx.Payload)
			metadata := s.extractMetadata(payloadStr)

			// Extract SDP info (media ports and connection IP) for RTP correlation
			sdpInfo := s.extractSDPInfo(payloadStr)
			if len(sdpInfo.MediaPorts) > 0 {
				// Store in flow context for RTP correlation
				if ctx.Flow != nil {
					// Get or create SIP flow state
					var sipState *SIPFlowState
					if ctx.Flow.State != nil {
						sipState, _ = ctx.Flow.State.(*SIPFlowState)
					}
					if sipState == nil {
						sipState = &SIPFlowState{
							MediaPorts: make([]uint16, 0),
						}
						ctx.Flow.State = sipState
					}

					// Update Call-ID if available
					if callID, ok := metadata["call_id"].(string); ok {
						sipState.CallID = callID
					}

					// Add new media ports (avoid duplicates)
					for _, port := range sdpInfo.MediaPorts {
						found := false
						for _, existing := range sipState.MediaPorts {
							if existing == port {
								found = true
								break
							}
						}
						if !found {
							sipState.MediaPorts = append(sipState.MediaPorts, port)
						}
					}

					metadata["media_ports"] = sdpInfo.MediaPorts
					// Store connection IP for RTP endpoint registration
					if sdpInfo.ConnectionIP != "" {
						metadata["media_ip"] = sdpInfo.ConnectionIP
					}
				}
			}

			// Calculate confidence
			confidence := s.calculateConfidence(ctx, metadata)

			// Check if we're on standard SIP port for confidence boost
			portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{5060, 5061})
			if portFactor < 1.0 {
				portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{5060, 5061})
			}
			confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
				"port": portFactor,
			})

			// Add method name to metadata from pre-computed list
			metadata["matched_method"] = s.methods[i]

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
				metadata["from_tag"] = extractTagFromHeader(value)
			case "To", "t":
				metadata["to"] = value
				metadata["to_user"] = extractUserFromURI(value)
				metadata["to_tag"] = extractTagFromHeader(value)
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
	indicators := []signatures.Indicator{}

	// Method/response indicator (very strong)
	indicators = append(indicators, signatures.Indicator{
		Name:       "sip_method",
		Weight:     0.5,
		Confidence: signatures.ConfidenceVeryHigh,
	})

	// Has Call-ID header (strong indicator)
	if _, ok := metadata["call_id"]; ok {
		indicators = append(indicators, signatures.Indicator{
			Name:       "has_call_id",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Has From/To headers (strong indicator)
	if _, ok := metadata["from"]; ok {
		indicators = append(indicators, signatures.Indicator{
			Name:       "has_from",
			Weight:     0.2,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Has valid SIP structure
	if headers, ok := metadata["headers"].(map[string]string); ok && len(headers) > 0 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "has_headers",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

// Helper functions

func splitLines(s string) []string {
	// Use bytes.Split for better performance (stdlib is optimized)
	lines := strings.Split(s, "\r\n")
	if len(lines) == 1 {
		// Try splitting by \n only
		lines = strings.Split(s, "\n")
	}

	// Filter out empty lines
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			filtered = append(filtered, line)
		}
	}
	return filtered
}

func extractUserFromURI(uri string) string {
	// Extract username from SIP URI: "Alicent <sip:alicent@domain.com>"
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

func extractTagFromHeader(header string) string {
	// Extract tag parameter from SIP From/To header
	// Example: "Alicent <sip:alicent@domain.com>;tag=abc123" -> "abc123"
	tagStart := strings.Index(strings.ToLower(header), ";tag=")
	if tagStart == -1 {
		return ""
	}

	valueStart := tagStart + 5 // len(";tag=")
	if valueStart >= len(header) {
		return ""
	}

	// Find the end of the tag value
	value := header[valueStart:]
	for i, ch := range value {
		if ch == ';' || ch == ' ' || ch == '\r' || ch == '\n' || ch == '>' {
			return value[:i]
		}
	}
	return value
}

// SDPInfo contains parsed SDP information for RTP correlation
type SDPInfo struct {
	MediaPorts   []uint16
	ConnectionIP string // From c= line
}

// extractSDPInfo extracts RTP media ports and connection IP from SDP
func (s *SIPSignature) extractSDPInfo(payload string) SDPInfo {
	info := SDPInfo{
		MediaPorts: make([]uint16, 0),
	}

	// Look for SDP content (appears after empty line in SIP message)
	lines := strings.Split(payload, "\n")
	inSDP := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Empty line marks start of SDP body
		if line == "" {
			inSDP = true
			continue
		}

		if !inSDP {
			continue
		}

		// SDP connection line: c=IN IP4 10.0.0.5
		// Format: c=<nettype> <addrtype> <connection-address>
		if strings.HasPrefix(line, "c=") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				// parts[0] = "c=IN"
				// parts[1] = "IP4" or "IP6"
				// parts[2] = IP address (may have TTL suffix like /127)
				ip := parts[2]
				// Remove TTL suffix if present (e.g., "224.2.1.1/127" -> "224.2.1.1")
				if idx := strings.Index(ip, "/"); idx > 0 {
					ip = ip[:idx]
				}
				// Only use non-zero IPs
				if ip != "0.0.0.0" && ip != "" {
					info.ConnectionIP = ip
				}
			}
		}

		// SDP media lines: m=audio 49170 RTP/AVP 0
		// Format: m=<media> <port> <proto> <fmt>
		if strings.HasPrefix(line, "m=") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				// parts[0] = "m=audio" or "m=video"
				// parts[1] = port number
				// parts[2] = protocol (RTP/AVP, etc.)

				// Extract port from parts[1]
				var port int
				if _, err := fmt.Sscanf(parts[1], "%d", &port); err == nil {
					if port > 0 && port <= 65535 {
						info.MediaPorts = append(info.MediaPorts, uint16(port))
					}
				}
			}
		}
	}

	return info
}

// extractSDPMediaPorts extracts RTP media ports from SDP (Session Description Protocol)
// embedded in SIP messages
// Deprecated: Use extractSDPInfo for full SDP parsing including connection IP
func (s *SIPSignature) extractSDPMediaPorts(payload string) []uint16 {
	return s.extractSDPInfo(payload).MediaPorts
}

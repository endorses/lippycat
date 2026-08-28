package voip

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/simd"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// sipIPEntry stores a timestamp for TTL-based eviction.
type sipIPEntry struct {
	timestamp time.Time
}

// SIPSignature detects SIP (Session Initiation Protocol) traffic
type SIPSignature struct {
	methods         []string
	methodsBytes    [][]byte // Byte versions for SIMD matching
	knownSIPIPPairs sync.Map // key: "ip1|ip2" (normalized) → sipIPEntry
	sipIPPairTTL    time.Duration
}

// NewSIPSignature creates a new SIP signature detector
func NewSIPSignature() *SIPSignature {
	methods := append([]string(nil), sharedsip.RequestMethods[:]...)
	methods = append(methods, "SIP/2.0")

	// Pre-convert methods to byte slices for SIMD matching
	methodsBytes := make([][]byte, len(methods))
	for i, m := range methods {
		methodsBytes[i] = []byte(m)
	}

	return &SIPSignature{
		methods:      methods,
		methodsBytes: methodsBytes,
		sipIPPairTTL: 30 * time.Minute,
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
		// For TCP RST/FIN with no payload, check if this IP pair has carried SIP before.
		// In IMS/VoLTE, ESP-NULL tunnels SIP-over-TCP sessions; the TCP teardown packet
		// has no SIP payload but belongs to the same SIP signalling path.
		if ctx.Transport == "TCP" && ctx.Packet != nil {
			if tcp, ok := ctx.Packet.TransportLayer().(*layers.TCP); ok && (tcp.RST || tcp.FIN) {
				if s.isKnownSIPIPPair(ctx.SrcIP, ctx.DstIP) && hasDSCPEF(ctx.Packet) {
					return &signatures.DetectionResult{
						Protocol:    "SIP",
						Confidence:  signatures.ConfidenceLow,
						Metadata:    map[string]interface{}{"type": "tcp_teardown"},
						ShouldCache: false,
					}
				}
			}
		}
		return nil
	}

	// Check for SIP methods using SIMD byte matching (zero allocation)
	for i, methodBytes := range s.methodsBytes {
		if len(ctx.Payload) >= len(methodBytes) &&
			simd.BytesEqual(ctx.Payload[:len(methodBytes)], methodBytes) {
			event, err := sharedsip.Parse(ctx.Payload, sharedsip.ParseOptions{})
			if err != nil {
				return nil
			}
			metadata := s.metadataFromEvent(event)

			// Extract SDP info (media ports and connection IP) for RTP correlation
			sdpInfo := s.extractSDPInfo(string(event.SDP))
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

					// Add new media ports (avoid duplicates).
					// Also register RTCP port (RTP+1) per RFC 3550 so RTCP packets
					// can be correlated even without an explicit a=rtcp: SDP attribute.
					for _, port := range sdpInfo.MediaPorts {
						for _, candidate := range []uint16{port, port + 1} {
							found := false
							for _, existing := range sipState.MediaPorts {
								if existing == candidate {
									found = true
									break
								}
							}
							if !found {
								sipState.MediaPorts = append(sipState.MediaPorts, candidate)
							}
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

			// Record this IP pair as a known SIP endpoint pair for future TCP teardown correlation.
			s.recordSIPIPPair(ctx.SrcIP, ctx.DstIP)

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

// normalizeSIPIPPair returns a canonical key for an IP pair, direction-independent.
func normalizeSIPIPPair(ip1, ip2 string) string {
	if ip1 <= ip2 {
		return ip1 + "|" + ip2
	}
	return ip2 + "|" + ip1
}

// recordSIPIPPair stores an IP pair as a known SIP endpoint pair.
func (s *SIPSignature) recordSIPIPPair(srcIP, dstIP string) {
	key := normalizeSIPIPPair(srcIP, dstIP)
	s.knownSIPIPPairs.Store(key, sipIPEntry{timestamp: time.Now()})
}

// isKnownSIPIPPair reports whether the given IP pair has previously been observed
// carrying SIP traffic and the entry has not expired.
func (s *SIPSignature) isKnownSIPIPPair(srcIP, dstIP string) bool {
	key := normalizeSIPIPPair(srcIP, dstIP)
	val, ok := s.knownSIPIPPairs.Load(key)
	if !ok {
		return false
	}
	entry := val.(sipIPEntry)
	if time.Since(entry.timestamp) > s.sipIPPairTTL {
		s.knownSIPIPPairs.Delete(key)
		return false
	}
	return true
}

// SweepSIPIPPairs removes expired SIP IP pair entries. Called periodically
// by the detector to prevent unbounded growth.
func (s *SIPSignature) SweepSIPIPPairs() int {
	now := time.Now()
	removed := 0
	s.knownSIPIPPairs.Range(func(key, value any) bool {
		entry := value.(sipIPEntry)
		if now.Sub(entry.timestamp) > s.sipIPPairTTL {
			s.knownSIPIPPairs.Delete(key)
			removed++
		}
		return true
	})
	return removed
}

// hasDSCPEF reports whether the packet carries DSCP Expedited Forwarding marking
// (traffic class / TOS byte == 0xb8, i.e. DSCP 46 with ECN bits clear).
// VoIP signalling and media are standardly marked EF; general-purpose TCP traffic
// (HTTP, SSH, …) is not, so this greatly reduces false positives when classifying
// TCP teardowns on known SIP IP pairs.
func hasDSCPEF(pkt gopacket.Packet) bool {
	if netLayer := pkt.NetworkLayer(); netLayer != nil {
		switch net := netLayer.(type) {
		case *layers.IPv4:
			return net.TOS == 0xb8
		case *layers.IPv6:
			return net.TrafficClass == 0xb8
		}
	}
	return false
}

// extractMetadata extracts SIP-specific metadata from the payload
func (s *SIPSignature) extractMetadata(payload string) map[string]interface{} {
	event, err := sharedsip.Parse([]byte(payload), sharedsip.ParseOptions{})
	if err != nil {
		return map[string]interface{}{}
	}
	return s.metadataFromEvent(event)
}

func (s *SIPSignature) metadataFromEvent(event sharedsip.SIPEvent) map[string]interface{} {
	metadata := make(map[string]interface{})
	metadata["first_line"] = event.StartLine
	if event.Method == "RESPONSE" {
		metadata["type"] = "response"
		metadata["status_code"] = fmt.Sprint(event.ResponseCode)
		parts := strings.SplitN(event.StartLine, " ", 3)
		if len(parts) >= 3 {
			metadata["reason"] = parts[2]
		}
	} else {
		metadata["type"] = "request"
		metadata["method"] = event.Method
	}
	metadata["from"], metadata["from_user"], metadata["from_tag"] = event.From, event.FromUser, event.FromTag
	metadata["to"], metadata["to_user"], metadata["to_tag"] = event.To, event.ToUser, event.ToTag
	metadata["call_id"], metadata["cseq"] = event.CallID, event.Headers["cseq"]
	if via := event.Headers["via"]; via != "" {
		metadata["via"] = via
	}
	if contact := event.Headers["contact"]; contact != "" {
		metadata["contact"] = contact
	}
	if ua := event.Headers["user-agent"]; ua != "" {
		metadata["user_agent"] = ua
	}
	metadata["headers"] = event.Headers

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
	return sharedsip.Tag(header)
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

	lines := strings.Split(payload, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

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

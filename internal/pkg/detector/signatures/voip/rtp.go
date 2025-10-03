package voip

import (
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// RTPSignature detects RTP (Real-time Transport Protocol) traffic
type RTPSignature struct{}

// NewRTPSignature creates a new RTP signature detector
func NewRTPSignature() *RTPSignature {
	return &RTPSignature{}
}

func (r *RTPSignature) Name() string {
	return "RTP Detector"
}

func (r *RTPSignature) Protocols() []string {
	return []string{"RTP"}
}

func (r *RTPSignature) Priority() int {
	return 140 // Slightly lower than SIP
}

func (r *RTPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (r *RTPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// RTP requires minimum 12 bytes for header
	if len(ctx.Payload) < 12 {
		return nil
	}

	// Check RTP version (must be 2)
	version := (ctx.Payload[0] >> 6) & 0x03
	if version != 2 {
		return nil
	}

	// Additional validation: check payload type range (0-127)
	payloadType := ctx.Payload[1] & 0x7F
	if payloadType > 127 {
		return nil
	}

	// Extract metadata
	metadata := r.extractMetadata(ctx.Payload)

	// Calculate confidence
	confidence := r.calculateConfidence(ctx, metadata)

	// Check if this RTP stream was negotiated in SIP (if flow context available)
	if ctx.Flow != nil && ctx.Flow.State != nil {
		if sipState, ok := ctx.Flow.State.(*SIPFlowState); ok {
			// Check if this port was negotiated in SIP SDP
			for _, port := range sipState.MediaPorts {
				if ctx.DstPort == port || ctx.SrcPort == port {
					// Very high confidence - RTP port was explicitly negotiated
					confidence = signatures.ConfidenceVeryHigh
					metadata["sip_correlated"] = true
					metadata["call_id"] = sipState.CallID
					break
				}
			}
		}
	}

	return &signatures.DetectionResult{
		Protocol:    "RTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

// extractMetadata extracts RTP-specific metadata
func (r *RTPSignature) extractMetadata(payload []byte) map[string]interface{} {
	metadata := make(map[string]interface{})

	// Version
	version := (payload[0] >> 6) & 0x03
	metadata["version"] = version

	// Padding flag
	padding := (payload[0] >> 5) & 0x01
	metadata["padding"] = padding == 1

	// Extension flag
	extension := (payload[0] >> 4) & 0x01
	metadata["extension"] = extension == 1

	// CSRC count
	csrcCount := payload[0] & 0x0F
	metadata["csrc_count"] = csrcCount

	// Marker bit
	marker := (payload[1] >> 7) & 0x01
	metadata["marker"] = marker == 1

	// Payload type
	payloadType := payload[1] & 0x7F
	metadata["payload_type"] = payloadType
	metadata["codec"] = payloadTypeToCodec(payloadType)

	// Sequence number
	seqNum := uint16(payload[2])<<8 | uint16(payload[3])
	metadata["sequence_number"] = seqNum

	// Timestamp
	timestamp := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	metadata["timestamp"] = timestamp

	// SSRC (Synchronization Source)
	ssrc := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])
	metadata["ssrc"] = ssrc

	return metadata
}

// calculateConfidence determines confidence level for RTP detection
func (r *RTPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}) float64 {
	indicators := []signatures.Indicator{}

	// Version 2 (strong indicator)
	if version, ok := metadata["version"].(uint8); ok && version == 2 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "rtp_version",
			Weight:     0.4,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Valid payload type (medium indicator)
	if pt, ok := metadata["payload_type"].(uint8); ok && pt < 128 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_payload_type",
			Weight:     0.3,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	// UDP transport (RTP is almost always UDP)
	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	// Typical RTP port range (10000-20000)
	if (ctx.SrcPort >= 10000 && ctx.SrcPort <= 20000) || (ctx.DstPort >= 10000 && ctx.DstPort <= 20000) {
		indicators = append(indicators, signatures.Indicator{
			Name:       "typical_port_range",
			Weight:     0.1,
			Confidence: signatures.ConfidenceLow,
		})
	}

	return signatures.ScoreDetection(indicators)
}

// SIPFlowState holds SIP flow state for RTP correlation
type SIPFlowState struct {
	CallID     string
	MediaPorts []uint16
	CodecInfo  string
}

// payloadTypeToCodec maps RTP payload type to codec name
func payloadTypeToCodec(pt uint8) string {
	codecs := map[uint8]string{
		0:  "G.711 µ-law (PCMU)",
		3:  "GSM",
		4:  "G.723",
		5:  "DVI4 8kHz",
		6:  "DVI4 16kHz",
		7:  "LPC",
		8:  "G.711 A-law (PCMA)",
		9:  "G.722",
		10: "L16 Stereo",
		11: "L16 Mono",
		12: "QCELP",
		13: "Comfort Noise",
		14: "MPA",
		15: "G.728",
		16: "DVI4 11kHz",
		17: "DVI4 22kHz",
		18: "G.729",
		25: "CelB",
		26: "JPEG",
		28: "nv",
		31: "H.261",
		32: "MPV",
		33: "MP2T",
		34: "H.263",
		96: "Dynamic",
		97: "Dynamic",
		98: "Dynamic",
		99: "Dynamic",
		100: "Dynamic",
		101: "Dynamic (often telephone-event)",
		102: "Dynamic",
		103: "Dynamic",
	}

	if codec, ok := codecs[pt]; ok {
		return codec
	}

	if pt >= 96 && pt <= 127 {
		return "Dynamic"
	}

	return "Unknown"
}

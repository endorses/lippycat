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
	// RTP requires minimum 12 bytes for header + some payload
	// Require at least 16 bytes to reduce false positives
	if len(ctx.Payload) < 16 {
		return nil
	}

	// RTP is almost always UDP - reject TCP to avoid false positives on encrypted protocols
	if ctx.Transport != "UDP" {
		return nil
	}

	// Reject well-known TCP/TLS ports to avoid false positives
	// (even though we already filtered TCP above, this is defense in depth)
	if isWellKnownTCPPort(ctx.SrcPort) || isWellKnownTCPPort(ctx.DstPort) {
		return nil
	}

	// Reject well-known UDP service ports (DNS, NTP, DHCP, etc.)
	// These can have payloads that accidentally match RTP header patterns
	if isWellKnownUDPPort(ctx.SrcPort) || isWellKnownUDPPort(ctx.DstPort) {
		return nil
	}

	// Check RTP version (must be 2)
	version := (ctx.Payload[0] >> 6) & 0x03
	if version != 2 {
		return nil
	}

	// Extract key fields for validation
	payloadType := ctx.Payload[1] & 0x7F
	csrcCount := int(ctx.Payload[0] & 0x0F)
	extension := (ctx.Payload[0] >> 4) & 0x01

	// Validate CSRC count is reasonable (typically 0-4, max 15)
	if csrcCount > 15 {
		return nil
	}

	// Validate payload type is in valid range
	// Common types: 0-34 (static), 96-127 (dynamic)
	// Reject 35-95 as these are unassigned/reserved
	if payloadType >= 35 && payloadType < 96 {
		return nil
	}

	// Additional validation: Calculate expected header size
	headerSize := 12 + (csrcCount * 4)
	if extension == 1 {
		headerSize += 4 // Extension header is at least 4 bytes
	}

	// Ensure packet is large enough for declared header size
	if len(ctx.Payload) < headerSize {
		return nil
	}

	// Validate sequence number and timestamp are not all zeros or all ones
	// (very unlikely in real RTP)
	seqNum := uint16(ctx.Payload[2])<<8 | uint16(ctx.Payload[3])
	timestamp := uint32(ctx.Payload[4])<<24 | uint32(ctx.Payload[5])<<16 | uint32(ctx.Payload[6])<<8 | uint32(ctx.Payload[7])
	ssrc := uint32(ctx.Payload[8])<<24 | uint32(ctx.Payload[9])<<16 | uint32(ctx.Payload[10])<<8 | uint32(ctx.Payload[11])

	// Reject pathological cases
	if ssrc == 0 || ssrc == 0xFFFFFFFF {
		return nil
	}
	if timestamp == 0xFFFFFFFF {
		return nil
	}

	// Additional heuristics to reduce false positives:
	// 1. Check that at least some bits vary in timestamp and seqnum
	//    (all zeros or simple patterns are suspicious)
	if timestamp == 0 && seqNum == 0 {
		return nil
	}

	// 2. Marker bit validation - it should be 0 for most packets
	//    Marker bit is typically only set on key frames or end of talk spurts
	marker := (ctx.Payload[1] >> 7) & 0x01
	if marker == 1 {
		// Reduce confidence for marked packets (less common)
		// But don't reject outright as they are valid
	}

	// 3. Stricter payload type validation
	//    Only accept well-known static types OR clearly dynamic types
	isValidPayloadType := false
	if payloadType <= 23 {
		// Well-known static audio/video types (PCMU, GSM, G722, etc.)
		isValidPayloadType = true
	} else if payloadType >= 96 && payloadType <= 127 {
		// Dynamic types - but require additional validation
		// Dynamic types should only be accepted with SIP correlation or port hints
		isValidPayloadType = false // Will be validated below
	}

	// 4. Check port ranges - RTP typically uses even ports 16384-32768
	//    This is the IANA recommended range for RTP
	inTypicalRange := false
	if (ctx.SrcPort >= 16384 && ctx.SrcPort <= 32768 && ctx.SrcPort%2 == 0) ||
		(ctx.DstPort >= 16384 && ctx.DstPort <= 32768 && ctx.DstPort%2 == 0) {
		inTypicalRange = true
	}
	// Legacy implementations sometimes use 10000-20000, but be more restrictive
	// Require even ports in this range too
	if (ctx.SrcPort >= 10000 && ctx.SrcPort <= 20000 && ctx.SrcPort%2 == 0) ||
		(ctx.DstPort >= 10000 && ctx.DstPort <= 20000 && ctx.DstPort%2 == 0) {
		inTypicalRange = true
	}

	// 5. Require typical port range OR correlation for detection
	//    Correlation can be: SIP negotiation OR existing RTP flow state
	hasSIPCorrelation := false
	hasRTPFlowCorrelation := false

	// Store SSRC in flow for validation across packets
	if ctx.Flow != nil {
		// Check for SIP correlation first
		if sipState, ok := ctx.Flow.State.(*SIPFlowState); ok {
			for _, port := range sipState.MediaPorts {
				if ctx.DstPort == port || ctx.SrcPort == port {
					hasSIPCorrelation = true
					break
				}
			}
		}

		if rtpState, ok := ctx.Flow.State.(*RTPFlowState); ok {
			// We already have RTP state for this flow - this is likely the return path!
			hasRTPFlowCorrelation = true

			// Determine if this is forward or reverse direction
			isForward := (rtpState.FirstSrcPort == ctx.SrcPort)

			// Check SSRC and sequence consistency for this direction
			if isForward {
				if rtpState.SSRCForward != 0 && rtpState.SSRCForward != ssrc {
					// Forward SSRC changed - possible false positive
					return nil
				}
				rtpState.SSRCForward = ssrc

				// Check sequence progression for forward direction
				if rtpState.LastSeqForward != 0 {
					seqDiff := int32(seqNum) - int32(rtpState.LastSeqForward)
					// Allow wrap-around but reject huge jumps
					if seqDiff > 1000 || seqDiff < -1000 {
						return nil
					}
				}
				rtpState.LastSeqForward = seqNum
			} else {
				// Reverse direction
				if rtpState.SSRCReverse != 0 && rtpState.SSRCReverse != ssrc {
					// Reverse SSRC changed - possible false positive
					return nil
				}
				rtpState.SSRCReverse = ssrc

				// Check sequence progression for reverse direction
				if rtpState.LastSeqReverse != 0 {
					seqDiff := int32(seqNum) - int32(rtpState.LastSeqReverse)
					// Allow wrap-around but reject huge jumps
					if seqDiff > 1000 || seqDiff < -1000 {
						return nil
					}
				}
				rtpState.LastSeqReverse = seqNum
			}

			rtpState.PacketCount++
		} else if !hasSIPCorrelation {
			// Initialize RTP flow state (only if not SIP-correlated)
			ctx.Flow.State = &RTPFlowState{
				SSRCForward:    ssrc,
				SSRCReverse:    0, // Will be set when reverse packet arrives
				LastSeqForward: seqNum,
				LastSeqReverse: 0,
				PacketCount:    1,
				FirstSrcPort:   ctx.SrcPort,
			}
		}
	}

	// Require either correlation OR BOTH (typical port range AND valid static payload type)
	// Correlation = SIP negotiation OR existing RTP flow (bidirectional support)
	if !hasSIPCorrelation && !hasRTPFlowCorrelation {
		// Must have typical port range
		if !inTypicalRange {
			return nil
		}
		// Must have valid static payload type (not dynamic)
		// Dynamic types (96-127) require SIP correlation
		if !isValidPayloadType {
			return nil
		}
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

	// Typical RTP port range (IANA recommended 16384-32768 or legacy 10000-20000)
	inTypicalRange := false
	if (ctx.SrcPort >= 16384 && ctx.SrcPort <= 32768) || (ctx.DstPort >= 16384 && ctx.DstPort <= 32768) {
		inTypicalRange = true
	}
	if (ctx.SrcPort >= 10000 && ctx.SrcPort <= 20000) || (ctx.DstPort >= 10000 && ctx.DstPort <= 20000) {
		inTypicalRange = true
	}

	if inTypicalRange {
		indicators = append(indicators, signatures.Indicator{
			Name:       "typical_port_range",
			Weight:     0.15,                        // Increased from 0.1
			Confidence: signatures.ConfidenceMedium, // Upgraded from Low
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

// RTPFlowState holds RTP flow state for SSRC and sequence validation
// Supports bidirectional flows with different SSRCs
type RTPFlowState struct {
	SSRCForward    uint32 // SSRC for forward direction
	SSRCReverse    uint32 // SSRC for reverse direction
	LastSeqForward uint16 // Last sequence number in forward direction
	LastSeqReverse uint16 // Last sequence number in reverse direction
	PacketCount    int
	FirstSrcPort   uint16 // Port of first packet to determine direction
}

// payloadTypeToCodec maps RTP payload type to codec name
func payloadTypeToCodec(pt uint8) string {
	codecs := map[uint8]string{
		0:   "G.711 µ-law (PCMU)",
		3:   "GSM",
		4:   "G.723",
		5:   "DVI4 8kHz",
		6:   "DVI4 16kHz",
		7:   "LPC",
		8:   "G.711 A-law (PCMA)",
		9:   "G.722",
		10:  "L16 Stereo",
		11:  "L16 Mono",
		12:  "QCELP",
		13:  "Comfort Noise",
		14:  "MPA",
		15:  "G.728",
		16:  "DVI4 11kHz",
		17:  "DVI4 22kHz",
		18:  "G.729",
		25:  "CelB",
		26:  "JPEG",
		28:  "nv",
		31:  "H.261",
		32:  "MPV",
		33:  "MP2T",
		34:  "H.263",
		96:  "Dynamic",
		97:  "Dynamic",
		98:  "Dynamic",
		99:  "Dynamic",
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

// isWellKnownTCPPort checks if a port is a well-known TCP port
// to avoid false RTP detection on encrypted TCP protocols
func isWellKnownTCPPort(port uint16) bool {
	wellKnownPorts := map[uint16]bool{
		80:    true, // HTTP
		443:   true, // HTTPS
		8080:  true, // HTTP alternate
		8443:  true, // HTTPS alternate
		22:    true, // SSH
		21:    true, // FTP
		25:    true, // SMTP
		110:   true, // POP3
		143:   true, // IMAP
		993:   true, // IMAPS
		995:   true, // POP3S
		3306:  true, // MySQL
		5432:  true, // PostgreSQL
		6379:  true, // Redis
		27017: true, // MongoDB
	}
	return wellKnownPorts[port]
}

// isWellKnownUDPPort checks if a port is a well-known UDP service port
// to avoid false RTP detection on DNS, NTP, DHCP, etc.
func isWellKnownUDPPort(port uint16) bool {
	wellKnownPorts := map[uint16]bool{
		53:  true, // DNS
		67:  true, // DHCP server
		68:  true, // DHCP client
		69:  true, // TFTP
		123: true, // NTP
		137: true, // NetBIOS Name Service
		138: true, // NetBIOS Datagram Service
		161: true, // SNMP
		162: true, // SNMP Trap
		500: true, // IKE (IPSec)
		514: true, // Syslog
	}
	return wellKnownPorts[port]
}

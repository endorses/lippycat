package vpn

import (
	"encoding/binary"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// L2TPSignature detects L2TP (Layer 2 Tunneling Protocol) traffic
type L2TPSignature struct{}

// NewL2TPSignature creates a new L2TP signature detector
func NewL2TPSignature() *L2TPSignature {
	return &L2TPSignature{}
}

func (l *L2TPSignature) Name() string {
	return "L2TP Detector"
}

func (l *L2TPSignature) Protocols() []string {
	return []string{"L2TP"}
}

func (l *L2TPSignature) Priority() int {
	return 100 // High priority for VPN protocol
}

func (l *L2TPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (l *L2TPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// L2TP packet structure (RFC 2661):
	// Flags and Version (2 bytes):
	//   T L x x S x O P x x x x Ver (bits)
	//   T=1: Control message, T=0: Data message
	//   L=1: Length field present
	//   S=1: Sequence numbers present
	//   O=1: Offset field present
	//   P=1: Priority
	//   Ver=2 for L2TPv2, Ver=3 for L2TPv3

	// L2TP uses UDP on port 1701
	if ctx.Transport != "UDP" {
		return nil
	}

	// STRICT: Only detect on well-known L2TP port to avoid false positives
	if ctx.SrcPort != 1701 && ctx.DstPort != 1701 {
		return nil
	}

	if len(ctx.Payload) < 6 {
		return nil
	}

	payload := ctx.Payload

	// Extract flags and version (first 2 bytes)
	flagsAndVer := binary.BigEndian.Uint16(payload[0:2])

	// Extract version (lower 4 bits)
	version := flagsAndVer & 0x000F

	// Valid L2TP versions: 2 or 3
	if version != 2 && version != 3 {
		return nil
	}

	// Extract flags
	typeFlag := (flagsAndVer & 0x8000) != 0     // T bit
	lengthFlag := (flagsAndVer & 0x4000) != 0   // L bit
	seqFlag := (flagsAndVer & 0x0800) != 0      // S bit
	offsetFlag := (flagsAndVer & 0x0200) != 0   // O bit
	priorityFlag := (flagsAndVer & 0x0100) != 0 // P bit

	metadata := map[string]interface{}{
		"version": version,
	}

	// Determine packet type
	if typeFlag {
		metadata["packet_type"] = "control"
	} else {
		metadata["packet_type"] = "data"
	}

	// Track which fields are present
	offset := 2
	minLength := 2

	// Length field (2 bytes) - if L bit is set
	if lengthFlag {
		if len(payload) < offset+2 {
			return nil
		}
		length := binary.BigEndian.Uint16(payload[offset : offset+2])
		metadata["length"] = length
		offset += 2
		minLength += 2

		// Validate length
		if int(length) > len(payload) || int(length) < minLength {
			return nil
		}
	}

	// Tunnel ID (2 bytes)
	if len(payload) < offset+2 {
		return nil
	}
	tunnelID := binary.BigEndian.Uint16(payload[offset : offset+2])
	metadata["tunnel_id"] = tunnelID
	offset += 2

	// Session ID (2 bytes)
	if len(payload) < offset+2 {
		return nil
	}
	sessionID := binary.BigEndian.Uint16(payload[offset : offset+2])
	metadata["session_id"] = sessionID
	offset += 2

	// For control messages, tunnel and session can be 0 during setup
	if typeFlag {
		if tunnelID == 0 && sessionID == 0 {
			metadata["setup_phase"] = true
		}
	}

	// Sequence numbers (4 bytes total: Ns and Nr) - if S bit is set
	if seqFlag {
		if len(payload) < offset+4 {
			return nil
		}
		ns := binary.BigEndian.Uint16(payload[offset : offset+2])
		nr := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
		metadata["sequence_ns"] = ns
		metadata["sequence_nr"] = nr
		offset += 4
	}

	// Offset size and padding (if O bit is set)
	if offsetFlag {
		if len(payload) < offset+2 {
			return nil
		}
		offsetSize := binary.BigEndian.Uint16(payload[offset : offset+2])
		metadata["offset_size"] = offsetSize
		offset += 2
	}

	// For control messages, check for AVPs (Attribute-Value Pairs)
	if typeFlag && len(payload) > offset+6 {
		// AVP structure: Flags (2) + Length (2) + Vendor ID (2) + Attribute (2) + Value
		avpFlags := binary.BigEndian.Uint16(payload[offset : offset+2])
		avpLength := binary.BigEndian.Uint16(payload[offset+2 : offset+4])

		// Mandatory bit should be set for critical AVPs
		mandatoryBit := (avpFlags & 0x8000) != 0
		if mandatoryBit {
			metadata["has_mandatory_avp"] = true
		}

		// Validate AVP length
		if avpLength >= 6 && avpLength <= uint16(len(payload)-offset) {
			metadata["has_valid_avp"] = true
		}
	}

	if priorityFlag {
		metadata["priority"] = true
	}

	// Calculate confidence
	confidence := l.calculateConfidence(ctx, metadata, typeFlag, version)

	// Port-based confidence adjustment
	// L2TP commonly uses 1701 (UDP)
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{1701})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{1701})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "L2TP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (l *L2TPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, isControl bool, version uint16) float64 {
	indicators := []signatures.Indicator{}

	// Valid version (2 or 3)
	if version == 2 || version == 3 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_version",
			Weight:     0.4,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Control message with valid AVP
	if isControl {
		if hasAVP, ok := metadata["has_valid_avp"].(bool); ok && hasAVP {
			indicators = append(indicators, signatures.Indicator{
				Name:       "control_with_avp",
				Weight:     0.3,
				Confidence: signatures.ConfidenceVeryHigh,
			})
		} else {
			indicators = append(indicators, signatures.Indicator{
				Name:       "control_message",
				Weight:     0.3,
				Confidence: signatures.ConfidenceHigh,
			})
		}
	} else {
		// Data message
		indicators = append(indicators, signatures.Indicator{
			Name:       "data_message",
			Weight:     0.3,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	// UDP transport (L2TP is typically UDP, but can be over IP for L2TPv3)
	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	return signatures.ScoreDetection(indicators)
}

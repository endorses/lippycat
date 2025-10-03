package vpn

import (
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// OpenVPNSignature detects OpenVPN protocol traffic
type OpenVPNSignature struct{}

// NewOpenVPNSignature creates a new OpenVPN signature detector
func NewOpenVPNSignature() *OpenVPNSignature {
	return &OpenVPNSignature{}
}

func (o *OpenVPNSignature) Name() string {
	return "OpenVPN Detector"
}

func (o *OpenVPNSignature) Protocols() []string {
	return []string{"OpenVPN"}
}

func (o *OpenVPNSignature) Priority() int {
	return 100 // High priority for VPN protocol
}

func (o *OpenVPNSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (o *OpenVPNSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// OpenVPN packet structure:
	// - P_CONTROL_HARD_RESET_CLIENT_V1: 0x38
	// - P_CONTROL_HARD_RESET_SERVER_V1: 0x40
	// - P_CONTROL_HARD_RESET_CLIENT_V2: 0x07
	// - P_CONTROL_HARD_RESET_SERVER_V2: 0x08
	// - P_CONTROL_SOFT_RESET_V1: 0x03
	// - P_CONTROL_V1: 0x20
	// - P_ACK_V1: 0x28
	// - P_DATA_V1: 0x30
	// - P_DATA_V2: 0x09

	// First byte contains opcode and key_id
	// Format: opcode (5 bits) | key_id (3 bits)

	if len(ctx.Payload) < 14 {
		return nil
	}

	payload := ctx.Payload

	// Exclude TLS traffic (content types 0x14-0x18)
	// TLS starts with content type byte, which would create false positives
	firstByte := payload[0]
	if firstByte >= 0x14 && firstByte <= 0x18 {
		// This is likely TLS (ChangeCipherSpec=20, Alert=21, Handshake=22, Application=23, Heartbeat=24)
		return nil
	}

	// Extract opcode from first byte (upper 5 bits)
	opcode := firstByte >> 3

	// Valid OpenVPN opcodes: 1-9
	// 1 (0x08) = P_CONTROL_HARD_RESET_CLIENT_V2
	// 2 (0x10) = P_CONTROL_HARD_RESET_SERVER_V2
	// 3 (0x18) = P_CONTROL_SOFT_RESET_V1
	// 4 (0x20) = P_CONTROL_V1
	// 5 (0x28) = P_ACK_V1
	// 6 (0x30) = P_DATA_V1
	// 7 (0x38) = P_CONTROL_HARD_RESET_CLIENT_V1
	// 8 (0x40) = P_CONTROL_HARD_RESET_SERVER_V1
	// 9 (0x48) = P_DATA_V2

	if !o.isValidOpcode(opcode) {
		return nil
	}

	keyID := firstByte & 0x07

	// STRICT VALIDATION: OpenVPN detection is very prone to false positives
	// Only detect if we're on the well-known OpenVPN port OR have very strong indicators
	onOpenVPNPort := ctx.SrcPort == 1194 || ctx.DstPort == 1194

	// If not on standard port, require VERY strict validation
	if !onOpenVPNPort {
		// Must be a control packet (more distinctive than data)
		if !o.isControlPacket(opcode) {
			return nil
		}

		// For control packets, validate session ID structure
		// Session ID is at bytes 1-8
		sessionID := payload[1:9]

		// Check if it looks like a valid session ID (all zeros OR has some structure)
		// Random data would be very unlikely to have all zeros
		allZero := true
		for _, b := range sessionID {
			if b != 0 {
				allZero = false
				break
			}
		}

		// Require either:
		// 1. Hard reset with zero session ID (initial handshake)
		// 2. Port in typical VPN range (1024-65535) to avoid system ports
		isHardReset := opcode == 1 || opcode == 2 || opcode == 7 || opcode == 8
		if !isHardReset || !allZero {
			// Additional check: packet ID at bytes 9-12 should be reasonable
			if len(payload) >= 13 {
				// Packet ID should be small for initial packets
				packetID := uint32(payload[9])<<24 | uint32(payload[10])<<16 |
				           uint32(payload[11])<<8 | uint32(payload[12])
				// Reject if packet ID is too large (likely random data)
				if packetID > 1000000 {
					return nil
				}
			}
		}
	}

	metadata := map[string]interface{}{
		"opcode":      opcode,
		"opcode_name": o.opcodeToString(opcode),
		"key_id":      keyID,
	}

	// For control packets, check session ID (8 bytes starting at offset 1)
	if o.isControlPacket(opcode) {
		// Session ID should be present
		// For hard reset from client, session ID is typically all zeros initially
		sessionID := payload[1:9]
		allZero := true
		for _, b := range sessionID {
			if b != 0 {
				allZero = false
				break
			}
		}

		if opcode == 1 || opcode == 7 {
			// Hard reset from client
			metadata["packet_type"] = "control"
			metadata["control_type"] = "hard_reset_client"
			if allZero {
				metadata["initial_handshake"] = true
			}
		} else if opcode == 2 || opcode == 8 {
			// Hard reset from server
			metadata["packet_type"] = "control"
			metadata["control_type"] = "hard_reset_server"
		} else if opcode == 3 {
			// Soft reset
			metadata["packet_type"] = "control"
			metadata["control_type"] = "soft_reset"
		} else if opcode == 4 {
			// Control packet
			metadata["packet_type"] = "control"
		} else if opcode == 5 {
			// ACK
			metadata["packet_type"] = "ack"
		}
	} else {
		// Data packet
		metadata["packet_type"] = "data"
	}

	// Calculate confidence
	confidence := o.calculateConfidence(ctx, metadata, opcode)

	// Port-based confidence adjustment
	// OpenVPN commonly uses 1194 (UDP/TCP), but can use any port
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{1194})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{1194})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "OpenVPN",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (o *OpenVPNSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, opcode byte) float64 {
	indicators := []signatures.Indicator{}

	// Valid opcode
	if o.isValidOpcode(opcode) {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_opcode",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Hard reset packets are very distinctive
	if opcode == 1 || opcode == 2 || opcode == 7 || opcode == 8 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "hard_reset_packet",
			Weight:     0.2,
			Confidence: signatures.ConfidenceVeryHigh,
		})
	}

	// UDP or TCP transport (OpenVPN supports both)
	if ctx.Transport == "UDP" || ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (o *OpenVPNSignature) isValidOpcode(opcode byte) bool {
	// Valid opcodes are 1-9
	return opcode >= 1 && opcode <= 9
}

func (o *OpenVPNSignature) isControlPacket(opcode byte) bool {
	// Control packets: 1-5, 7-8
	return opcode >= 1 && opcode <= 5 || opcode == 7 || opcode == 8
}

func (o *OpenVPNSignature) opcodeToString(opcode byte) string {
	opcodes := map[byte]string{
		1: "P_CONTROL_HARD_RESET_CLIENT_V2",
		2: "P_CONTROL_HARD_RESET_SERVER_V2",
		3: "P_CONTROL_SOFT_RESET_V1",
		4: "P_CONTROL_V1",
		5: "P_ACK_V1",
		6: "P_DATA_V1",
		7: "P_CONTROL_HARD_RESET_CLIENT_V1",
		8: "P_CONTROL_HARD_RESET_SERVER_V1",
		9: "P_DATA_V2",
	}
	if name, ok := opcodes[opcode]; ok {
		return name
	}
	return "Unknown"
}

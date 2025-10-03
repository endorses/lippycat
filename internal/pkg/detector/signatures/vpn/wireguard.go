package vpn

import (
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// WireGuardSignature detects WireGuard VPN protocol traffic
type WireGuardSignature struct{}

// NewWireGuardSignature creates a new WireGuard signature detector
func NewWireGuardSignature() *WireGuardSignature {
	return &WireGuardSignature{}
}

func (w *WireGuardSignature) Name() string {
	return "WireGuard Detector"
}

func (w *WireGuardSignature) Protocols() []string {
	return []string{"WireGuard"}
}

func (w *WireGuardSignature) Priority() int {
	return 100 // High priority for VPN protocol
}

func (w *WireGuardSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (w *WireGuardSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// WireGuard packet types:
	// Type 1: Handshake Initiation (148 bytes)
	// Type 2: Handshake Response (92 bytes)
	// Type 3: Cookie Reply (64 bytes)
	// Type 4: Transport Data (variable, minimum 32 bytes)

	// All WireGuard packets start with:
	// - Message type (1 byte): 1, 2, 3, or 4
	// - Reserved (3 bytes): typically zero
	// Followed by type-specific data

	if len(ctx.Payload) < 4 {
		return nil
	}

	payload := ctx.Payload

	// Extract message type
	msgType := payload[0]

	// Valid WireGuard message types: 1, 2, 3, 4
	if msgType < 1 || msgType > 4 {
		return nil
	}

	// Reserved bytes should typically be zero (bytes 1-3)
	// We check them but don't strictly require zero for robustness
	reserved := payload[1:4]

	metadata := map[string]interface{}{
		"message_type": msgType,
		"type_name":    w.messageTypeToString(msgType),
	}

	// Validate packet length based on message type
	expectedLen := 0
	switch msgType {
	case 1:
		// Handshake Initiation: 148 bytes
		expectedLen = 148
		metadata["packet_type"] = "handshake_initiation"
		if len(payload) >= 8 {
			// Sender index at offset 4 (4 bytes)
			// This is used to identify the initiator
			metadata["has_sender_index"] = true
		}
	case 2:
		// Handshake Response: 92 bytes
		expectedLen = 92
		metadata["packet_type"] = "handshake_response"
		if len(payload) >= 12 {
			// Sender and receiver indices
			metadata["has_indices"] = true
		}
	case 3:
		// Cookie Reply: 64 bytes
		expectedLen = 64
		metadata["packet_type"] = "cookie_reply"
	case 4:
		// Transport Data: variable length (minimum 32 bytes)
		// Format: type (1) + reserved (3) + receiver (4) + counter (8) + encrypted_data (>=16)
		expectedLen = 32
		metadata["packet_type"] = "transport_data"
		if len(payload) >= 16 {
			// Receiver index at offset 4 (4 bytes)
			metadata["has_receiver_index"] = true
			metadata["data_length"] = len(payload) - 16
		}
	}

	// Validate packet length
	if len(payload) < expectedLen {
		return nil
	}

	// For handshake packets (types 1 and 2), the length should be exact
	// For transport data (type 4), length should be >= 32
	// For cookie reply (type 3), the length should be exact
	if msgType != 4 && len(payload) != expectedLen {
		// Allow some tolerance for fragmentation or padding
		if len(payload) < expectedLen || len(payload) > expectedLen+16 {
			return nil
		}
	}

	// Check reserved bytes - if all three are zero, it's a stronger indicator
	allZero := reserved[0] == 0 && reserved[1] == 0 && reserved[2] == 0
	if allZero {
		metadata["reserved_zero"] = true
	}

	// Calculate confidence
	confidence := w.calculateConfidence(ctx, metadata, msgType, allZero, len(payload))

	// Port-based confidence adjustment
	// WireGuard commonly uses 51820 (UDP), but can use any port
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{51820})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{51820})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "WireGuard",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (w *WireGuardSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, msgType byte, reservedZero bool, payloadLen int) float64 {
	indicators := []signatures.Indicator{}

	// Valid message type
	if msgType >= 1 && msgType <= 4 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_message_type",
			Weight:     0.4,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Reserved bytes are zero (stronger indicator)
	if reservedZero {
		indicators = append(indicators, signatures.Indicator{
			Name:       "reserved_zero",
			Weight:     0.2,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Exact length match for handshake packets
	expectedLen := 0
	switch msgType {
	case 1:
		expectedLen = 148
	case 2:
		expectedLen = 92
	case 3:
		expectedLen = 64
	case 4:
		// Transport data is variable, so we check minimum
		if payloadLen >= 32 {
			indicators = append(indicators, signatures.Indicator{
				Name:       "valid_transport_length",
				Weight:     0.2,
				Confidence: signatures.ConfidenceMedium,
			})
		}
	}

	if expectedLen > 0 && payloadLen == expectedLen {
		indicators = append(indicators, signatures.Indicator{
			Name:       "exact_length_match",
			Weight:     0.2,
			Confidence: signatures.ConfidenceVeryHigh,
		})
	}

	// UDP transport (WireGuard is always UDP)
	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (w *WireGuardSignature) messageTypeToString(msgType byte) string {
	types := map[byte]string{
		1: "Handshake Initiation",
		2: "Handshake Response",
		3: "Cookie Reply",
		4: "Transport Data",
	}
	if name, ok := types[msgType]; ok {
		return name
	}
	return "Unknown"
}

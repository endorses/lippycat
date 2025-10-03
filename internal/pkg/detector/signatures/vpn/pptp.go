package vpn

import (
	"encoding/binary"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// PPTPSignature detects PPTP (Point-to-Point Tunneling Protocol) traffic
type PPTPSignature struct{}

// NewPPTPSignature creates a new PPTP signature detector
func NewPPTPSignature() *PPTPSignature {
	return &PPTPSignature{}
}

func (p *PPTPSignature) Name() string {
	return "PPTP Detector"
}

func (p *PPTPSignature) Protocols() []string {
	return []string{"PPTP"}
}

func (p *PPTPSignature) Priority() int {
	return 100 // High priority for VPN protocol
}

func (p *PPTPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (p *PPTPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// PPTP Control Connection (RFC 2637):
	// Uses TCP port 1723
	// Message structure:
	//   Length (2 bytes) - total length including header
	//   PPTP Message Type (2 bytes) - 1 for control message
	//   Magic Cookie (4 bytes) - 0x1A2B3C4D
	//   Control Message Type (2 bytes)
	//   Reserved (2 bytes)
	//   ... message-specific fields

	// PPTP control uses TCP only
	if ctx.Transport != "TCP" {
		return nil
	}

	// STRICT: Only detect on well-known PPTP port
	if ctx.SrcPort != 1723 && ctx.DstPort != 1723 {
		return nil
	}

	if len(ctx.Payload) < 12 {
		return nil
	}

	payload := ctx.Payload

	// Extract length (first 2 bytes)
	length := binary.BigEndian.Uint16(payload[0:2])

	// Length should be reasonable (at least 12 bytes for header, max ~1500 for typical packet)
	if length < 12 || length > 2000 {
		return nil
	}

	// Validate length matches payload (with some tolerance)
	if int(length) > len(payload)+100 || int(length) < len(payload)-100 {
		// Allow some tolerance for TCP segmentation
		// If first packet, length might be larger than current segment
		if len(payload) < 12 {
			return nil
		}
	}

	// Extract PPTP Message Type (2 bytes at offset 2)
	pptpMsgType := binary.BigEndian.Uint16(payload[2:4])

	// PPTP Message Type should be 1 for control message
	if pptpMsgType != 1 {
		return nil
	}

	// Extract Magic Cookie (4 bytes at offset 4)
	magicCookie := binary.BigEndian.Uint32(payload[4:8])

	// Magic Cookie should be 0x1A2B3C4D
	if magicCookie != 0x1A2B3C4D {
		return nil
	}

	// Extract Control Message Type (2 bytes at offset 8)
	controlMsgType := binary.BigEndian.Uint16(payload[8:10])

	// Valid control message types: 1-15
	if controlMsgType < 1 || controlMsgType > 15 {
		return nil
	}

	// Extract Reserved field (2 bytes at offset 10)
	reserved := binary.BigEndian.Uint16(payload[10:12])

	metadata := map[string]interface{}{
		"length":              length,
		"pptp_message_type":   pptpMsgType,
		"magic_cookie":        "0x1A2B3C4D",
		"control_type":        controlMsgType,
		"control_type_name":   p.controlTypeToString(controlMsgType),
		"packet_type":         "control",
	}

	// Reserved field should typically be 0
	if reserved == 0 {
		metadata["reserved_zero"] = true
	}

	// Categorize message type
	switch controlMsgType {
	case 1:
		metadata["category"] = "start_control_connection"
	case 2:
		metadata["category"] = "start_control_connection_reply"
	case 3:
		metadata["category"] = "stop_control_connection"
	case 4:
		metadata["category"] = "stop_control_connection_reply"
	case 5:
		metadata["category"] = "echo_request"
	case 6:
		metadata["category"] = "echo_reply"
	case 7:
		metadata["category"] = "outgoing_call_request"
	case 8:
		metadata["category"] = "outgoing_call_reply"
	case 9:
		metadata["category"] = "incoming_call_request"
	case 10:
		metadata["category"] = "incoming_call_reply"
	case 11:
		metadata["category"] = "incoming_call_connected"
	case 12:
		metadata["category"] = "call_clear_request"
	case 13:
		metadata["category"] = "call_disconnect_notify"
	case 14:
		metadata["category"] = "wan_error_notify"
	case 15:
		metadata["category"] = "set_link_info"
	}

	// For Start-Control-Connection messages, extract version info if available
	if (controlMsgType == 1 || controlMsgType == 2) && len(payload) >= 16 {
		// Protocol version at offset 12 (2 bytes)
		version := binary.BigEndian.Uint16(payload[12:14])
		major := version >> 8
		minor := version & 0xFF
		metadata["protocol_version"] = float64(major) + float64(minor)/100.0
	}

	// Calculate confidence
	confidence := p.calculateConfidence(ctx, metadata, reserved == 0)

	// Port-based confidence adjustment
	// PPTP control uses TCP port 1723
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{1723})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{1723})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "PPTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (p *PPTPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, reservedZero bool) float64 {
	indicators := []signatures.Indicator{}

	// Magic cookie match (very distinctive)
	indicators = append(indicators, signatures.Indicator{
		Name:       "magic_cookie_match",
		Weight:     0.5,
		Confidence: signatures.ConfidenceVeryHigh,
	})

	// Valid control message type
	if controlType, ok := metadata["control_type"].(uint16); ok && controlType >= 1 && controlType <= 15 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_control_type",
			Weight:     0.2,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Reserved field is zero
	if reservedZero {
		indicators = append(indicators, signatures.Indicator{
			Name:       "reserved_zero",
			Weight:     0.1,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	// TCP transport (PPTP control is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (p *PPTPSignature) controlTypeToString(controlType uint16) string {
	types := map[uint16]string{
		1:  "Start-Control-Connection-Request",
		2:  "Start-Control-Connection-Reply",
		3:  "Stop-Control-Connection-Request",
		4:  "Stop-Control-Connection-Reply",
		5:  "Echo-Request",
		6:  "Echo-Reply",
		7:  "Outgoing-Call-Request",
		8:  "Outgoing-Call-Reply",
		9:  "Incoming-Call-Request",
		10: "Incoming-Call-Reply",
		11: "Incoming-Call-Connected",
		12: "Call-Clear-Request",
		13: "Call-Disconnect-Notify",
		14: "WAN-Error-Notify",
		15: "Set-Link-Info",
	}
	if name, ok := types[controlType]; ok {
		return name
	}
	return "Unknown"
}

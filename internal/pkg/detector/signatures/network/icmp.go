package network

import (
	"encoding/binary"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// ICMPSignature detects ICMP (Internet Control Message Protocol) traffic
type ICMPSignature struct{}

// NewICMPSignature creates a new ICMP signature detector
func NewICMPSignature() *ICMPSignature {
	return &ICMPSignature{}
}

func (i *ICMPSignature) Name() string {
	return "ICMP Detector"
}

func (i *ICMPSignature) Protocols() []string {
	return []string{"ICMP"}
}

func (i *ICMPSignature) Priority() int {
	return 90 // High priority for network-layer protocol
}

func (i *ICMPSignature) Layer() signatures.LayerType {
	return signatures.LayerNetwork
}

func (i *ICMPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// ICMP requires minimum 8 bytes (type + code + checksum + rest of header)
	if len(ctx.Payload) < 8 {
		return nil
	}

	payload := ctx.Payload

	// ICMP header structure:
	// Type (1 byte) + Code (1 byte) + Checksum (2 bytes) + Rest of Header (4 bytes)

	icmpType := payload[0]
	icmpCode := payload[1]
	checksum := binary.BigEndian.Uint16(payload[2:4])

	// Validate ICMP type (0-255, but only certain values are defined)
	if !i.isValidType(icmpType) {
		return nil
	}

	// Validate code for the given type
	if !i.isValidCode(icmpType, icmpCode) {
		return nil
	}

	metadata := map[string]interface{}{
		"type":        icmpType,
		"code":        icmpCode,
		"type_name":   i.typeToString(icmpType),
		"code_name":   i.codeToString(icmpType, icmpCode),
		"checksum":    checksum,
	}

	// Extract additional fields based on ICMP type
	switch icmpType {
	case 0, 8: // Echo Reply / Echo Request
		if len(payload) >= 8 {
			identifier := binary.BigEndian.Uint16(payload[4:6])
			sequence := binary.BigEndian.Uint16(payload[6:8])
			metadata["identifier"] = identifier
			metadata["sequence"] = sequence
		}

	case 3: // Destination Unreachable
		// Rest of header contains original datagram information
		metadata["mtu"] = binary.BigEndian.Uint16(payload[6:8])

	case 5: // Redirect
		// Gateway address in rest of header
		if len(payload) >= 8 {
			gateway := payload[4:8]
			metadata["gateway"] = i.ipToString(gateway)
		}

	case 11: // Time Exceeded
		// Code 0 = TTL expired, Code 1 = Fragment reassembly time exceeded
		// Rest of header is unused (should be 0)
	}

	// Calculate confidence
	confidence := i.calculateConfidence(ctx, metadata, icmpType, icmpCode)

	return &signatures.DetectionResult{
		Protocol:    "ICMP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (i *ICMPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, icmpType, icmpCode byte) float64 {
	indicators := []signatures.Indicator{}

	// Valid ICMP type
	if i.isValidType(icmpType) {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_type",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Valid code for type
	if i.isValidCode(icmpType, icmpCode) {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_code",
			Weight:     0.4,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (i *ICMPSignature) isValidType(icmpType byte) bool {
	// Common ICMP types
	validTypes := map[byte]bool{
		0:  true, // Echo Reply
		3:  true, // Destination Unreachable
		4:  true, // Source Quench (deprecated)
		5:  true, // Redirect
		8:  true, // Echo Request
		9:  true, // Router Advertisement
		10: true, // Router Solicitation
		11: true, // Time Exceeded
		12: true, // Parameter Problem
		13: true, // Timestamp Request
		14: true, // Timestamp Reply
		15: true, // Information Request (deprecated)
		16: true, // Information Reply (deprecated)
		17: true, // Address Mask Request (deprecated)
		18: true, // Address Mask Reply (deprecated)
		30: true, // Traceroute (deprecated)
		40: true, // Photuris
		42: true, // Extended Echo Request
		43: true, // Extended Echo Reply
	}
	return validTypes[icmpType]
}

func (i *ICMPSignature) isValidCode(icmpType, code byte) bool {
	// Validate code based on type
	switch icmpType {
	case 0, 8: // Echo Reply/Request
		return code == 0
	case 3: // Destination Unreachable
		return code <= 15 // Codes 0-15 are defined
	case 5: // Redirect
		return code <= 3 // Codes 0-3 are defined
	case 11: // Time Exceeded
		return code <= 1 // Codes 0-1 are defined
	case 12: // Parameter Problem
		return code <= 2 // Codes 0-2 are defined
	default:
		return code == 0 // Most other types use code 0
	}
}

func (i *ICMPSignature) typeToString(icmpType byte) string {
	types := map[byte]string{
		0:  "Echo Reply",
		3:  "Destination Unreachable",
		4:  "Source Quench",
		5:  "Redirect",
		8:  "Echo Request",
		9:  "Router Advertisement",
		10: "Router Solicitation",
		11: "Time Exceeded",
		12: "Parameter Problem",
		13: "Timestamp Request",
		14: "Timestamp Reply",
		15: "Information Request",
		16: "Information Reply",
		17: "Address Mask Request",
		18: "Address Mask Reply",
		30: "Traceroute",
		40: "Photuris",
		42: "Extended Echo Request",
		43: "Extended Echo Reply",
	}
	if s, ok := types[icmpType]; ok {
		return s
	}
	return "Unknown"
}

func (i *ICMPSignature) codeToString(icmpType, code byte) string {
	switch icmpType {
	case 3: // Destination Unreachable
		codes := map[byte]string{
			0:  "Network Unreachable",
			1:  "Host Unreachable",
			2:  "Protocol Unreachable",
			3:  "Port Unreachable",
			4:  "Fragmentation Needed",
			5:  "Source Route Failed",
			6:  "Destination Network Unknown",
			7:  "Destination Host Unknown",
			8:  "Source Host Isolated",
			9:  "Network Administratively Prohibited",
			10: "Host Administratively Prohibited",
			11: "Network Unreachable for ToS",
			12: "Host Unreachable for ToS",
			13: "Communication Administratively Prohibited",
			14: "Host Precedence Violation",
			15: "Precedence Cutoff in Effect",
		}
		if s, ok := codes[code]; ok {
			return s
		}
	case 5: // Redirect
		codes := map[byte]string{
			0: "Redirect for Network",
			1: "Redirect for Host",
			2: "Redirect for ToS and Network",
			3: "Redirect for ToS and Host",
		}
		if s, ok := codes[code]; ok {
			return s
		}
	case 11: // Time Exceeded
		codes := map[byte]string{
			0: "TTL Expired in Transit",
			1: "Fragment Reassembly Time Exceeded",
		}
		if s, ok := codes[code]; ok {
			return s
		}
	case 12: // Parameter Problem
		codes := map[byte]string{
			0: "Pointer Indicates Error",
			1: "Missing Required Option",
			2: "Bad Length",
		}
		if s, ok := codes[code]; ok {
			return s
		}
	}
	return ""
}

func (i *ICMPSignature) ipToString(ip []byte) string {
	if len(ip) != 4 {
		return "0.0.0.0"
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

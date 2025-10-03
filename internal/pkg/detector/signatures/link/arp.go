package link

import (
	"encoding/binary"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// ARPSignature detects ARP (Address Resolution Protocol) traffic
type ARPSignature struct{}

// NewARPSignature creates a new ARP signature detector
func NewARPSignature() *ARPSignature {
	return &ARPSignature{}
}

func (a *ARPSignature) Name() string {
	return "ARP Detector"
}

func (a *ARPSignature) Protocols() []string {
	return []string{"ARP"}
}

func (a *ARPSignature) Priority() int {
	return 95 // High priority for link-layer protocol
}

func (a *ARPSignature) Layer() signatures.LayerType {
	return signatures.LayerLink
}

func (a *ARPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// ARP packet is 28 bytes for IPv4 over Ethernet
	// Minimum: 8 bytes header + variable addresses
	if len(ctx.Payload) < 28 {
		return nil
	}

	payload := ctx.Payload

	// ARP header structure:
	// Hardware Type (2) + Protocol Type (2) + Hardware Len (1) + Protocol Len (1) + Operation (2)
	// Sender Hardware Address (6) + Sender Protocol Address (4)
	// Target Hardware Address (6) + Target Protocol Address (4)

	// Extract hardware type
	htype := binary.BigEndian.Uint16(payload[0:2])

	// Check for Ethernet (1 is most common, but others exist)
	if htype == 0 || htype > 256 {
		return nil // Invalid hardware type
	}

	// Extract protocol type
	ptype := binary.BigEndian.Uint16(payload[2:4])

	// Check for IPv4 (0x0800)
	if ptype != 0x0800 {
		// Could be IPv6 (0x86DD) or other, but we'll focus on IPv4 for now
		return nil
	}

	// Extract hardware address length
	hlen := payload[4]

	// For Ethernet, should be 6
	if hlen != 6 {
		return nil
	}

	// Extract protocol address length
	plen := payload[5]

	// For IPv4, should be 4
	if plen != 4 {
		return nil
	}

	// Extract operation
	operation := binary.BigEndian.Uint16(payload[6:8])

	// Valid operations: 1 = Request, 2 = Reply, 3 = RARP Request, 4 = RARP Reply
	// 8 = InARP Request, 9 = InARP Reply
	if operation == 0 || operation > 9 {
		return nil
	}

	// Extract addresses (for Ethernet + IPv4)
	senderMAC := payload[8:14]
	senderIP := payload[14:18]
	targetMAC := payload[18:24]
	targetIP := payload[24:28]

	metadata := map[string]interface{}{
		"operation":        a.operationToString(operation),
		"hardware_type":    htype,
		"protocol_type":    ptype,
		"sender_mac":       a.macToString(senderMAC),
		"sender_ip":        a.ipToString(senderIP),
		"target_mac":       a.macToString(targetMAC),
		"target_ip":        a.ipToString(targetIP),
	}

	// Detect gratuitous ARP (sender IP == target IP)
	if a.ipEqual(senderIP, targetIP) {
		metadata["gratuitous"] = true
	}

	// Detect ARP probe (sender IP == 0.0.0.0)
	if senderIP[0] == 0 && senderIP[1] == 0 && senderIP[2] == 0 && senderIP[3] == 0 {
		metadata["probe"] = true
	}

	// Calculate confidence
	confidence := a.calculateConfidence(ctx, metadata, operation)

	return &signatures.DetectionResult{
		Protocol:    "ARP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (a *ARPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, operation uint16) float64 {
	indicators := []signatures.Indicator{}

	// Valid hardware type (Ethernet)
	indicators = append(indicators, signatures.Indicator{
		Name:       "valid_hardware_type",
		Weight:     0.3,
		Confidence: signatures.ConfidenceHigh,
	})

	// Valid protocol type (IPv4)
	indicators = append(indicators, signatures.Indicator{
		Name:       "valid_protocol_type",
		Weight:     0.3,
		Confidence: signatures.ConfidenceHigh,
	})

	// Valid operation
	if operation >= 1 && operation <= 9 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_operation",
			Weight:     0.4,
			Confidence: signatures.ConfidenceVeryHigh,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (a *ARPSignature) operationToString(operation uint16) string {
	operations := map[uint16]string{
		1: "Request",
		2: "Reply",
		3: "RARP Request",
		4: "RARP Reply",
		5: "DRARP Request",
		6: "DRARP Reply",
		7: "DRARP Error",
		8: "InARP Request",
		9: "InARP Reply",
	}
	if s, ok := operations[operation]; ok {
		return s
	}
	return "Unknown"
}

func (a *ARPSignature) macToString(mac []byte) string {
	if len(mac) != 6 {
		return "00:00:00:00:00:00"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func (a *ARPSignature) ipToString(ip []byte) string {
	if len(ip) != 4 {
		return "0.0.0.0"
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func (a *ARPSignature) ipEqual(ip1, ip2 []byte) bool {
	if len(ip1) != 4 || len(ip2) != 4 {
		return false
	}
	return ip1[0] == ip2[0] && ip1[1] == ip2[1] && ip1[2] == ip2[2] && ip1[3] == ip2[3]
}

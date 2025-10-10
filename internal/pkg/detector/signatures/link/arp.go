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
	// ARP minimum: 8 bytes header + addresses (variable based on hlen/plen)
	if len(ctx.Payload) < 8 {
		return nil
	}

	payload := ctx.Payload

	// ARP header structure:
	// Hardware Type (2) + Protocol Type (2) + Hardware Len (1) + Protocol Len (1) + Operation (2)
	// Sender Hardware Address (hlen) + Sender Protocol Address (plen)
	// Target Hardware Address (hlen) + Target Protocol Address (plen)

	// Extract hardware type
	htype := binary.BigEndian.Uint16(payload[0:2])

	// Valid hardware types: 1=Ethernet, 15=Frame Relay, etc.
	// See: https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
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

	// Hardware address length varies: Ethernet=6, Frame Relay=2-4, etc.
	if hlen == 0 || hlen > 20 {
		return nil // Invalid or too large
	}

	// Extract protocol address length
	plen := payload[5]

	// For IPv4, should be 4
	if plen != 4 {
		return nil
	}

	// Verify we have enough data for the full packet
	minLength := 8 + int(hlen)*2 + int(plen)*2
	if len(payload) < minLength {
		return nil
	}

	// Extract operation
	operation := binary.BigEndian.Uint16(payload[6:8])

	// Valid operations: 1 = Request, 2 = Reply, 3 = RARP Request, 4 = RARP Reply
	// 8 = InARP Request, 9 = InARP Reply
	if operation == 0 || operation > 9 {
		return nil
	}

	// Extract addresses (variable length based on hlen/plen)
	addrStart := 8
	senderHW := payload[addrStart : addrStart+int(hlen)]
	senderIP := payload[addrStart+int(hlen) : addrStart+int(hlen)+int(plen)]
	targetHW := payload[addrStart+int(hlen)+int(plen) : addrStart+int(hlen)*2+int(plen)]
	targetIP := payload[addrStart+int(hlen)*2+int(plen) : addrStart+int(hlen)*2+int(plen)*2]

	metadata := map[string]interface{}{
		"operation":          a.operationToString(operation),
		"hardware_type":      htype,
		"hardware_type_name": a.hardwareTypeToString(htype),
		"protocol_type":      ptype,
		"hardware_length":    hlen,
		"protocol_length":    plen,
		"sender_hw":          a.hwAddrToString(senderHW, htype),
		"sender_ip":          a.ipToString(senderIP),
		"target_hw":          a.hwAddrToString(targetHW, htype),
		"target_ip":          a.ipToString(targetIP),
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
	confidence := a.calculateConfidence(ctx, metadata, operation, htype)

	return &signatures.DetectionResult{
		Protocol:    "ARP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (a *ARPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, operation uint16, htype uint16) float64 {
	indicators := []signatures.Indicator{}

	// Valid hardware type
	hwConfidence := signatures.ConfidenceHigh
	if htype == 1 { // Ethernet is most common
		hwConfidence = signatures.ConfidenceVeryHigh
	}
	indicators = append(indicators, signatures.Indicator{
		Name:       "valid_hardware_type",
		Weight:     0.3,
		Confidence: hwConfidence,
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

func (a *ARPSignature) hardwareTypeToString(htype uint16) string {
	types := map[uint16]string{
		1:  "Ethernet",
		6:  "IEEE 802",
		7:  "ARCNET",
		15: "Frame Relay",
		16: "ATM",
		17: "HDLC",
		18: "Fibre Channel",
		19: "ATM (RFC2225)",
		20: "Serial Line",
	}
	if s, ok := types[htype]; ok {
		return s
	}
	return fmt.Sprintf("Type %d", htype)
}

func (a *ARPSignature) hwAddrToString(hw []byte, htype uint16) string {
	if len(hw) == 0 {
		return "00:00:00:00:00:00"
	}

	// For Ethernet (most common), format as MAC address
	if htype == 1 && len(hw) == 6 {
		return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			hw[0], hw[1], hw[2], hw[3], hw[4], hw[5])
	}

	// For other types, show as hex bytes separated by colons
	hexParts := make([]string, len(hw))
	for i, b := range hw {
		hexParts[i] = fmt.Sprintf("%02x", b)
	}
	return fmt.Sprintf("%s", hexParts)
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

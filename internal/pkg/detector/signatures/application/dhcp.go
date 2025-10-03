package application

import (
	"encoding/binary"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// DHCPSignature detects DHCP (Dynamic Host Configuration Protocol) traffic
type DHCPSignature struct{}

// NewDHCPSignature creates a new DHCP signature detector
func NewDHCPSignature() *DHCPSignature {
	return &DHCPSignature{}
}

func (d *DHCPSignature) Name() string {
	return "DHCP Detector"
}

func (d *DHCPSignature) Protocols() []string {
	return []string{"DHCP"}
}

func (d *DHCPSignature) Priority() int {
	return 110 // High priority for infrastructure protocol
}

func (d *DHCPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (d *DHCPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// DHCP requires minimum 240 bytes (236 + 4 magic cookie)
	if len(ctx.Payload) < 240 {
		return nil
	}

	payload := ctx.Payload

	// DHCP packet structure:
	// op(1) + htype(1) + hlen(1) + hops(1) + xid(4) + secs(2) + flags(2) +
	// ciaddr(4) + yiaddr(4) + siaddr(4) + giaddr(4) + chaddr(16) +
	// sname(64) + file(128) + magic(4) = 236 bytes minimum

	// Check op field (1 = BOOTREQUEST, 2 = BOOTREPLY)
	op := payload[0]
	if op != 1 && op != 2 {
		return nil
	}

	// Check htype (hardware type, 1 = Ethernet is most common)
	htype := payload[1]
	if htype == 0 || htype > 32 {
		// Valid hardware types are 1-32
		return nil
	}

	// Check hlen (hardware address length, 6 for Ethernet MAC)
	hlen := payload[2]
	if hlen == 0 || hlen > 16 {
		// MAC address length should be reasonable
		return nil
	}

	// Check hops (should be 0-16 in normal scenarios)
	hops := payload[3]
	if hops > 16 {
		return nil
	}

	// Extract transaction ID (XID)
	xid := binary.BigEndian.Uint32(payload[4:8])

	// Check for DHCP magic cookie at offset 236: 0x63825363
	magicCookie := binary.BigEndian.Uint32(payload[236:240])
	if magicCookie != 0x63825363 {
		// This is BOOTP without DHCP options
		return d.detectBOOTP(ctx, op, xid)
	}

	// Extract IP addresses
	ciaddr := payload[12:16] // Client IP
	yiaddr := payload[16:20] // Your (client) IP
	siaddr := payload[20:24] // Server IP
	giaddr := payload[24:28] // Gateway IP

	metadata := map[string]interface{}{
		"type":           d.opToString(op),
		"transaction_id": xid,
		"htype":          htype,
		"hlen":           hlen,
		"hops":           hops,
		"client_ip":      d.ipToString(ciaddr),
		"your_ip":        d.ipToString(yiaddr),
		"server_ip":      d.ipToString(siaddr),
		"gateway_ip":     d.ipToString(giaddr),
	}

	// Parse DHCP options (starting at offset 240)
	if len(payload) > 240 {
		messageType, options := d.parseOptions(payload[240:])
		if messageType != 0 {
			metadata["message_type"] = d.messageTypeToString(messageType)
		}
		if len(options) > 0 {
			metadata["options"] = options
		}
	}

	// Calculate confidence
	confidence := d.calculateConfidence(ctx, metadata)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{67, 68})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{67, 68})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "DHCP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (d *DHCPSignature) detectBOOTP(ctx *signatures.DetectionContext, op byte, xid uint32) *signatures.DetectionResult {
	metadata := map[string]interface{}{
		"type":           d.opToString(op),
		"transaction_id": xid,
		"protocol":       "BOOTP",
	}

	// BOOTP has lower confidence than DHCP
	indicators := []signatures.Indicator{
		{Name: "bootp_format", Weight: 0.7, Confidence: signatures.ConfidenceHigh},
	}

	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.3,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{67, 68})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{67, 68})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "BOOTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (d *DHCPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}) float64 {
	indicators := []signatures.Indicator{
		{Name: "magic_cookie", Weight: 0.5, Confidence: signatures.ConfidenceVeryHigh},
	}

	// Valid message type
	if _, hasMessageType := metadata["message_type"]; hasMessageType {
		indicators = append(indicators, signatures.Indicator{
			Name:       "message_type",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// UDP transport (DHCP is always UDP)
	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (d *DHCPSignature) parseOptions(options []byte) (byte, map[string]interface{}) {
	var messageType byte
	parsedOptions := make(map[string]interface{})

	i := 0
	for i < len(options) {
		if options[i] == 0xFF { // End option
			break
		}
		if options[i] == 0x00 { // Pad option
			i++
			continue
		}

		// Option format: code(1) + len(1) + data(len)
		if i+1 >= len(options) {
			break
		}

		code := options[i]
		length := int(options[i+1])

		if i+2+length > len(options) {
			break // Malformed option
		}

		data := options[i+2 : i+2+length]

		switch code {
		case 53: // DHCP Message Type
			if length == 1 {
				messageType = data[0]
			}
		case 12: // Hostname
			if length > 0 {
				parsedOptions["hostname"] = string(data)
			}
		case 50: // Requested IP Address
			if length == 4 {
				parsedOptions["requested_ip"] = d.ipToString(data)
			}
		case 54: // Server Identifier
			if length == 4 {
				parsedOptions["server_identifier"] = d.ipToString(data)
			}
		case 51: // IP Address Lease Time
			if length == 4 {
				parsedOptions["lease_time"] = binary.BigEndian.Uint32(data)
			}
		case 55: // Parameter Request List
			parsedOptions["param_request_list"] = data
		}

		i += 2 + length
	}

	return messageType, parsedOptions
}

func (d *DHCPSignature) opToString(op byte) string {
	if op == 1 {
		return "BOOTREQUEST"
	}
	if op == 2 {
		return "BOOTREPLY"
	}
	return "Unknown"
}

func (d *DHCPSignature) messageTypeToString(msgType byte) string {
	types := map[byte]string{
		1: "DHCPDISCOVER",
		2: "DHCPOFFER",
		3: "DHCPREQUEST",
		4: "DHCPDECLINE",
		5: "DHCPACK",
		6: "DHCPNAK",
		7: "DHCPRELEASE",
		8: "DHCPINFORM",
	}
	if s, ok := types[msgType]; ok {
		return s
	}
	return "Unknown"
}

func (d *DHCPSignature) ipToString(ip []byte) string {
	if len(ip) != 4 {
		return "0.0.0.0"
	}
	// Only return non-zero IPs as strings
	if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 {
		return "0.0.0.0"
	}
	// Format as dotted decimal
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

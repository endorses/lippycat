package application

import (
	"encoding/binary"
	"github.com/endorses/lippycat/internal/pkg/dhcp"

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
	if !dhcp.ValidBOOTPHeader(ctx.Payload) {
		return nil
	}
	payload := ctx.Payload
	if len(payload) < 240 || binary.BigEndian.Uint32(payload[236:240]) != 0x63825363 {
		return d.detectBOOTP(ctx, payload[0], binary.BigEndian.Uint32(payload[4:8]))
	}
	message, err := dhcp.Decode(payload)
	if message == nil {
		// BOOTP can use the RFC vendor cookie without DHCP message type.
		if err == dhcp.ErrBOOTP {
			return d.detectBOOTP(ctx, payload[0], binary.BigEndian.Uint32(payload[4:8]))
		}
		return nil
	}
	metadata := map[string]interface{}{
		"type":           d.opToString(message.Operation),
		"transaction_id": message.TransactionID,
		"htype":          message.HardwareType,
		"hlen":           uint8(len(message.HardwareAddress)),
		"hops":           message.Hops,
		"client_ip":      message.ClientAddress.String(),
		"your_ip":        message.OfferedAddress.String(),
		"server_ip":      message.NextServerAddress.String(),
		"gateway_ip":     message.RelayAddress.String(),
		"message_type":   d.messageTypeToString(message.MessageType),
	}
	options := make(map[string]interface{})
	if message.Hostname != "" {
		options["hostname"] = message.Hostname
	}
	if message.RequestedAddress.IsValid() {
		options["requested_ip"] = message.RequestedAddress.String()
	}
	if message.ServerIdentifier.IsValid() {
		options["server_identifier"] = message.ServerIdentifier.String()
	}
	if message.LeaseSeconds != nil {
		options["lease_time"] = *message.LeaseSeconds
	}
	if message.ParameterRequestList != nil {
		options["param_request_list"] = message.ParameterRequestList
	}
	if len(options) > 0 {
		metadata["options"] = options
	}
	if err != nil {
		metadata["partial"] = true
		metadata["truncated"] = message.Truncated
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

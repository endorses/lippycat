package vpn

import (
	"encoding/binary"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// IKEv2Signature detects IKEv2 (Internet Key Exchange version 2) traffic
// IKEv2 is used for IPsec VPN key negotiation
type IKEv2Signature struct{}

// NewIKEv2Signature creates a new IKEv2 signature detector
func NewIKEv2Signature() *IKEv2Signature {
	return &IKEv2Signature{}
}

func (i *IKEv2Signature) Name() string {
	return "IKEv2 Detector"
}

func (i *IKEv2Signature) Protocols() []string {
	return []string{"IKEv2", "IKE"}
}

func (i *IKEv2Signature) Priority() int {
	return 100 // High priority for VPN protocol
}

func (i *IKEv2Signature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (i *IKEv2Signature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// IKEv2 Header (RFC 7296):
	// IKE SA Initiator's SPI (8 bytes)
	// IKE SA Responder's SPI (8 bytes)
	// Next Payload (1 byte)
	// Version (1 byte) - Major version (4 bits) | Minor version (4 bits)
	// Exchange Type (1 byte)
	// Flags (1 byte)
	// Message ID (4 bytes)
	// Length (4 bytes) - total message length
	// Total header: 28 bytes

	// IKE/IKEv2 uses UDP only
	if ctx.Transport != "UDP" {
		return nil
	}

	// STRICT: Only detect on well-known IKE ports (500, 4500 for NAT-T)
	onIKEPort := ctx.SrcPort == 500 || ctx.DstPort == 500 ||
		ctx.SrcPort == 4500 || ctx.DstPort == 4500
	if !onIKEPort {
		return nil
	}

	if len(ctx.Payload) < 28 {
		return nil
	}

	payload := ctx.Payload

	// Extract version byte (offset 17)
	versionByte := payload[17]
	majorVersion := (versionByte >> 4) & 0x0F
	minorVersion := versionByte & 0x0F

	// IKEv2 is major version 2, minor version 0
	// IKEv1 is major version 1, minor version 0
	// We focus on IKEv2 but can detect IKEv1 as well
	if majorVersion != 2 && majorVersion != 1 {
		return nil
	}

	// For IKEv2, minor version should be 0
	if majorVersion == 2 && minorVersion != 0 {
		return nil
	}

	// Extract Next Payload (offset 16)
	nextPayload := payload[16]

	// Valid Next Payload types: 0, 33-53
	// 0 = No next payload
	// 33-53 = various payload types (SA, KE, IDi, IDr, CERT, AUTH, etc.)
	validNextPayload := nextPayload == 0 || (nextPayload >= 33 && nextPayload <= 53)
	if !validNextPayload {
		return nil
	}

	// Extract Exchange Type (offset 18)
	exchangeType := payload[18]

	// Valid IKEv2 Exchange Types:
	// 34 = IKE_SA_INIT
	// 35 = IKE_AUTH
	// 36 = CREATE_CHILD_SA
	// 37 = INFORMATIONAL
	// Valid IKEv1 Exchange Types: 0-6, 32-33
	validExchangeType := false
	switch majorVersion {
	case 2:
		validExchangeType = exchangeType >= 34 && exchangeType <= 37
	case 1:
		validExchangeType = exchangeType <= 6 || exchangeType == 32 || exchangeType == 33
	}

	if !validExchangeType {
		return nil
	}

	// Extract Flags (offset 19)
	flags := payload[19]
	// Bit meanings:
	// R (bit 5): Response (0=request, 1=response)
	// V (bit 4): Version (should be 0)
	// I (bit 3): Initiator (0=responder, 1=initiator)
	// Bits 0-2 and 6-7: Reserved, should be 0

	responseFlag := (flags & 0x20) != 0
	versionFlag := (flags & 0x10) != 0
	initiatorFlag := (flags & 0x08) != 0

	// Version flag should be 0 for IKEv2
	if majorVersion == 2 && versionFlag {
		return nil
	}

	// Extract Message ID (offset 20, 4 bytes)
	messageID := binary.BigEndian.Uint32(payload[20:24])

	// Extract Length (offset 24, 4 bytes)
	length := binary.BigEndian.Uint32(payload[24:28])

	// Validate length
	if length < 28 || length > 10000 {
		// IKE messages are at least 28 bytes (header)
		// Max reasonable size is ~10KB
		return nil
	}

	// Length should match or be close to payload length
	if int(length) > len(payload)+1000 || int(length) < len(payload)-1000 {
		// Allow tolerance for fragmentation
		if len(payload) < 28 {
			return nil
		}
	}

	// Extract SPIs (Security Parameter Indexes)
	// Initiator SPI: offset 0-7
	// Responder SPI: offset 8-15
	initiatorSPI := payload[0:8]
	responderSPI := payload[8:16]

	// Check if SPIs are non-zero (zero SPI can be valid in some cases)
	initiatorSPIZero := true
	responderSPIZero := true
	for _, b := range initiatorSPI {
		if b != 0 {
			initiatorSPIZero = false
			break
		}
	}
	for _, b := range responderSPI {
		if b != 0 {
			responderSPIZero = false
			break
		}
	}

	metadata := map[string]interface{}{
		"version":       float64(majorVersion) + float64(minorVersion)/10.0,
		"major_version": majorVersion,
		"minor_version": minorVersion,
		"exchange_type": exchangeType,
		"exchange_name": i.exchangeTypeToString(exchangeType, majorVersion),
		"next_payload":  nextPayload,
		"message_id":    messageID,
		"length":        length,
		"is_response":   responseFlag,
		"is_initiator":  initiatorFlag,
	}

	// Categorize based on exchange type (IKEv2)
	if majorVersion == 2 {
		switch exchangeType {
		case 34:
			metadata["phase"] = "SA_INIT"
			if !responseFlag {
				metadata["direction"] = "request"
			} else {
				metadata["direction"] = "response"
			}
		case 35:
			metadata["phase"] = "AUTH"
		case 36:
			metadata["phase"] = "CREATE_CHILD_SA"
		case 37:
			metadata["phase"] = "INFORMATIONAL"
		}
	}

	// For IKE_SA_INIT request, responder SPI should be zero
	if majorVersion == 2 && exchangeType == 34 && !responseFlag {
		if responderSPIZero {
			metadata["valid_sa_init_request"] = true
		}
	}

	if !initiatorSPIZero {
		metadata["has_initiator_spi"] = true
	}
	if !responderSPIZero {
		metadata["has_responder_spi"] = true
	}

	// Calculate confidence
	confidence := i.calculateConfidence(ctx, metadata, majorVersion)

	// Port-based confidence adjustment
	// IKE/IKEv2 uses UDP port 500 for initial exchange, 4500 for NAT-T
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{500, 4500})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{500, 4500})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	protocol := "IKEv2"
	if majorVersion == 1 {
		protocol = "IKEv1"
	}

	return &signatures.DetectionResult{
		Protocol:    protocol,
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (i *IKEv2Signature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, majorVersion uint8) float64 {
	indicators := []signatures.Indicator{}

	// Valid version
	switch majorVersion {
	case 2:
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_ikev2_version",
			Weight:     0.3,
			Confidence: signatures.ConfidenceVeryHigh,
		})
	case 1:
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_ikev1_version",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Valid exchange type
	if _, ok := metadata["exchange_name"].(string); ok {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_exchange_type",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Valid SA_INIT request structure
	if validSAInit, ok := metadata["valid_sa_init_request"].(bool); ok && validSAInit {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_sa_init_structure",
			Weight:     0.2,
			Confidence: signatures.ConfidenceVeryHigh,
		})
	}

	// UDP transport (IKE is always UDP)
	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (i *IKEv2Signature) exchangeTypeToString(exchangeType, majorVersion uint8) string {
	switch majorVersion {
	case 2:
		// IKEv2 exchange types
		types := map[uint8]string{
			34: "IKE_SA_INIT",
			35: "IKE_AUTH",
			36: "CREATE_CHILD_SA",
			37: "INFORMATIONAL",
		}
		if name, ok := types[exchangeType]; ok {
			return name
		}
	case 1:
		// IKEv1 exchange types
		types := map[uint8]string{
			0:  "None",
			1:  "Base",
			2:  "Identity Protection",
			3:  "Authentication Only",
			4:  "Aggressive",
			5:  "Informational",
			6:  "Transaction",
			32: "Quick Mode",
			33: "New Group Mode",
		}
		if name, ok := types[exchangeType]; ok {
			return name
		}
	}
	return "Unknown"
}

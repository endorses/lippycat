package application

import (
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// SNMPSignature detects SNMP (Simple Network Management Protocol) traffic
type SNMPSignature struct{}

// NewSNMPSignature creates a new SNMP signature detector
func NewSNMPSignature() *SNMPSignature {
	return &SNMPSignature{}
}

func (s *SNMPSignature) Name() string {
	return "SNMP Detector"
}

func (s *SNMPSignature) Protocols() []string {
	return []string{"SNMP"}
}

func (s *SNMPSignature) Priority() int {
	return 100 // High priority for management protocol
}

func (s *SNMPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (s *SNMPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// SNMP uses ASN.1 BER encoding
	// Basic structure: SEQUENCE tag (0x30) + length + version + community/msgAuthoritativeEngineID + PDU

	if len(ctx.Payload) < 10 {
		return nil
	}

	payload := ctx.Payload

	// Check for SEQUENCE tag (0x30)
	if payload[0] != 0x30 {
		return nil
	}

	// Parse length
	lengthByte := payload[1]
	var length int
	var offset int

	if lengthByte&0x80 == 0 {
		// Short form (0-127)
		length = int(lengthByte)
		offset = 2
	} else {
		// Long form
		numLengthBytes := int(lengthByte & 0x7f)
		if numLengthBytes > 4 || len(payload) < 2+numLengthBytes {
			return nil
		}
		length = 0
		for i := 0; i < numLengthBytes; i++ {
			length = (length << 8) | int(payload[2+i])
		}
		offset = 2 + numLengthBytes
	}

	// Validate length
	if length < 3 || length > 65535 {
		return nil
	}

	// Check for INTEGER tag for version (0x02)
	if offset >= len(payload) || payload[offset] != 0x02 {
		return nil
	}
	offset++

	// Version length (should be 1)
	if offset >= len(payload) || payload[offset] != 0x01 {
		return nil
	}
	offset++

	// Get version
	if offset >= len(payload) {
		return nil
	}
	version := payload[offset]
	offset++

	// Valid SNMP versions: 0 (v1), 1 (v2c), 2 (v2u - not common), 3 (v3)
	if version > 3 {
		return nil
	}

	metadata := map[string]interface{}{
		"version":      s.versionToString(version),
		"version_code": version,
	}

	// For SNMPv1/v2c, next is community string (OCTET STRING, tag 0x04)
	// For SNMPv3, it's more complex (msgGlobalData)
	if version <= 1 {
		if offset < len(payload) && payload[offset] == 0x04 {
			offset++
			// Community string length
			if offset < len(payload) {
				communityLen := int(payload[offset])
				offset++
				if offset+communityLen <= len(payload) {
					community := string(payload[offset : offset+communityLen])
					// Don't expose actual community string (security)
					metadata["has_community"] = true
					if community != "" {
						metadata["community_length"] = communityLen
					}
					offset += communityLen
				}
			}
		}
	}

	// Try to detect PDU type
	if offset < len(payload) {
		pduType := payload[offset]
		// SNMP PDU types have context-specific tags (0xa0-0xa8)
		if pduType >= 0xa0 && pduType <= 0xa8 {
			metadata["pdu_type"] = s.pduTypeToString(pduType)
		}
	}

	// Calculate confidence
	confidence := s.calculateConfidence(ctx, metadata, version)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{161, 162})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{161, 162})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "SNMP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (s *SNMPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, version byte) float64 {
	indicators := []signatures.Indicator{
		{Name: "asn1_structure", Weight: 0.4, Confidence: signatures.ConfidenceHigh},
	}

	// Valid SNMP version
	if version <= 3 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_version",
			Weight:     0.4,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// UDP transport (SNMP is typically UDP)
	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (s *SNMPSignature) versionToString(version byte) string {
	versions := map[byte]string{
		0: "SNMPv1",
		1: "SNMPv2c",
		2: "SNMPv2u",
		3: "SNMPv3",
	}
	if v, ok := versions[version]; ok {
		return v
	}
	return "Unknown"
}

func (s *SNMPSignature) pduTypeToString(pduType byte) string {
	types := map[byte]string{
		0xa0: "GetRequest",
		0xa1: "GetNextRequest",
		0xa2: "Response",
		0xa3: "SetRequest",
		0xa4: "Trap",           // SNMPv1
		0xa5: "GetBulkRequest", // SNMPv2
		0xa6: "InformRequest",  // SNMPv2
		0xa7: "SNMPv2-Trap",
		0xa8: "Report", // SNMPv3
	}
	if t, ok := types[pduType]; ok {
		return t
	}
	return "Unknown"
}

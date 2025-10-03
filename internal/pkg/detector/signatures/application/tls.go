package application

import (
	"encoding/binary"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// TLSSignature detects TLS/SSL protocol
type TLSSignature struct {
	// TLS record types
	contentTypes map[byte]string
	// TLS handshake types
	handshakeTypes map[byte]string
}

// NewTLSSignature creates a new TLS signature detector
func NewTLSSignature() *TLSSignature {
	return &TLSSignature{
		contentTypes: map[byte]string{
			20: "ChangeCipherSpec",
			21: "Alert",
			22: "Handshake",
			23: "ApplicationData",
			24: "Heartbeat",
		},
		handshakeTypes: map[byte]string{
			1:  "ClientHello",
			2:  "ServerHello",
			11: "Certificate",
			12: "ServerKeyExchange",
			13: "CertificateRequest",
			14: "ServerHelloDone",
			15: "CertificateVerify",
			16: "ClientKeyExchange",
			20: "Finished",
		},
	}
}

func (t *TLSSignature) Name() string {
	return "TLS/SSL Detector"
}

func (t *TLSSignature) Protocols() []string {
	return []string{"TLS", "SSL"}
}

func (t *TLSSignature) Priority() int {
	return 85 // High priority, often encapsulates other protocols
}

func (t *TLSSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (t *TLSSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if len(ctx.Payload) < 6 {
		return nil
	}

	// TLS record format:
	// byte 0: Content Type (20-24)
	// bytes 1-2: Version (0x0301 = TLS 1.0, 0x0303 = TLS 1.2, 0x0304 = TLS 1.3)
	// bytes 3-4: Length
	contentType := ctx.Payload[0]
	majorVersion := ctx.Payload[1]
	minorVersion := ctx.Payload[2]
	length := binary.BigEndian.Uint16(ctx.Payload[3:5])

	// Validate content type
	contentTypeName, validContentType := t.contentTypes[contentType]
	if !validContentType {
		return nil
	}

	// Validate TLS/SSL version
	// SSL 3.0: 0x0300
	// TLS 1.0: 0x0301
	// TLS 1.1: 0x0302
	// TLS 1.2: 0x0303
	// TLS 1.3: 0x0304
	if majorVersion != 0x03 {
		return nil
	}
	if minorVersion > 0x04 {
		return nil
	}

	// Validate length is reasonable (max TLS record is 16KB)
	if length > 16384 {
		return nil
	}

	// Determine version string
	version := t.getVersionString(majorVersion, minorVersion)

	metadata := map[string]interface{}{
		"version":      version,
		"content_type": contentTypeName,
		"record_length": int(length),
	}

	// For handshake messages, extract additional details
	if contentType == 22 && len(ctx.Payload) >= 6 {
		handshakeType := ctx.Payload[5]
		if handshakeTypeName, ok := t.handshakeTypes[handshakeType]; ok {
			metadata["handshake_type"] = handshakeTypeName

			// Extract SNI for ClientHello
			if handshakeType == 1 && len(ctx.Payload) > 43 {
				sni := t.extractSNI(ctx.Payload)
				if sni != "" {
					metadata["sni"] = sni
				}
			}
		}
	}

	// Calculate confidence
	indicators := []signatures.Indicator{
		{Name: "content_type", Weight: 0.4, Confidence: 1.0},
		{Name: "version", Weight: 0.4, Confidence: 1.0},
		{Name: "length_valid", Weight: 0.2, Confidence: 1.0},
	}

	confidence := signatures.ScoreDetection(indicators)

	// Port-based confidence adjustment (443 for HTTPS, 465/995/993 for email SSL)
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{443, 465, 563, 636, 989, 990, 992, 993, 994, 995})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{443, 465, 563, 636, 989, 990, 992, 993, 994, 995})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "TLS",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (t *TLSSignature) getVersionString(major, minor byte) string {
	version := uint16(major)<<8 | uint16(minor)
	switch version {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

func (t *TLSSignature) extractSNI(payload []byte) string {
	// This is a simplified SNI extraction
	// Full implementation would need proper TLS record parsing
	// ClientHello structure:
	// - Handshake Type (1 byte)
	// - Length (3 bytes)
	// - Version (2 bytes)
	// - Random (32 bytes)
	// - Session ID length (1 byte) + Session ID
	// - Cipher Suites length (2 bytes) + Cipher Suites
	// - Compression Methods length (1 byte) + Compression Methods
	// - Extensions length (2 bytes)
	// - Extensions...

	if len(payload) < 44 {
		return ""
	}

	// Skip to session ID
	pos := 43 // After handshake header, version, and random
	sessionIDLen := int(payload[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(payload) {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + cipherSuitesLen

	if pos+1 > len(payload) {
		return ""
	}

	// Skip compression methods
	compressionMethodsLen := int(payload[pos])
	pos += 1 + compressionMethodsLen

	if pos+2 > len(payload) {
		return ""
	}

	// Extensions length
	extensionsLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	// Parse extensions
	endPos := pos + extensionsLen
	for pos+4 <= endPos && pos+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4

		// SNI extension type is 0
		if extType == 0 && pos+extLen <= len(payload) {
			return t.parseSNIExtension(payload[pos : pos+extLen])
		}

		pos += extLen
	}

	return ""
}

func (t *TLSSignature) parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}

	// SNI Extension structure:
	// - Server Name List Length (2 bytes)
	// - Server Name Type (1 byte, 0 for hostname)
	// - Server Name Length (2 bytes)
	// - Server Name

	nameType := data[2]
	if nameType != 0 { // 0 = hostname
		return ""
	}

	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+nameLen {
		return ""
	}

	return string(data[5 : 5+nameLen])
}

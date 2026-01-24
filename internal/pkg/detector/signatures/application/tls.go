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
	return 110 // Higher than VPN protocols (100) - TLS is far more common on port 443
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
		// Not a valid TLS record header - check for mid-stream encrypted TLS
		return t.detectMidStreamTLS(ctx)
	}

	// Validate TLS/SSL version
	// SSL 3.0: 0x0300
	// TLS 1.0: 0x0301
	// TLS 1.1: 0x0302
	// TLS 1.2: 0x0303
	// TLS 1.3: 0x0304
	if majorVersion != 0x03 {
		return t.detectMidStreamTLS(ctx)
	}
	if minorVersion > 0x04 {
		return t.detectMidStreamTLS(ctx)
	}

	// Validate length is reasonable (max TLS record is 16KB)
	if length > 16384 {
		return t.detectMidStreamTLS(ctx)
	}

	// Determine version string
	version := t.getVersionString(majorVersion, minorVersion)

	metadata := map[string]interface{}{
		"version":       version,
		"content_type":  contentTypeName,
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
		Protocol:      "TLS",
		Confidence:    confidence,
		Metadata:      metadata,
		ShouldCache:   true,
		CacheStrategy: signatures.CacheSession, // TLS connections are session-based
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

// detectMidStreamTLS detects encrypted TLS traffic that doesn't start with a TLS record header.
// This handles TCP segments in the middle of an ongoing TLS session where the payload
// is encrypted application data without a visible TLS header.
func (t *TLSSignature) detectMidStreamTLS(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// Only detect mid-stream TLS on well-known TLS ports
	if !t.isWellKnownTLSPort(ctx.SrcPort) && !t.isWellKnownTLSPort(ctx.DstPort) {
		return nil
	}

	// Require TCP transport (TLS runs over TCP)
	if ctx.Transport != "TCP" {
		return nil
	}

	// Need enough data to analyze
	if len(ctx.Payload) < 20 {
		return nil
	}

	// Check if payload looks like encrypted data (high entropy, no ASCII text patterns)
	if !t.looksEncrypted(ctx.Payload) {
		return nil
	}

	// Return lower-confidence TLS detection for mid-stream traffic
	return &signatures.DetectionResult{
		Protocol:   "TLS",
		Confidence: signatures.ConfidenceMedium, // Lower confidence for mid-stream
		Metadata: map[string]any{
			"mid_stream":   true,
			"content_type": "ApplicationData (mid-stream)",
		},
		ShouldCache:   true,
		CacheStrategy: signatures.CacheSession,
	}
}

// isWellKnownTLSPort returns true if the port is commonly used for TLS traffic.
func (t *TLSSignature) isWellKnownTLSPort(port uint16) bool {
	switch port {
	case 443, 8443, // HTTPS
		465, // SMTPS
		563, // NNTPS
		636, // LDAPS
		853, // DNS over TLS
		989, // FTPS data
		990, // FTPS control
		992, // Telnet over TLS
		993, // IMAPS
		994, // IRC over TLS
		995: // POP3S
		return true
	default:
		return false
	}
}

// looksEncrypted checks if payload appears to be encrypted data.
// Encrypted data has high entropy and lacks ASCII text patterns.
func (t *TLSSignature) looksEncrypted(payload []byte) bool {
	if len(payload) < 20 {
		return false
	}

	// Check first 64 bytes (or less if payload is smaller)
	checkLen := 64
	if len(payload) < checkLen {
		checkLen = len(payload)
	}

	// Count printable ASCII characters and check byte distribution
	printableCount := 0
	var byteFreq [256]int

	for i := 0; i < checkLen; i++ {
		b := payload[i]
		byteFreq[b]++

		// Printable ASCII range (space to tilde)
		if b >= 0x20 && b <= 0x7E {
			printableCount++
		}
	}

	// If >70% printable ASCII, likely not encrypted (probably plaintext HTTP, etc.)
	if float64(printableCount)/float64(checkLen) > 0.7 {
		return false
	}

	// Check for common plaintext protocol signatures that should NOT be detected as TLS
	// HTTP methods
	if len(payload) >= 4 {
		prefix := string(payload[:4])
		if prefix == "GET " || prefix == "POST" || prefix == "HTTP" || prefix == "HEAD" ||
			prefix == "PUT " || prefix == "DELE" || prefix == "OPTI" {
			return false
		}
	}

	// Encrypted data should have relatively uniform byte distribution
	// Count how many unique byte values appear
	uniqueBytes := 0
	for _, count := range byteFreq {
		if count > 0 {
			uniqueBytes++
		}
	}

	// Encrypted data should use many different byte values
	// If only a small number of unique bytes, probably not encrypted
	return uniqueBytes >= 30
}

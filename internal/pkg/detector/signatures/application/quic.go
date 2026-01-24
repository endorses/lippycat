package application

import (
	"encoding/binary"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// QUICSignature detects QUIC (HTTP/3) protocol traffic
type QUICSignature struct {
	// Known QUIC versions
	versions map[uint32]string
}

// NewQUICSignature creates a new QUIC signature detector
func NewQUICSignature() *QUICSignature {
	return &QUICSignature{
		versions: map[uint32]string{
			0x00000001: "QUIC v1",  // RFC 9000
			0x6b3343cf: "QUIC v2",  // RFC 9369
			0xff000020: "draft-32", // Draft versions
			0xff00001d: "draft-29",
			0xff00001e: "draft-30",
			0xff00001f: "draft-31",
			0xff000022: "draft-34",
			// Version negotiation uses 0x00000000
			0x00000000: "Version Negotiation",
		},
	}
}

func (q *QUICSignature) Name() string {
	return "QUIC Detector"
}

func (q *QUICSignature) Protocols() []string {
	return []string{"QUIC"}
}

func (q *QUICSignature) Priority() int {
	return 115 // Above TLS (110) since QUIC on UDP:443 is more specific
}

func (q *QUICSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (q *QUICSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// QUIC runs exclusively over UDP
	if ctx.Transport != "UDP" {
		return nil
	}

	// Need at least 5 bytes for minimal header detection
	if len(ctx.Payload) < 5 {
		return nil
	}

	payload := ctx.Payload
	firstByte := payload[0]

	// QUIC has two header formats:
	// Long Header: bit 7 = 1 (0x80), used for handshake
	// Short Header: bit 7 = 0, bit 6 = 1 (0x40), used for data

	// Fixed bit (bit 6) should be 1 for valid QUIC packets
	// (except for some version negotiation scenarios)
	fixedBit := (firstByte & 0x40) != 0

	if (firstByte & 0x80) != 0 {
		// Long Header format
		return q.detectLongHeader(ctx, payload, fixedBit)
	}

	// Short Header format
	return q.detectShortHeader(ctx, payload, fixedBit)
}

// detectLongHeader handles QUIC Long Header packets (handshake, 0-RTT, etc.)
func (q *QUICSignature) detectLongHeader(ctx *signatures.DetectionContext, payload []byte, fixedBit bool) *signatures.DetectionResult {
	// Long Header minimum: 1 (header) + 4 (version) + 1 (DCID len) = 6 bytes
	if len(payload) < 6 {
		return nil
	}

	firstByte := payload[0]

	// Extract version (bytes 1-4, big endian)
	version := binary.BigEndian.Uint32(payload[1:5])

	// Validate version
	versionName, knownVersion := q.versions[version]
	if !knownVersion {
		// Check if it's a draft version (0xff0000xx pattern)
		if (version & 0xffffff00) == 0xff000000 {
			draftNum := version & 0xff
			versionName = fmt.Sprintf("draft-%d", draftNum)
			knownVersion = true
		} else if version == 0 {
			// Version negotiation
			versionName = "Version Negotiation"
			knownVersion = true
		}
	}

	// If version is completely unknown, be more cautious
	if !knownVersion {
		// Only accept on well-known QUIC ports
		if !q.isQUICPort(ctx.SrcPort) && !q.isQUICPort(ctx.DstPort) {
			return nil
		}
		versionName = fmt.Sprintf("Unknown (0x%08x)", version)
	}

	// Extract packet type from Long Header (bits 4-5)
	packetType := (firstByte >> 4) & 0x03
	packetTypeName := q.longHeaderPacketType(packetType)

	// Validate DCID length
	dcidLen := int(payload[5])
	if dcidLen > 20 {
		// QUIC connection IDs are max 20 bytes
		return nil
	}

	// Check we have enough bytes for DCID
	if len(payload) < 6+dcidLen {
		return nil
	}

	// If we have SCID length, validate it too
	scidLen := 0
	if len(payload) > 6+dcidLen {
		scidLen = int(payload[6+dcidLen])
		if scidLen > 20 {
			return nil
		}
	}

	metadata := map[string]any{
		"header_type": "long",
		"version":     versionName,
		"packet_type": packetTypeName,
		"dcid_length": dcidLen,
		"scid_length": scidLen,
		"fixed_bit":   fixedBit,
	}

	confidence := q.calculateConfidence(ctx, metadata, knownVersion, fixedBit)

	return &signatures.DetectionResult{
		Protocol:      "QUIC",
		Confidence:    confidence,
		Metadata:      metadata,
		ShouldCache:   true,
		CacheStrategy: signatures.CacheFlow,
	}
}

// detectShortHeader handles QUIC Short Header packets (application data)
func (q *QUICSignature) detectShortHeader(ctx *signatures.DetectionContext, payload []byte, fixedBit bool) *signatures.DetectionResult {
	// Short header is harder to identify definitively without connection context
	// It lacks the version field

	// Fixed bit (bit 6) must be 1 for valid QUIC
	if !fixedBit {
		return nil
	}

	firstByte := payload[0]

	// For short headers, we need port hints since there's no version
	onQUICPort := q.isQUICPort(ctx.SrcPort) || q.isQUICPort(ctx.DstPort)
	if !onQUICPort {
		// Without a QUIC port, we can't reliably detect short headers
		return nil
	}

	// Extract spin bit and key phase
	spinBit := (firstByte & 0x20) != 0
	keyPhase := (firstByte & 0x04) != 0

	// Packet number length is in bits 0-1 (encoded as 0-3, meaning 1-4 bytes)
	pnLength := (firstByte & 0x03) + 1

	// Short header packets should have reasonable size
	// Minimum: 1 (header) + 0-20 (DCID) + 1-4 (PN) + 16 (AEAD tag) = 18+ bytes
	if len(payload) < 18 {
		return nil
	}

	metadata := map[string]any{
		"header_type":          "short",
		"spin_bit":             spinBit,
		"key_phase":            keyPhase,
		"packet_number_length": pnLength,
		"fixed_bit":            fixedBit,
	}

	// Lower confidence for short headers since they're less distinctive
	confidence := signatures.ConfidenceMedium
	if onQUICPort {
		confidence = signatures.ConfidenceHigh
	}

	return &signatures.DetectionResult{
		Protocol:      "QUIC",
		Confidence:    confidence,
		Metadata:      metadata,
		ShouldCache:   true,
		CacheStrategy: signatures.CacheFlow,
	}
}

func (q *QUICSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]any, knownVersion, fixedBit bool) float64 {
	indicators := []signatures.Indicator{}

	// Known version is a strong indicator
	if knownVersion {
		indicators = append(indicators, signatures.Indicator{
			Name:       "known_version",
			Weight:     0.4,
			Confidence: signatures.ConfidenceVeryHigh,
		})
	}

	// Fixed bit should be set
	if fixedBit {
		indicators = append(indicators, signatures.Indicator{
			Name:       "fixed_bit_set",
			Weight:     0.2,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Port-based confidence
	onQUICPort := q.isQUICPort(ctx.SrcPort) || q.isQUICPort(ctx.DstPort)
	if onQUICPort {
		indicators = append(indicators, signatures.Indicator{
			Name:       "quic_port",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Valid packet type
	indicators = append(indicators, signatures.Indicator{
		Name:       "valid_structure",
		Weight:     0.1,
		Confidence: signatures.ConfidenceMedium,
	})

	return signatures.ScoreDetection(indicators)
}

func (q *QUICSignature) longHeaderPacketType(packetType byte) string {
	switch packetType {
	case 0:
		return "Initial"
	case 1:
		return "0-RTT"
	case 2:
		return "Handshake"
	case 3:
		return "Retry"
	default:
		return "Unknown"
	}
}

func (q *QUICSignature) isQUICPort(port uint16) bool {
	switch port {
	case 443, // HTTPS/QUIC
		8443, // Alternate HTTPS
		80,   // HTTP (some QUIC implementations)
		8080: // Alternate HTTP
		return true
	default:
		return false
	}
}

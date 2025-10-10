package application

import (
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// NTPSignature detects NTP (Network Time Protocol) traffic
type NTPSignature struct{}

// NewNTPSignature creates a new NTP signature detector
func NewNTPSignature() *NTPSignature {
	return &NTPSignature{}
}

func (n *NTPSignature) Name() string {
	return "NTP Detector"
}

func (n *NTPSignature) Protocols() []string {
	return []string{"NTP"}
}

func (n *NTPSignature) Priority() int {
	return 105 // High priority for infrastructure protocol
}

func (n *NTPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (n *NTPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// NTP is UDP-only protocol
	if ctx.Transport != "UDP" {
		return nil
	}

	// NTP packet is typically 48 bytes
	// Minimum size is 48 bytes for standard NTP
	if len(ctx.Payload) < 48 {
		return nil
	}

	payload := ctx.Payload

	// NTP header structure (first byte):
	// LI (2 bits) + VN (3 bits) + Mode (3 bits)

	firstByte := payload[0]

	// Extract fields from first byte
	li := (firstByte >> 6) & 0x03 // Leap Indicator (bits 0-1)
	vn := (firstByte >> 3) & 0x07 // Version Number (bits 2-4)
	mode := firstByte & 0x07      // Mode (bits 5-7)

	// Validate version (1-4 are valid NTP versions)
	if vn == 0 || vn > 4 {
		return nil
	}

	// Validate mode (0-7, but 0 and 6-7 are reserved/rare)
	if mode == 0 || mode == 6 {
		return nil // Reserved modes
	}

	// Extract stratum (second byte)
	stratum := payload[1]

	// Validate stratum (0-16, where 0 is special and 16 is unsynchronized)
	if stratum > 16 {
		return nil
	}

	// Extract poll interval (third byte)
	poll := payload[2]

	// Poll interval should be reasonable (typically 4-17, representing 2^poll seconds)
	if poll > 24 {
		return nil // Unreasonable poll interval
	}

	// Extract precision (fourth byte, signed)
	precision := int8(payload[3])

	// Precision should be reasonable (typically -6 to -20)
	if precision > 0 || precision < -30 {
		return nil
	}

	metadata := map[string]interface{}{
		"version":        vn,
		"mode":           n.modeToString(mode),
		"stratum":        stratum,
		"poll":           poll,
		"precision":      precision,
		"leap_indicator": n.leapIndicatorToString(li),
	}

	// Add stratum description
	if stratumDesc := n.stratumDescription(stratum); stratumDesc != "" {
		metadata["stratum_description"] = stratumDesc
	}

	// Calculate confidence
	confidence := n.calculateConfidence(ctx, metadata, vn, mode, stratum)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{123})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{123})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "NTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (n *NTPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, version, mode, stratum byte) float64 {
	indicators := []signatures.Indicator{}

	// Valid NTP version
	if version >= 1 && version <= 4 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_version",
			Weight:     0.4,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Valid mode (client, server, broadcast, etc.)
	if mode >= 1 && mode <= 5 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_mode",
			Weight:     0.3,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// Reasonable stratum
	if stratum <= 16 {
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_stratum",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	// UDP transport (NTP is always UDP)
	if ctx.Transport == "UDP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "udp_transport",
			Weight:     0.1,
			Confidence: signatures.ConfidenceLow,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (n *NTPSignature) modeToString(mode byte) string {
	modes := map[byte]string{
		0: "reserved",
		1: "symmetric_active",
		2: "symmetric_passive",
		3: "client",
		4: "server",
		5: "broadcast",
		6: "reserved_ntp_control",
		7: "reserved_private",
	}
	if s, ok := modes[mode]; ok {
		return s
	}
	return "unknown"
}

func (n *NTPSignature) leapIndicatorToString(li byte) string {
	indicators := map[byte]string{
		0: "no_warning",
		1: "last_minute_61_seconds",
		2: "last_minute_59_seconds",
		3: "alarm_condition",
	}
	if s, ok := indicators[li]; ok {
		return s
	}
	return "unknown"
}

func (n *NTPSignature) stratumDescription(stratum byte) string {
	switch stratum {
	case 0:
		return "unspecified or invalid"
	case 1:
		return "primary reference (e.g., GPS, atomic clock)"
	case 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15:
		return "secondary reference (via NTP)"
	case 16:
		return "unsynchronized"
	default:
		return ""
	}
}

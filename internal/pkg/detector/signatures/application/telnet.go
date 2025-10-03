package application

import (
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// TelnetSignature detects Telnet protocol traffic
type TelnetSignature struct{}

// NewTelnetSignature creates a new Telnet signature detector
func NewTelnetSignature() *TelnetSignature {
	return &TelnetSignature{}
}

func (t *TelnetSignature) Name() string {
	return "Telnet Detector"
}

func (t *TelnetSignature) Protocols() []string {
	return []string{"Telnet"}
}

func (t *TelnetSignature) Priority() int {
	return 85 // Medium-high priority
}

func (t *TelnetSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (t *TelnetSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// Telnet uses IAC (Interpret As Command) byte 0xFF for negotiations
	// Common patterns:
	// - IAC WILL/WONT/DO/DONT option
	// - IAC SB option ... IAC SE (subnegotiation)

	if len(ctx.Payload) < 3 {
		return nil
	}

	payload := ctx.Payload

	// Look for IAC commands
	iacCount := 0
	hasValidCommand := false

	for i := 0; i < len(payload)-2; i++ {
		if payload[i] == 0xFF { // IAC
			iacCount++
			// Check for valid command following IAC
			cmd := payload[i+1]
			if t.isValidTelnetCommand(cmd) {
				hasValidCommand = true
				// For WILL/WONT/DO/DONT, there should be an option byte
				if cmd >= 251 && cmd <= 254 && i+2 < len(payload) {
					option := payload[i+2]
					// Most telnet options are < 50
					if option < 100 {
						hasValidCommand = true
					}
				}
			}
		}
	}

	// Need at least one IAC sequence to consider it Telnet
	if iacCount == 0 || !hasValidCommand {
		return nil
	}

	metadata := map[string]interface{}{
		"iac_count": iacCount,
	}

	// Try to extract negotiation details
	if iacCount > 0 {
		negotiations := t.extractNegotiations(payload)
		if len(negotiations) > 0 {
			metadata["negotiations"] = negotiations
		}
	}

	// Calculate confidence
	confidence := t.calculateConfidence(ctx, metadata, iacCount)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{23})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{23})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "Telnet",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (t *TelnetSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, iacCount int) float64 {
	indicators := []signatures.Indicator{}

	// Has IAC sequences
	if iacCount > 0 {
		conf := signatures.ConfidenceMedium
		if iacCount >= 3 {
			conf = signatures.ConfidenceHigh
		}
		indicators = append(indicators, signatures.Indicator{
			Name:       "iac_sequences",
			Weight:     0.7,
			Confidence: conf,
		})
	}

	// TCP transport (Telnet is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.3,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (t *TelnetSignature) isValidTelnetCommand(cmd byte) bool {
	// Telnet commands (240-255)
	// 240 SE  - End of subnegotiation
	// 241 NOP - No operation
	// 242 Data Mark
	// 243 Break
	// 244 Interrupt Process
	// 245 Abort Output
	// 246 Are You There
	// 247 Erase Character
	// 248 Erase Line
	// 249 Go Ahead
	// 250 SB  - Subnegotiation begin
	// 251 WILL
	// 252 WONT
	// 253 DO
	// 254 DONT
	// 255 IAC
	return cmd >= 240 && cmd <= 255
}

func (t *TelnetSignature) extractNegotiations(payload []byte) []string {
	negotiations := []string{}

	for i := 0; i < len(payload)-2; i++ {
		if payload[i] == 0xFF { // IAC
			cmd := payload[i+1]
			if cmd >= 251 && cmd <= 254 { // WILL/WONT/DO/DONT
				if i+2 < len(payload) {
					option := payload[i+2]
					negotiation := t.commandToString(cmd) + " " + t.optionToString(option)
					negotiations = append(negotiations, negotiation)
				}
			}
		}
	}

	return negotiations
}

func (t *TelnetSignature) commandToString(cmd byte) string {
	commands := map[byte]string{
		240: "SE",
		241: "NOP",
		242: "Data Mark",
		243: "Break",
		244: "Interrupt Process",
		245: "Abort Output",
		246: "Are You There",
		247: "Erase Character",
		248: "Erase Line",
		249: "Go Ahead",
		250: "SB",
		251: "WILL",
		252: "WONT",
		253: "DO",
		254: "DONT",
		255: "IAC",
	}
	if name, ok := commands[cmd]; ok {
		return name
	}
	return "Unknown"
}

func (t *TelnetSignature) optionToString(option byte) string {
	options := map[byte]string{
		0:  "Binary Transmission",
		1:  "Echo",
		3:  "Suppress Go Ahead",
		5:  "Status",
		6:  "Timing Mark",
		24: "Terminal Type",
		31: "Window Size",
		32: "Terminal Speed",
		33: "Remote Flow Control",
		34: "Linemode",
		36: "Environment Variables",
	}
	if name, ok := options[option]; ok {
		return name
	}
	return string(option)
}

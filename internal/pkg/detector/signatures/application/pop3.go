package application

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// POP3Signature detects POP3 (Post Office Protocol version 3) traffic
type POP3Signature struct{}

// NewPOP3Signature creates a new POP3 signature detector
func NewPOP3Signature() *POP3Signature {
	return &POP3Signature{}
}

func (p *POP3Signature) Name() string {
	return "POP3 Detector"
}

func (p *POP3Signature) Protocols() []string {
	return []string{"POP3"}
}

func (p *POP3Signature) Priority() int {
	return 95 // High priority for mail protocol
}

func (p *POP3Signature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (p *POP3Signature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// POP3 is text-based with CRLF line endings
	// Server responses: "+OK" or "-ERR" followed by message
	// Client commands: USER, PASS, STAT, LIST, RETR, DELE, QUIT, etc.

	// POP3 uses TCP only
	if ctx.Transport != "TCP" {
		return nil
	}

	// STRICT: Only detect on well-known POP3 ports (110, 995)
	if ctx.SrcPort != 110 && ctx.SrcPort != 995 && ctx.DstPort != 110 && ctx.DstPort != 995 {
		return nil
	}

	if len(ctx.Payload) < 4 {
		return nil
	}

	payload := string(ctx.Payload[:min(500, len(ctx.Payload))])

	// Check for server responses
	if strings.HasPrefix(payload, "+OK") || strings.HasPrefix(payload, "-ERR") {
		return p.detectResponse(ctx, payload)
	}

	// Check for client commands
	upperPayload := strings.ToUpper(payload[:min(20, len(payload))])

	pop3Commands := []string{
		"USER ", "PASS ", "STAT", "LIST", "RETR ", "DELE ",
		"NOOP", "RSET", "QUIT", "TOP ", "UIDL", "APOP ",
		"STLS", "CAPA", // Extensions
	}

	for _, cmd := range pop3Commands {
		if strings.HasPrefix(upperPayload, cmd) {
			return p.detectCommand(ctx, payload)
		}
	}

	return nil
}

func (p *POP3Signature) detectResponse(ctx *signatures.DetectionContext, payload string) *signatures.DetectionResult {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := lines[0]
	isOK := strings.HasPrefix(firstLine, "+OK")
	isErr := strings.HasPrefix(firstLine, "-ERR")

	if !isOK && !isErr {
		return nil
	}

	metadata := map[string]interface{}{
		"type": "response",
	}

	if isOK {
		metadata["status"] = "OK"
		if len(firstLine) > 4 {
			metadata["message"] = strings.TrimSpace(firstLine[4:])
		}
	} else {
		metadata["status"] = "ERR"
		if len(firstLine) > 5 {
			metadata["message"] = strings.TrimSpace(firstLine[5:])
		}
	}

	// Detect greeting (typically contains "POP3" or "ready")
	if strings.Contains(strings.ToLower(firstLine), "pop3") ||
		strings.Contains(strings.ToLower(firstLine), "ready") {
		metadata["greeting"] = true
	}

	// Detect STLS capability
	if strings.Contains(strings.ToUpper(payload), "STLS") {
		metadata["stls_capable"] = true
	}

	// Calculate confidence
	confidence := p.calculateConfidence(ctx, metadata, true)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{110, 995})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{110, 995})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "POP3",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (p *POP3Signature) detectCommand(ctx *signatures.DetectionContext, payload string) *signatures.DetectionResult {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := lines[0]
	parts := strings.SplitN(firstLine, " ", 2)

	command := strings.ToUpper(strings.TrimSpace(parts[0]))
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}

	metadata := map[string]interface{}{
		"type":    "command",
		"command": command,
	}

	if args != "" {
		// Redact password from PASS command
		if command == "PASS" {
			metadata["args"] = "***"
		} else {
			metadata["args"] = args
		}
	}

	// Detect STLS (STARTTLS for POP3)
	if command == "STLS" {
		metadata["stls_request"] = true
	}

	// Calculate confidence
	confidence := p.calculateConfidence(ctx, metadata, false)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{110, 995})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{110, 995})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "POP3",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (p *POP3Signature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, isResponse bool) float64 {
	indicators := []signatures.Indicator{}

	if isResponse {
		// Valid POP3 response
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_response",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})

		// Greeting response
		if greeting, ok := metadata["greeting"].(bool); ok && greeting {
			indicators = append(indicators, signatures.Indicator{
				Name:       "greeting_response",
				Weight:     0.2,
				Confidence: signatures.ConfidenceVeryHigh,
			})
		}
	} else {
		// Valid POP3 command
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_command",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// TCP transport (POP3 is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

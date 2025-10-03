package application

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// SMTPSignature detects SMTP (Simple Mail Transfer Protocol) traffic
type SMTPSignature struct{}

// NewSMTPSignature creates a new SMTP signature detector
func NewSMTPSignature() *SMTPSignature {
	return &SMTPSignature{}
}

func (s *SMTPSignature) Name() string {
	return "SMTP Detector"
}

func (s *SMTPSignature) Protocols() []string {
	return []string{"SMTP"}
}

func (s *SMTPSignature) Priority() int {
	return 95 // High priority for common protocol
}

func (s *SMTPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (s *SMTPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// SMTP uses TCP only
	if ctx.Transport != "TCP" {
		return nil
	}

	// STRICT: Only detect on well-known SMTP ports (25, 465, 587)
	onSMTPPort := ctx.SrcPort == 25 || ctx.SrcPort == 465 || ctx.SrcPort == 587 ||
		ctx.DstPort == 25 || ctx.DstPort == 465 || ctx.DstPort == 587
	if !onSMTPPort {
		return nil
	}

	if len(ctx.Payload) < 4 {
		return nil
	}

	payload := string(ctx.Payload[:min(500, len(ctx.Payload))])

	// SMTP is text-based with CRLF line endings
	// Server responses: "NNN message\r\n" where NNN is 3-digit code
	// Client commands: "COMMAND args\r\n"

	// Detect server responses (3-digit code followed by space or dash)
	if len(payload) >= 4 && s.isDigit(payload[0]) && s.isDigit(payload[1]) && s.isDigit(payload[2]) {
		if payload[3] == ' ' || payload[3] == '-' {
			return s.detectResponse(ctx, payload)
		}
	}

	// Detect client commands
	upperPayload := strings.ToUpper(payload[:min(20, len(payload))])

	smtpCommands := []string{
		"HELO ", "EHLO ", "MAIL FROM:", "RCPT TO:", "DATA",
		"RSET", "VRFY ", "EXPN ", "HELP", "NOOP", "QUIT",
		"STARTTLS", "AUTH ", "TURN",
	}

	for _, cmd := range smtpCommands {
		if strings.HasPrefix(upperPayload, cmd) {
			return s.detectCommand(ctx, payload)
		}
	}

	return nil
}

func (s *SMTPSignature) detectResponse(ctx *signatures.DetectionContext, payload string) *signatures.DetectionResult {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := lines[0]
	if len(firstLine) < 4 {
		return nil
	}

	// Extract response code
	codeStr := firstLine[:3]
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		return nil
	}

	// Validate SMTP response codes (200-599, but typically 200-559)
	if code < 200 || code > 599 {
		return nil
	}

	message := ""
	if len(firstLine) > 4 {
		message = strings.TrimSpace(firstLine[4:])
	}

	metadata := map[string]interface{}{
		"type":          "response",
		"code":          code,
		"code_category": s.getCodeCategory(code),
		"message":       message,
	}

	// Check for multiline response (code followed by dash)
	if len(firstLine) > 3 && firstLine[3] == '-' {
		metadata["multiline"] = true
	}

	// Detect STARTTLS capability
	if strings.Contains(strings.ToUpper(payload), "STARTTLS") {
		metadata["starttls_capable"] = true
	}

	// Detect server greeting (220)
	if code == 220 {
		metadata["greeting"] = true
	}

	// Calculate confidence
	confidence := s.calculateConfidence(ctx, metadata, true)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{25, 587, 465})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{25, 587, 465})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "SMTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (s *SMTPSignature) detectCommand(ctx *signatures.DetectionContext, payload string) *signatures.DetectionResult {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := lines[0]
	parts := strings.SplitN(firstLine, " ", 2)

	command := strings.ToUpper(strings.TrimSpace(parts[0]))

	// Handle special commands with ":"
	if strings.Contains(command, ":") {
		command = strings.SplitN(command, ":", 1)[0]
	}

	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	} else if strings.Contains(firstLine, ":") {
		// For MAIL FROM: and RCPT TO:
		colonParts := strings.SplitN(firstLine, ":", 2)
		if len(colonParts) > 1 {
			args = strings.TrimSpace(colonParts[1])
		}
	}

	metadata := map[string]interface{}{
		"type":    "command",
		"command": command,
	}

	if args != "" {
		// Redact password from AUTH command
		if command == "AUTH" && strings.Contains(strings.ToUpper(args), "PLAIN") {
			metadata["args"] = "PLAIN ***"
		} else {
			metadata["args"] = args
		}
	}

	// Detect STARTTLS
	if command == "STARTTLS" {
		metadata["starttls_request"] = true
	}

	// Calculate confidence
	confidence := s.calculateConfidence(ctx, metadata, false)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{25, 587, 465})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{25, 587, 465})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "SMTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (s *SMTPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, isResponse bool) float64 {
	indicators := []signatures.Indicator{}

	if isResponse {
		// Valid SMTP response code
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_response_code",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})

		// Greeting response (220)
		if greeting, ok := metadata["greeting"].(bool); ok && greeting {
			indicators = append(indicators, signatures.Indicator{
				Name:       "greeting_response",
				Weight:     0.2,
				Confidence: signatures.ConfidenceVeryHigh,
			})
		}
	} else {
		// Valid SMTP command
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_command",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// TCP transport (SMTP is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (s *SMTPSignature) getCodeCategory(code int) string {
	switch code / 100 {
	case 2:
		return "Success"
	case 3:
		return "Intermediate"
	case 4:
		return "Transient Failure"
	case 5:
		return "Permanent Failure"
	default:
		return "Unknown"
	}
}

func (s *SMTPSignature) isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

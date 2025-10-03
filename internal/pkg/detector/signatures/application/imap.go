package application

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// IMAPSignature detects IMAP (Internet Message Access Protocol) traffic
type IMAPSignature struct{}

// NewIMAPSignature creates a new IMAP signature detector
func NewIMAPSignature() *IMAPSignature {
	return &IMAPSignature{}
}

func (i *IMAPSignature) Name() string {
	return "IMAP Detector"
}

func (i *IMAPSignature) Protocols() []string {
	return []string{"IMAP"}
}

func (i *IMAPSignature) Priority() int {
	return 95 // High priority for mail protocol
}

func (i *IMAPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (i *IMAPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	// IMAP is text-based with CRLF line endings
	// Server responses: "* " or "tag OK/NO/BAD"
	// Client commands: "tag COMMAND args"

	// IMAP uses TCP only
	if ctx.Transport != "TCP" {
		return nil
	}

	// STRICT: Only detect on well-known IMAP ports (143, 993)
	// Text patterns like " OK " are too common in HTTP and other protocols
	if ctx.SrcPort != 143 && ctx.SrcPort != 993 && ctx.DstPort != 143 && ctx.DstPort != 993 {
		return nil
	}

	if len(ctx.Payload) < 4 {
		return nil
	}

	payload := string(ctx.Payload[:min(500, len(ctx.Payload))])

	// Check for server responses
	// Untagged responses start with "* "
	if strings.HasPrefix(payload, "* ") {
		return i.detectResponse(ctx, payload, true)
	}

	// Tagged responses: look for " OK ", " NO ", " BAD "
	if strings.Contains(payload[:min(50, len(payload))], " OK ") ||
		strings.Contains(payload[:min(50, len(payload))], " NO ") ||
		strings.Contains(payload[:min(50, len(payload))], " BAD ") {
		return i.detectResponse(ctx, payload, false)
	}

	// Check for client commands
	// IMAP commands have format: tag COMMAND
	// Common commands: CAPABILITY, LOGIN, SELECT, EXAMINE, FETCH, STORE, etc.
	upperPayload := strings.ToUpper(payload[:min(100, len(payload))])

	imapCommands := []string{
		" CAPABILITY", " NOOP", " LOGOUT",
		" LOGIN ", " AUTHENTICATE ", " STARTTLS",
		" SELECT ", " EXAMINE ", " CREATE ", " DELETE ",
		" RENAME ", " SUBSCRIBE ", " UNSUBSCRIBE ",
		" LIST ", " LSUB ", " STATUS ", " APPEND ",
		" CHECK", " CLOSE", " EXPUNGE",
		" SEARCH ", " FETCH ", " STORE ", " COPY ",
		" UID ", " IDLE",
	}

	for _, cmd := range imapCommands {
		if strings.Contains(upperPayload, cmd) {
			return i.detectCommand(ctx, payload)
		}
	}

	return nil
}

func (i *IMAPSignature) detectResponse(ctx *signatures.DetectionContext, payload string, untagged bool) *signatures.DetectionResult {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := lines[0]

	metadata := map[string]interface{}{
		"type": "response",
	}

	if untagged {
		metadata["untagged"] = true
		// Extract the response type
		if len(firstLine) > 2 {
			parts := strings.SplitN(firstLine[2:], " ", 2)
			if len(parts) > 0 {
				metadata["response_type"] = parts[0]
			}
		}
	} else {
		metadata["tagged"] = true
		// Extract status
		if strings.Contains(firstLine, " OK ") {
			metadata["status"] = "OK"
		} else if strings.Contains(firstLine, " NO ") {
			metadata["status"] = "NO"
		} else if strings.Contains(firstLine, " BAD ") {
			metadata["status"] = "BAD"
		}
	}

	// Detect greeting (typically contains "IMAP4" or "ready")
	if strings.Contains(strings.ToUpper(firstLine), "IMAP4") ||
		strings.Contains(strings.ToLower(firstLine), "ready") {
		metadata["greeting"] = true
	}

	// Detect STARTTLS capability
	if strings.Contains(strings.ToUpper(payload), "STARTTLS") {
		metadata["starttls_capable"] = true
	}

	// Calculate confidence
	confidence := i.calculateConfidence(ctx, metadata, true)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{143, 993})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{143, 993})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "IMAP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (i *IMAPSignature) detectCommand(ctx *signatures.DetectionContext, payload string) *signatures.DetectionResult {
	lines := strings.Split(payload, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := lines[0]
	parts := strings.SplitN(firstLine, " ", 3)

	if len(parts) < 2 {
		return nil
	}

	tag := parts[0]
	command := strings.ToUpper(parts[1])
	args := ""
	if len(parts) > 2 {
		args = parts[2]
	}

	metadata := map[string]interface{}{
		"type":    "command",
		"tag":     tag,
		"command": command,
	}

	if args != "" {
		// Redact password from LOGIN command
		if command == "LOGIN" {
			metadata["args"] = "*** ***"
		} else {
			metadata["args"] = args
		}
	}

	// Detect STARTTLS
	if command == "STARTTLS" {
		metadata["starttls_request"] = true
	}

	// Calculate confidence
	confidence := i.calculateConfidence(ctx, metadata, false)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{143, 993})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{143, 993})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "IMAP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (i *IMAPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, isResponse bool) float64 {
	indicators := []signatures.Indicator{}

	if isResponse {
		// Valid IMAP response
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
		// Valid IMAP command
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_command",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// TCP transport (IMAP is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.2,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

package application

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
)

// FTPSignature detects FTP (File Transfer Protocol) traffic
type FTPSignature struct{}

// NewFTPSignature creates a new FTP signature detector
func NewFTPSignature() *FTPSignature {
	return &FTPSignature{}
}

func (f *FTPSignature) Name() string {
	return "FTP Detector"
}

func (f *FTPSignature) Protocols() []string {
	return []string{"FTP"}
}

func (f *FTPSignature) Priority() int {
	return 95 // High priority for common protocol
}

func (f *FTPSignature) Layer() signatures.LayerType {
	return signatures.LayerApplication
}

func (f *FTPSignature) Detect(ctx *signatures.DetectionContext) *signatures.DetectionResult {
	if len(ctx.Payload) < 4 {
		return nil
	}

	payload := string(ctx.Payload[:min(500, len(ctx.Payload))])

	// FTP is text-based with CRLF line endings
	// Check for common FTP patterns

	// Server responses: "NNN message\r\n" where NNN is 3-digit code
	// Client commands: "COMMAND args\r\n"

	// Detect server responses (3-digit code followed by space or dash)
	if len(payload) >= 4 && f.isDigit(payload[0]) && f.isDigit(payload[1]) && f.isDigit(payload[2]) {
		if payload[3] == ' ' || payload[3] == '-' {
			return f.detectResponse(ctx, payload)
		}
	}

	// Detect client commands
	// Common FTP commands: USER, PASS, SYST, PWD, CWD, LIST, RETR, STOR, etc.
	upperPayload := strings.ToUpper(payload[:min(10, len(payload))])

	ftpCommands := []string{
		"USER ", "PASS ", "ACCT ", "CWD ", "CDUP", "SMNT ",
		"QUIT", "REIN", "PORT ", "PASV", "TYPE ", "STRU ",
		"MODE ", "RETR ", "STOR ", "STOU ", "APPE ", "ALLO ",
		"REST ", "RNFR ", "RNTO ", "ABOR", "DELE ", "RMD ",
		"MKD ", "PWD", "LIST", "NLST ", "SITE ", "SYST",
		"STAT ", "HELP", "NOOP", "FEAT", "OPTS ", "AUTH ",
		"PBSZ ", "PROT ", "EPSV", "EPRT ",
	}

	for _, cmd := range ftpCommands {
		if strings.HasPrefix(upperPayload, cmd) {
			return f.detectCommand(ctx, payload)
		}
	}

	return nil
}

func (f *FTPSignature) detectResponse(ctx *signatures.DetectionContext, payload string) *signatures.DetectionResult {
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

	// Validate FTP response codes (100-599)
	if code < 100 || code > 599 {
		return nil
	}

	message := ""
	if len(firstLine) > 4 {
		message = strings.TrimSpace(firstLine[4:])
	}

	metadata := map[string]interface{}{
		"type":          "response",
		"code":          code,
		"code_category": f.getCodeCategory(code),
		"message":       message,
	}

	// Check for multiline response (code followed by dash)
	if len(firstLine) > 3 && firstLine[3] == '-' {
		metadata["multiline"] = true
	}

	// Calculate confidence
	confidence := f.calculateConfidence(ctx, metadata, true)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.SrcPort, []uint16{21})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.DstPort, []uint16{21})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "FTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (f *FTPSignature) detectCommand(ctx *signatures.DetectionContext, payload string) *signatures.DetectionResult {
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

	// Calculate confidence
	confidence := f.calculateConfidence(ctx, metadata, false)

	// Port-based confidence adjustment
	portFactor := signatures.PortBasedConfidence(ctx.DstPort, []uint16{21})
	if portFactor < 1.0 {
		portFactor = signatures.PortBasedConfidence(ctx.SrcPort, []uint16{21})
	}
	confidence = signatures.AdjustConfidenceByContext(confidence, map[string]float64{
		"port": portFactor,
	})

	return &signatures.DetectionResult{
		Protocol:    "FTP",
		Confidence:  confidence,
		Metadata:    metadata,
		ShouldCache: true,
	}
}

func (f *FTPSignature) calculateConfidence(ctx *signatures.DetectionContext, metadata map[string]interface{}, isResponse bool) float64 {
	indicators := []signatures.Indicator{}

	if isResponse {
		// Valid FTP response code
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_response_code",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})
	} else {
		// Valid FTP command
		indicators = append(indicators, signatures.Indicator{
			Name:       "valid_command",
			Weight:     0.6,
			Confidence: signatures.ConfidenceHigh,
		})
	}

	// TCP transport (FTP control is always TCP)
	if ctx.Transport == "TCP" {
		indicators = append(indicators, signatures.Indicator{
			Name:       "tcp_transport",
			Weight:     0.4,
			Confidence: signatures.ConfidenceMedium,
		})
	}

	return signatures.ScoreDetection(indicators)
}

func (f *FTPSignature) getCodeCategory(code int) string {
	switch code / 100 {
	case 1:
		return "Positive Preliminary"
	case 2:
		return "Positive Completion"
	case 3:
		return "Positive Intermediate"
	case 4:
		return "Transient Negative Completion"
	case 5:
		return "Permanent Negative Completion"
	default:
		return "Unknown"
	}
}

func (f *FTPSignature) isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

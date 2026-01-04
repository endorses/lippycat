package email

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// Parser extracts SMTP metadata from packet payloads.
type Parser struct {
	emailRegex   *regexp.Regexp
	messageIDReg *regexp.Regexp
	subjectReg   *regexp.Regexp
}

// NewParser creates a new SMTP parser.
func NewParser() *Parser {
	return &Parser{
		emailRegex:   regexp.MustCompile(`<([^>]+)>`),
		messageIDReg: regexp.MustCompile(`(?i)^Message-ID:\s*<?([^>\s]+)>?`),
		subjectReg:   regexp.MustCompile(`(?i)^Subject:\s*(.+)`),
	}
}

// ParseLine parses a single SMTP line and updates the metadata.
// Returns true if the line was recognized as SMTP protocol.
func (p *Parser) ParseLine(line string, metadata *types.EmailMetadata, isFromServer bool) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}

	metadata.IsServer = isFromServer
	metadata.Protocol = "SMTP"
	metadata.Timestamp = time.Now()

	if isFromServer {
		return p.parseServerResponse(line, metadata)
	}
	return p.parseClientCommand(line, metadata)
}

// parseServerResponse parses SMTP server responses (e.g., "220 mail.example.com ESMTP").
func (p *Parser) parseServerResponse(line string, metadata *types.EmailMetadata) bool {
	// SMTP responses start with 3-digit code
	if len(line) < 3 {
		return false
	}

	// Check if first 3 characters are digits
	if !isDigit(line[0]) || !isDigit(line[1]) || !isDigit(line[2]) {
		return false
	}

	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return false
	}

	metadata.ResponseCode = code

	// Extract response text (after code and space/dash)
	if len(line) > 4 {
		metadata.ResponseText = strings.TrimSpace(line[4:])
	}

	// Check for specific responses
	switch code {
	case 220:
		// Server greeting or TLS ready
		metadata.ServerBanner = metadata.ResponseText
		// Check if this is a TLS ready response
		if strings.Contains(strings.ToUpper(metadata.ResponseText), "TLS") {
			metadata.Encrypted = true
		}
	case 250:
		// Check for STARTTLS capability in EHLO response
		if strings.Contains(strings.ToUpper(metadata.ResponseText), "STARTTLS") {
			metadata.STARTTLSOffered = true
		}
	case 354:
		// Start of DATA
		metadata.Command = "DATA"
	}

	return true
}

// parseClientCommand parses SMTP client commands (e.g., "MAIL FROM:<user@example.com>").
func (p *Parser) parseClientCommand(line string, metadata *types.EmailMetadata) bool {
	upperLine := strings.ToUpper(line)

	// Parse command
	switch {
	case strings.HasPrefix(upperLine, "HELO "):
		metadata.Command = "HELO"
		metadata.ClientHelo = strings.TrimSpace(line[5:])
		return true

	case strings.HasPrefix(upperLine, "EHLO "):
		metadata.Command = "EHLO"
		metadata.ClientHelo = strings.TrimSpace(line[5:])
		return true

	case strings.HasPrefix(upperLine, "MAIL FROM:"):
		metadata.Command = "MAIL"
		addr := p.extractEmailAddress(line[10:])
		if addr != "" {
			metadata.MailFrom = addr
		}
		// Check for SIZE parameter
		if idx := strings.Index(upperLine, "SIZE="); idx != -1 {
			sizeStr := line[idx+5:]
			if spaceIdx := strings.IndexAny(sizeStr, " \t"); spaceIdx != -1 {
				sizeStr = sizeStr[:spaceIdx]
			}
			if size, err := strconv.Atoi(sizeStr); err == nil {
				metadata.MessageSize = size
			}
		}
		return true

	case strings.HasPrefix(upperLine, "RCPT TO:"):
		metadata.Command = "RCPT"
		addr := p.extractEmailAddress(line[8:])
		if addr != "" {
			metadata.RcptTo = append(metadata.RcptTo, addr)
		}
		return true

	case strings.HasPrefix(upperLine, "DATA"):
		metadata.Command = "DATA"
		return true

	case strings.HasPrefix(upperLine, "STARTTLS"):
		metadata.Command = "STARTTLS"
		metadata.STARTTLSRequested = true
		return true

	case strings.HasPrefix(upperLine, "AUTH "):
		metadata.Command = "AUTH"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			metadata.AuthMethod = strings.ToUpper(parts[1])
		}
		return true

	case strings.HasPrefix(upperLine, "RSET"):
		metadata.Command = "RSET"
		return true

	case strings.HasPrefix(upperLine, "QUIT"):
		metadata.Command = "QUIT"
		return true

	case strings.HasPrefix(upperLine, "NOOP"):
		metadata.Command = "NOOP"
		return true

	case strings.HasPrefix(upperLine, "VRFY "):
		metadata.Command = "VRFY"
		return true

	case strings.HasPrefix(upperLine, "EXPN "):
		metadata.Command = "EXPN"
		return true

	case strings.HasPrefix(upperLine, "HELP"):
		metadata.Command = "HELP"
		return true
	}

	return false
}

// ParseDataHeader parses headers from the DATA section of an SMTP message.
func (p *Parser) ParseDataHeader(line string, metadata *types.EmailMetadata) {
	// Check for Message-ID
	if match := p.messageIDReg.FindStringSubmatch(line); match != nil {
		metadata.MessageID = match[1]
	}

	// Check for Subject
	if match := p.subjectReg.FindStringSubmatch(line); match != nil {
		metadata.Subject = strings.TrimSpace(match[1])
	}
}

// extractEmailAddress extracts an email address from MAIL FROM or RCPT TO parameters.
func (p *Parser) extractEmailAddress(s string) string {
	s = strings.TrimSpace(s)

	// Try to extract from angle brackets
	if match := p.emailRegex.FindStringSubmatch(s); match != nil {
		return match[1]
	}

	// If no brackets, try to find bare address
	if idx := strings.Index(s, " "); idx != -1 {
		s = s[:idx]
	}
	s = strings.Trim(s, "<>")

	if strings.Contains(s, "@") {
		return s
	}

	return ""
}

// isDigit checks if a byte is a digit.
func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// FormatInfo creates a human-readable info string from email metadata.
func FormatInfo(metadata *types.EmailMetadata) string {
	if metadata == nil {
		return ""
	}

	var parts []string

	if metadata.IsServer {
		// Server response
		if metadata.ResponseCode > 0 {
			parts = append(parts, strconv.Itoa(metadata.ResponseCode))
		}
		if metadata.ResponseText != "" {
			// Truncate long response text
			text := metadata.ResponseText
			if len(text) > 50 {
				text = text[:50] + "..."
			}
			parts = append(parts, text)
		}
	} else {
		// Client command
		if metadata.Command != "" {
			parts = append(parts, metadata.Command)
		}
		if metadata.MailFrom != "" {
			parts = append(parts, "FROM:"+metadata.MailFrom)
		}
		if len(metadata.RcptTo) > 0 {
			parts = append(parts, "TO:"+metadata.RcptTo[0])
			if len(metadata.RcptTo) > 1 {
				parts = append(parts, "(+"+strconv.Itoa(len(metadata.RcptTo)-1)+")")
			}
		}
	}

	return strings.Join(parts, " ")
}

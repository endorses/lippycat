package email

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// POP3Parser extracts POP3 metadata from packet payloads.
type POP3Parser struct {
	// Regex patterns for parsing
	okRe        *regexp.Regexp // +OK [message]
	errRe       *regexp.Regexp // -ERR [message]
	statRe      *regexp.Regexp // +OK nn mm (STAT response)
	listRe      *regexp.Regexp // nn mm (LIST response line)
	uidlRe      *regexp.Regexp // nn unique-id (UIDL response line)
	messageIDRe *regexp.Regexp // Message-ID: <...>
	subjectRe   *regexp.Regexp // Subject: ...
	fromRe      *regexp.Regexp // From: ...
	toRe        *regexp.Regexp // To: ...
}

// NewPOP3Parser creates a new POP3 parser.
func NewPOP3Parser() *POP3Parser {
	return &POP3Parser{
		okRe:        regexp.MustCompile(`^\+OK\s*(.*)$`),
		errRe:       regexp.MustCompile(`^-ERR\s*(.*)$`),
		statRe:      regexp.MustCompile(`^\+OK\s+(\d+)\s+(\d+)`),
		listRe:      regexp.MustCompile(`^(\d+)\s+(\d+)$`),
		uidlRe:      regexp.MustCompile(`^(\d+)\s+(\S+)$`),
		messageIDRe: regexp.MustCompile(`(?i)^Message-ID:\s*<?([^>\s]+)>?`),
		subjectRe:   regexp.MustCompile(`(?i)^Subject:\s*(.+)`),
		fromRe:      regexp.MustCompile(`(?i)^From:\s*(.+)`),
		toRe:        regexp.MustCompile(`(?i)^To:\s*(.+)`),
	}
}

// ParseLine parses a single POP3 line and updates the metadata.
// Returns true if the line was recognized as POP3 protocol.
func (p *POP3Parser) ParseLine(line string, metadata *types.EmailMetadata, isFromServer bool) bool {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return false
	}

	metadata.IsServer = isFromServer
	metadata.Protocol = "POP3"
	metadata.Timestamp = time.Now()

	if isFromServer {
		return p.parseServerResponse(line, metadata)
	}
	return p.parseClientCommand(line, metadata)
}

// parseServerResponse parses POP3 server responses.
// POP3 responses start with +OK or -ERR.
func (p *POP3Parser) parseServerResponse(line string, metadata *types.EmailMetadata) bool {
	// Check for +OK response
	if match := p.okRe.FindStringSubmatch(line); match != nil {
		metadata.POP3Status = "+OK"
		metadata.ResponseText = match[1]

		// Check for STAT response: +OK nn mm
		if statMatch := p.statRe.FindStringSubmatch(line); statMatch != nil {
			if count, err := strconv.ParseUint(statMatch[1], 10, 32); err == nil {
				metadata.POP3MsgCount = uint32(count)
			}
			if size, err := strconv.ParseUint(statMatch[2], 10, 64); err == nil {
				metadata.POP3TotalSize = size
			}
		}

		// Check for capability response
		upperText := strings.ToUpper(metadata.ResponseText)
		if strings.Contains(upperText, "STLS") || strings.Contains(upperText, "STARTTLS") {
			metadata.STARTTLSOffered = true
		}

		return true
	}

	// Check for -ERR response
	if match := p.errRe.FindStringSubmatch(line); match != nil {
		metadata.POP3Status = "-ERR"
		metadata.ResponseText = match[1]
		return true
	}

	// Check for multi-line response data
	// LIST response: nn mm
	if match := p.listRe.FindStringSubmatch(line); match != nil {
		if msgNum, err := strconv.ParseUint(match[1], 10, 32); err == nil {
			metadata.POP3MsgNum = uint32(msgNum)
		}
		if size, err := strconv.ParseUint(match[2], 10, 32); err == nil {
			metadata.POP3MsgSize = uint32(size)
		}
		return true
	}

	// UIDL response: nn unique-id
	if match := p.uidlRe.FindStringSubmatch(line); match != nil {
		if msgNum, err := strconv.ParseUint(match[1], 10, 32); err == nil {
			metadata.POP3MsgNum = uint32(msgNum)
		}
		// Could store unique-id in MessageID
		metadata.MessageID = match[2]
		return true
	}

	// Check for email headers in RETR/TOP response
	if match := p.messageIDRe.FindStringSubmatch(line); match != nil {
		metadata.MessageID = match[1]
		return true
	}
	if match := p.subjectRe.FindStringSubmatch(line); match != nil {
		metadata.Subject = strings.TrimSpace(match[1])
		return true
	}
	if match := p.fromRe.FindStringSubmatch(line); match != nil {
		addr := extractEmailAddr(match[1])
		if addr != "" {
			metadata.MailFrom = addr
		}
		return true
	}
	if match := p.toRe.FindStringSubmatch(line); match != nil {
		addr := extractEmailAddr(match[1])
		if addr != "" {
			metadata.RcptTo = append(metadata.RcptTo, addr)
		}
		return true
	}

	// Multi-line terminator
	if line == "." {
		return true
	}

	// Continuation of server response or message body
	return false
}

// parseClientCommand parses POP3 client commands.
// POP3 commands are simple: COMMAND [args]
func (p *POP3Parser) parseClientCommand(line string, metadata *types.EmailMetadata) bool {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 1 {
		return false
	}

	cmd := strings.ToUpper(parts[0])
	metadata.POP3Command = cmd
	metadata.Command = cmd // Also set generic Command field

	var args string
	if len(parts) >= 2 {
		args = parts[1]
	}

	switch cmd {
	case "USER":
		// USER username
		metadata.AuthUser = args
		metadata.AuthMethod = "USER/PASS"
		return true

	case "PASS":
		// PASS password (we don't log the password)
		return true

	case "APOP":
		// APOP username digest
		if argParts := strings.SplitN(args, " ", 2); len(argParts) >= 1 {
			metadata.AuthUser = argParts[0]
			metadata.AuthMethod = "APOP"
		}
		return true

	case "AUTH":
		// AUTH mechanism
		if args != "" {
			metadata.AuthMethod = args
		}
		return true

	case "STAT":
		// STAT - get mailbox status
		return true

	case "LIST":
		// LIST [msg] - list messages
		if args != "" {
			if msgNum, err := strconv.ParseUint(args, 10, 32); err == nil {
				metadata.POP3MsgNum = uint32(msgNum)
			}
		}
		return true

	case "UIDL":
		// UIDL [msg] - unique-id listing
		if args != "" {
			if msgNum, err := strconv.ParseUint(args, 10, 32); err == nil {
				metadata.POP3MsgNum = uint32(msgNum)
			}
		}
		return true

	case "RETR":
		// RETR msg - retrieve message
		if msgNum, err := strconv.ParseUint(args, 10, 32); err == nil {
			metadata.POP3MsgNum = uint32(msgNum)
		}
		return true

	case "DELE":
		// DELE msg - delete message
		if msgNum, err := strconv.ParseUint(args, 10, 32); err == nil {
			metadata.POP3MsgNum = uint32(msgNum)
		}
		return true

	case "TOP":
		// TOP msg n - get headers + n lines
		argParts := strings.Fields(args)
		if len(argParts) >= 1 {
			if msgNum, err := strconv.ParseUint(argParts[0], 10, 32); err == nil {
				metadata.POP3MsgNum = uint32(msgNum)
			}
		}
		return true

	case "RSET":
		// RSET - reset deleted messages
		return true

	case "NOOP":
		// NOOP - no operation
		return true

	case "QUIT":
		// QUIT - end session
		return true

	case "CAPA":
		// CAPA - request capabilities
		return true

	case "STLS":
		// STLS - start TLS
		metadata.STARTTLSRequested = true
		return true
	}

	// Unknown command
	return false
}

// extractEmailAddr extracts an email address from a header value.
func extractEmailAddr(s string) string {
	s = strings.TrimSpace(s)

	// Try to find address in angle brackets: "Name <addr@example.com>"
	start := strings.LastIndex(s, "<")
	end := strings.LastIndex(s, ">")
	if start != -1 && end > start {
		return s[start+1 : end]
	}

	// Try to find bare address
	if strings.Contains(s, "@") {
		// Remove any quotes or surrounding whitespace
		s = strings.Trim(s, "\"' \t")
		// If there's a space (like "Name addr@example.com"), take the part with @
		parts := strings.Fields(s)
		for _, part := range parts {
			if strings.Contains(part, "@") {
				return strings.Trim(part, "<>\"'")
			}
		}
	}

	return ""
}

// FormatPOP3Info creates a human-readable info string from POP3 metadata.
func FormatPOP3Info(metadata *types.EmailMetadata) string {
	if metadata == nil || metadata.Protocol != "POP3" {
		return ""
	}

	var parts []string

	if metadata.IsServer {
		// Server response
		if metadata.POP3Status != "" {
			parts = append(parts, metadata.POP3Status)
		}
		if metadata.POP3MsgCount > 0 {
			parts = append(parts, strconv.FormatUint(uint64(metadata.POP3MsgCount), 10)+" messages")
		}
		if metadata.POP3MsgNum > 0 && metadata.POP3MsgSize > 0 {
			parts = append(parts, "msg "+strconv.FormatUint(uint64(metadata.POP3MsgNum), 10)+
				" ("+strconv.FormatUint(uint64(metadata.POP3MsgSize), 10)+" bytes)")
		}
		if metadata.ResponseText != "" && len(parts) < 2 {
			text := metadata.ResponseText
			if len(text) > 40 {
				text = text[:40] + "..."
			}
			parts = append(parts, text)
		}
	} else {
		// Client command
		if metadata.POP3Command != "" {
			parts = append(parts, metadata.POP3Command)
		}
		if metadata.POP3MsgNum > 0 {
			parts = append(parts, strconv.FormatUint(uint64(metadata.POP3MsgNum), 10))
		}
		if metadata.AuthUser != "" {
			parts = append(parts, "user:"+metadata.AuthUser)
		}
	}

	return strings.Join(parts, " ")
}

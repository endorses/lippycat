package email

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// IMAPParser extracts IMAP metadata from packet payloads.
type IMAPParser struct {
	// Regex patterns for parsing
	taggedRespRe  *regexp.Regexp // Tagged response: A001 OK ...
	untaggedRe    *regexp.Regexp // Untagged response: * ...
	existsRe      *regexp.Regexp // * 23 EXISTS
	recentRe      *regexp.Regexp // * 5 RECENT
	fetchRe       *regexp.Regexp // * 1 FETCH (...)
	flagsRe       *regexp.Regexp // FLAGS (\Seen \Answered ...)
	uidNextRe     *regexp.Regexp // UIDNEXT 12345
	uidValidityRe *regexp.Regexp // UIDVALIDITY 12345
	messageIDRe   *regexp.Regexp // Message-ID: <...>
	subjectRe     *regexp.Regexp // Subject: ...
}

// NewIMAPParser creates a new IMAP parser.
func NewIMAPParser() *IMAPParser {
	return &IMAPParser{
		taggedRespRe:  regexp.MustCompile(`^([A-Za-z0-9]+)\s+(OK|NO|BAD)\s*(.*)$`),
		untaggedRe:    regexp.MustCompile(`^\*\s+(.+)$`),
		existsRe:      regexp.MustCompile(`(?i)^(\d+)\s+EXISTS$`),
		recentRe:      regexp.MustCompile(`(?i)^(\d+)\s+RECENT$`),
		fetchRe:       regexp.MustCompile(`(?i)^(\d+)\s+FETCH\s+\((.+)\)$`),
		flagsRe:       regexp.MustCompile(`(?i)FLAGS\s+\(([^)]*)\)`),
		uidNextRe:     regexp.MustCompile(`(?i)UIDNEXT\s+(\d+)`),
		uidValidityRe: regexp.MustCompile(`(?i)UIDVALIDITY\s+(\d+)`),
		messageIDRe:   regexp.MustCompile(`(?i)^Message-ID:\s*<?([^>\s]+)>?`),
		subjectRe:     regexp.MustCompile(`(?i)^Subject:\s*(.+)`),
	}
}

// ParseLine parses a single IMAP line and updates the metadata.
// Returns true if the line was recognized as IMAP protocol.
func (p *IMAPParser) ParseLine(line string, metadata *types.EmailMetadata, isFromServer bool) bool {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return false
	}

	metadata.IsServer = isFromServer
	metadata.Protocol = "IMAP"
	metadata.Timestamp = time.Now()

	if isFromServer {
		return p.parseServerResponse(line, metadata)
	}
	return p.parseClientCommand(line, metadata)
}

// parseServerResponse parses IMAP server responses.
// IMAP responses can be:
// - Untagged: * OK/NO/BAD/PREAUTH/BYE ...
// - Untagged data: * 23 EXISTS, * 5 RECENT, * 1 FETCH ...
// - Tagged: A001 OK/NO/BAD ...
// - Continuation: + ...
func (p *IMAPParser) parseServerResponse(line string, metadata *types.EmailMetadata) bool {
	// Check for continuation response
	if strings.HasPrefix(line, "+ ") {
		metadata.IMAPStatus = "CONTINUE"
		metadata.ResponseText = strings.TrimPrefix(line, "+ ")
		return true
	}

	// Check for untagged response (* ...)
	if strings.HasPrefix(line, "* ") {
		return p.parseUntaggedResponse(line[2:], metadata)
	}

	// Check for tagged response (A001 OK ...)
	if match := p.taggedRespRe.FindStringSubmatch(line); match != nil {
		metadata.IMAPTag = match[1]
		metadata.IMAPStatus = match[2]
		metadata.ResponseText = match[3]
		metadata.Correlated = true
		return true
	}

	// Check for literal data (part of FETCH response body)
	// This might contain email headers
	if match := p.messageIDRe.FindStringSubmatch(line); match != nil {
		metadata.MessageID = match[1]
		return true
	}
	if match := p.subjectRe.FindStringSubmatch(line); match != nil {
		metadata.Subject = strings.TrimSpace(match[1])
		return true
	}

	return false
}

// parseUntaggedResponse parses untagged IMAP responses (after "* ").
func (p *IMAPParser) parseUntaggedResponse(line string, metadata *types.EmailMetadata) bool {
	// Check for EXISTS
	if match := p.existsRe.FindStringSubmatch(line); match != nil {
		if count, err := strconv.ParseUint(match[1], 10, 32); err == nil {
			metadata.IMAPExists = uint32(count)
		}
		return true
	}

	// Check for RECENT
	if match := p.recentRe.FindStringSubmatch(line); match != nil {
		if count, err := strconv.ParseUint(match[1], 10, 32); err == nil {
			metadata.IMAPRecent = uint32(count)
		}
		return true
	}

	// Check for FETCH response
	if match := p.fetchRe.FindStringSubmatch(line); match != nil {
		if seqNum, err := strconv.ParseUint(match[1], 10, 32); err == nil {
			metadata.IMAPSeqNum = uint32(seqNum)
		}
		p.parseFetchData(match[2], metadata)
		return true
	}

	// Check for untagged status responses
	upperLine := strings.ToUpper(line)
	switch {
	case strings.HasPrefix(upperLine, "OK "):
		metadata.IMAPStatus = "OK"
		metadata.ResponseText = line[3:]
		p.parseStatusData(metadata.ResponseText, metadata)
		return true
	case strings.HasPrefix(upperLine, "NO "):
		metadata.IMAPStatus = "NO"
		metadata.ResponseText = line[3:]
		return true
	case strings.HasPrefix(upperLine, "BAD "):
		metadata.IMAPStatus = "BAD"
		metadata.ResponseText = line[4:]
		return true
	case strings.HasPrefix(upperLine, "PREAUTH "):
		metadata.IMAPStatus = "PREAUTH"
		metadata.ResponseText = line[8:]
		metadata.ServerBanner = line[8:]
		return true
	case strings.HasPrefix(upperLine, "BYE "):
		metadata.IMAPStatus = "BYE"
		metadata.ResponseText = line[4:]
		return true
	case strings.HasPrefix(upperLine, "CAPABILITY "):
		// Server capabilities
		metadata.ResponseText = line[11:]
		// Check for STARTTLS capability
		if strings.Contains(upperLine, "STARTTLS") {
			metadata.STARTTLSOffered = true
		}
		return true
	case strings.HasPrefix(upperLine, "FLAGS "):
		// Mailbox flags
		if match := p.flagsRe.FindStringSubmatch(line); match != nil {
			metadata.IMAPFlags = parseFlags(match[1])
		}
		return true
	case strings.HasPrefix(upperLine, "LIST "):
		// Mailbox list response
		metadata.ResponseText = line[5:]
		return true
	case strings.HasPrefix(upperLine, "LSUB "):
		// Subscribed mailbox list
		metadata.ResponseText = line[5:]
		return true
	case strings.HasPrefix(upperLine, "SEARCH "):
		// Search results (UIDs or sequence numbers)
		metadata.ResponseText = line[7:]
		return true
	}

	// Generic untagged response
	metadata.ResponseText = line
	return true
}

// parseFetchData parses the content inside a FETCH response parentheses.
func (p *IMAPParser) parseFetchData(data string, metadata *types.EmailMetadata) {
	// Parse FLAGS
	if match := p.flagsRe.FindStringSubmatch(data); match != nil {
		metadata.IMAPFlags = parseFlags(match[1])
	}

	// Parse UID
	uidRe := regexp.MustCompile(`(?i)UID\s+(\d+)`)
	if match := uidRe.FindStringSubmatch(data); match != nil {
		if uid, err := strconv.ParseUint(match[1], 10, 32); err == nil {
			metadata.IMAPUID = uint32(uid)
		}
	}

	// Parse RFC822.SIZE or BODY.SIZE
	sizeRe := regexp.MustCompile(`(?i)(?:RFC822\.SIZE|BODY\.SIZE)\s+(\d+)`)
	if match := sizeRe.FindStringSubmatch(data); match != nil {
		if size, err := strconv.Atoi(match[1]); err == nil {
			metadata.MessageSize = size
		}
	}

	// Parse ENVELOPE for subject
	envRe := regexp.MustCompile(`(?i)ENVELOPE\s+\(([^)]+)\)`)
	if match := envRe.FindStringSubmatch(data); match != nil {
		// ENVELOPE format: (date subject from sender reply-to to cc bcc in-reply-to message-id)
		// Subject is the second element
		parts := parseEnvelopeParts(match[1])
		if len(parts) >= 2 && parts[1] != "NIL" {
			metadata.Subject = unquoteIMAPString(parts[1])
		}
		// Message-ID is the last element (10th, index 9)
		if len(parts) >= 10 && parts[9] != "NIL" {
			metadata.MessageID = unquoteIMAPString(parts[9])
		}
	}
}

// parseStatusData parses data from OK response brackets [...]
func (p *IMAPParser) parseStatusData(data string, metadata *types.EmailMetadata) {
	// Look for bracketed response codes
	if !strings.HasPrefix(data, "[") {
		return
	}
	endBracket := strings.Index(data, "]")
	if endBracket == -1 {
		return
	}
	bracketContent := data[1:endBracket]

	// Parse UIDNEXT
	if match := p.uidNextRe.FindStringSubmatch(bracketContent); match != nil {
		if uid, err := strconv.ParseUint(match[1], 10, 32); err == nil {
			metadata.IMAPUIDNext = uint32(uid)
		}
	}

	// Parse UIDVALIDITY
	if match := p.uidValidityRe.FindStringSubmatch(bracketContent); match != nil {
		if uid, err := strconv.ParseUint(match[1], 10, 32); err == nil {
			metadata.IMAPUIDValidity = uint32(uid)
		}
	}

	// Check for READ-WRITE/READ-ONLY
	if strings.Contains(strings.ToUpper(bracketContent), "READ-ONLY") {
		// Could track this in metadata if needed
	}
}

// parseClientCommand parses IMAP client commands.
func (p *IMAPParser) parseClientCommand(line string, metadata *types.EmailMetadata) bool {
	// IMAP commands are: TAG COMMAND [args]
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return false
	}

	metadata.IMAPTag = parts[0]
	cmd := strings.ToUpper(parts[1])
	metadata.IMAPCommand = cmd
	metadata.Command = cmd // Also set generic Command field

	var args string
	if len(parts) >= 3 {
		args = parts[2]
	}

	switch cmd {
	case "LOGIN":
		metadata.AuthMethod = "LOGIN"
		// LOGIN username password
		if argParts := strings.SplitN(args, " ", 2); len(argParts) >= 1 {
			metadata.AuthUser = unquoteIMAPString(argParts[0])
		}
		return true

	case "AUTHENTICATE":
		// AUTHENTICATE mechanism [initial-response]
		if argParts := strings.SplitN(args, " ", 2); len(argParts) >= 1 {
			metadata.AuthMethod = argParts[0]
		}
		return true

	case "SELECT", "EXAMINE":
		// SELECT/EXAMINE mailbox
		metadata.IMAPMailbox = unquoteIMAPString(args)
		return true

	case "CREATE", "DELETE", "RENAME", "SUBSCRIBE", "UNSUBSCRIBE":
		// Mailbox management commands
		metadata.IMAPMailbox = unquoteIMAPString(args)
		return true

	case "LIST", "LSUB":
		// LIST reference mailbox
		// List mailboxes
		return true

	case "STATUS":
		// STATUS mailbox (items)
		if idx := strings.Index(args, " "); idx != -1 {
			metadata.IMAPMailbox = unquoteIMAPString(args[:idx])
		}
		return true

	case "APPEND":
		// APPEND mailbox [flags] [date-time] literal
		if idx := strings.Index(args, " "); idx != -1 {
			metadata.IMAPMailbox = unquoteIMAPString(args[:idx])
		}
		return true

	case "FETCH":
		// FETCH sequence-set items
		p.parseFetchCommand(args, metadata)
		return true

	case "UID":
		// UID FETCH/STORE/SEARCH/COPY sequence-set ...
		if argParts := strings.SplitN(args, " ", 2); len(argParts) >= 1 {
			metadata.IMAPCommand = "UID " + argParts[0]
			metadata.Command = "UID " + argParts[0]
			if len(argParts) >= 2 && strings.ToUpper(argParts[0]) == "FETCH" {
				p.parseFetchCommand(argParts[1], metadata)
			}
		}
		return true

	case "STORE":
		// STORE sequence-set flags
		return true

	case "COPY", "MOVE":
		// COPY/MOVE sequence-set mailbox
		if argParts := strings.Fields(args); len(argParts) >= 2 {
			metadata.IMAPMailbox = unquoteIMAPString(argParts[len(argParts)-1])
		}
		return true

	case "SEARCH":
		// SEARCH [CHARSET charset] search-criteria
		return true

	case "EXPUNGE":
		// EXPUNGE - permanently remove deleted messages
		return true

	case "CLOSE":
		// CLOSE - close mailbox and expunge deleted
		return true

	case "NOOP":
		// NOOP - no operation (keepalive)
		return true

	case "LOGOUT":
		// LOGOUT - end session
		return true

	case "CAPABILITY":
		// CAPABILITY - request capabilities
		return true

	case "STARTTLS":
		metadata.STARTTLSRequested = true
		return true

	case "IDLE":
		// IDLE - wait for server notifications
		return true

	case "DONE":
		// DONE - end IDLE
		metadata.IMAPCommand = "DONE"
		metadata.Command = "DONE"
		return true

	case "CHECK":
		// CHECK - request checkpoint
		return true

	case "GETQUOTAROOT", "GETQUOTA", "SETQUOTA":
		// Quota commands
		return true

	case "SETACL", "DELETEACL", "GETACL", "LISTRIGHTS", "MYRIGHTS":
		// ACL commands
		return true

	case "NAMESPACE":
		// NAMESPACE command
		return true

	case "ID":
		// ID command (client identification)
		return true
	}

	// Unknown command but still looks like IMAP (has tag)
	return true
}

// parseFetchCommand parses the arguments to a FETCH command.
func (p *IMAPParser) parseFetchCommand(args string, metadata *types.EmailMetadata) {
	// Format: sequence-set items
	// e.g., "1:* (FLAGS)", "1,2,3 BODY[]", "1 (UID FLAGS BODY.PEEK[HEADER])"
	parts := strings.SplitN(args, " ", 2)
	if len(parts) >= 1 {
		// Parse sequence set - could be a single number
		seqSet := parts[0]
		if !strings.ContainsAny(seqSet, ":,*") {
			if num, err := strconv.ParseUint(seqSet, 10, 32); err == nil {
				metadata.IMAPSeqNum = uint32(num)
			}
		}
	}
}

// parseFlags parses IMAP flags from a space-separated list.
func parseFlags(flagStr string) []string {
	flagStr = strings.TrimSpace(flagStr)
	if flagStr == "" {
		return nil
	}
	flags := strings.Fields(flagStr)
	return flags
}

// parseEnvelopeParts attempts to parse envelope parts.
// This is a simplified parser - full ENVELOPE parsing is complex.
func parseEnvelopeParts(envelope string) []string {
	var parts []string
	var current strings.Builder
	depth := 0
	inQuote := false

	for i := 0; i < len(envelope); i++ {
		c := envelope[i]
		switch {
		case c == '"' && (i == 0 || envelope[i-1] != '\\'):
			inQuote = !inQuote
			current.WriteByte(c)
		case c == '(' && !inQuote:
			depth++
			current.WriteByte(c)
		case c == ')' && !inQuote:
			depth--
			current.WriteByte(c)
		case c == ' ' && depth == 0 && !inQuote:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// unquoteIMAPString removes IMAP string quoting.
func unquoteIMAPString(s string) string {
	s = strings.TrimSpace(s)
	if s == "NIL" || s == "nil" {
		return ""
	}
	// Remove surrounding quotes
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	// Unescape backslash-quoted characters
	s = strings.ReplaceAll(s, "\\\"", "\"")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}

// FormatIMAPInfo creates a human-readable info string from IMAP metadata.
func FormatIMAPInfo(metadata *types.EmailMetadata) string {
	if metadata == nil || metadata.Protocol != "IMAP" {
		return ""
	}

	var parts []string

	if metadata.IsServer {
		// Server response
		if metadata.IMAPTag != "" {
			parts = append(parts, metadata.IMAPTag)
		}
		if metadata.IMAPStatus != "" {
			parts = append(parts, metadata.IMAPStatus)
		}
		if metadata.IMAPExists > 0 {
			parts = append(parts, strconv.FormatUint(uint64(metadata.IMAPExists), 10)+" EXISTS")
		}
		if metadata.IMAPRecent > 0 {
			parts = append(parts, strconv.FormatUint(uint64(metadata.IMAPRecent), 10)+" RECENT")
		}
		if metadata.ResponseText != "" && len(parts) < 3 {
			text := metadata.ResponseText
			if len(text) > 40 {
				text = text[:40] + "..."
			}
			parts = append(parts, text)
		}
	} else {
		// Client command
		if metadata.IMAPTag != "" {
			parts = append(parts, metadata.IMAPTag)
		}
		if metadata.IMAPCommand != "" {
			parts = append(parts, metadata.IMAPCommand)
		}
		if metadata.IMAPMailbox != "" {
			parts = append(parts, metadata.IMAPMailbox)
		}
		if metadata.AuthUser != "" {
			parts = append(parts, "user:"+metadata.AuthUser)
		}
	}

	return strings.Join(parts, " ")
}

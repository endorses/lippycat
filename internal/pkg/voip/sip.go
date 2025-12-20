package voip

import (
	"bytes"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/layers"
)

// extractUserFromSIPURI extracts the username from a SIP URI
// Example: "Alicent <sip:alicent@domain.com>" -> "alicent"
// Example: "sip:robb@example.org" -> "robb"
func extractUserFromSIPURI(uri string) string {
	// Find "sip:" or "sips:" prefix
	start := strings.Index(uri, "sip:")
	if start == -1 {
		start = strings.Index(uri, "sips:")
		if start == -1 {
			return ""
		}
		start += 5 // len("sips:")
	} else {
		start += 4 // len("sip:")
	}

	// Find the @ symbol
	end := strings.Index(uri[start:], "@")
	if end == -1 {
		return ""
	}

	return uri[start : start+end]
}

// extractFullSIPURI extracts the full SIP URI from a header value
// Example: "Alicent <sip:alicent@domain.com>;tag=123" -> "sip:alicent@domain.com"
// Example: "sip:robb@example.org" -> "sip:robb@example.org"
func extractFullSIPURI(header string) string {
	// Find the URI between < and > if present
	start := strings.Index(header, "<")
	if start != -1 {
		end := strings.Index(header[start:], ">")
		if end != -1 {
			return header[start+1 : start+end]
		}
	}

	// No angle brackets, find sip: or sips: prefix
	sipStart := strings.Index(header, "sip:")
	if sipStart == -1 {
		sipStart = strings.Index(header, "sips:")
		if sipStart == -1 {
			return ""
		}
	}

	// Find the end of the URI (space, semicolon, or newline)
	uri := header[sipStart:]
	for i, ch := range uri {
		if ch == ' ' || ch == ';' || ch == '\r' || ch == '\n' || ch == '>' {
			return uri[:i]
		}
	}

	return uri
}

// ExtractUserFromHeader extracts the username from a SIP header value (From, To, P-Asserted-Identity)
// This is the exported version for use by other packages.
// Example: "Alicent <sip:alicent@domain.com>;tag=123" -> "alicent"
// Example: "sip:+49123456789@domain.com" -> "+49123456789"
func ExtractUserFromHeader(header string) string {
	return extractUserFromSIPURI(header)
}

// ExtractUserFromHeaderBytes extracts the username from a SIP header value (byte slice version)
// This is optimized for the hunter's application filter which works with byte slices.
// Example: "Alicent <sip:alicent@domain.com>;tag=123" -> "alicent"
// Example: "sip:+49123456789@domain.com" -> "+49123456789"
func ExtractUserFromHeaderBytes(header []byte) string {
	return extractUserFromSIPURI(string(header))
}

// extractTagFromHeader extracts the tag parameter from a SIP From/To header
// Example: "Alicent <sip:alicent@domain.com>;tag=abc123" -> "abc123"
// Example: "<sip:user@host>;tag=xyz789;other=param" -> "xyz789"
// Returns empty string if no tag parameter found
func extractTagFromHeader(header string) string {
	// Look for ";tag=" parameter (case-insensitive)
	tagStart := strings.Index(strings.ToLower(header), ";tag=")
	if tagStart == -1 {
		return ""
	}

	// Start after ";tag="
	valueStart := tagStart + 5 // len(";tag=")
	if valueStart >= len(header) {
		return ""
	}

	// Find the end of the tag value (semicolon, space, or end of string)
	value := header[valueStart:]
	for i, ch := range value {
		if ch == ';' || ch == ' ' || ch == '\r' || ch == '\n' || ch == '>' {
			return value[:i]
		}
	}

	return value
}

func handleSipMessage(data []byte, linkType layers.LinkType) bool {
	logger.Debug("handleSipMessage called", "data_len", len(data))
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) == 0 {
		logger.Debug("handleSipMessage: no lines in data")
		return false
	}
	startLine := strings.TrimSpace(string(lines[0]))
	logger.Debug("handleSipMessage: checking start line", "start_line", startLine)
	if !isSipStartLine(startLine) {
		logger.Debug("handleSipMessage: not a SIP start line")
		return false
	}

	logger.Debug("handleSipMessage: parsing SIP headers")
	headers, body := parseSipHeaders(data)

	logger.Debug("handleSipMessage: checking user filter", "call_id", headers["call-id"])
	if containsUserInHeaders(headers) {
		callID := headers["call-id"]
		if callID != "" {
			// Truncate excessively long Call-IDs (for DoS protection)
			const maxCallIDLength = 1024
			if len(callID) > maxCallIDLength {
				logger.Warn("Truncating excessively long Call-ID",
					"original_length", len(callID),
					"truncated_length", maxCallIDLength,
					"source", "sip_processing")
				callID = callID[:maxCallIDLength]
				headers["call-id"] = callID
			}

			// Validate the Call-ID for security
			if err := ValidateCallIDForSecurity(callID); err != nil {
				logger.Warn("Malicious Call-ID detected and rejected",
					"call_id", SanitizeCallIDForLogging(callID),
					"error", err,
					"source", "sip_processing")
				return false
			}

			// Detect SIP method for state tracking
			method := detectSipMethod(startLine)

			// Update call state if call already exists
			// Note: In hunter mode, calls should be created separately for local tracking
			call, err := getCall(callID)
			if err == nil {
				call.SetCallInfoState(method)
			}

			// Extract RTP ports from SDP if present
			bodyBytes := StringToBytes(body)
			if BytesContains(bodyBytes, []byte("m=audio")) {
				ExtractPortFromSdp(body, callID)
			}
		}
		return true
	}
	return false
}

func detectSipMethod(line string) string {
	lineBytes := StringToBytes(line)

	// Use SIMD-optimized method matching if available
	return SIPMethodMatchSIMD(lineBytes)
}

// extractSipResponseCode extracts the response code from a SIP response message.
// Returns 0 if this is not a response or if the response code cannot be parsed.
// Example: "SIP/2.0 200 OK" returns 200
func extractSipResponseCode(payload []byte) uint32 {
	// SIP responses start with "SIP/2.0 <code>"
	// Minimum: "SIP/2.0 100" = 12 bytes
	if len(payload) < 12 {
		return 0
	}

	// Check if this is a SIP response (starts with "SIP/2.0 ")
	if !BytesHasPrefixString(payload, "SIP/2.0 ") {
		return 0
	}

	// Extract the status code (3 digits after "SIP/2.0 ")
	// Format: "SIP/2.0 <code> <reason>"
	codeStart := 8 // Length of "SIP/2.0 "
	if len(payload) < codeStart+3 {
		return 0
	}

	// Parse 3-digit response code
	code := uint32(0)
	for i := 0; i < 3; i++ {
		digit := payload[codeStart+i]
		if digit < '0' || digit > '9' {
			return 0 // Invalid response code
		}
		code = code*10 + uint32(digit-'0')
	}

	return code
}

func isSipStartLine(line string) bool {
	lineBytes := StringToBytes(line)

	// SIP responses start with SIP/2.0
	if BytesHasPrefixString(lineBytes, "SIP/2.0") {
		return true
	}

	// SIP requests must contain "SIP/2.0" at the end
	if !BytesContains(lineBytes, []byte("SIP/2.0")) {
		return false
	}

	// Check for valid SIP methods at the beginning
	return BytesHasPrefixString(lineBytes, "INVITE ") ||
		BytesHasPrefixString(lineBytes, "BYE ") ||
		BytesHasPrefixString(lineBytes, "ACK ") ||
		BytesHasPrefixString(lineBytes, "OPTIONS ") ||
		BytesHasPrefixString(lineBytes, "REGISTER ") ||
		BytesHasPrefixString(lineBytes, "CANCEL ")
}

func parseSipHeaders(data []byte) (map[string]string, string) {
	// Protect against buffer overflow by limiting input size
	const maxSipMessageSize = 65536 // 64KB limit for SIP messages
	if len(data) > maxSipMessageSize {
		logger.Debug("SIP message too large, truncating",
			"size", len(data),
			"max_size", maxSipMessageSize)
		data = data[:maxSipMessageSize]
	}

	headers := make(map[string]string)
	lines := bytes.Split(data, []byte("\n"))

	var bodyStart bool
	var bodyBuilder strings.Builder
	var isFirstLine = true
	var headerCount int
	const maxHeaders = 100 // Reasonable limit for SIP headers

	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			bodyStart = true
			continue
		}
		if !bodyStart {
			// Skip the first line (SIP request/response line)
			if isFirstLine {
				isFirstLine = false
				continue
			}

			// Prevent header overflow attacks
			if headerCount >= maxHeaders {
				logger.Debug("Too many SIP headers, ignoring remaining",
					"header_count", headerCount,
					"max_headers", maxHeaders)
				break
			}

			key, val := parseHeaderLineBytes(trimmed)
			if key != "" {
				headers[key] = val
				headerCount++
			}
		} else {
			// Convert to string only when building body
			bodyBuilder.Write(trimmed)
			bodyBuilder.WriteByte('\n')
		}
	}

	return headers, bodyBuilder.String()
}

func parseHeaderLine(line string) (string, string) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	key := strings.ToLower(strings.TrimSpace(parts[0]))
	if key == "" {
		return "", ""
	}

	// Normalize compact form headers to full form
	key = normalizeHeaderName(key)

	return key, strings.TrimSpace(parts[1])
}

// parseHeaderLineBytes parses a header line from bytes without intermediate string allocations
func parseHeaderLineBytes(line []byte) (string, string) {
	idx := bytes.IndexByte(line, ':')
	if idx == -1 {
		return "", ""
	}

	keyBytes := bytes.TrimSpace(line[:idx])
	if len(keyBytes) == 0 {
		return "", ""
	}

	// Convert to lowercase for key (unavoidable allocation for map key)
	key := strings.ToLower(string(keyBytes))

	// Normalize compact form headers to full form
	key = normalizeHeaderName(key)

	// Trim value bytes and convert to string (unavoidable allocation for map value)
	valBytes := bytes.TrimSpace(line[idx+1:])
	return key, string(valBytes)
}

// normalizeHeaderName converts SIP compact header names to their full form
func normalizeHeaderName(compact string) string {
	compactToFull := map[string]string{
		"i": "call-id",
		"f": "from",
		"t": "to",
		"v": "via",
		"c": "contact",
		"m": "contact", // m can also be contact in some contexts
		"l": "content-length",
		"x": "expires",
		"s": "subject",
		"k": "supported",
		"r": "refer-to",
		"b": "referred-by",
		"j": "reject-contact",
		"d": "request-disposition",
		"u": "allow-events",
		"o": "event",
		"a": "accept-contact",
		"n": "in-reply-to",
		"p": "p-access-network-info",
	}

	if full, exists := compactToFull[compact]; exists {
		return full
	}
	return compact
}

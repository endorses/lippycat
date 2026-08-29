package voip

import (
	"bytes"
	"strings"

	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
)

// extractUserFromSIPURI extracts the username from a SIP URI
// Example: "Alicent <sip:alicent@domain.com>" -> "alicent"
// Example: "sip:robb@example.org" -> "robb"
func extractUserFromSIPURI(uri string) string {
	return sharedsip.User(sharedsip.URI(uri))
}

// extractFullSIPURI extracts the full SIP URI from a header value
// Example: "Alicent <sip:alicent@domain.com>;tag=123" -> "sip:alicent@domain.com"
// Example: "sip:robb@example.org" -> "sip:robb@example.org"
func extractFullSIPURI(header string) string {
	return sharedsip.URI(header)
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

// extractURIFromSIPHeader extracts user@domain from a SIP URI (without the sip: prefix)
// Example: "Alicent <sip:alicent@domain.com>;tag=123" -> "alicent@domain.com"
// Example: "sip:robb@example.org" -> "robb@example.org"
func extractURIFromSIPHeader(header string) string {
	// Get the full SIP URI first (e.g., "sip:alice@domain.com")
	fullURI := extractFullSIPURI(header)
	if fullURI == "" {
		return ""
	}

	// Strip the sip: or sips: prefix to get user@domain
	if strings.HasPrefix(fullURI, "sips:") {
		return fullURI[5:]
	}
	if strings.HasPrefix(fullURI, "sip:") {
		return fullURI[4:]
	}
	return fullURI
}

// ExtractURIFromHeader extracts user@domain from a SIP header value (From, To, P-Asserted-Identity)
// This is used for SIPURI filter matching where the full identity is needed.
// Example: "Alicent <sip:alicent@domain.com>;tag=123" -> "alicent@domain.com"
// Example: "sip:+49123456789@carrier.com" -> "+49123456789@carrier.com"
func ExtractURIFromHeader(header string) string {
	return extractURIFromSIPHeader(header)
}

// ExtractURIFromHeaderBytes extracts user@domain from a SIP header value (byte slice version)
// This is optimized for the hunter's application filter which works with byte slices.
// Example: "Alicent <sip:alicent@domain.com>;tag=123" -> "alicent@domain.com"
// Example: "sip:+49123456789@carrier.com" -> "+49123456789@carrier.com"
func ExtractURIFromHeaderBytes(header []byte) string {
	return extractURIFromSIPHeader(string(header))
}

// extractTagFromHeader extracts the tag parameter from a SIP From/To header
// Example: "Alicent <sip:alicent@domain.com>;tag=abc123" -> "abc123"
// Example: "<sip:user@host>;tag=xyz789;other=param" -> "xyz789"
// Returns empty string if no tag parameter found
func extractTagFromHeader(header string) string {
	return sharedsip.Tag(header)
}

func detectSipMethod(line string) string {
	event, err := sharedsip.Parse([]byte(line), sharedsip.ParseOptions{})
	if err == nil {
		return event.Method
	}
	return ""
}

// extractCSeqMethod returns the method token from a CSeq header value.
// SIP CSeq is "<sequence-number> <method>" (RFC 3261 §8.1.1.5), e.g.
// "1 INVITE" -> "INVITE". Returns "" when the value is empty or malformed.
// The method lets a SIP response — whose status line carries no method of
// its own — still be attributed to its originating transaction, so a call
// first observed via a response (capture started mid-call, or packets
// reordered) can still be classified.
func extractCSeqMethod(cseq string) string {
	return sharedsip.CSeqMethod(cseq)
}

// extractSipResponseCode extracts the response code from a SIP response message.
// Returns 0 if this is not a response or if the response code cannot be parsed.
// Example: "SIP/2.0 200 OK" returns 200
func extractSipResponseCode(payload []byte) uint32 {
	if event, err := sharedsip.Parse(payload, sharedsip.ParseOptions{}); err == nil {
		return uint32(event.ResponseCode)
	}
	return 0
}

func isSipStartLine(line string) bool {
	return sharedsip.IsStartLine(line)
}

func parseSipHeaders(data []byte) (map[string]string, string) {
	if event, err := sharedsip.Parse(data, sharedsip.ParseOptions{}); err == nil {
		body := string(event.Body)
		if body != "" && !strings.HasSuffix(body, "\n") {
			body += "\n" // retain the legacy helper contract during migration
		}
		return event.Headers, body
	}
	return map[string]string{}, ""
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
	if full, exists := sharedsip.CompactHeaders[compact]; exists {
		return full
	}
	return compact
}

// ExtractIMSI extracts the IMSI from SIP headers.
// IMSI can be found in:
// - Authorization header username (format: <IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org)
// - P-Asserted-Identity header (same format)
// Returns empty string if not found or invalid.
// Example: "310260123456789@ims.mnc260.mcc310.3gppnetwork.org" -> "310260123456789"
func ExtractIMSI(authHeader, paiHeader string) string {
	// Try Authorization header first (username=)
	if authHeader != "" {
		if imsi := extractIMSIFromAuth(authHeader); imsi != "" {
			return imsi
		}
	}

	// Try P-Asserted-Identity header
	if paiHeader != "" {
		if imsi := extractIMSIFromURI(paiHeader); imsi != "" {
			return imsi
		}
	}

	return ""
}

// extractIMSIFromAuth extracts IMSI from Authorization header.
// Authorization header format: Digest username="<IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org", ...
func extractIMSIFromAuth(header string) string {
	// Find username="..."
	usernameStart := strings.Index(strings.ToLower(header), "username=")
	if usernameStart == -1 {
		return ""
	}

	// Skip past "username="
	valueStart := usernameStart + 9 // len("username=")
	if valueStart >= len(header) {
		return ""
	}

	// Handle quoted and unquoted values
	var value string
	if header[valueStart] == '"' {
		// Quoted value - find closing quote
		endQuote := strings.Index(header[valueStart+1:], "\"")
		if endQuote == -1 {
			return ""
		}
		value = header[valueStart+1 : valueStart+1+endQuote]
	} else {
		// Unquoted value - find delimiter (comma or whitespace)
		end := strings.IndexAny(header[valueStart:], ", \t")
		if end == -1 {
			value = header[valueStart:]
		} else {
			value = header[valueStart : valueStart+end]
		}
	}

	return extractIMSIFromURI(value)
}

// extractIMSIFromURI extracts IMSI from a SIP URI or NAI.
// Format: <IMSI>@ims.mnc<MNC>.mcc<MCC>.3gppnetwork.org
// IMSI is 15 digits (MCC + MNC + MSIN)
func extractIMSIFromURI(uri string) string {
	// Strip sip: or sips: prefix if present
	lowerURI := strings.ToLower(uri)
	if strings.HasPrefix(lowerURI, "sips:") {
		uri = uri[5:]
	} else if strings.HasPrefix(lowerURI, "sip:") {
		uri = uri[4:]
	}

	// Extract user part (before @)
	atIdx := strings.Index(uri, "@")
	if atIdx == -1 {
		return ""
	}
	userPart := uri[:atIdx]

	// Check if domain looks like 3GPP IMS format
	domain := strings.ToLower(uri[atIdx+1:])
	if !strings.Contains(domain, "3gppnetwork.org") && !strings.Contains(domain, ".mnc") {
		return ""
	}

	// Validate IMSI: must be exactly 15 digits
	if len(userPart) != 15 {
		return ""
	}
	for _, c := range userPart {
		if c < '0' || c > '9' {
			return ""
		}
	}

	return userPart
}

// ExtractIMEI extracts the IMEI from the Contact header's +sip.instance parameter.
// Format: +sip.instance="<urn:gsma:imei:35345678-9012345-0>"
// The IMEI is in URN format with dashes, normalized to 15 digits.
// Example: "urn:gsma:imei:35345678-9012345-0" -> "353456789012345"
func ExtractIMEI(contactHeader string) string {
	// Look for +sip.instance parameter
	instanceStart := strings.Index(strings.ToLower(contactHeader), "+sip.instance")
	if instanceStart == -1 {
		return ""
	}

	// Find the value (after "=")
	eqIdx := strings.Index(contactHeader[instanceStart:], "=")
	if eqIdx == -1 {
		return ""
	}
	valueStart := instanceStart + eqIdx + 1

	// Skip whitespace and quotes
	for valueStart < len(contactHeader) && (contactHeader[valueStart] == ' ' || contactHeader[valueStart] == '"' || contactHeader[valueStart] == '<') {
		valueStart++
	}

	// Find the end of the value
	valueEnd := valueStart
	for valueEnd < len(contactHeader) {
		c := contactHeader[valueEnd]
		if c == '"' || c == '>' || c == ';' || c == ',' || c == ' ' {
			break
		}
		valueEnd++
	}

	if valueStart >= valueEnd {
		return ""
	}

	value := contactHeader[valueStart:valueEnd]

	// Check for urn:gsma:imei: prefix
	lowerValue := strings.ToLower(value)
	if !strings.HasPrefix(lowerValue, "urn:gsma:imei:") {
		// Also try urn:urn-7:3gpp-imei: (alternative format)
		if !strings.HasPrefix(lowerValue, "urn:urn-7:3gpp-imei:") {
			return ""
		}
		value = value[20:] // len("urn:urn-7:3gpp-imei:")
	} else {
		value = value[14:] // len("urn:gsma:imei:")
	}

	// Extract and normalize IMEI (remove dashes)
	var digits strings.Builder
	for _, c := range value {
		if c >= '0' && c <= '9' {
			digits.WriteRune(c)
		}
	}

	imei := digits.String()

	// IMEI should be 15 digits (or 14 without check digit)
	if len(imei) == 15 || len(imei) == 14 {
		return imei
	}

	return ""
}

package voip

import (
	"bytes"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

func handleSipMessage(data []byte) bool {
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) == 0 {
		return false
	}
	startLine := strings.TrimSpace(string(lines[0]))
	if !isSipStartLine(startLine) {
		return false
	}

	headers, body := parseSipHeaders(data)

	if containsUserInHeaders(headers) {
		callID := headers["call-id"]
		if callID != "" {
			// Validate the Call-ID for security
			if err := ValidateCallIDForSecurity(callID); err != nil {
				logger.Warn("Malicious Call-ID detected and rejected",
					"call_id", SanitizeCallIDForLogging(callID),
					"error", err,
					"source", "sip_processing")
				return false
			}
			bodyBytes := StringToBytes(body)
			if BytesContains(bodyBytes, []byte("m=audio")) {
				method := detectSipMethod(startLine)
				call, err := getCall(callID)
				if err == nil {
					call.SetCallInfoState(method)
				}
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

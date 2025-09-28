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
			if strings.Contains(body, "m=audio") {
				method := detectSipMethod(startLine)
				call, err := getCall(callID)
				if err == nil {
					call.SetCallInfoState(method)
				}
				// fmt.Println("extracting Port for callid", callID)
				ExtractPortFromSdp(body, callID)
			}
		}
		return true
	}
	return false
}

func detectSipMethod(line string) string {
	if strings.HasPrefix(line, "INVITE") {
		return "INVITE"
	}
	if strings.HasPrefix(line, "REGISTER") {
		return "REGISTER"
	}
	if strings.HasPrefix(line, "BYE") {
		return "BYE"
	}
	if strings.HasPrefix(line, "CANCEL") {
		return "CANCEL"
	}
	if strings.HasPrefix(line, "ACK") {
		return "ACK"
	}
	if strings.HasPrefix(line, "OPTIONS") {
		return "OPTIONS"
	}
	if strings.HasPrefix(line, "SIP/2.0") {
		return ""
	}
	return ""
}

func isSipStartLine(line string) bool {
	// SIP responses start with SIP/2.0
	if strings.HasPrefix(line, "SIP/2.0") {
		return true
	}

	// SIP requests must contain "SIP/2.0" at the end
	if !strings.Contains(line, "SIP/2.0") {
		return false
	}

	// Check for valid SIP methods at the beginning
	return strings.HasPrefix(line, "INVITE ") ||
		strings.HasPrefix(line, "BYE ") ||
		strings.HasPrefix(line, "ACK ") ||
		strings.HasPrefix(line, "OPTIONS ") ||
		strings.HasPrefix(line, "REGISTER ") ||
		strings.HasPrefix(line, "CANCEL ")
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
	text := string(data)
	lines := strings.Split(text, "\n")

	var bodyStart bool
	var bodyBuilder strings.Builder
	var isFirstLine = true
	var headerCount int
	const maxHeaders = 100 // Reasonable limit for SIP headers

	for _, line := range lines {
		str := strings.TrimSpace(string(line))
		if str == "" {
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

			key, val := parseHeaderLine(str)
			if key != "" {
				headers[key] = val
				headerCount++
			}
		} else {
			bodyBuilder.WriteString(str + "\n")
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

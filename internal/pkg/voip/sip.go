package voip

import (
	"bytes"
	"strings"
)

func handleSIPMessage(data []byte) bool {
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) == 0 {
		return false
	}
	startLine := strings.TrimSpace(string(lines[0]))
	if !isSIPStartLine(startLine) {
		return false
	}

	headers, body := parseSIPHeaders(data)

	if containsUserInHeaders(headers) {
		callID := headers["call-id"]
		if callID != "" {
			if strings.Contains(body, "m=audio") {
				method := detectSIPMethod(startLine)
				call, err := getCall(callID)
				if err != nil {
					call.SetCallInfoState(method)
				}
				// fmt.Println("extracting Port for callid", callID)
				ExtractPortFromSDP(body, callID)
			}
		}
		return true
	}
	return false
}

func detectSIPMethod(line string) string {
	if strings.HasPrefix(line, "INVITE") {
		return "INVITE"
	}
	if strings.HasPrefix(line, "BYE") {
		return "BYE"
	}
	if strings.HasPrefix(line, "ACK") {
		return "ACK"
	}
	if strings.HasPrefix(line, "SIP/2.0 200") {
		return "OK"
	}
	return "UNKNOWN"
}

func isSIPStartLine(line string) bool {
	return strings.HasPrefix(line, "INVITE") ||
		strings.HasPrefix(line, "BYE") ||
		strings.HasPrefix(line, "ACK") ||
		strings.HasPrefix(line, "OPTIONS") ||
		strings.HasPrefix(line, "REGISTER") ||
		strings.HasPrefix(line, "CANCEL") ||
		strings.HasPrefix(line, "SIP/2.0")
}

func parseSIPHeaders(data []byte) (map[string]string, string) {
	headers := make(map[string]string)
	text := string(data)
	lines := strings.Split(text, "\n")

	var bodyStart bool
	var bodyBuilder strings.Builder

	for _, line := range lines {
		str := strings.TrimSpace(string(line))
		if str == "" {
			bodyStart = true
			continue
		}
		if !bodyStart {
			key, val := parseHeaderLine(str)
			if key != "" {
				headers[key] = val
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
	return strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
}

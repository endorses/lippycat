package capture

import (
	"strings"
)

func ParseSIPHeaders(data []byte) (map[string]string, string) {
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

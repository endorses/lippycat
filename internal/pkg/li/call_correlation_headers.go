//go:build li

package li

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/types"
)

const correlationHeaderBlockLimit = 64 * 1024
const correlationHeaderCountLimit = 128
const correlationHeaderValueLimit = 4096

// correlationHeaders retains repeated fields. RawSIP is authoritative when
// present: metadata must not hide a conflicting repeat or repair a truncated
// raw message. The metadata fallback can detect differently cased map keys,
// but cannot recover repeats that an upstream producer has already discarded.
func correlationHeaders(pkt *types.PacketDisplay) (map[string][]string, bool) {
	result := make(map[string][]string)
	if pkt == nil || pkt.VoIPData == nil {
		return result, false
	}
	raw := pkt.VoIPData.RawSIP
	if len(raw) == 0 {
		if len(pkt.VoIPData.Headers) > correlationHeaderCountLimit {
			return nil, true
		}
		total := 0
		for name, value := range pkt.VoIPData.Headers {
			total += len(name) + len(value)
			if !validCorrelationHeader(name) || len(value) > correlationHeaderValueLimit || total > correlationHeaderBlockLimit || !validCorrelationHeaderValue(value) {
				return nil, true
			}
			key := strings.ToLower(name)
			result[key] = append(result[key], strings.TrimSpace(value))
		}
		return result, false
	}
	prefix := raw[:min(len(raw), correlationHeaderBlockLimit+4)]
	headerEnd := strings.Index(string(prefix), "\r\n\r\n")
	if headerEnd < 0 {
		headerEnd = strings.Index(string(prefix), "\n\n")
	}
	if headerEnd < 0 || headerEnd > correlationHeaderBlockLimit {
		return nil, true
	}
	lines := strings.Split(string(raw[:headerEnd]), "\n")
	if len(lines) < 1 {
		return nil, true
	}
	first := strings.TrimSuffix(lines[0], "\r")
	if !strings.HasPrefix(first, "SIP/2.0 ") && !strings.HasSuffix(first, " SIP/2.0") {
		return nil, true
	}
	last := ""
	count := 0
	for _, line := range lines[1:] {
		line = strings.TrimSuffix(line, "\r")
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if last == "" {
				return nil, true
			}
			values := result[last]
			values[len(values)-1] += " " + strings.TrimSpace(line)
			if len(values[len(values)-1]) > correlationHeaderValueLimit || !validCorrelationHeaderValue(values[len(values)-1]) {
				return nil, true
			}
			result[last] = values
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !validCorrelationHeader(name) {
			return nil, true
		}
		count++
		if count > correlationHeaderCountLimit {
			return nil, true
		}
		value = strings.TrimSpace(value)
		if len(value) > correlationHeaderValueLimit || !validCorrelationHeaderValue(value) {
			return nil, true
		}
		last = strings.ToLower(name)
		result[last] = append(result[last], value)
	}
	return result, false
}

func validCorrelationHeaderValue(value string) bool {
	for _, r := range value {
		if r < 32 && r != '\t' || r == 127 {
			return false
		}
	}
	return true
}

// Repeated configured fields must have identical trimmed wire values. Identical
// usable repeats are accepted; differing or unusable repeats are ambiguous and
// veto weaker matching. One malformed standard value provides no usable key.
// Opaque proprietary values retain exact case and parameters.
func correlationSessionKeys(pkt *types.PacketDisplay, names []string) (map[string]string, bool) {
	result := make(map[string]string)
	if len(names) == 0 {
		return result, false
	}
	headers, invalid := correlationHeaders(pkt)
	if invalid {
		return result, true
	}
	for _, name := range names {
		key := strings.ToLower(name)
		value, present, conflict := oneCorrelationHeader(headers[key])
		if conflict {
			return result, true
		}
		if !present {
			continue
		}
		switch key {
		case "session-id":
			var valid bool
			response := pkt != nil && pkt.VoIPData != nil && pkt.VoIPData.Status > 0
			if pkt != nil && len(pkt.VoIPData.RawSIP) > 0 {
				response = len(pkt.VoIPData.RawSIP) >= 8 && string(pkt.VoIPData.RawSIP[:8]) == "SIP/2.0 "
			}
			var conflict bool
			value, valid, conflict = parseCorrelationSessionID(value, response)
			if conflict || !valid && len(headers[key]) > 1 {
				return result, true
			}
			if !valid {
				continue
			}
		case "p-charging-vector":
			var valid bool
			value, valid = correlationICID(value)
			if !valid {
				if len(headers[key]) > 1 || correlationICIDConflict(headers[key][0]) {
					return result, true
				}
				continue
			}
		}
		if value != "" {
			result[key] = value
		}
	}
	return result, false
}

func correlationParent(pkt *types.PacketDisplay, names []string) (string, bool, bool) {
	if len(names) == 0 {
		return "", false, false
	}
	headers, invalid := correlationHeaders(pkt)
	if invalid {
		return "", false, true
	}
	parent := ""
	present := false
	for _, name := range names {
		values := headers[strings.ToLower(name)]
		if len(values) == 0 {
			continue
		}
		present = true
		value, found, conflict := oneCorrelationHeader(values)
		if conflict || !found || !validCorrelationParentID(value) {
			return "", true, true
		}
		if parent != "" && parent != value {
			return "", true, true
		}
		parent = value
	}
	return parent, present, false
}
func oneCorrelationHeader(values []string) (string, bool, bool) {
	if len(values) == 0 {
		return "", false, false
	}
	value := strings.TrimSpace(values[0])
	for _, other := range values[1:] {
		if strings.TrimSpace(other) != value {
			return "", true, true
		}
	}
	return value, value != "", false
}
func validCorrelationParentID(value string) bool {
	if len(value) == 0 || len(value) > correlationHeaderValueLimit {
		return false
	}
	// SIP Call-ID is one word, optionally two words separated by '@'. A parent
	// header is not a URI, list, or parameterized header.
	for _, r := range value {
		if r <= 32 || r >= 127 || !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.!%*_+`'~()<>:\\/[ ]?{}\"@", r) || r == ' ' {
			return false
		}
	}
	return strings.Count(value, "@") <= 1 && !strings.HasPrefix(value, "@") && !strings.HasSuffix(value, "@")
}

// A single syntactically unusable value is missing evidence. Duplicate remote
// parameters are explicit ambiguity, even if their UUIDs are identical.
func correlationSessionID(value string, response bool) (string, bool) {
	key, valid, _ := parseCorrelationSessionID(value, response)
	return key, valid
}
func parseCorrelationSessionID(value string, response bool) (string, bool, bool) {
	if len(value) > correlationHeaderValueLimit {
		return "", false, false
	}
	parts, ok := correlationParameters(value)
	if !ok {
		return "", false, false
	}
	remoteCount := 0
	for _, part := range parts[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(strings.TrimSpace(name), "remote") {
			remoteCount++
		}
	}
	if remoteCount > 1 {
		return "", false, true
	}
	if !validCorrelationUUID(strings.TrimSpace(parts[0])) {
		return "", false, false
	}
	local := strings.TrimSpace(parts[0])
	remote := ""
	seenRemote := false
	for _, part := range parts[1:] {
		name, v, hasValue := strings.Cut(strings.TrimSpace(part), "=")
		name = strings.TrimSpace(name)
		if !correlationSIPToken(name) {
			return "", false, false
		}
		v = strings.TrimSpace(v)
		if strings.EqualFold(name, "remote") {
			if seenRemote {
				return "", false, true
			}
			seenRemote = true
			if !hasValue || !validCorrelationUUID(v) {
				return "", false, false
			}
			remote = v
		} else if hasValue && !correlationGenericValue(v) {
			return "", false, false
		}
	}
	selected := local
	if response {
		selected = remote
	}
	if selected == "" || selected == strings.Repeat("0", 32) {
		return "", true, false
	}
	return strings.ToLower(selected), true, false
}

// RFC 3261 generic-param permits a token, host, or quoted-string value. SIP
// folding has already been unfolded by correlationHeaders; CR/LF are rejected.
func correlationSIPToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-.!%*_+`'~", r)) {
			return false
		}
	}
	return true
}
func correlationGenericValue(value string) bool {
	if correlationSIPToken(value) {
		return true
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		addr, err := netip.ParseAddr(value[1 : len(value)-1])
		return err == nil && addr.Is6() && addr.Zone() == ""
	}
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' || !utf8.ValidString(value) {
		return false
	}
	inside := value[1 : len(value)-1]
	for i := 0; i < len(inside); i++ {
		ch := inside[i]
		if ch == '\\' {
			i++
			if i >= len(inside) || inside[i] >= 128 || inside[i] == '\r' || inside[i] == '\n' {
				return false
			}
		} else if ch == '"' || ch < 32 && ch != '\t' || ch == 127 {
			return false
		}
	}
	return true
}

func correlationICIDConflict(value string) bool {
	parts, ok := correlationParameters(value)
	if !ok {
		return false
	}
	seen := ""
	for _, part := range parts {
		name, _, found := strings.Cut(strings.TrimSpace(part), "=")
		if found && strings.EqualFold(strings.TrimSpace(name), "icid-value") {
			key, valid := correlationICID(part)
			if valid && key != "" {
				if seen != "" && seen != key {
					return true
				}
				seen = key
			}
		}
	}
	return false
}
func validCorrelationUUID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// correlationICID parses parameters without treating semicolons inside quoted
// strings as separators. The parsed icid-value is case-preserved.
func correlationICID(value string) (string, bool) {
	parameters, ok := correlationParameters(value)
	if !ok {
		return "", false
	}
	icid := ""
	for _, parameter := range parameters {
		name, v, found := strings.Cut(strings.TrimSpace(parameter), "=")
		if !found || strings.TrimSpace(name) == "" {
			return "", false
		}
		name = strings.TrimSpace(name)
		v = strings.TrimSpace(v)
		if !strings.EqualFold(name, "icid-value") {
			continue
		}
		if strings.HasPrefix(v, "\"") {
			if len(v) < 2 || !strings.HasSuffix(v, "\"") {
				return "", false
			}
			var out strings.Builder
			escaped := false
			for _, r := range v[1 : len(v)-1] {
				if escaped {
					out.WriteRune(r)
					escaped = false
				} else if r == '\\' {
					escaped = true
				} else if r == '"' {
					return "", false
				} else {
					out.WriteRune(r)
				}
			}
			if escaped {
				return "", false
			}
			v = out.String()
		} else if strings.ContainsAny(v, " \t\"") {
			return "", false
		}
		if v == "" {
			return "", false
		}
		if icid != "" && icid != v {
			return "", false
		}
		icid = v
	}
	return icid, true
}
func correlationParameters(value string) ([]string, bool) {
	var result []string
	start := 0
	quoted := false
	escaped := false
	for i, r := range value {
		if escaped {
			escaped = false
			continue
		}
		if quoted && r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			quoted = !quoted
			continue
		}
		if r == ';' && !quoted {
			result = append(result, value[start:i])
			start = i + 1
		}
	}
	if quoted || escaped {
		return nil, false
	}
	result = append(result, value[start:])
	return result, true
}

//go:build li

package li

import (
	"encoding/json"
	"maps"
	"sort"
	"strconv"
	"strings"
)

type correlationURI struct {
	scheme, user, host string
	params             map[string]string
}

// parseCorrelationURI deliberately does not reuse the authorization extractor:
// comparison needs parameters which the shared extractor intentionally discards.
func parseCorrelationURI(header string) (correlationURI, bool) {
	var u correlationURI
	if header == "" || len(header) > 4096 || strings.ContainsAny(header, "\r\n\x00") {
		return u, false
	}
	raw := strings.TrimSpace(header)
	if left := strings.IndexByte(raw, '<'); left >= 0 {
		right := strings.IndexByte(raw[left+1:], '>')
		if right < 0 {
			return u, false
		}
		raw = raw[left+1 : left+1+right]
	} else {
		raw = strings.TrimSpace(raw)
	}
	scheme, rest, ok := strings.Cut(raw, ":")
	if !ok {
		return u, false
	}
	u.scheme = strings.ToLower(scheme)
	if u.scheme != "sip" && u.scheme != "sips" && u.scheme != "tel" || strings.ContainsAny(rest, " \t<>\\") {
		return u, false
	}
	u.params = map[string]string{}
	if u.scheme == "tel" {
		if strings.Contains(rest, "?") {
			return u, false
		}
		u.user, rest, _ = strings.Cut(rest, ";")
	} else {
		user, host, found := strings.Cut(rest, "@")
		if !found || user == "" || strings.ContainsAny(host, "@?") {
			return u, false
		}
		u.user = user
		u.host, rest, _ = strings.Cut(host, ";")
		u.host = strings.ToLower(u.host)
		if !validCorrelationSIPHost(u.host) {
			return u, false
		}
	}
	var escapedOK bool
	u.user, escapedOK = correlationPercentEncoding(u.user)
	if !escapedOK || u.user == "" {
		return u, false
	}
	if !addCorrelationParameters(u.params, rest) {
		return u, false
	}

	// A bare From/To addr-spec carries tag as a header parameter, not identity.
	if !strings.Contains(header, "<") {
		delete(u.params, "tag")
	}
	if !validCorrelationIdentityParameters(u.params) {
		return u, false
	}

	if u.scheme == "tel" {
		number := stripPhoneSeparators(u.user)
		if !validCorrelationLocalNumber(number) {
			return u, false
		}
		if strings.HasPrefix(number, "+") && u.params["phone-context"] != "" {
			return u, false
		}
		if !strings.HasPrefix(number, "+") && u.params["phone-context"] == "" {
			return u, false
		}
	}
	return u, true
}

// Userinfo is kept whole by parsing. Only a selected telephone profile may
// reinterpret its semicolon suffix as subscriber parameters.
func correlationTelephoneURI(u correlationURI, p correlationIdentityProfile) (correlationURI, bool) {
	if u.scheme == "tel" || !p.numericSIP && !strings.EqualFold(u.params["user"], "phone") {
		return u, true
	}
	number, suffix, found := strings.Cut(u.user, ";")
	if !found {
		return u, true
	}
	subscriber := number
	number = stripPhoneSeparators(number)
	if !validCorrelationNumber(number) && !p.matchesRoutingRewrite(number) {
		return u, !strings.EqualFold(u.params["user"], "phone")
	}
	u.params = maps.Clone(u.params)
	if !addCorrelationParameters(u.params, suffix) || !validCorrelationIdentityParameters(u.params) {
		return u, false
	}
	u.user = subscriber
	return u, true
}
func addCorrelationParameters(params map[string]string, rest string) bool {
	if rest == "" {
		return true
	}
	for _, part := range strings.Split(rest, ";") {
		name, value, hasValue := strings.Cut(part, "=")
		var nameOK, valueOK bool
		name, nameOK = correlationPercentEncoding(name)
		value, valueOK = correlationPercentEncoding(value)
		if !nameOK || !valueOK {
			return false
		}
		name = strings.ToLower(name)
		if name == "" || !validCorrelationParameterName(name) {
			return false
		}
		if _, exists := params[name]; exists {
			return false
		}
		if hasValue && value == "" {
			return false
		}
		params[name] = value
	}
	return true
}
func validCorrelationIdentityParameters(params map[string]string) bool {
	if _, ext := params["ext"]; ext {
		if _, sub := params["isub"]; sub {
			return false
		}
	}
	for _, name := range []string{"ext", "isub", "user", "phone-context"} {
		if value, exists := params[name]; exists && value == "" {
			return false
		}
	}
	if extension, exists := params["ext"]; exists && !asciiDigits(stripPhoneSeparators(extension)) {
		return false
	}
	if context, exists := params["phone-context"]; exists && !validCorrelationPhoneContext(canonicalPhoneContext(context)) {
		return false
	}
	return true
}

// Unreserved escapes are equivalent to their literal character. Reserved
// delimiters stay escaped, so an encoded plus never acquires global semantics.
func correlationPercentEncoding(s string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 33 || b > 126 {
			return "", false
		}
		if b != '%' {
			out.WriteByte(b)
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		value, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", false
		}
		b = byte(value)
		if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-_.!~*'()", rune(b)) {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteString(strings.ToUpper(s[i+1 : i+3]))
		}
		i += 2
	}
	return out.String(), true
}

func correlationIdentityWithProfiles(header string, profiles []correlationIdentityProfile) string {
	if len(profiles) == 0 {
		return correlationIdentity(header)
	}
	u, ok := parseCorrelationURI(header)
	if !ok {
		return ""
	}
	original := u
	selected := -1
	for i, p := range profiles {
		candidate := original
		if candidate.scheme != "tel" {
			if !p.hosts[candidate.host] {
				continue
			}
			var valid bool
			candidate, valid = correlationTelephoneURI(candidate, p)
			if !valid {
				return ""
			}
		}
		context := canonicalPhoneContext(candidate.params["phone-context"])
		applies := false
		if candidate.scheme == "tel" {
			if strings.HasPrefix(candidate.user, "+") {
				applies = p.globalTEL
			} else {
				applies = context != "" && p.contexts[context]
			}
		} else {
			applies = context == "" || p.contexts[context]
		}
		if applies {
			if selected >= 0 {
				return ""
			}
			selected = i
			u = candidate
		}
	}
	if selected < 0 {
		return correlationExactURIKey(original)
	}
	p := profiles[selected]
	context := canonicalPhoneContext(u.params["phone-context"])
	if u.scheme != "tel" && !strings.EqualFold(u.params["user"], "phone") && !p.numericSIP {
		return correlationExactURIKey(original)
	}
	number := stripPhoneSeparators(u.user)
	// Alphanumeric routing prefixes require an explicitly matching anchored rule.
	// Merely enabling numeric SIP interpretation never classifies a username.
	if !validCorrelationNumber(number) && !p.matchesRoutingRewrite(number) {
		if u.scheme == "tel" && validCorrelationLocalNumber(number) {
			u.user = strings.ToLower(number)
			u.params["phone-context"] = context
			return correlationExactURIKey(u)
		}
		if u.scheme == "tel" || strings.EqualFold(u.params["user"], "phone") || asciiDigits(strings.TrimPrefix(number, "+")) {
			return ""
		}
		return correlationExactURIKey(original)
	}
	// An explicit local context prevents implicit global dial-format assumptions.
	if context != "" && !strings.HasPrefix(number, "+") {
		p.bareGlobal = false
		p.prefixes = nil
	}
	canonical, ok := p.canonical(number)
	if !ok {
		return ""
	}
	localContext := ""
	if !strings.HasPrefix(canonical, "+") {
		localContext = context
		if localContext == "" {
			localContext = u.host
		}
		if localContext == "" {
			return ""
		}
	}
	params := make(map[string]string, len(u.params))
	for name, value := range u.params {
		switch name {
		case "user":
			if !strings.EqualFold(value, "phone") {
				params[name] = value
			}
		case "phone-context":
			if strings.HasPrefix(canonical, "+") {
				params[name] = context
			}
		case "ext":
			value = stripPhoneSeparators(value)
			if !asciiDigits(value) {
				return ""
			}
			params[name] = value
		default:
			if u.scheme == "tel" {
				value = strings.ToLower(value)
			}
			params[name] = value
		}
	}
	if _, ext := params["ext"]; ext {
		if _, sub := params["isub"]; sub {
			return ""
		}
	}
	return correlationTuple("phone", p.namespace, canonical, localContext, correlationParams(params))
}
func validCorrelationParameterName(name string) bool {
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.!~*'()+$", r)) {
			return false
		}
	}
	return true
}
func correlationExactURIKey(u correlationURI) string {
	return correlationTuple("uri", u.scheme, u.user, u.host, correlationParams(u.params))
}
func correlationTuple(parts ...string) string {
	data, err := json.Marshal(parts)
	if err != nil {
		return ""
	}
	return string(data)
}
func correlationParams(params map[string]string) string {
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, 2*len(names))
	for _, name := range names {
		parts = append(parts, name, params[name])
	}
	return correlationTuple(parts...)
}
func validCorrelationLocalNumber(s string) bool {
	if strings.HasPrefix(s, "+") {
		return validCorrelationNumber(s)
	}
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == '*' || r == '#') {
			return false
		}
	}
	return true
}
func validCorrelationNumber(s string) bool {
	if len(s) > 128 {
		return false
	}
	return asciiDigits(strings.TrimPrefix(s, "+"))
}
func (p correlationIdentityProfile) matchesRoutingRewrite(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, rule := range p.rules {
		if rule.pattern.MatchString(value) {
			return true
		}
	}
	return false
}
func (p correlationIdentityProfile) transform(number string) (string, bool) {
	result := ""
	matched := false
	for _, rule := range p.rules {
		if !rule.pattern.MatchString(number) {
			continue
		}
		value := rule.pattern.ReplaceAllString(number, rule.replacement)
		if !validCorrelationNumber(value) || matched && value != result {
			return "", false
		}
		result = value
		matched = true
	}
	if !matched {
		result = number
	}
	if !strings.HasPrefix(result, "+") {
		interpreted := ""
		for _, prefix := range p.prefixes {
			if strings.HasPrefix(result, prefix) {
				value := "+" + strings.TrimPrefix(result, prefix)
				if !validCorrelationNumber(value) || interpreted != "" && interpreted != value {
					return "", false
				}
				interpreted = value
			}
		}
		if interpreted != "" {
			result = interpreted
		} else if p.bareGlobal {
			result = "+" + result
		}
	}
	return result, validCorrelationNumber(result)
}
func (p correlationIdentityProfile) canonical(number string) (string, bool) {
	value, ok := p.transform(number)
	if !ok {
		return "", false
	}
	again, ok := p.transform(value)
	if !ok || again != value {
		return "", false
	}
	return value, true
}

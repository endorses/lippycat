package li

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// CorrelationIdentityProfile explicitly scopes telephone comparison for weak
// call correlation. It has no effect on target matching or authorization.
type CorrelationIdentityProfile struct {
	Name                  string                       `mapstructure:"name" json:"name"`
	Namespace             string                       `mapstructure:"namespace" json:"namespace"`
	SIPHosts              []string                     `mapstructure:"sip_hosts" json:"sip_hosts"`
	PhoneContexts         []string                     `mapstructure:"phone_contexts" json:"phone_contexts"`
	GlobalTEL             bool                         `mapstructure:"global_tel" json:"global_tel"`
	AllowNumericSIP       bool                         `mapstructure:"allow_numeric_sip" json:"allow_numeric_sip"`
	AllowBareGlobal       bool                         `mapstructure:"allow_bare_global" json:"allow_bare_global"`
	InternationalPrefixes []string                     `mapstructure:"international_prefixes" json:"international_prefixes"`
	RewriteRules          []CorrelationIdentityRewrite `mapstructure:"rewrite_rules" json:"rewrite_rules"`
}

// CorrelationIdentityRewrite rewrites the entire separator-free subscriber once.
// Matching rules must agree and their result must remain stable on reapplication.
type CorrelationIdentityRewrite struct {
	Pattern     string `mapstructure:"pattern" json:"pattern"`
	Replacement string `mapstructure:"replacement" json:"replacement"`
}

type correlationIdentityRewrite struct {
	pattern     *regexp.Regexp
	replacement string
}
type correlationIdentityProfile struct {
	namespace                         string
	hosts, contexts                   map[string]bool
	globalTEL, numericSIP, bareGlobal bool
	prefixes                          []string
	rules                             []correlationIdentityRewrite
}

func compileCorrelationIdentityProfiles(config []CorrelationIdentityProfile) ([]correlationIdentityProfile, error) {
	if len(config) > 32 {
		return nil, fmt.Errorf("LI correlation supports at most 32 identity profiles")
	}
	profiles := make([]correlationIdentityProfile, 0, len(config))
	names := map[string]bool{}
	for i, p := range config {
		invalid := func() error { return fmt.Errorf("invalid LI correlation identity profile at index %d", i) }
		if !validCorrelationProfileValue(p.Name) || !validCorrelationProfileValue(p.Namespace) || names[p.Name] {
			return nil, invalid()
		}
		names[p.Name] = true
		if len(p.SIPHosts) > 64 || len(p.PhoneContexts) > 64 || len(p.InternationalPrefixes) > 16 || len(p.RewriteRules) > 16 || len(p.SIPHosts)+len(p.PhoneContexts) == 0 && !p.GlobalTEL {
			return nil, invalid()
		}
		v := correlationIdentityProfile{namespace: p.Namespace, hosts: map[string]bool{}, contexts: map[string]bool{}, globalTEL: p.GlobalTEL, numericSIP: p.AllowNumericSIP, bareGlobal: p.AllowBareGlobal, prefixes: append([]string(nil), p.InternationalPrefixes...)}
		for _, host := range p.SIPHosts {
			if !validCorrelationSIPHost(host) || v.hosts[strings.ToLower(host)] {
				return nil, invalid()
			}
			v.hosts[strings.ToLower(host)] = true
		}
		for _, context := range p.PhoneContexts {
			context = canonicalPhoneContext(context)
			if !validCorrelationPhoneContext(context) || v.contexts[context] {
				return nil, invalid()
			}
			v.contexts[context] = true
		}
		seen := map[string]bool{}
		for _, prefix := range p.InternationalPrefixes {
			if !asciiDigits(prefix) || len(prefix) > 16 || seen[prefix] {
				return nil, invalid()
			}
			seen[prefix] = true
		}
		for _, rule := range p.RewriteRules {
			if len(rule.Pattern) > 512 || len(rule.Replacement) > 512 || !strings.HasPrefix(rule.Pattern, "^") || !strings.HasSuffix(rule.Pattern, "$") {
				return nil, invalid()
			}
			re, err := regexp.Compile(rule.Pattern)
			if err != nil || !validCorrelationReplacement(re, rule.Replacement) {
				return nil, invalid()
			}
			// A noncapturing outer anchor prevents alternation escaping textual anchors.
			re, err = regexp.Compile("^(?:" + rule.Pattern + ")$")
			if err != nil {
				return nil, invalid()
			}
			v.rules = append(v.rules, correlationIdentityRewrite{re, rule.Replacement})
		}
		profiles = append(profiles, v)
	}
	return profiles, nil
}
func validCorrelationProfileValue(s string) bool {
	if s == "" || len(s) > 256 {
		return false
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}
func validCorrelationScope(s string) bool {
	return validCorrelationProfileValue(s) && !strings.ContainsAny(s, "@;?<>%/\\#*")
}
func validCorrelationSIPHost(host string) bool {
	if !validCorrelationScope(host) {
		return false
	}
	// SIP IPv6 references are bracketed, including when no port is present.
	// Raw IPv6 and scoped addresses must not acquire a host comparison key.
	if strings.HasPrefix(host, "[") {
		close := strings.IndexByte(host, ']')
		if close < 0 {
			return false
		}
		addr, err := netip.ParseAddr(host[1:close])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return false
		}
		rest := host[close+1:]
		if rest == "" {
			return true
		}
		if !strings.HasPrefix(rest, ":") {
			return false
		}
		return validCorrelationPort(rest[1:])
	}
	if strings.ContainsAny(host, "[]") {
		return false
	}
	if strings.Contains(host, ":") {
		h, p, err := net.SplitHostPort(host)
		if err != nil || strings.Contains(h, ":") || !validCorrelationPort(p) {
			return false
		}
		host = h
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Is4()
	}
	return validCorrelationDomain(host)
}
func validCorrelationPort(port string) bool {
	if !asciiDigits(port) {
		return false
	}
	value, err := strconv.Atoi(port)
	return err == nil && value > 0 && value <= 65535
}
func validCorrelationDomain(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func validCorrelationPhoneContext(context string) bool {
	if strings.HasPrefix(context, "+") {
		return len(context) <= 128 && asciiDigits(strings.TrimPrefix(context, "+"))
	}
	return validCorrelationScope(context) && validCorrelationDomain(context)
}
func validCorrelationReplacement(re *regexp.Regexp, s string) bool {
	if s == "" {
		return false
	}
	original := s
	for len(s) > 0 {
		at := strings.IndexByte(s, '$')
		if at < 0 {
			return validCorrelationReplacementLiteral(s, len(original)-len(s))
		}
		if !validCorrelationReplacementLiteral(s[:at], len(original)-len(s)) {
			return false
		}
		s = s[at+1:]
		if s == "" {
			return false
		}
		if s[0] == '$' {
			return false
		}
		name := ""
		if s[0] == '{' {
			end := strings.IndexByte(s, '}')
			if end < 0 {
				return false
			}
			name = s[1:end]
			s = s[end+1:]
		} else {
			i := 0
			for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' || s[i] == '_') {
				i++
			}
			name = s[:i]
			s = s[i:]
		}
		if name == "" {
			return false
		}
		valid := false
		for i, n := range re.SubexpNames() {
			if fmt.Sprint(i) == name || n != "" && n == name {
				valid = true
				break
			}
		}
		if !valid {
			return false
		}
	}
	return true
}
func validCorrelationReplacementLiteral(s string, offset int) bool {
	for i, r := range s {
		if !(r >= '0' && r <= '9' || r == '+' && offset+i == 0) {
			return false
		}
	}
	return true
}
func asciiDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func canonicalPhoneContext(s string) string {
	if strings.HasPrefix(s, "+") {
		return stripPhoneSeparators(s)
	}
	return strings.ToLower(s)
}
func stripPhoneSeparators(s string) string {
	return strings.NewReplacer("-", "", ".", "", "(", "", ")", "").Replace(s)
}

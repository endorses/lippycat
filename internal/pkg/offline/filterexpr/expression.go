// Package filterexpr defines immutable packet filter expressions independent of storage and presentation.
package filterexpr

import (
	"fmt"
	"net"
	"strings"
)

type Record interface {
	GetStringField(string) string
	GetNumericField(string) float64
	HasField(string) bool
	RecordType() string
}

// ExpressionSpec describes a packet filter independently of presentation packages.
// Operators are all, none, and, or, not, equal, contains, text, has, numeric,
// cidr, node and voip. Fields retain PacketDisplay accessor alias semantics.
type ExpressionSpec struct {
	Op         string
	Fields     []string
	Text       string
	Number     float64
	Comparison string
	Children   []*Expression
}

// Expression is a validated immutable filter snapshot. Its field dependencies
// allow storage to omit unrelated projection columns. A zero value is invalid.
type Expression struct {
	spec    ExpressionSpec
	fields  []string
	network *net.IPNet
	valid   bool
	bytes   uint64
}

func NewExpression(s ExpressionSpec) (*Expression, error) {
	// Bound input before copying slices or parsing text. Each expression tree is
	// limited to 1 MiB including repeated child occurrences and dependencies.
	if len(s.Fields) > 256 || len(s.Children) > 256 {
		return nil, fmt.Errorf("expression exceeds dependency limit")
	}
	size := uint64(2048 + len(s.Text) + len(s.Op) + len(s.Comparison) + len(s.Children)*8)
	for _, f := range s.Fields {
		size += uint64(32 + len(f))
	}
	if size > 1<<20 {
		return nil, fmt.Errorf("expression exceeds byte limit")
	}
	switch s.Op {
	case "node":
		s.Fields = []string{"node"}
	case "voip":
		s.Fields = []string{"protocol", "info", "sip.user", "sip.from", "sip.to", "sip.fromtag", "sip.totag", "sip.method", "sip.callid", "sip.codec"}
	}
	for _, c := range s.Children {
		if c == nil || !c.valid {
			return nil, fmt.Errorf("invalid expression child")
		}
		size += c.bytes
		if size > 1<<20 {
			return nil, fmt.Errorf("expression exceeds byte limit")
		}
	}
	e := &Expression{spec: s, bytes: size}
	e.spec.Text = strings.Clone(s.Text)
	e.spec.Op = strings.Clone(s.Op)
	e.spec.Comparison = strings.Clone(s.Comparison)
	e.spec.Fields = make([]string, len(s.Fields))
	for i, f := range s.Fields {
		e.spec.Fields[i] = strings.Clone(f)
	}
	e.spec.Children = append([]*Expression(nil), s.Children...)
	s = e.spec
	switch s.Op {
	case "all", "none":
	case "and", "or":
	case "not":
		if len(s.Children) != 1 {
			return nil, fmt.Errorf("not requires one child")
		}
	case "equal", "contains", "text", "has", "node", "voip", "cidr", "numeric":
		if len(s.Fields) == 0 {
			return nil, fmt.Errorf("%s requires fields", s.Op)
		}
	default:
		return nil, fmt.Errorf("unknown expression operator %q", s.Op)
	}
	if s.Op != "and" && s.Op != "or" && s.Op != "not" && len(s.Children) != 0 {
		return nil, fmt.Errorf("leaf expression has children")
	}
	if len(s.Fields) > 256 || len(s.Children) > 256 {
		return nil, fmt.Errorf("expression exceeds dependency limit")
	}
	if s.Op == "numeric" {
		switch s.Comparison {
		case "=", "==", ">", "<", ">=", "<=":
		default:
			return nil, fmt.Errorf("invalid numeric comparison")
		}
	}
	if s.Op == "cidr" {
		_, n, err := net.ParseCIDR(s.Text)
		if err != nil {
			return nil, err
		}
		e.network = n
	}
	seen := map[string]bool{}
	add := func(f string) {
		if !seen[f] {
			seen[f] = true
			e.fields = append(e.fields, f)
		}
	}
	for _, f := range s.Fields {
		add(f)
	}
	nodes := 0
	var visit func(*Expression, int) error
	visit = func(c *Expression, depth int) error {
		nodes++
		if nodes > 4096 || depth > 64 {
			return fmt.Errorf("expression exceeds complexity limit")
		}
		if c == nil || !c.valid {
			return fmt.Errorf("invalid expression child")
		}
		for _, ch := range c.spec.Children {
			if err := visit(ch, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, c := range s.Children {
		if err := visit(c, 1); err != nil {
			return nil, err
		}
		for _, f := range c.fields {
			add(f)
		}
	}
	if len(e.fields) > 256 {
		return nil, fmt.Errorf("expression exceeds aggregate dependency limit")
	}
	e.valid = true
	return e, nil
}
func (e *Expression) Validate() error {
	if e == nil || !e.valid {
		return fmt.Errorf("invalid filter expression")
	}
	return nil
}

// AccountedBytes bounds the retained expression tree, including shared children.
func (e *Expression) AccountedBytes() uint64 {
	if e == nil {
		return 0
	}
	return e.bytes
}
func (e *Expression) RequiredFields() []string { return append([]string(nil), e.fields...) }
func (e *Expression) Match(s Record) bool {
	if e == nil || !e.valid {
		return false
	}
	p := e.spec
	switch p.Op {
	case "all":
		return true
	case "none":
		return false
	case "and":
		for _, c := range p.Children {
			if !c.Match(s) {
				return false
			}
		}
		return true
	case "or":
		for _, c := range p.Children {
			if c.Match(s) {
				return true
			}
		}
		return false
	case "not":
		return !p.Children[0].Match(s)
	case "numeric":
		v := s.GetNumericField(p.Fields[0])
		switch p.Comparison {
		case ">":
			return v > p.Number
		case "<":
			return v < p.Number
		case ">=":
			return v >= p.Number
		case "<=":
			return v <= p.Number
		default:
			d := v - p.Number
			if d < 0 {
				d = -d
			}
			return d < 0.0001
		}
	case "node":
		v := s.GetStringField("node")
		pattern := p.Text
		if !strings.Contains(pattern, "*") {
			return v == pattern
		}
		if pattern == "*" {
			return v != "" && v != "Local"
		}
		if strings.HasSuffix(pattern, "*") && !strings.HasPrefix(pattern, "*") {
			return strings.HasPrefix(v, strings.TrimSuffix(pattern, "*"))
		}
		if strings.HasPrefix(pattern, "*") {
			return strings.HasSuffix(v, strings.TrimPrefix(pattern, "*"))
		}
		parts := strings.Split(pattern, "*")
		if len(parts) == 2 {
			return strings.HasPrefix(v, parts[0]) && strings.HasSuffix(v, parts[1])
		}
		return v == pattern
	case "voip":
		return e.matchVoIP(s)
	}
	for _, f := range p.Fields {
		v := s.GetStringField(f)
		switch p.Op {
		case "equal":
			if v == p.Text {
				return true
			}
		case "contains":
			if strings.Contains(v, p.Text) {
				return true
			}
		case "text":
			if strings.Contains(strings.ToLower(v), p.Text) {
				return true
			}
		case "has":
			if s.HasField(f) {
				return true
			}
		case "cidr":
			if e.network.Contains(net.ParseIP(v)) {
				return true
			}
		}
	}
	return false
}
func (e *Expression) matchVoIP(record Record) bool {
	f := struct {
		field, value string
		wildcard     bool
	}{e.spec.Comparison, e.spec.Text, strings.Contains(e.spec.Text, "*")}
	// VoIP filter only works on packets
	if record.RecordType() != "packet" {
		return false
	}

	// Check protocol - only match SIP packets
	if record.GetStringField("protocol") != "SIP" {
		return false
	}

	// Get field value using Filterable interface
	var fieldValue string
	switch f.field {
	case "user", "from":
		fieldValue = record.GetStringField("sip.user")
		if fieldValue == "" {
			fieldValue = record.GetStringField("sip.from")
		}
	case "to":
		fieldValue = record.GetStringField("sip.to")
	case "fromtag":
		fieldValue = record.GetStringField("sip.fromtag")
	case "totag":
		fieldValue = record.GetStringField("sip.totag")
	case "method":
		fieldValue = record.GetStringField("sip.method")
	case "callid":
		fieldValue = record.GetStringField("sip.callid")
	case "codec":
		fieldValue = record.GetStringField("sip.codec")
	}

	// Fall back to parsing Info string if field value not available
	if fieldValue == "" {
		info := strings.ToLower(record.GetStringField("info"))
		switch f.field {
		case "user", "from":
			// Look for "From: " or "sip:" in the info
			if idx := strings.Index(info, "from:"); idx != -1 {
				fieldValue = extractSIPField(record.GetStringField("info")[idx:])
			} else if idx := strings.Index(info, "sip:"); idx != -1 {
				fieldValue = extractSIPField(record.GetStringField("info")[idx:])
			}

		case "to":
			if idx := strings.Index(info, "to:"); idx != -1 {
				fieldValue = extractSIPField(record.GetStringField("info")[idx:])
			}

		case "method":
			// SIP methods appear at the start of the info
			words := strings.Fields(record.GetStringField("info"))
			if len(words) > 0 {
				fieldValue = words[0]
			}

		case "callid":
			if idx := strings.Index(info, "call-id:"); idx != -1 {
				fieldValue = extractSIPField(record.GetStringField("info")[idx:])
			}
		}
	}

	if fieldValue == "" {
		return false
	}

	// Match with wildcard support
	return expressionVoIPValue(strings.ToLower(fieldValue), f.value, f.wildcard)
}

func expressionVoIPValue(value, patternValue string, wildcard bool) bool {
	if !wildcard {
		// Exact match (case-insensitive)
		return strings.Contains(value, strings.ToLower(patternValue))
	}

	// Wildcard matching
	pattern := strings.ToLower(patternValue)

	// Handle simple prefix/suffix wildcards
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		// *pattern* - contains
		return strings.Contains(value, strings.Trim(pattern, "*"))
	} else if strings.HasPrefix(pattern, "*") {
		// *pattern - ends with
		return strings.HasSuffix(value, strings.TrimPrefix(pattern, "*"))
	} else if strings.HasSuffix(pattern, "*") {
		// pattern* - starts with
		return strings.HasPrefix(value, strings.TrimSuffix(pattern, "*"))
	}

	// Default to contains
	return strings.Contains(value, pattern)
}

func extractSIPField(s string) string {
	// Simple extraction - get everything up to the next space or special char
	var result strings.Builder
	inBrackets := false
	started := false

	for _, r := range s {
		if r == '<' {
			inBrackets = true
			continue
		}
		if r == '>' {
			break
		}
		if !started && (r == ' ' || r == ':') {
			continue
		}
		if !inBrackets && (r == ' ' || r == ';' || r == ',') {
			break
		}
		started = true
		result.WriteRune(r)
	}

	return strings.TrimSpace(result.String())
}

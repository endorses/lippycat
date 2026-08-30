package eventquery

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logschema"
)

// Predicate is an immutable compiled event query.
type Predicate func(events.Event) bool

type tokenKind uint8

const (
	tokEOF tokenKind = iota
	tokWord
	tokLParen
	tokRParen
	tokAnd
	tokOr
	tokNot
)

type token struct {
	kind   tokenKind
	text   string
	quoted bool
}
type node interface{ match(Projection) bool }
type binary struct {
	or          bool
	left, right node
}

func (n binary) match(p Projection) bool {
	if n.or {
		return n.left.match(p) || n.right.match(p)
	}
	return n.left.match(p) && n.right.match(p)
}

type negated struct{ child node }

func (n negated) match(p Projection) bool { return !n.child.match(p) }

type term struct {
	field, op, text, typ string
	typed                any
}

var aliases = map[string]string{"event": "kind", "node": "node_id", "src": "id.orig_h", "dst": "id.resp_h", "sport": "id.orig_p", "dport": "id.resp_p", "source": "capture_source"}

// Compile parses and validates an event query. An empty query is rejected.
func Compile(input string) (Predicate, error) {
	tokens, err := lex(input)
	if err != nil {
		return nil, err
	}
	p := parser{tokens: tokens}
	root, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected %q", p.peek().text)
	}
	return func(event events.Event) bool { return root.match(Project(event)) }, nil
}

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{kind: tokEOF}
	}
	return p.tokens[p.pos]
}
func (p *parser) take() token { t := p.peek(); p.pos++; return t }
func (p *parser) parseOr() (node, error) {
	left, e := p.parseAnd()
	if e != nil {
		return nil, e
	}
	for p.peek().kind == tokOr {
		p.take()
		r, e := p.parseAnd()
		if e != nil {
			return nil, e
		}
		left = binary{or: true, left: left, right: r}
	}
	return left, nil
}
func (p *parser) parseAnd() (node, error) {
	left, e := p.parseUnary()
	if e != nil {
		return nil, e
	}
	for {
		k := p.peek().kind
		if k == tokAnd {
			p.take()
		} else if k != tokWord && k != tokLParen && k != tokNot {
			break
		}
		r, e := p.parseUnary()
		if e != nil {
			return nil, e
		}
		left = binary{left: left, right: r}
	}
	return left, nil
}
func (p *parser) parseUnary() (node, error) {
	if p.peek().kind == tokNot {
		p.take()
		n, e := p.parseUnary()
		return negated{n}, e
	}
	if p.peek().kind == tokLParen {
		p.take()
		n, e := p.parseOr()
		if e != nil {
			return nil, e
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("missing closing parenthesis")
		}
		p.take()
		return n, nil
	}
	if p.peek().kind != tokWord {
		return nil, fmt.Errorf("expected query term")
	}
	return compileTerm(p.take())
}

func compileTerm(t token) (node, error) {
	if t.quoted && !strings.Contains(t.text, ":") {
		return term{text: t.text}, nil
	}
	i := strings.IndexByte(t.text, ':')
	if i < 0 {
		return term{text: t.text}, nil
	}
	field, value := strings.ToLower(t.text[:i]), t.text[i+1:]
	if alias, ok := aliases[field]; ok {
		field = alias
	}
	if field == "kind" {
		if value == "" {
			return nil, fmt.Errorf("kind requires a value")
		}
		return term{field: field, op: "=", text: value, typ: "string", typed: value}, nil
	}
	typ, ok := knownFields()[field]
	if !ok {
		return nil, fmt.Errorf("unknown event field %q", field)
	}
	op := "="
	for _, candidate := range []string{">=", "<=", "!=", ">", "<", "="} {
		if strings.HasPrefix(value, candidate) {
			op = candidate
			value = strings.TrimPrefix(value, candidate)
			break
		}
	}
	parsed, err := parseTyped(typ, value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s value %q: %w", field, value, err)
	}
	return term{field: field, op: op, text: value, typ: typ, typed: parsed}, nil
}

func knownFields() map[string]string {
	m := map[string]string{"event_id": "string", "producer_session_id": "string", "event_sequence": "count", "capture_source": "string", "interface_name": "string", "interface_index": "count", "input_file": "string", "processor_node_ids": "vector[string]"}
	for _, s := range logschema.Streams {
		for _, f := range s.Fields {
			m[strings.ToLower(f.Name)] = f.Type
		}
	}
	return m
}

func (n term) match(p Projection) bool {
	if n.field == "" {
		needle := strings.ToLower(n.text)
		if strings.Contains(strings.ToLower(string(p.Kind)), needle) || strings.Contains(strings.ToLower(p.Summary), needle) {
			return true
		}
		for _, v := range p.Fields {
			for _, x := range v.Values {
				if strings.Contains(strings.ToLower(fmt.Sprint(x)), needle) {
					return true
				}
			}
		}
		return false
	}
	if n.field == "kind" {
		return compareStrings(string(p.Kind), n.text, n.op)
	}
	v, ok := p.Fields[n.field]
	if !ok {
		for name, candidate := range p.Fields {
			if strings.EqualFold(name, n.field) {
				v, ok = candidate, true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, x := range v.Values {
		if compareValue(x, n.typed, n.typ, n.op) {
			return true
		}
	}
	return false
}

func parseTyped(typ, value string) (any, error) {
	switch baseType(typ) {
	case "count", "port":
		v, e := strconv.ParseUint(value, 10, 64)
		return v, e
	case "interval":
		return time.ParseDuration(value)
	case "time":
		return time.Parse(time.RFC3339Nano, value)
	case "bool":
		return strconv.ParseBool(value)
	case "addr":
		return netip.ParseAddr(value)
	default:
		return value, nil
	}
}
func baseType(t string) string {
	if i := strings.IndexByte(t, '['); i >= 0 {
		return t[i+1 : len(t)-1]
	}
	return t
}
func compareValue(a, b any, typ, op string) bool {
	switch baseType(typ) {
	case "count", "port":
		return compareOrdered(float64(toUint(a)), float64(b.(uint64)), op)
	case "interval":
		return compareOrdered(float64(a.(time.Duration)), float64(b.(time.Duration)), op)
	case "time":
		return compareOrdered(float64(a.(time.Time).UnixNano()), float64(b.(time.Time).UnixNano()), op)
	case "bool":
		av, ok := a.(bool)
		return ok && compareStrings(strconv.FormatBool(av), strconv.FormatBool(b.(bool)), op)
	default:
		return compareStrings(fmt.Sprint(a), fmt.Sprint(b), op)
	}
}
func toUint(v any) uint64 {
	switch x := v.(type) {
	case uint8:
		return uint64(x)
	case uint16:
		return uint64(x)
	case uint32:
		return uint64(x)
	case uint64:
		return x
	case int:
		return uint64(x)
	default:
		return 0
	}
}
func compareOrdered(a, b float64, op string) bool {
	switch op {
	case ">":
		return a > b
	case ">=":
		return a >= b
	case "<":
		return a < b
	case "<=":
		return a <= b
	case "!=":
		return a != b
	default:
		return a == b
	}
}
func compareStrings(a, b, op string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)
	switch op {
	case "!=":
		return !strings.Contains(a, b)
	case ">":
		return a > b
	case ">=":
		return a >= b
	case "<":
		return a < b
	case "<=":
		return a <= b
	default:
		return strings.Contains(a, b)
	}
}

func lex(input string) ([]token, error) {
	var out []token
	for i := 0; i < len(input); {
		r := rune(input[i])
		if unicode.IsSpace(r) {
			i++
			continue
		}
		if input[i] == '(' {
			out = append(out, token{kind: tokLParen, text: "("})
			i++
			continue
		}
		if input[i] == ')' {
			out = append(out, token{kind: tokRParen, text: ")"})
			i++
			continue
		}
		var b strings.Builder
		quoted := false
		for i < len(input) && !unicode.IsSpace(rune(input[i])) && input[i] != '(' && input[i] != ')' {
			if input[i] == '"' {
				quoted = true
				i++
				closed := false
				for i < len(input) {
					if input[i] == '"' {
						i++
						closed = true
						break
					}
					if input[i] == '\\' && i+1 < len(input) {
						i++
						b.WriteByte(input[i])
						i++
						continue
					}
					b.WriteByte(input[i])
					i++
				}
				if !closed {
					return nil, fmt.Errorf("unterminated quoted value")
				}
				continue
			}
			b.WriteByte(input[i])
			i++
		}
		word := b.String()
		if word == "" && !quoted {
			continue
		}
		kind := tokWord
		if !quoted {
			switch strings.ToUpper(word) {
			case "AND":
				kind = tokAnd
			case "OR":
				kind = tokOr
			case "NOT":
				kind = tokNot
			}
		}
		out = append(out, token{kind: kind, text: word, quoted: quoted})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("query is empty")
	}
	out = append(out, token{kind: tokEOF})
	return out, nil
}

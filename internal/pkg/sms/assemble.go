package sms

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config bounds all pending and completed-deduplication state. Zero or negative
// fields use defaults. Lifetime is measured from first observation; duplicates
// never renew it. Callers supply capture timestamps for deterministic replay.
type Config struct {
	MaxAssemblies int
	MaxBytes      int
	MaxSegments   int
	Lifetime      time.Duration
}

// Stats describes current retained state and cumulative outcomes since Reset.
type Stats struct {
	Assemblies, Bytes, Segments         int
	Expired, Conflicts, ResourceLimited uint64
}

type assembly struct {
	id       string
	start    time.Time
	parts    map[uint8]*Message
	bytes    int
	conflict bool
	total    uint8
}

// Assembler owns bounded per-observation-scope state and is safe for concurrent
// use. It holds decoded text only; adapters own SIP transaction packet retention.
type Assembler struct {
	mu       sync.Mutex
	config   Config
	groups   map[string]*assembly
	stats    Stats
	sequence uint64
	closed   bool
}

// NewAssembler constructs an assembler with bounded defaults (1024 assemblies,
// 4 MiB retained content, 255 parts per message, five minutes from first part).
func NewAssembler(config Config) *Assembler {
	if config.MaxAssemblies <= 0 {
		config.MaxAssemblies = 1024
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = 4 << 20
	}
	if config.MaxSegments <= 0 {
		config.MaxSegments = 255
	}
	if config.MaxSegments > 255 {
		config.MaxSegments = 255
	}
	if config.Lifetime <= 0 {
		config.Lifetime = 5 * time.Minute
	}
	return &Assembler{config: config, groups: make(map[string]*assembly)}
}

// GroupKey identifies a concatenation reference in an external
// subscriber/source/session scope. It contains no SMS text. The scope must not
// be a Call-ID or TCP connection: parts can cross both. Empty scope or absent
// SMS parties is deliberately ambiguous and cannot produce an assembly.
func GroupKey(scope string, m *Message) string {
	if m == nil || m.Concat == nil || scope == "" || (m.From == "" && m.To == "") {
		return ""
	}
	// Quoted strings and explicit field separators preserve the distinction
	// between scope/party boundaries without retaining caller-owned scope data.
	// Total, alphabet and non-concatenation headers are validated against the
	// first part instead of splitting contradictory parts into separate groups.
	b := fmt.Sprintf("%q|%q|%q|%q|%d|%d", scope, m.Direction, m.From, m.To, m.Concat.Reference, m.Concat.ReferenceBits)
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])
}

// Add returns an owned per-segment result with assembly progress. Complete
// upstream metadata is preserved. Exact repeats do not consume state or renew
// expiry, while contradictory content poisons that assembly until expiry.
func (a *Assembler) Add(scope string, m *Message, now time.Time) *Message {
	out := Clone(m)
	if out == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		a.stats.ResourceLimited++
		out.Assembly.Status = AssemblyResourceLimited
		return out
	}
	if out.Status != StatusDecoded {
		return out
	}
	if out.Assembly.Status == AssemblyComplete {
		return out
	}
	if out.Concat == nil {
		out.Assembly = AssemblyInfo{Status: AssemblyComplete, Text: out.Text}
		return out
	}
	a.expire(now)
	c := out.Concat
	if c.Total == 0 || c.Part == 0 || c.Part > c.Total || (c.ReferenceBits != 8 && c.ReferenceBits != 16) {
		out.Assembly.Status = AssemblyConflict
		return out
	}
	key := GroupKey(scope, out)
	if key == "" {
		out.Assembly = AssemblyInfo{Status: AssemblyPending, Text: out.Text, Received: []uint8{c.Part}}
		for p := 1; p <= int(c.Total); p++ {
			if uint8(p) != c.Part {
				out.Assembly.Missing = append(out.Assembly.Missing, uint8(p))
			}
		}
		return out
	}
	g := a.groups[key]
	if g != nil {
		var exemplar *Message
		for _, part := range g.parts {
			exemplar = part
			break
		}
		if c.Total != g.total || exemplar.Encoding != out.Encoding || exemplar.DCS != out.DCS || exemplar.PID != out.PID || !bytes.Equal(exemplar.Header, out.Header) {
			if !g.conflict {
				a.stats.Conflicts++
			}
			g.conflict = true
			out.Assembly = assemblyInfo(g, g.total)
			return out
		}
		if previous := g.parts[c.Part]; previous != nil {
			if previous.Text != out.Text {
				if !g.conflict {
					a.stats.Conflicts++
				}
				g.conflict = true
			}
			out.Assembly = assemblyInfo(g, c.Total)
			return out
		}
		if g.conflict {
			out.Assembly = assemblyInfo(g, c.Total)
			return out
		}
	}
	size := retainedBytes(out)
	if a.closed || int(c.Total) > a.config.MaxSegments || (g == nil && len(a.groups) >= a.config.MaxAssemblies) || size > a.config.MaxBytes-a.stats.Bytes {
		a.stats.ResourceLimited++
		if g != nil {
			out.Assembly = assemblyInfo(g, c.Total)
			a.remove(key, g)
		}
		out.Assembly.Status = AssemblyResourceLimited
		return out
	}
	if g == nil {
		a.sequence++
		g = &assembly{id: fmt.Sprintf("%s:%d:%d", key, now.UnixNano(), a.sequence), start: now, parts: make(map[uint8]*Message), total: c.Total}
		a.groups[key] = g
		a.stats.Assemblies++
	}
	part := Clone(out)
	part.Assembly = AssemblyInfo{}
	g.parts[c.Part] = part
	g.bytes += size
	a.stats.Bytes += size
	a.stats.Segments++
	out.Assembly = assemblyInfo(g, c.Total)
	return out
}

func retainedBytes(m *Message) int {
	// Include fixed record/map overhead as well as every retained variable field.
	return 512 + len(m.Text) + len(m.From) + len(m.To) + len(m.Header) + len(m.Encoding) + len(m.Direction) + len(m.Status)
}

func assemblyInfo(g *assembly, total uint8) AssemblyInfo {
	info := AssemblyInfo{ID: g.id, Status: AssemblyPending}
	var text strings.Builder
	for i := 1; i <= int(total); i++ {
		if p := g.parts[uint8(i)]; p != nil {
			info.Received = append(info.Received, uint8(i))
			text.WriteString(p.Text)
		} else {
			info.Missing = append(info.Missing, uint8(i))
		}
	}
	info.Text = text.String()
	if len(info.Missing) == 0 {
		info.Status = AssemblyComplete
	}
	if g.conflict {
		info.Status = AssemblyConflict
	}
	return info
}

func (a *Assembler) remove(key string, g *assembly) {
	delete(a.groups, key)
	a.stats.Assemblies--
	a.stats.Bytes -= g.bytes
	a.stats.Segments -= len(g.parts)
}

func (a *Assembler) expire(now time.Time) []*Message {
	var expired []*Message
	keys := make([]string, 0, len(a.groups))
	for key, g := range a.groups {
		if now.Before(g.start.Add(a.config.Lifetime)) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		g := a.groups[key]
		var m *Message
		for part := 1; part <= a.config.MaxSegments; part++ {
			if p := g.parts[uint8(part)]; p != nil {
				m = p
				break
			}
		}
		if m != nil {
			out := Clone(m)
			out.Assembly = assemblyInfo(g, m.Concat.Total)
			// Expiring deduplication storage does not invalidate complete SMS
			// text already displayed by a consumer.
			if out.Assembly.Status != AssemblyComplete {
				out.Assembly.Status = AssemblyExpired
				expired = append(expired, out)
			}
		}
		a.remove(key, g)
		a.stats.Expired++
	}
	return expired
}

// Expire releases pending and completed deduplication state at the deadline.
// Results contain partial previews for display; they cannot authorize filtering.
func (a *Assembler) Expire(now time.Time) []*Message {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.expire(now)
}

// Stats returns a snapshot including completed results retained for deduplication.
func (a *Assembler) Stats() Stats { a.mu.Lock(); defer a.mu.Unlock(); return a.stats }

// Forget releases an assembly when an adapter loses one of its contributing
// transactions. Later parts start a new group and cannot borrow discarded text.
func (a *Assembler) Forget(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, g := range a.groups {
		if g.id == id {
			a.remove(key, g)
			return
		}
	}
}

// Reset releases content and counters for capture replacement. It does not reopen
// a closed assembler; create a new instance for a new lifecycle after Close.
func (a *Assembler) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.groups = make(map[string]*assembly)
	a.stats = Stats{}
}

// Close releases retained content and rejects future multipart retention.
func (a *Assembler) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.groups = nil
	a.stats = Stats{}
	a.closed = true
}

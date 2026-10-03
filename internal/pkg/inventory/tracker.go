// Package inventory derives bounded observations of hosts and services
// from positive connection evidence. It is not a persistent asset database.
package inventory

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
)

// EntryBytes is the conservative accounted charge for a retained entry,
// including keys, linked-list membership, map overhead and one scope's overhead
// in the worst case of a unique scope per entry. Packet bytes, raw scope strings,
// event envelopes and arbitrary protocol names are never retained.
const EntryBytes int64 = 512

// Evidence must be supplied by the analysis/tracker that observed the exchange.
// Empty fields mean unproven; packet counts and a connection's Service label do
// not provide evidence. Responder must be one of the actual observed endpoints.
type Evidence struct {
	Host      events.InventoryEvidence
	Service   events.InventoryEvidence
	Responder netip.AddrPort
	Protocol  string
}

type Stats struct {
	Entries, Scopes                                    int
	Bytes                                              int64
	EmittedHosts, EmittedServices, Deduplicated        uint64
	Expired, Evicted, ScopeEvicted, CapacitySuppressed uint64
	Late, Unqualified                                  uint64
}

type key struct {
	scope               [32]byte
	host                netip.Addr
	port                uint16
	transport, protocol uint8
	service             bool
}

type entry struct {
	key                      key
	first                    time.Time
	previous, next           *entry
	scopePrevious, scopeNext *entry
}

type scopeState struct {
	count      int
	head, tail *entry
}

// Tracker serializes access, keeps insertion-ordered global and per-scope lists,
// and expires against a monotonic capture-time watermark. Suppressed duplicate
// observations never extend retention. Call Reset at producer session boundaries.
type Tracker struct {
	mu         sync.Mutex
	cfg        eventconfig.Inventory
	prefixes   []netip.Prefix
	entries    map[key]*entry
	scopes     map[[32]byte]*scopeState
	head, tail *entry
	watermark  time.Time
	stats      Stats
}

func New(config eventconfig.Inventory) (*Tracker, error) {
	// Reuse the shared policy validator without silently replacing explicit zeros.
	policy := eventconfig.Default()
	policy.Inventory = config
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("inventory policy: %w", err)
	}
	t := &Tracker{cfg: config}
	t.cfg.LocalCIDRs = nil
	if !config.Enabled {
		return t, nil
	}
	for _, cidr := range config.LocalCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("inventory CIDR: %w", err)
		}
		if prefix.Addr().Is4In6() {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		t.prefixes = append(t.prefixes, prefix.Masked())
	}
	// Most-specific policy wins for overlapping networks, so an explicitly
	// configured point-to-point /31 or host /32 does not inherit a broader broadcast.
	sort.Slice(t.prefixes, func(i, j int) bool {
		if t.prefixes[i].Bits() != t.prefixes[j].Bits() {
			return t.prefixes[i].Bits() > t.prefixes[j].Bits()
		}
		return t.prefixes[i].Addr().Less(t.prefixes[j].Addr())
	})
	t.entries = make(map[key]*entry)
	t.scopes = make(map[[32]byte]*scopeState)
	return t, nil
}

func normalized(address netip.Addr) netip.Addr { return address.WithZone("").Unmap() }

// Local applies the explicit policy; there is no implicit private-address rule.
// Unspecified, multicast and limited-broadcast addresses are never subjects.
// IPv4 directed broadcast is evaluated against the most specific local prefix;
// /31 and /32 contain no directed-broadcast address.
func (t *Tracker) Local(address netip.Addr) bool {
	address = normalized(address)
	if !t.cfg.Enabled || !t.Unicast(address) {
		return false
	}
	for _, prefix := range t.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

// subject applies the optional inventory filter. An omitted filter admits all
// eligible unicast endpoints without declaring those addresses local.
func (t *Tracker) subject(address netip.Addr) bool {
	if !t.cfg.Enabled || !t.Unicast(address) {
		return false
	}
	return len(t.prefixes) == 0 || t.Local(address)
}

// Unicast excludes special subjects and directed broadcast in configured local
// prefixes, while accepting ordinary endpoints outside the local policy. This
// lets producers validate a remote client without treating it as local.
func (t *Tracker) Unicast(address netip.Addr) bool {
	address = normalized(address)
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	for _, prefix := range t.prefixes {
		if !prefix.Contains(address) {
			continue
		}
		if address.Is4() && prefix.Bits() < 31 {
			a, p := address.As4(), prefix.Addr().As4()
			broadcast := binary.BigEndian.Uint32(p[:]) | (^uint32(0) >> uint(prefix.Bits()))
			if binary.BigEndian.Uint32(a[:]) == broadcast {
				return false
			}
		}
		return true
	}
	return true
}

func hostEvidenceValid(e events.InventoryEvidence, transport uint8) bool {
	if transport == 6 {
		return e == events.EvidenceTCPHandshake
	}
	if transport != 17 {
		return false
	}
	switch e {
	case events.EvidenceUDPBidirectional, events.EvidenceDNSExchange, events.EvidenceNTPExchange, events.EvidenceDHCPExchange:
		return true
	default:
		return false
	}
}

// Numeric IDs bound retained protocol storage and keep it independent of display.
func protocolID(protocol string) (uint8, string) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "dns":
		return 1, "dns"
	case "ntp":
		return 2, "ntp"
	case "dhcp":
		return 3, "dhcp"
	case "tls", "ssl":
		return 4, "tls"
	case "http":
		return 5, "http"
	case "smtp":
		return 6, "smtp"
	case "sip":
		return 7, "sip"
	default:
		return 0, ""
	}
}

func serviceEvidenceValid(e Evidence, transport uint8, id uint8) bool {
	if id == 0 {
		return false
	}
	if transport == 6 {
		return e.Service == events.EvidenceTCPHandshake && id != 2 && id != 3
	}
	if transport != 17 {
		return false
	}
	return id == 1 && e.Service == events.EvidenceDNSExchange || id == 2 && e.Service == events.EvidenceNTPExchange || id == 3 && e.Service == events.EvidenceDHCPExchange
}

func (t *Tracker) remove(e *entry) {
	if e.previous != nil {
		e.previous.next = e.next
	} else {
		t.head = e.next
	}
	if e.next != nil {
		e.next.previous = e.previous
	} else {
		t.tail = e.previous
	}
	scope := t.scopes[e.key.scope]
	if e.scopePrevious != nil {
		e.scopePrevious.scopeNext = e.scopeNext
	} else {
		scope.head = e.scopeNext
	}
	if e.scopeNext != nil {
		e.scopeNext.scopePrevious = e.scopePrevious
	} else {
		scope.tail = e.scopePrevious
	}
	scope.count--
	if scope.count == 0 {
		delete(t.scopes, e.key.scope)
	}
	delete(t.entries, e.key)
	// Removed entries must not retain references to the remaining inventory.
	e.previous, e.next, e.scopePrevious, e.scopeNext = nil, nil, nil, nil
}

func (t *Tracker) advance(at time.Time) {
	if at.After(t.watermark) {
		t.watermark = at
	}
	cutoff := t.watermark.Add(-t.cfg.Retention)
	for t.head != nil && !t.head.first.After(cutoff) {
		t.remove(t.head)
		t.stats.Expired++
	}
}

// Advance expires observations even when unrelated protocols advance capture time.
func (t *Tracker) Advance(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg.Enabled {
		t.advance(at)
	}
}

func (t *Tracker) admit(k key, at time.Time) bool {
	if _, found := t.entries[k]; found {
		t.stats.Deduplicated++
		return false
	}
	if t.cfg.MaxBytes < EntryBytes || t.cfg.MaxBytesPerScope < EntryBytes {
		t.stats.CapacitySuppressed++
		return false
	}
	for {
		s := t.scopes[k.scope]
		if s == nil || s.count < t.cfg.MaxEntriesPerScope && int64(s.count+1)*EntryBytes <= t.cfg.MaxBytesPerScope {
			break
		}
		t.remove(s.head)
		t.stats.Evicted++
		t.stats.ScopeEvicted++
	}
	for len(t.entries) >= t.cfg.MaxEntries || int64(len(t.entries)+1)*EntryBytes > t.cfg.MaxBytes {
		t.remove(t.head)
		t.stats.Evicted++
	}
	s := t.scopes[k.scope]
	if s == nil {
		s = &scopeState{}
		t.scopes[k.scope] = s
	}
	e := &entry{key: k, first: at, previous: t.tail, scopePrevious: s.tail}
	if t.tail != nil {
		t.tail.next = e
	} else {
		t.head = e
	}
	if s.tail != nil {
		s.tail.scopeNext = e
	} else {
		s.head = e
	}
	t.tail, s.tail = e, e
	s.count++
	t.entries[k] = e
	return true
}

// Observe emits inventory only for proven evidence, preserving the qualifying
// connection envelope. at is when positive evidence becomes available in capture
// time; the derived envelope retains the connection timestamp. Late observations
// cannot revive state, even after eviction. Equal timestamps are processed in caller
// order, with origin host, response host, then service as stable candidate order.
func (t *Tracker) Observe(scope string, at time.Time, conn events.ConnEvent, evidence Evidence) []events.Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.cfg.Enabled {
		return nil
	}
	if at.Before(t.watermark) {
		t.stats.Late++
		return nil
	}
	t.advance(at)
	if scope == "" || at.IsZero() {
		t.stats.Unqualified++
		return nil
	}
	env := conn.Envelope()
	origin, response := normalized(env.Flow.SourceAddress), normalized(env.Flow.DestinationAddress)
	if !origin.IsValid() || !response.IsValid() {
		t.stats.Unqualified++
		return nil
	}
	scopeID := sha256.Sum256([]byte(scope))
	var output []events.Event
	if hostEvidenceValid(evidence.Host, env.Flow.Protocol) {
		for _, host := range []netip.Addr{origin, response} {
			if !t.subject(host) || !t.admit(key{scope: scopeID, host: host}, at) {
				continue
			}
			event := events.NewKnownHostEvent(env)
			event.Host, event.Evidence = host, evidence.Host
			output = append(output, event.Clone())
			t.stats.EmittedHosts++
		}
	} else {
		t.stats.Unqualified++
	}
	id, protocol := protocolID(evidence.Protocol)
	responder := evidence.Responder
	if responder.IsValid() {
		responder = netip.AddrPortFrom(normalized(responder.Addr()), responder.Port())
	}
	observed := responder.IsValid() && (responder.Addr() == origin && responder.Port() == env.Flow.SourcePort || responder.Addr() == response && responder.Port() == env.Flow.DestinationPort)
	if serviceEvidenceValid(evidence, env.Flow.Protocol, id) && observed && responder.Port() != 0 && t.subject(responder.Addr()) {
		k := key{scope: scopeID, host: responder.Addr(), port: responder.Port(), transport: env.Flow.Protocol, protocol: id, service: true}
		if t.admit(k, at) {
			event := events.NewKnownServiceEvent(env)
			event.Host, event.Port, event.Transport, event.Protocol, event.Evidence = responder.Addr(), responder.Port(), env.Flow.Protocol, protocol, evidence.Service
			output = append(output, event.Clone())
			t.stats.EmittedServices++
		}
	} else if evidence.Service != "" {
		t.stats.Unqualified++
	}
	return output
}

func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.stats
	s.Entries, s.Scopes, s.Bytes = len(t.entries), len(t.scopes), int64(len(t.entries))*EntryBytes
	return s
}

// Reset releases retained entries and capture watermark. Cumulative counters
// remain available for shutdown reporting; a subsequent observation may emit.
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.entries)
	clear(t.scopes)
	t.head, t.tail = nil, nil
	t.watermark = time.Time{}
}

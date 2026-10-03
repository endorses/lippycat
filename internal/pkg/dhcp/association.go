package dhcp

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type AssociationStatus string

const (
	AssociationRequest            AssociationStatus = "request"
	AssociationUnique             AssociationStatus = "unique"
	AssociationMissing            AssociationStatus = "missing"
	AssociationAmbiguous          AssociationStatus = "ambiguous"
	AssociationExpired            AssociationStatus = "expired"
	AssociationCapacitySuppressed AssociationStatus = "capacity_suppressed"
	AssociationNotApplicable      AssociationStatus = "not_applicable"
)

// Association IDs identify scoped exchanges, never replace observed flow IDs.
// A separate ServerID identifies the server branch when a server is known.
type Association struct {
	Status   AssociationStatus
	ID       string
	ServerID string
}

type Config struct {
	MaxEntries int
	MaxBytes   int
	Timeout    time.Duration
}

func DefaultConfig() Config {
	return Config{MaxEntries: 4096, MaxBytes: 4 << 20, Timeout: 2 * time.Minute}
}

func (c Config) Validate() error {
	if c.MaxEntries <= 0 || c.MaxBytes <= 0 || c.Timeout <= 0 {
		return fmt.Errorf("DHCP association limits and timeout must be positive")
	}
	return nil
}

// EntryBytes conservatively accounts for each fixed-size entry including its
// map slot. Scope and identifiers are digested, so no caller strings or packet
// buffers remain retained. This is a state accounting bound, not a heap metric.
const EntryBytes = 512

type Stats struct {
	Entries, Bytes                                  int
	Expired, Evicted, CapacitySuppressed, Ambiguous uint64
}
type key struct {
	scope, identity [32]byte
	xid             uint32
	relay           netip.Addr
}
type entry struct {
	key         key
	hardware    [32]byte
	hasHardware bool
	messageType uint8
	server      netip.Addr
	last        time.Time
	sequence    uint64
	id          [32]byte
}

// Tracker is safe for concurrent callers. Callers provide a scope containing
// capture authority, producer epoch and input identity. Capture-time watermarks
// only advance. Reset must accompany producer-session/EOF/close boundaries.
type Tracker struct {
	mu        sync.Mutex
	config    Config
	entries   map[key]entry
	watermark time.Time
	sequence  uint64
	stats     Stats
}

func NewTracker(c Config) (*Tracker, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &Tracker{config: c, entries: make(map[key]entry)}, nil
}

func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	clear(t.entries)
	t.watermark = time.Time{}
	t.stats.Entries = 0
	t.stats.Bytes = 0
}

func (t *Tracker) Stats() Stats { t.mu.Lock(); defer t.mu.Unlock(); return t.stats }

// Advance expires state during idle periods or while observing other protocols.
func (t *Tracker) Advance(at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if at.After(t.watermark) {
		t.watermark = at
	}
	t.expire()
}

// Observe never suppresses a message; capacity and correlation loss are solely
// association outcomes. Retransmissions remain observations with the same ID.
// Responses without client identifiers match hardware only when unambiguous.
func (t *Tracker) Observe(scope string, at time.Time, m *Message) Association {
	t.mu.Lock()
	defer t.mu.Unlock()
	if at.After(t.watermark) {
		t.watermark = at
	}
	t.expire()
	if m == nil || m.Partial || m.Truncated || m.Role() == RoleUnknown || scope == "" {
		return Association{Status: AssociationNotApplicable}
	}
	if !at.After(t.watermark.Add(-t.config.Timeout)) {
		return Association{Status: AssociationExpired}
	}
	hardware := sha256.Sum256(append([]byte{m.HardwareType}, m.HardwareAddress...))
	identity := hardware
	if len(m.ClientIdentifier) > 0 {
		identity = sha256.Sum256(append([]byte{0}, m.ClientIdentifier...))
	} else if len(m.HardwareAddress) == 0 {
		return Association{Status: AssociationMissing}
	}
	k := key{scope: sha256.Sum256([]byte(scope)), identity: identity, xid: m.TransactionID, relay: m.RelayAddress}
	if m.Role() == RoleRequest {
		// DECLINE/RELEASE carry no matching server reply. Preserve any previous
		// exchange context, but do not turn them into request/reply evidence.
		if m.MessageType == 4 || m.MessageType == 7 {
			if e, ok := t.entries[k]; ok {
				return association(AssociationNotApplicable, e, m.ServerIdentifier)
			}
			return Association{Status: AssociationNotApplicable}
		}
		if e, ok := t.entries[k]; ok {
			if at.Before(e.last) {
				return association(AssociationRequest, e, m.ServerIdentifier)
			}
			e.last = at
			e.messageType = m.MessageType
			e.server = m.ServerIdentifier
			t.entries[k] = e
			return association(AssociationRequest, e, m.ServerIdentifier)
		}
		// Do not let reordered requests revive an exchange already expired or
		// evicted at the current watermark. No unbounded tombstones are needed.
		if at.Before(t.watermark) {
			return Association{Status: AssociationExpired}
		}
		if t.config.MaxBytes < EntryBytes {
			t.stats.CapacitySuppressed++
			return Association{Status: AssociationCapacitySuppressed}
		}
		for len(t.entries) >= t.config.MaxEntries || t.stats.Bytes > t.config.MaxBytes-EntryBytes {
			t.evict()
		}
		t.sequence++
		e := entry{key: k, hardware: hardware, hasHardware: len(m.HardwareAddress) > 0, messageType: m.MessageType, server: m.ServerIdentifier, last: at, sequence: t.sequence}
		h := sha256.New()
		h.Write(k.scope[:])
		h.Write(k.identity[:])
		h.Write([]byte(k.relay.String()))
		var numeric [20]byte
		binary.BigEndian.PutUint32(numeric[:4], k.xid)
		binary.BigEndian.PutUint64(numeric[4:12], uint64(at.UnixNano()))
		binary.BigEndian.PutUint64(numeric[12:], t.sequence)
		h.Write(numeric[:])
		copy(e.id[:], h.Sum(nil))
		t.entries[k] = e
		t.stats.Entries++
		t.stats.Bytes += EntryBytes
		return association(AssociationRequest, e, m.ServerIdentifier)
	}
	var matched entry
	count := 0
	for _, e := range t.entries {
		if e.key.scope != k.scope || e.key.xid != k.xid || e.key.relay != k.relay || at.Before(e.last) {
			continue
		}
		if len(m.ClientIdentifier) > 0 {
			if e.key.identity != identity {
				continue
			}
		} else if !e.hasHardware || len(m.HardwareAddress) == 0 || e.hardware != hardware {
			continue
		}
		if m.MessageType == 2 && e.messageType != 1 {
			continue
		}
		if (m.MessageType == 5 || m.MessageType == 6) && e.messageType != 3 && e.messageType != 8 {
			continue
		}
		if e.server.IsValid() && !e.server.IsUnspecified() && e.server != m.ServerIdentifier {
			continue
		}
		matched = e
		count++
	}
	if count == 0 {
		return Association{Status: AssociationMissing}
	}
	if count > 1 {
		t.stats.Ambiguous++
		return Association{Status: AssociationAmbiguous}
	}
	return association(AssociationUnique, matched, m.ServerIdentifier)
}

func association(status AssociationStatus, e entry, server netip.Addr) Association {
	a := Association{Status: status, ID: hex.EncodeToString(e.id[:16])}
	if server.IsValid() && !server.IsUnspecified() {
		h := sha256.New()
		h.Write(e.id[:])
		h.Write([]byte(server.String()))
		a.ServerID = hex.EncodeToString(h.Sum(nil)[:16])
	}
	return a
}

func (t *Tracker) expire() {
	cutoff := t.watermark.Add(-t.config.Timeout)
	for k, e := range t.entries {
		if !e.last.After(cutoff) {
			delete(t.entries, k)
			t.stats.Entries--
			t.stats.Bytes -= EntryBytes
			t.stats.Expired++
		}
	}
}

func (t *Tracker) evict() {
	var oldest entry
	found := false
	for _, e := range t.entries {
		if !found || e.last.Before(oldest.last) || (e.last.Equal(oldest.last) && e.sequence < oldest.sequence) {
			oldest = e
			found = true
		}
	}
	if found {
		delete(t.entries, oldest.key)
		t.stats.Entries--
		t.stats.Bytes -= EntryBytes
		t.stats.Evicted++
	}
}

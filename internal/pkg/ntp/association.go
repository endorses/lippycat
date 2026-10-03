package ntp

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

type Association struct {
	Status      AssociationStatus
	ID          string
	RequestSeen bool
}

type Config struct {
	MaxEntries int
	MaxBytes   int64
	Timeout    time.Duration
}

func DefaultConfig() Config {
	return Config{MaxEntries: 4096, MaxBytes: 4 << 20, Timeout: 30 * time.Second}
}

// Each entry retains only fixed-size digests, timestamps, and flags. This
// conservative charge includes the entry, map key, and map overhead allowance;
// packet bytes, scope strings and endpoint strings are never retained.
const AssociationEntryBytes int64 = 256

type Stats struct {
	Entries                                                        int
	Bytes                                                          int64
	Expired, Evicted, Ambiguous, Missing, CapacitySuppressed, Late uint64
}

type associationEntry struct {
	id        [32]byte
	first     time.Time
	ambiguous bool
}

// Associator uses a monotonic capture-time watermark and deterministic oldest
// eviction. Callers supply scope containing origin, producer epoch and capture
// source/input identity. Reset at every producer session boundary and EOF/close.
// Duplicate client timestamps are ambiguous even if they may be retransmissions:
// their replies cannot establish which independently observed request was echoed.
type Associator struct {
	mu              sync.Mutex
	cfg             Config
	entries         map[[32]byte]associationEntry
	watermark       time.Time // Capture progress used to reject reordered new requests.
	expiryWatermark time.Time // Capture progress plus live idle aging used for timeout expiry.
	stats           Stats
}

func NewAssociator(cfg Config) (*Associator, error) {
	if cfg.MaxEntries <= 0 || cfg.MaxBytes <= 0 || cfg.Timeout <= 0 {
		return nil, fmt.Errorf("NTP association limits and timeout must be positive")
	}
	return &Associator{cfg: cfg, entries: make(map[[32]byte]associationEntry)}, nil
}

func associationKey(scope string, client, server netip.AddrPort, raw uint64) [32]byte {
	h := sha256.New()
	// Hashing scope first bounds retained state regardless of the caller's scope.
	scopeHash := sha256.Sum256([]byte(scope))
	h.Write(scopeHash[:])
	for _, ep := range []netip.AddrPort{client, server} {
		addr := ep.Addr().Unmap().As16()
		h.Write(addr[:])
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], ep.Port())
		h.Write(port[:])
	}
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], raw)
	h.Write(timestamp[:])
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

func (a *Associator) advance(at time.Time) {
	if at.After(a.watermark) {
		a.watermark = at
	}
	a.expireIdle(at)
}

func (a *Associator) expireIdle(at time.Time) {
	if at.After(a.expiryWatermark) {
		a.expiryWatermark = at
	}
	cutoff := a.expiryWatermark.Add(-a.cfg.Timeout)
	for key, entry := range a.entries {
		if !entry.first.After(cutoff) {
			delete(a.entries, key)
			a.stats.Expired++
		}
	}
}

// Advance expires state as capture time advances, including other protocols.
func (a *Associator) Advance(at time.Time) { a.mu.Lock(); defer a.mu.Unlock(); a.advance(at) }

// ExpireIdle expires state without advancing capture admission. Live timers
// may run ahead of transport-delayed packets that are still within the timeout.
func (a *Associator) ExpireIdle(at time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireIdle(at)
}

func (a *Associator) Observe(scope string, src, dst netip.AddrPort, at time.Time, o *Observation) Association {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.advance(at)
	if o == nil || o.Mode != 3 && o.Mode != 4 {
		return Association{Status: AssociationNotApplicable}
	}
	if o.Partial || o.Truncated || scope == "" || at.IsZero() || !src.IsValid() || !dst.IsValid() || !associationEndpoint(src) || !associationEndpoint(dst) {
		a.stats.Missing++
		return Association{Status: AssociationMissing}
	}
	if !at.After(a.expiryWatermark.Add(-a.cfg.Timeout)) {
		a.stats.Late++
		return Association{Status: AssociationExpired}
	}
	client, server, raw := src, dst, o.Transmit.Raw
	if o.Mode == 4 {
		client, server, raw = dst, src, o.Origin.Raw
	}
	if raw == 0 {
		a.stats.Missing++
		return Association{Status: AssociationMissing}
	}
	key := associationKey(scope, client, server, raw)
	entry, found := a.entries[key]
	if o.Mode == 4 {
		if !found || at.Before(entry.first) {
			a.stats.Missing++
			return Association{Status: AssociationMissing}
		}
		if entry.ambiguous {
			a.stats.Ambiguous++
			return Association{Status: AssociationAmbiguous, RequestSeen: true}
		}
		return Association{Status: AssociationUnique, ID: hex.EncodeToString(entry.id[:]), RequestSeen: true}
	}
	if found {
		entry.ambiguous = true
		a.entries[key] = entry
		a.stats.Ambiguous++
		return Association{Status: AssociationAmbiguous, RequestSeen: true}
	}
	// An out-of-order request cannot revive evicted or expired state, even
	// when its timestamp is still inside the configured timeout window.
	if at.Before(a.watermark) {
		a.stats.Late++
		return Association{Status: AssociationExpired}
	}
	if a.cfg.MaxBytes < AssociationEntryBytes {
		a.stats.CapacitySuppressed++
		return Association{Status: AssociationCapacitySuppressed}
	}
	for len(a.entries) >= a.cfg.MaxEntries || int64(len(a.entries)+1)*AssociationEntryBytes > a.cfg.MaxBytes {
		var oldestKey [32]byte
		var oldest time.Time
		for k, e := range a.entries {
			if oldest.IsZero() || e.first.Before(oldest) || e.first.Equal(oldest) && string(k[:]) < string(oldestKey[:]) {
				oldestKey, oldest = k, e.first
			}
		}
		delete(a.entries, oldestKey)
		a.stats.Evicted++
	}
	// Distinguish a later reuse of an expired request timestamp from its old exchange.
	var idInput [44]byte
	copy(idInput[:32], key[:])
	binary.BigEndian.PutUint64(idInput[32:40], uint64(at.Unix()))
	binary.BigEndian.PutUint32(idInput[40:], uint32(at.Nanosecond()))
	entry = associationEntry{id: sha256.Sum256(idInput[:]), first: at}
	a.entries[key] = entry
	return Association{Status: AssociationRequest, ID: hex.EncodeToString(entry.id[:]), RequestSeen: true}
}

func (a *Associator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.stats
	s.Entries, s.Bytes = len(a.entries), int64(len(a.entries))*AssociationEntryBytes
	return s
}

func (a *Associator) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.entries)
	a.watermark = time.Time{}
	a.expiryWatermark = time.Time{}
}

func associationEndpoint(ep netip.AddrPort) bool {
	addr := ep.Addr().Unmap()
	return !addr.IsUnspecified() && !addr.IsMulticast() && addr != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

//go:build li

package li

import (
	"crypto/sha256"
	"math"
	"net/netip"
	"strings"
	"time"
)

// These are input accounting bounds, not acceptance or performance targets.
const (
	correlationSDPMaxBody         = 64 * 1024
	correlationSDPMaxField        = 1024
	correlationSDPMaxTransactions = 256
	correlationSDPMaxTrustedKeys  = 32
)

type sdpOrigin struct {
	Username, SessionID, NetType, AddrType, Address string
}
type parsedSDPOrigin struct {
	Identity sdpOrigin
	Version  string
}
type sdpOriginRole uint8

const (
	sdpOriginUnknown sdpOriginRole = iota
	sdpOriginOffer
	sdpOriginAnswer
)

type sdpOriginHistoryKey struct {
	Origin sdpOrigin
	Role   sdpOriginRole
}

// parseCorrelationSDPOrigin preserves the complete origin identity. Version is
// revision metadata, deliberately excluded from the matching key. Duplicate
// origins and origins in media sections cannot provide authoritative evidence.
func parseCorrelationSDPOrigin(body string) (parsedSDPOrigin, bool) {
	if len(body) == 0 || len(body) > correlationSDPMaxBody {
		return parsedSDPOrigin{}, false
	}
	var result parsedSDPOrigin
	found := false
	inMedia := false
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.HasPrefix(line, "m=") {
			inMedia = true
		}
		if !strings.HasPrefix(line, "o=") {
			continue
		}
		if found || inMedia {
			return parsedSDPOrigin{}, false
		}
		fields := strings.Fields(line[2:])
		if len(fields) != 6 {
			return parsedSDPOrigin{}, false
		}
		for _, field := range fields {
			if !validSDPOriginToken(field) {
				return parsedSDPOrigin{}, false
			}
		}
		if !decimalSDPToken(fields[1]) || !decimalSDPToken(fields[2]) {
			return parsedSDPOrigin{}, false
		}
		if fields[3] != "IN" || (fields[4] != "IP4" && fields[4] != "IP6") {
			return parsedSDPOrigin{}, false
		}
		if !validSDPOriginAddress(fields[4], fields[5]) {
			return parsedSDPOrigin{}, false
		}
		result = parsedSDPOrigin{Identity: sdpOrigin{fields[0], fields[1], fields[3], fields[4], fields[5]}, Version: fields[2]}
		found = true
	}
	return result, found
}
func validSDPOriginToken(value string) bool {
	if len(value) == 0 || len(value) > correlationSDPMaxField {
		return false
	}
	for _, r := range value {
		if r <= 32 || r == 127 {
			return false
		}
	}
	return true
}
func decimalSDPToken(value string) bool {
	if !validSDPOriginToken(value) {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func validCorrelationSDPOrigin(o sdpOrigin) bool {
	return validSDPOriginToken(o.Username) && decimalSDPToken(o.SessionID) && o.NetType == "IN" && (o.AddrType == "IP4" || o.AddrType == "IP6") && validSDPOriginAddress(o.AddrType, o.Address)
}

// SDP permits a literal unicast address or an FQDN. Keep the original spelling
// as identity rather than resolving DNS or substituting a media connection.
func validSDPOriginAddress(addrType, value string) bool {
	if !validSDPOriginToken(value) {
		return false
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Zone() == "" && !addr.IsMulticast() && ((addrType == "IP4" && addr.Is4()) || (addrType == "IP6" && addr.Is6()))
	}
	host := strings.TrimSuffix(value, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

type sdpOriginObservation struct {
	firstSeen, latestStart, lastSeen time.Time
	transactions                     map[[32]byte]struct{}
	trusted                          map[string]string
	suspendedUntil                   time.Time
	renew                            bool
	generation                       uint64
	// Exhaustion cannot safely classify new transactions after the exact set
	// fills. Quarantine only this origin until a full traffic-free observation
	// horizon, retaining its bounded set instead of clearing replay guards.
	exhausted   bool
	lastTraffic time.Time
}

// sdpOriginHistory is serialized by the caller's correlator mutex. Capture time
// measures reuse, while processor time measures expiry. It is independent of
// group membership and must be observed before candidate lookup.
type sdpOriginHistory struct {
	reuseWindow, observationTTL, suspend time.Duration
	maxTracked                           int
	entries                              map[sdpOriginHistoryKey]*sdpOriginObservation
	disabledUntil                        time.Time
	nextGeneration                       uint64
	generationExhausted                  bool
}

func newSDPOriginHistory(config CallCorrelationConfig) *sdpOriginHistory {
	return &sdpOriginHistory{reuseWindow: config.SDPOriginReuseWindow, observationTTL: config.SDPOriginObservationTTL, suspend: config.SDPOriginSuspend, maxTracked: config.SDPOriginMaxTracked, entries: make(map[sdpOriginHistoryKey]*sdpOriginObservation)}
}
func (h *sdpOriginHistory) Disabled() bool { return h.generationExhausted || !h.disabledUntil.IsZero() }
func (h *sdpOriginHistory) Len() int       { return len(h.entries) }

// Expire processes fixed suspension deadlines before observations at the same
// processor instant. Capacity disablement lasts a complete history horizon;
// release discards history that could be incomplete during the disabled period.
func (h *sdpOriginHistory) expireGlobal(now time.Time) {
	if !h.disabledUntil.IsZero() && !now.Before(h.disabledUntil) {
		h.entries = make(map[sdpOriginHistoryKey]*sdpOriginObservation)
		h.disabledUntil = time.Time{}
	}
}

// expireOrigin performs logical expiry for a single lookup. Full-map cleanup
// belongs to maintenance; packets never scan unrelated origins.
func (h *sdpOriginHistory) expireOrigin(key sdpOriginHistoryKey, now time.Time) {
	entry := h.entries[key]
	if entry == nil {
		return
	}
	if entry.exhausted {
		if !now.Before(entry.lastTraffic.Add(h.observationTTL)) {
			delete(h.entries, key)
		}
		return
	}
	if !entry.suspendedUntil.IsZero() {
		if !now.Before(entry.suspendedUntil) {
			if entry.renew {
				entry.suspendedUntil = entry.suspendedUntil.Add(h.suspend)
				entry.renew = false
				if !now.Before(entry.suspendedUntil) {
					delete(h.entries, key)
				}
			} else {
				delete(h.entries, key)
			}
		}
	} else if !now.Before(entry.lastSeen.Add(h.observationTTL)) {
		delete(h.entries, key)
	}
}

func (h *sdpOriginHistory) Expire(now time.Time) {
	h.expireGlobal(now)
	for key := range h.entries {
		h.expireOrigin(key, now)
	}
}

func (h *sdpOriginHistory) exhaust(entry *sdpOriginObservation, now time.Time) bool {
	entry.exhausted = true
	entry.lastTraffic = now
	return false
}

// Observe returns whether this origin may supply S evidence. The caller passes
// only initial transactions with established offer/answer role. transaction must
// identify retransmissions across packets and matching tasks. Trusted key names
// must be normalized by the caller. Their differing valid values suspend S.
func (h *sdpOriginHistory) Observe(origin sdpOrigin, role sdpOriginRole, transaction string, captureTime, now time.Time, trustedKeys map[string]string) bool {
	h.expireGlobal(now)
	if (role != sdpOriginOffer && role != sdpOriginAnswer) || !validCorrelationSDPOrigin(origin) || transaction == "" || len(transaction) > 4096 || captureTime.IsZero() || h.maxTracked <= 0 || h.observationTTL <= h.reuseWindow || h.suspend <= 0 {
		return false
	}
	if h.Disabled() {
		return false
	}
	key := sdpOriginHistoryKey{origin, role}
	h.expireOrigin(key, now)
	entry := h.entries[key]
	if entry == nil {
		if len(h.entries) >= h.maxTracked {
			h.disabledUntil = now.Add(max(h.observationTTL, 2*h.suspend))
			return false
		}
		if h.nextGeneration == math.MaxUint64 {
			h.generationExhausted = true
			return false
		}
		h.nextGeneration++
		entry = &sdpOriginObservation{generation: h.nextGeneration, firstSeen: captureTime, latestStart: captureTime, lastSeen: now, transactions: make(map[[32]byte]struct{}), trusted: make(map[string]string)}
		h.entries[key] = entry
	}
	if entry.exhausted {
		entry.lastTraffic = now
		return false
	}
	tx := sha256.Sum256([]byte(transaction))
	_, duplicate := entry.transactions[tx]
	if !duplicate {
		if len(entry.transactions) >= correlationSDPMaxTransactions {
			return h.exhaust(entry, now)
		}
		entry.transactions[tx] = struct{}{}
		if captureTime.Before(entry.firstSeen) {
			entry.firstSeen = captureTime
		}
		if captureTime.After(entry.latestStart) {
			entry.latestStart = captureTime
		}
		entry.lastSeen = now
		if !entry.suspendedUntil.IsZero() {
			entry.renew = true
		}
	}
	conflict := false
	for name, value := range trustedKeys {
		if name == "" || value == "" {
			continue
		}
		if len(name) > correlationSDPMaxField || len(value) > correlationSDPMaxField {
			return h.exhaust(entry, now)
		}
		if previous, ok := entry.trusted[name]; ok && previous != value {
			conflict = true
		}
		if _, ok := entry.trusted[name]; !ok && len(entry.trusted) >= correlationSDPMaxTrustedKeys {
			return h.exhaust(entry, now)
		}
		entry.trusted[name] = value
	}
	if entry.suspendedUntil.IsZero() && (conflict || entry.latestStart.Sub(entry.firstSeen) > h.reuseWindow) {
		entry.suspendedUntil = now.Add(h.suspend)
		entry.renew = false
	}
	return entry.suspendedUntil.IsZero()
}

// Usable consults already gathered observations without creating or refreshing
// evidence. Call this after Observe, under the same correlator lock.
func (h *sdpOriginHistory) Usable(origin sdpOrigin, role sdpOriginRole, now time.Time) bool {
	return h.Generation(origin, role, now) != 0
}

// Generation binds candidate evidence to the precise observation that validated
// it. Expiry and global resets cannot revive evidence from a previous lifetime.
func (h *sdpOriginHistory) Generation(origin sdpOrigin, role sdpOriginRole, now time.Time) uint64 {
	h.expireGlobal(now)
	if h.Disabled() || (role != sdpOriginOffer && role != sdpOriginAnswer) {
		return 0
	}
	key := sdpOriginHistoryKey{origin, role}
	h.expireOrigin(key, now)
	entry := h.entries[key]
	if entry == nil || entry.exhausted || !entry.suspendedUntil.IsZero() {
		return 0
	}
	return entry.generation
}

type sdpOriginHistoryStats struct {
	Tracked, Suspended int
	Disabled           bool
}

func (h *sdpOriginHistory) Stats(now time.Time) sdpOriginHistoryStats {
	h.Expire(now)
	stats := sdpOriginHistoryStats{Tracked: len(h.entries), Disabled: h.Disabled()}
	for _, entry := range h.entries {
		if entry.exhausted || !entry.suspendedUntil.IsZero() {
			stats.Suspended++
		}
	}
	return stats
}

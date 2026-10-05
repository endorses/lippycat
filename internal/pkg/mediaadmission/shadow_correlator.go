package mediaadmission

import (
	"sync"
	"sync/atomic"
)

// ShadowIdentityBytes limits transient full-frame correlation. No prefix or
// fingerprint can stand in for a larger or truncated frame.
const ShadowIdentityBytes = 256

type ShadowStats struct {
	Preselection, PublicationWindow, RejectedAfterPublication, Admitted uint64
	Incomplete, Ambiguous, TooLarge, Late, TrackingRejected             uint64
	Pending, Owners                                                     int
}

type shadowIdentity struct {
	domain DomainID
	length uint32
	frame  [ShadowIdentityBytes]byte
}
type shadowEntry struct {
	first                               uint64
	sample                              ShadowSample
	samples, observations, attributions uint64
	observed, attributed                uint64
	owner                               OwnerID
	revision                            uint64
	evidenceEpoch                       uint64
}
type shadowOwner struct {
	domain                       DomainID
	revision, validFrom, created uint64
	known, active                bool
	window                       ShadowWindow
}

// Lifetime supplies the authoritative start of the selected call lifetime.
// Without it, attribution learned after selection cannot prove a packet belongs
// to that lifetime before selection.
func (c *ShadowCorrelator) RecordLifetimeStart(owner OwnerID, domain DomainID, createdNS uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.owners[owner]
	if !ok || v.domain != domain || createdNS == 0 || createdNS > v.window.SelectedNS {
		return
	}
	v.created = createdNS
	if v.revision <= 1 {
		v.validFrom = createdNS
	}
	c.owners[owner] = v
}

// ShadowCorrelator joins full bytes with a separate capture observation and
// verified attribution. Settling waits a bounded interval for duplicates and
// late evidence. Historical owner windows come from actual lifecycle hooks;
// current endpoint map contents never supply a past publication boundary.
type ShadowCorrelator struct {
	mu                      sync.Mutex
	capacity, ownerCapacity int
	ttl                     uint64
	entries                 map[shadowIdentity]*shadowEntry
	owners                  map[OwnerID]shadowOwner
	stats                   ShadowStats
	pressure                atomic.Uint64
	evidenceEpoch           atomic.Uint64
	lossAt                  atomic.Uint64
}

func NewShadowCorrelator(capacity, ownerCapacity int, ttlNS uint64) *ShadowCorrelator {
	return &ShadowCorrelator{capacity: capacity, ownerCapacity: ownerCapacity, ttl: ttlNS, entries: make(map[shadowIdentity]*shadowEntry), owners: make(map[OwnerID]shadowOwner)}
}
func (c *ShadowCorrelator) Selection(owner OwnerID, domain DomainID, selectedNS uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.owners[owner]; exists {
		return
	}
	if len(c.owners) >= c.ownerCapacity {
		c.stats.TrackingRejected++
		return
	}
	c.owners[owner] = shadowOwner{domain: domain, window: ShadowWindow{SelectedNS: selectedNS}}
}
func (c *ShadowCorrelator) Expectation(owner OwnerID, domain DomainID, known, active bool, revision, publishedNS, generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, exists := c.owners[owner]
	if !exists || v.domain != domain || v.window.RetiredNS != 0 {
		return
	}
	if v.revision != revision || v.known != known || v.active != active {
		// Earlier endpoint revisions cannot borrow the current publication.
		v.window.PublishedNS, v.window.PublishedGeneration = 0, 0
		if v.revision == 0 {
			v.validFrom = v.window.SelectedNS
			if v.created != 0 {
				v.validFrom = v.created
			}
		} else {
			v.validFrom = publishedNS
		}
	}
	v.revision, v.known, v.active = revision, known, active
	if known && active && publishedNS != 0 && v.window.PublishedNS == 0 {
		v.window.PublishedNS, v.window.PublishedGeneration = publishedNS, generation
	}
	if !known {
		v.window.PublishedNS, v.window.PublishedGeneration = 0, 0
	}
	c.owners[owner] = v
}
func (c *ShadowCorrelator) Finalized(owner OwnerID, at uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.owners[owner]
	if !ok {
		return
	}
	v.window.RetiredNS = at
	c.owners[owner] = v
}
func identity(domain DomainID, frame []byte) (shadowIdentity, bool) {
	key := shadowIdentity{domain: domain, length: uint32(len(frame))}
	if len(frame) == 0 || len(frame) > ShadowIdentityBytes {
		return key, false
	}
	copy(key.frame[:], frame)
	return key, true
}
func (c *ShadowCorrelator) entry(key shadowIdentity, now uint64) *shadowEntry {
	v := c.entries[key]
	if v == nil {
		if len(c.entries) >= c.capacity {
			c.stats.TrackingRejected++
			c.markLoss(now)
			return nil
		}
		v = &shadowEntry{first: now, evidenceEpoch: c.evidenceEpoch.Load()}
		c.entries[key] = v
	}
	return v
}
func (c *ShadowCorrelator) Sample(sample ShadowSample, now uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sample.IdentityLength == 0 || sample.IdentityLength > ShadowIdentityBytes || sample.IdentityLength != sample.Length {
		c.stats.Incomplete++
		c.stats.TooLarge++
		return
	}
	if sample.EventMonotonicNS == 0 || now < sample.EventMonotonicNS || now-sample.EventMonotonicNS > c.ttl {
		c.stats.Incomplete++
		c.stats.Late++
		return
	}
	key := shadowIdentity{domain: sample.Domain, length: sample.IdentityLength, frame: sample.Identity}
	v := c.entry(key, now)
	if v == nil {
		c.stats.Incomplete++
		return
	}
	v.samples++
	if v.samples == 1 {
		v.sample = sample
	}
}
func (c *ShadowCorrelator) Observed(domain DomainID, frame []byte, now uint64) {
	if !c.mu.TryLock() {
		c.pressure.Add(1)
		c.markLoss(now)
		return
	}
	defer c.mu.Unlock()
	key, valid := identity(domain, frame)
	if !valid {
		return
	}
	v := c.entry(key, now)
	if v == nil {
		return
	}
	v.observations++
	v.observed = now
}
func (c *ShadowCorrelator) Attributed(owner OwnerID, domain DomainID, frame []byte, now uint64) {
	if !c.mu.TryLock() {
		c.pressure.Add(1)
		c.markLoss(now)
		return
	}
	defer c.mu.Unlock()
	key, valid := identity(domain, frame)
	if !valid {
		return
	}
	v := c.entry(key, now)
	if v == nil {
		return
	}
	v.attributions++
	v.attributed, v.owner = now, owner
	if current, exists := c.owners[owner]; exists {
		v.revision = current.revision
	}
}
func (c *ShadowCorrelator) classification(v *shadowEntry) ShadowClassification {
	if v.samples != 1 || v.observations != 1 || v.attributions != 1 || v.evidenceEpoch != c.evidenceEpoch.Load() {
		return ShadowUnclassified
	}
	s := v.sample
	if lost := c.lossAt.Load(); lost != 0 && (s.EventMonotonicNS <= lost || s.EventMonotonicNS-lost <= c.ttl || s.EventMonotonicNS-lost-c.ttl <= c.ttl) {
		return ShadowUnclassified
	}
	if v.observed < s.EventMonotonicNS || v.observed-s.EventMonotonicNS > c.ttl || v.attributed < v.observed || v.attributed-v.observed > c.ttl {
		return ShadowUnclassified
	}
	owner, ok := c.owners[v.owner]
	if !ok || owner.domain != s.Domain || !owner.known || !owner.active || v.revision != owner.revision || owner.validFrom == 0 || s.EventMonotonicNS < owner.validFrom {
		return ShadowUnclassified
	}
	w := owner.window
	// A later generation may include an unrelated endpoint change. Without its
	// historical revision evidence, classification remains incomplete.
	if w.PublishedNS != 0 && s.EventMonotonicNS >= w.PublishedNS && s.Generation != w.PublishedGeneration {
		return ShadowUnclassified
	}
	w.IdentityVerified = true
	return ClassifyShadow(s, w)
}

// EvidenceLost conservatively invalidates pending uniqueness claims after
// kernel evidence loss or an unavailable collection counter. Packet paths do
// not wait for diagnostic maintenance and their pressure also invalidates it.
func (c *ShadowCorrelator) EvidenceLost(at uint64) { c.markLoss(at) }

func (c *ShadowCorrelator) markLoss(at uint64) {
	c.evidenceEpoch.Add(1)
	for previous := c.lossAt.Load(); previous < at; previous = c.lossAt.Load() {
		if c.lossAt.CompareAndSwap(previous, at) {
			break
		}
	}
}

// Advance settles samples and expires frame bytes and retired histories. It is
// invoked by session maintenance, not packet processing or status reads.
func (c *ShadowCorrelator) Advance(now uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, v := range c.entries {
		if now < v.first || now-v.first <= c.ttl || now-v.first-c.ttl <= c.ttl {
			continue
		}
		if v.samples != 0 {
			switch c.classification(v) {
			case ShadowPreselection:
				c.stats.Preselection++
			case ShadowPublicationWindow:
				c.stats.PublicationWindow++
			case ShadowUnexpectedRejection:
				c.stats.RejectedAfterPublication++
			case ShadowAdmitted:
				c.stats.Admitted++
			default:
				c.stats.Incomplete += v.samples
				if v.samples > 1 || v.observations > 1 || v.attributions > 1 {
					c.stats.Ambiguous += v.samples
				}
			}
		}
		delete(c.entries, key)
	}
	for owner, v := range c.owners {
		if v.window.RetiredNS != 0 && now >= v.window.RetiredNS && now-v.window.RetiredNS > c.ttl && now-v.window.RetiredNS-c.ttl > c.ttl && now-v.window.RetiredNS-c.ttl-c.ttl > c.ttl {
			delete(c.owners, owner)
		}
	}
}
func (c *ShadowCorrelator) Snapshot() ShadowStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.stats
	v.TrackingRejected += c.pressure.Load()
	v.Pending, v.Owners = len(c.entries), len(c.owners)
	return v
}

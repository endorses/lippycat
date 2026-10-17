// Package packetdedup conservatively identifies overlapping packet observations
// after the caller authenticates source identity. It is independent of capture
// transport receipts and output ownership. Callers must retain every Retain*
// decision and retry InFlight after its Done channel closes; InFlight alone is
// never evidence that any downstream consumer accepted a packet.
package packetdedup

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

// Config has no implicit capacity or timing defaults. MaxBytes bounds charged
// cache storage, including normalized content and conservative per-entry/source
// overhead; it is not an RSS measurement. There are no background goroutines.
type Config struct {
	MaxEntries int
	MaxBytes   int64
	Window     time.Duration
	Clock      func() time.Time
}

type Observation struct {
	// Consumer separates independent output/task acceptance boundaries. Domain
	// separates observation networks; Flow must include flow identity/direction.
	// Source must be an authenticated capture-origin identity, not peer input.
	Consumer, Domain, Flow, Source string
	CapturedAt                     time.Time
	Packet                         []byte
	LinkType                       layers.LinkType
}

type Decision uint8

const (
	Accept Decision = iota
	Duplicate
	InFlight
	RetainRepeat
	RetainUnsupported
	RetainAmbiguous
	RetainCapacity
	RetainOutsideWindow
)

func (decision Decision) String() string {
	switch decision {
	case Accept:
		return "accept"
	case Duplicate:
		return "duplicate"
	case InFlight:
		return "in_flight"
	case RetainRepeat:
		return "retain_repeat"
	case RetainUnsupported:
		return "retain_unsupported"
	case RetainAmbiguous:
		return "retain_ambiguous"
	case RetainCapacity:
		return "retain_capacity"
	case RetainOutsideWindow:
		return "retain_outside_window"
	default:
		return "unknown"
	}
}

// Stats counts raw attempts independently of eventual accepted claims. A caller
// retries Begin after InFlight, so attempts need not equal input packet count.
type Stats struct {
	Attempts, Claims, Commits, Duplicates, InFlight, Repeats uint64
	Unsupported, Ambiguous, Capacity, OutsideWindow          uint64
	Aborts, Expired, ExpiredPending                          uint64
	Entries, Contributors                                    int
	Bytes                                                    int64
}

type cacheKey struct {
	consumer, domain, flow string
	digest                 [sha256.Size]byte
}
type entry struct {
	key                 cacheKey
	content             []byte
	sources             map[string]struct{}
	created             time.Time
	size                int64
	accepted, ambiguous bool
	done                chan struct{}
	element             *list.Element
}

// Detector is safe for concurrent consumers. The bounded evidence cache is
// deliberately volatile; expired/over-capacity observations remain eligible.
type Detector struct {
	mu      sync.Mutex
	config  Config
	entries map[cacheKey]*entry
	order   list.List
	stats   Stats
}

func New(config Config) (*Detector, error) {
	if config.MaxEntries <= 0 || config.MaxBytes <= 0 || config.Window <= 0 {
		return nil, errors.New("packet duplicate detection requires positive count, byte and window limits")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Detector{config: config, entries: make(map[cacheKey]*entry)}, nil
}

const entryOverhead int64 = 384
const sourceOverhead int64 = 64

// Begin reserves one equivalent observation until Commit or Abort. A returned
// InFlight claim is wait-only. Its Done channel closes on acceptance, rejection
// or expiry; callers retry Begin with their own bounded cancellation policy.
func (d *Detector) Begin(observation Observation) (Decision, *Claim) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stats.Attempts++
	now := d.config.Clock()
	d.expire(now)
	if observation.Consumer == "" || observation.Domain == "" || observation.Flow == "" || observation.Source == "" || observation.CapturedAt.IsZero() || observation.CapturedAt.After(now.Add(d.config.Window)) {
		d.stats.Ambiguous++
		return RetainAmbiguous, nil
	}
	if now.Sub(observation.CapturedAt) >= d.config.Window {
		d.stats.OutsideWindow++
		return RetainOutsideWindow, nil
	}
	identityBytes := int64(len(observation.Consumer)) + int64(len(observation.Domain)) + int64(len(observation.Flow)) + int64(len(observation.Source))
	if identityBytes > d.config.MaxBytes || int64(len(observation.Packet)) > d.config.MaxBytes {
		d.stats.Capacity++
		return RetainCapacity, nil
	}
	canonical, decision := canonicalPacket(observation.Packet, observation.LinkType)
	if decision != Accept {
		if decision == RetainAmbiguous {
			d.stats.Ambiguous++
		} else {
			d.stats.Unsupported++
		}
		return decision, nil
	}
	key := cacheKey{consumer: observation.Consumer, domain: observation.Domain, flow: observation.Flow, digest: sha256.Sum256(canonical)}
	if found := d.entries[key]; found != nil {
		if !bytes.Equal(canonical, found.content) {
			d.stats.Ambiguous++
			return RetainAmbiguous, nil
		}
		if _, seen := found.sources[observation.Source]; seen {
			found.ambiguous = true
			d.stats.Repeats++
			return RetainRepeat, nil
		}
		if found.ambiguous {
			d.stats.Ambiguous++
			return RetainAmbiguous, nil
		}
		if !found.accepted {
			d.stats.InFlight++
			return InFlight, &Claim{detector: d, record: found}
		}
		cost := sourceOverhead + int64(len(observation.Source))
		if cost > d.config.MaxBytes-d.stats.Bytes {
			d.stats.Capacity++
			return RetainCapacity, nil
		}
		found.sources[strings.Clone(observation.Source)] = struct{}{}
		found.size += cost
		d.stats.Bytes += cost
		d.stats.Contributors++
		d.stats.Duplicates++
		return Duplicate, nil
	}
	cost := entryOverhead + sourceOverhead + identityBytes + int64(len(canonical))
	if len(d.entries) >= d.config.MaxEntries || cost > d.config.MaxBytes-d.stats.Bytes {
		d.stats.Capacity++
		return RetainCapacity, nil
	}
	// Clone identity strings so small keys cannot retain a large caller buffer.
	key.consumer = strings.Clone(key.consumer)
	key.domain = strings.Clone(key.domain)
	key.flow = strings.Clone(key.flow)
	record := &entry{key: key, content: canonical, sources: map[string]struct{}{strings.Clone(observation.Source): {}}, created: now, size: cost, done: make(chan struct{})}
	d.insert(record)
	d.entries[key] = record
	d.stats.Entries++
	d.stats.Contributors++
	d.stats.Bytes += cost
	d.stats.Claims++
	return Accept, &Claim{detector: d, record: record, owner: true}
}

// Claim is either an owned reservation or a wait-only reference. Repeated
// Commit/Abort calls are harmless. Commit succeeds only while this reservation
// is live; call it only after the downstream owner accepts the observation.
type Claim struct {
	detector *Detector
	record   *entry
	owner    bool
}

func (c *Claim) Done() <-chan struct{} { return c.record.done }
func (c *Claim) Commit() bool {
	if c == nil || !c.owner {
		return false
	}
	d := c.detector
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(d.config.Clock())
	if d.entries[c.record.key] != c.record || c.record.accepted {
		return false
	}
	c.record.accepted = true
	close(c.record.done)
	d.stats.Commits++
	return true
}
func (c *Claim) Abort() bool {
	if c == nil || !c.owner {
		return false
	}
	d := c.detector
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.entries[c.record.key] != c.record || c.record.accepted {
		return false
	}
	d.remove(c.record)
	d.stats.Aborts++
	return true
}

// insert keeps expiry order correct even if a supplied wall clock moves back.
// Normal monotonic insertion is constant time; only clock rollback scans.
func (d *Detector) insert(record *entry) {
	previous := d.order.Back()
	for previous != nil && previous.Value.(*entry).created.After(record.created) {
		previous = previous.Prev()
	}
	if previous == nil {
		record.element = d.order.PushFront(record)
	} else {
		record.element = d.order.InsertAfter(record, previous)
	}
}
func (d *Detector) expire(now time.Time) {
	for {
		element := d.order.Front()
		if element == nil {
			return
		}
		record := element.Value.(*entry)
		if now.Sub(record.created) < d.config.Window {
			return
		}
		d.stats.Expired++
		if !record.accepted {
			d.stats.ExpiredPending++
		}
		d.remove(record)
	}
}
func (d *Detector) remove(record *entry) {
	delete(d.entries, record.key)
	d.order.Remove(record.element)
	d.stats.Entries--
	d.stats.Contributors -= len(record.sources)
	d.stats.Bytes -= record.size
	if !record.accepted {
		close(record.done)
	}
}
func (d *Detector) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expire(d.config.Clock())
	return d.stats
}

// Contributors returns bounded contributing-source evidence for a live claim.
// It never exposes packet content. Source ordering is unspecified.
func (c *Claim) Contributors() []string {
	if c == nil {
		return nil
	}
	d := c.detector
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.entries[c.record.key] != c.record {
		return nil
	}
	result := make([]string, 0, len(c.record.sources))
	for source := range c.record.sources {
		result = append(result, source)
	}
	return result
}

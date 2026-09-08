package radius

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// CorrelatorConfig limits retained association state. Zero fields select defaults.
// Now must return monotonic logical time; backwards values are clamped. Offline
// readers can supply max(previous, packet timestamp). EvidenceCurrent must check
// every criterion and generation against one current filter/task snapshot. It is
// called under the correlator lock and must not call back into this correlator.
// Without it, no references inherit, including ordinary filter references.
type CorrelatorConfig struct {
	Lifetime, QuietGuard, CleanupInterval        time.Duration
	MaxCandidates, MaxPerKey, MaxSuppressionKeys int
	CandidateBytes, TotalBytes                   int64
	Now                                          func() time.Time
	EvidenceCurrent                              func(AttributionReference) bool
}

type transactionKey struct {
	Scope              CaptureScope
	Client, Server     netip.AddrPort
	Family, Identifier uint8
}
type requestCandidate struct {
	raw         []byte
	code        uint8
	association Association
	deadline    time.Time
	refs        []AttributionReference
	bytes       int64
}
type transactionState struct {
	candidates []requestCandidate
	guard      AssociationStatus
	until      time.Time
	bytes      int64
}

// CorrelatorStats counters count observations, except Expirations (candidates),
// Collisions (new competing instances), and CapacityLosses (state-loss events).
// RetainedBytes is conservative charged storage, including map/entry overhead.
type CorrelatorStats struct {
	Requests, Retransmissions, Unique, Missing, Ambiguous, Expired, Incompatible, CapacitySuppressed uint64
	Collisions, Expirations, CapacityLosses                                                          uint64
	Candidates, SuppressionKeys                                                                      int
	CandidateBytes, RetainedBytes                                                                    int64
	GlobalSuppressed                                                                                 bool
}

// Correlator serializes association decisions; no background goroutine or sink
// I/O is used. Owners may periodically call Cleanup; Process also expires state.
type Correlator struct {
	mapPeak                        int
	mu                             sync.Mutex
	config                         CorrelatorConfig
	states                         map[transactionKey]*transactionState
	stats                          CorrelatorStats
	last, nextCleanup, globalUntil time.Time
	closed                         bool
}

func NewCorrelator(config CorrelatorConfig) (*Correlator, error) {
	if config.Lifetime == 0 {
		config.Lifetime = 30 * time.Second
	}
	if config.QuietGuard == 0 {
		config.QuietGuard = config.Lifetime
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = time.Second
	}
	if config.MaxCandidates == 0 {
		config.MaxCandidates = 65536
	}
	if config.MaxPerKey == 0 {
		config.MaxPerKey = 4
	}
	if config.MaxSuppressionKeys == 0 {
		config.MaxSuppressionKeys = 65536
	}
	if config.CandidateBytes == 0 {
		config.CandidateBytes = 64 << 20
	}
	if config.TotalBytes == 0 {
		config.TotalBytes = 96 << 20
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Lifetime < time.Second || config.Lifetime > 300*time.Second || config.QuietGuard < config.Lifetime || config.CleanupInterval <= 0 || config.MaxCandidates < 1 || config.MaxCandidates > 1048576 || config.MaxPerKey < 1 || config.MaxPerKey > 16 || config.MaxSuppressionKeys < 1 || config.MaxSuppressionKeys > 1048576 || config.CandidateBytes < 1<<20 || config.CandidateBytes > 1024<<20 || config.TotalBytes < 2<<20 || config.TotalBytes > 2048<<20 || config.TotalBytes <= config.CandidateBytes {
		return nil, fmt.Errorf("invalid RADIUS correlator limits")
	}
	return &Correlator{config: config, states: make(map[transactionKey]*transactionState)}, nil
}

func (c *Correlator) now() time.Time {
	now := c.config.Now()
	if now.Before(c.last) {
		return c.last
	}
	c.last = now
	return now
}

func scopeBytes(s CaptureScope) int64 {
	return int64(len(s.OriginNodeID) + len(s.SourceID) + len(s.OperatorScope) + len(s.ProfileRevision))
}
func evidenceBytes(refs []AttributionReference) int64 {
	var n int64
	for _, r := range refs {
		n += 256 + int64(len(r.CriterionGroupID)+len(r.TaskID)) + scopeBytes(r.Scope)
		for _, p := range r.Criteria {
			n += 128 + int64(len(p.TargetKind)+len(p.FilterID)+len(p.Value))
		}
	}
	return n
}
func validAssociationScope(o *Observation) bool {
	s := o.Scope
	return s.OriginNodeID != "" && s.SourceID != "" && s.OperatorScope != "" && s.ProfileRevision != "" && s.Epoch != [16]byte{} && o.Capture.ID.Epoch == s.Epoch && o.Capture.ID.Sequence != 0 && o.Endpoints.Client.IsValid() && o.Endpoints.Server.IsValid() && (o.Endpoints.IPFamily == 4 || o.Endpoints.IPFamily == 6)
}

// Process returns an owned observation. Input must be a validated ingress
// observation whose origin provenance has been authenticated by its caller.
// Existing association/inherited claims are discarded. No response is buffered.
func (c *Correlator) Process(input *Observation) *Observation {
	o := input.Clone()
	if o == nil {
		return nil
	}
	o.Association = Association{Status: AssociationUnprocessed}
	o.Inherited = nil
	if o.Message == nil {
		o.Direct = nil
		return o
	}
	// Revalidate raw bytes to keep malformed/manual messages out of state.
	m, err := Decode(o.Message.Raw)
	if err != nil || !bytes.Equal(m.Raw, o.Message.Raw) || m.Code != o.Message.Code || m.Identifier != o.Message.Identifier {
		o.Direct = nil
		return o
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !now.Before(c.nextCleanup) {
		c.cleanup(now)
		c.nextCleanup = now.Add(c.config.CleanupInterval)
	}
	request := m.Code == 1 || m.Code == 4
	if request {
		c.stats.Requests++
	}
	finish := func(status AssociationStatus) *Observation {
		o.Association.Status = status
		if !request {
			c.countResponse(status)
		}
		return o
	}
	if c.closed {
		return finish(AssociationCapacitySuppressed)
	}
	if !validAssociationScope(o) {
		return finish(AssociationMissing)
	}
	if !c.globalUntil.IsZero() {
		if now.Before(c.globalUntil) {
			c.globalUntil = now.Add(c.config.QuietGuard)
			return finish(AssociationCapacitySuppressed)
		}
		c.globalUntil = time.Time{}
	}
	key := transactionKey{o.Scope, o.Endpoints.Client, o.Endpoints.Server, o.Endpoints.IPFamily, m.Identifier}
	c.expireKey(key, now)
	if !c.globalUntil.IsZero() {
		return finish(AssociationCapacitySuppressed)
	}
	state := c.states[key]
	if state != nil && state.guard != "" {
		if now.Before(state.until) {
			state.until = now.Add(c.config.QuietGuard)
			return finish(state.guard)
		}
		c.remove(key)
		state = nil
	}
	if !request {
		if state == nil {
			return finish(AssociationMissing)
		}
		if len(state.candidates) != 1 {
			return finish(AssociationAmbiguous)
		}
		candidate := state.candidates[0]
		if !(candidate.code == 1 && (m.Code == 2 || m.Code == 3 || m.Code == 11) || candidate.code == 4 && m.Code == 5) {
			return finish(AssociationIncompatible)
		}
		o.Association = candidate.association
		for _, ref := range candidate.refs {
			if ref.Scope != o.Scope || len(ref.Criteria) == 0 || ref.CriterionGroupID == "" {
				continue
			}
			if c.config.EvidenceCurrent == nil || !c.config.EvidenceCurrent(cloneReferences([]AttributionReference{ref})[0]) {
				continue
			}
			o.Inherited = append(o.Inherited, cloneReferences([]AttributionReference{ref})...)
		}
		return finish(AssociationUnique)
	}
	if state != nil {
		for _, candidate := range state.candidates {
			if bytes.Equal(candidate.raw, m.Raw) {
				c.stats.Retransmissions++
				o.Association = candidate.association
				return finish(AssociationRequest)
			}
		}
		c.stats.Collisions++
	}
	cost := int64(512+len(m.Raw)) + evidenceBytes(o.Direct)
	entryCost := int64(0)
	if state == nil {
		entryCost = 1024 + scopeBytes(key.Scope)
	}
	if state != nil && len(state.candidates) >= c.config.MaxPerKey || c.stats.Candidates >= c.config.MaxCandidates || cost > c.config.CandidateBytes-c.stats.CandidateBytes || cost+entryCost > c.config.TotalBytes-c.stats.RetainedBytes {
		c.stats.CapacityLosses++
		c.suppress(key, AssociationCapacitySuppressed, now)
		return finish(AssociationCapacitySuppressed)
	}
	if state == nil {
		state = &transactionState{bytes: entryCost}
		key.Scope = ownScope(key.Scope)
		c.states[key] = state
		c.mapPeak = max(c.mapPeak, len(c.states))
		c.stats.RetainedBytes += entryCost
	}
	association := Association{Status: AssociationRequest, RequestInstanceID: o.Capture.ID, RequestObservationID: o.Capture.ID, RequestFirstSeen: now}
	state.candidates = append(state.candidates, requestCandidate{raw: append([]byte(nil), m.Raw...), code: m.Code, association: association, deadline: now.Add(c.config.Lifetime), refs: ownReferences(o.Direct), bytes: cost})
	c.stats.Candidates++
	c.stats.CandidateBytes += cost
	c.stats.RetainedBytes += cost
	o.Association = association
	return o
}

func (c *Correlator) countResponse(s AssociationStatus) {
	switch s {
	case AssociationUnique:
		c.stats.Unique++
	case AssociationMissing:
		c.stats.Missing++
	case AssociationAmbiguous:
		c.stats.Ambiguous++
	case AssociationExpired:
		c.stats.Expired++
	case AssociationIncompatible:
		c.stats.Incompatible++
	case AssociationCapacitySuppressed:
		c.stats.CapacitySuppressed++
	}
}
func (c *Correlator) remove(key transactionKey) {
	s := c.states[key]
	if s == nil {
		return
	}
	for _, r := range s.candidates {
		c.stats.Candidates--
		c.stats.CandidateBytes -= r.bytes
		c.stats.RetainedBytes -= r.bytes
	}
	if s.guard != "" {
		c.stats.SuppressionKeys--
	}
	c.stats.RetainedBytes -= s.bytes
	delete(c.states, key)
	// Go maps retain buckets after deletion. Rebuild at half occupancy so the
	// conservative per-entry charge also bounds unused map backing storage.
	if len(c.states) == 0 || len(c.states)*2 < c.mapPeak {
		compact := make(map[transactionKey]*transactionState, len(c.states))
		for k, v := range c.states {
			compact[k] = v
		}
		c.states = compact
		c.mapPeak = len(compact)
	}
}
func (c *Correlator) suppress(key transactionKey, status AssociationStatus, now time.Time) {
	c.remove(key)
	cost := int64(1024) + scopeBytes(key.Scope)
	if c.stats.SuppressionKeys >= c.config.MaxSuppressionKeys || cost > c.config.TotalBytes-c.stats.RetainedBytes {
		c.states = make(map[transactionKey]*transactionState)
		c.mapPeak = 0
		if status != AssociationCapacitySuppressed {
			c.stats.CapacityLosses++
		}
		c.stats.Candidates = 0
		c.stats.CandidateBytes = 0
		c.stats.RetainedBytes = 0
		c.stats.SuppressionKeys = 0
		c.globalUntil = now.Add(c.config.QuietGuard)
		return
	}
	key.Scope = ownScope(key.Scope)
	c.states[key] = &transactionState{guard: status, until: now.Add(c.config.QuietGuard), bytes: cost}
	c.mapPeak = max(c.mapPeak, len(c.states))
	c.stats.SuppressionKeys++
	c.stats.RetainedBytes += cost
}
func (c *Correlator) expireKey(key transactionKey, now time.Time) {
	s := c.states[key]
	if s == nil {
		return
	}
	if s.guard != "" {
		if !now.Before(s.until) {
			c.remove(key)
		}
		return
	}
	expired := false
	for _, r := range s.candidates {
		if !now.Before(r.deadline) {
			c.stats.Expirations++
			expired = true
		}
	}
	if expired {
		status := AssociationExpired
		if len(s.candidates) > 1 {
			status = AssociationAmbiguous
		}
		c.suppress(key, status, now)
	}
}
func (c *Correlator) cleanup(now time.Time) {
	for key := range c.states {
		c.expireKey(key, now)
	}
	if !c.globalUntil.IsZero() && !now.Before(c.globalUntil) {
		c.globalUntil = time.Time{}
	}
}

// Cleanup expires idle state. It never extends a quiet guard without traffic.
func (c *Correlator) Cleanup() { c.mu.Lock(); defer c.mu.Unlock(); c.cleanup(c.now()) }

// Close releases state and permanently prevents new inherited associations.
func (c *Correlator) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.states = make(map[transactionKey]*transactionState)
	c.mapPeak = 0
	c.stats.Candidates = 0
	c.stats.CandidateBytes = 0
	c.stats.RetainedBytes = 0
	c.stats.SuppressionKeys = 0
}
func (c *Correlator) Stats() CorrelatorStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.GlobalSuppressed = !c.globalUntil.IsZero() || c.closed
	return s
}

// Own string backing too: a tiny substring may otherwise retain an arbitrarily
// large caller buffer despite fitting the configured logical byte budget.
func ownScope(s CaptureScope) CaptureScope {
	s.OriginNodeID = strings.Clone(s.OriginNodeID)
	s.SourceID = strings.Clone(s.SourceID)
	s.OperatorScope = strings.Clone(s.OperatorScope)
	s.ProfileRevision = strings.Clone(s.ProfileRevision)
	return s
}
func ownReferences(refs []AttributionReference) []AttributionReference {
	result := cloneReferences(refs)
	for i := range result {
		r := &result[i]
		r.CriterionGroupID = strings.Clone(r.CriterionGroupID)
		r.TaskID = strings.Clone(r.TaskID)
		r.Scope = ownScope(r.Scope)
		for j := range r.Criteria {
			p := &r.Criteria[j]
			p.FilterID = strings.Clone(p.FilterID)
			p.TargetKind = strings.Clone(p.TargetKind)
		}
	}
	return result
}

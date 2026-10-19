package learnedrules

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

type entry struct {
	rule       Binding
	start, end time.Duration
	active     bool
	bytes      int
}

type Store struct {
	mu          sync.Mutex
	config      Config
	clock       Clock
	anchorWall  time.Time
	anchorTick  time.Duration
	lastTick    time.Duration
	control     Control
	nextControl uint64
	rules       map[string]entry
	subscribers map[*Subscription]struct{}
	status      Status
	// Reconnect may repeat a snapshot at the same watermark, but cannot roll
	// back a still-current remote control generation.
	snapshotFloor Revision
	closed        bool
}

func New(config Config) (*Store, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	config.Domains = append([]DomainID(nil), config.Domains...)
	config.SupportedProtocols = append([]Protocol(nil), config.SupportedProtocols...)
	clock := config.Clock
	if clock == nil {
		clock = systemClock{start: time.Now()}
	}
	return &Store{config: config, clock: clock, anchorWall: clock.Now(), anchorTick: clock.Elapsed(), rules: make(map[string]entry), subscribers: make(map[*Subscription]struct{})}, nil
}

// StartSession must be called by the authenticated transport owner, using the
// actual authenticated peer identity rather than an identity in a message. It
// immediately fails closed until a complete snapshot is installed. Remote rule
// expiry is not renewed by reconnect or by reinstalling the same timestamps.
func (s *Store) StartSession(authenticatedProcessorID string, session Session) (Control, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return Control{}, ErrClosed
	}
	if authenticatedProcessorID != s.config.ProcessorID || session.ProcessorID != authenticatedProcessorID || session.Generation == 0 {
		s.mu.Unlock()
		return Control{}, ErrAuthority
	}
	s.nextControl++
	if session == s.status.Session {
		if s.status.Revision > s.snapshotFloor {
			s.snapshotFloor = s.status.Revision
		}
	} else {
		s.snapshotFloor = 0
	}
	s.control = Control{session: session, local: s.nextControl, store: s}
	s.status.Session = session
	s.status.Revision = 0
	s.status.Ready = false
	// Preserve the bounded old entries only as deadline guards until the first
	// snapshot; they are never usable while Ready is false.
	change := s.changeLocked(nil)
	control := s.control
	s.mu.Unlock()
	s.observe(change)
	return control, nil
}

func (s *Store) checkLocked(control Control) error {
	if s.closed {
		return ErrClosed
	}
	if control != s.control || control.local == 0 {
		s.status.StaleUpdates++
		return ErrSession
	}
	return nil
}

// ApplySnapshot accepts a complete, bounded snapshot assembled by the caller.
// No partial chunk is visible. Rejection leaves the previous state unchanged.
func (s *Store) ApplySnapshot(control Control, revision Revision, rules []Binding) error {
	s.mu.Lock()
	if err := s.checkLocked(control); err != nil {
		s.mu.Unlock()
		return err
	}
	if revision == 0 || revision < s.snapshotFloor || (s.status.Ready && revision <= s.status.Revision) {
		s.status.StaleUpdates++
		s.mu.Unlock()
		return ErrRevision
	}
	next, err := s.prepareLocked(rules, revision)
	if err != nil {
		if errors.Is(err, ErrCapacity) {
			s.status.CapacityRejections++
		}
		s.mu.Unlock()
		return err
	}
	removed := make([]Removal, 0)
	for id, old := range s.rules {
		if newEntry, ok := next[id]; !ok || !sameOwner(old.rule, newEntry.rule) {
			removed = append(removed, Removal{Rule: cloneRule(old.rule), Reason: RemovedSnapshot})
		}
	}
	s.rules = next
	s.status.Revision = revision
	s.status.Ready = true
	change := s.changeLocked(removed)
	s.mu.Unlock()
	s.observe(change)
	return nil
}

// ApplyDelta requires exactly the next global revision. Per-rule revisions must
// increase as well; removal and upsert of the same ID in one delta is rejected.
// A missing revision forces the transport to obtain a fresh complete snapshot.
func (s *Store) ApplyDelta(control Control, revision Revision, upserts []Binding, removals []string) error {
	s.mu.Lock()
	if err := s.checkLocked(control); err != nil {
		s.mu.Unlock()
		return err
	}
	if !s.status.Ready {
		s.mu.Unlock()
		return ErrNotReady
	}
	if s.status.Revision == ^Revision(0) || revision != s.status.Revision+1 {
		s.status.StaleUpdates++
		s.mu.Unlock()
		return ErrRevision
	}
	if len(upserts) > s.config.MaxRules || len(removals) > s.config.MaxRules {
		s.status.CapacityRejections++
		s.mu.Unlock()
		return ErrCapacity
	}
	seen := make(map[string]struct{}, len(upserts)+len(removals))
	for _, id := range removals {
		if id == "" {
			s.mu.Unlock()
			return ErrInvalid
		}
		if _, ok := seen[id]; ok {
			s.mu.Unlock()
			return ErrInvalid
		}
		seen[id] = struct{}{}
	}
	for _, rule := range upserts {
		if rule.Revision == 0 {
			s.status.StaleUpdates++
			s.mu.Unlock()
			return ErrRevision
		}
		if _, ok := seen[rule.ID]; ok {
			s.mu.Unlock()
			return ErrInvalid
		}
		seen[rule.ID] = struct{}{}
		if old, ok := s.rules[rule.ID]; ok && (rule.Revision <= old.rule.Revision || !sameOwner(old.rule, rule)) {
			s.status.StaleUpdates++
			s.mu.Unlock()
			return ErrRevision
		}
	}
	all := make([]Binding, 0, len(s.rules)+len(upserts))
	removed := make([]Removal, 0, len(removals))
	for id, old := range s.rules {
		if _, changed := seen[id]; !changed {
			all = append(all, old.rule)
		}
	}
	for _, id := range removals {
		if old, ok := s.rules[id]; ok {
			removed = append(removed, Removal{Rule: cloneRule(old.rule), Reason: RemovedExplicit})
		}
	}
	all = append(all, upserts...)
	next, err := s.prepareLocked(all, revision)
	if err != nil {
		if errors.Is(err, ErrCapacity) {
			s.status.CapacityRejections++
		}
		s.mu.Unlock()
		return err
	}
	s.rules = next
	s.status.Revision = revision
	change := s.changeLocked(removed)
	s.mu.Unlock()
	s.observe(change)
	return nil
}

// effectiveTimeLocked follows elapsed time even after a wall-clock rollback.
// Forward wall-clock corrections become a new lower bound for future receipts.
func (s *Store) effectiveTimeLocked() (time.Time, time.Duration) {
	tick := s.clock.Elapsed()
	if tick < s.lastTick {
		tick = s.lastTick
	}
	s.lastTick = tick
	now := s.anchorWall.Add(tick - s.anchorTick)
	if wall := s.clock.Now(); wall.After(now) {
		now = wall
		s.anchorWall, s.anchorTick = wall, tick
	}
	return now, tick
}

func (s *Store) prepareLocked(rules []Binding, revision Revision) (map[string]entry, error) {
	if len(rules) > s.config.MaxRules {
		return nil, ErrCapacity
	}
	now, tick := s.effectiveTimeLocked()
	next := make(map[string]entry, len(rules))
	bytes, endpoints := 0, 0
	for _, rule := range rules {
		if err := s.validateRule(rule, revision, now); err != nil {
			return nil, fmt.Errorf("learned binding %q: %w", rule.ID, err)
		}
		if old, exists := s.rules[rule.ID]; exists && sameOwner(old.rule, rule) {
			if rule.Revision < old.rule.Revision || (rule.Revision == old.rule.Revision && !equalRule(old.rule, rule)) {
				return nil, fmt.Errorf("learned binding %q: %w", rule.ID, ErrRevision)
			}
		}
		if old, exists := s.rules[rule.ID]; exists && sameOwner(old.rule, rule) {
			adapter, _ := s.config.Registry.Lookup(rule.AdapterID, rule.ContextVersion)
			if adapter.ValidateTransition != nil {
				if err := adapter.ValidateTransition(cloneRule(old.rule), cloneRule(rule)); err != nil {
					return nil, err
				}
			}
		}
		if _, exists := next[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate learned binding: %w", ErrInvalid)
		}
		size := ruleBytes(rule)
		if size > s.config.MaxBytes-bytes || len(rule.Selectors) > s.config.MaxEndpoints-endpoints {
			return nil, ErrCapacity
		}
		bytes += size
		endpoints += len(rule.Selectors)
		start := tick
		if notBefore := rule.NotBefore.Add(s.config.ClockUncertainty); notBefore.After(now) {
			start += notBefore.Sub(now)
		}
		end := tick
		if expiry := rule.ExpiresAt.Add(-s.config.ClockUncertainty); expiry.After(now) {
			end += expiry.Sub(now)
		}
		if old, exists := s.rules[rule.ID]; exists && sameOwner(old.rule, rule) {
			if old.rule.ExpiresAt.Equal(rule.ExpiresAt) && old.end < end {
				end = old.end
			}
			if old.rule.NotBefore.Equal(rule.NotBefore) && old.start > start {
				start = old.start
			}
		}
		next[rule.ID] = entry{rule: cloneRule(rule), start: start, end: end, active: start <= tick && tick < end, bytes: size}
	}
	return next, nil
}

// Sweep performs bounded expiry/activation reconciliation. The owner should call
// it from its existing periodic maintenance loop; no per-call timers are used.
// Packet resolution independently checks the same deadlines on every lookup.
func (s *Store) Sweep() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	now, tick := s.effectiveTimeLocked()
	removed := make([]Removal, 0)
	changed := false
	for id, value := range s.rules {
		if tick >= value.end || !now.Before(value.rule.ExpiresAt.Add(-s.config.ClockUncertainty)) {
			delete(s.rules, id)
			removed = append(removed, Removal{Rule: cloneRule(value.rule), Reason: RemovedExpired})
			s.status.Expired++
			changed = true
		} else if active := tick >= value.start && !now.Before(value.rule.NotBefore.Add(s.config.ClockUncertainty)); active != value.active {
			value.active = active
			s.rules[id] = value
			changed = true
		}
	}
	if !changed {
		s.mu.Unlock()
		return nil
	}
	change := s.changeLocked(removed)
	s.mu.Unlock()
	s.observe(change)
	return nil
}

func (s *Store) snapshotLocked() Snapshot {
	snapshot := Snapshot{Session: s.status.Session, Revision: s.status.Revision, Sequence: s.status.Sequence, Ready: s.status.Ready}
	if !snapshot.Ready {
		return snapshot
	}
	now, tick := s.effectiveTimeLocked()
	for _, value := range s.rules {
		if tick >= value.end || !now.Before(value.rule.ExpiresAt.Add(-s.config.ClockUncertainty)) {
			continue
		}
		snapshot.Rules = append(snapshot.Rules, cloneRule(value.rule))
	}
	sort.Slice(snapshot.Rules, func(i, j int) bool { return snapshot.Rules[i].ID < snapshot.Rules[j].ID })
	return snapshot
}

func (s *Store) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Store) activeLocked() []Binding {
	if !s.status.Ready || s.closed {
		return nil
	}
	now, tick := s.effectiveTimeLocked()
	var active []Binding
	for _, value := range s.rules {
		if tick >= value.start && tick < value.end && !now.Before(value.rule.NotBefore.Add(s.config.ClockUncertainty)) && now.Before(value.rule.ExpiresAt.Add(-s.config.ClockUncertainty)) {
			active = append(active, cloneRule(value.rule))
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
	return active
}

func (s *Store) ActiveRules() []Binding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.activeLocked()
}

func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recountLocked()
	return s.status
}

func (s *Store) recountLocked() {
	s.status.Rules, s.status.Bytes, s.status.Endpoints = len(s.rules), 0, 0
	for _, value := range s.rules {
		s.status.Bytes += value.bytes
		s.status.Endpoints += len(value.rule.Selectors)
	}
	s.status.Subscribers = len(s.subscribers)
}

func (s *Store) changeLocked(removed []Removal) Change {
	s.status.Sequence++
	s.recountLocked()
	change := Change{Snapshot: s.snapshotLocked(), Active: s.activeLocked(), Removed: removed}
	for sub := range s.subscribers {
		if !sub.offer(cloneChange(change)) {
			marker := Change{Snapshot: Snapshot{Session: s.status.Session, Revision: s.status.Revision, Sequence: s.status.Sequence}, ResyncRequired: true}
			sub.reset(marker)
			sub.closed()
			delete(s.subscribers, sub)
			s.status.Resyncs++
		}
	}

	return change
}

func cloneChange(change Change) Change {
	change.Rules = append([]Binding(nil), change.Rules...)
	for i := range change.Rules {
		change.Rules[i] = cloneRule(change.Rules[i])
	}
	change.Active = append([]Binding(nil), change.Active...)
	for i := range change.Active {
		change.Active[i] = cloneRule(change.Active[i])
	}
	change.Removed = append([]Removal(nil), change.Removed...)
	for i := range change.Removed {
		change.Removed[i].Rule = cloneRule(change.Removed[i].Rule)
	}
	return change
}

func (s *Store) observe(change Change) {
	if s.config.Observer != nil {
		s.config.Observer.OnLearnedRulesChanged(change)
	}
}

type Subscription struct {
	// Initial and Events share a watermark established under the store lock.
	Initial Change
	Events  <-chan Change
	events  chan Change
	store   *Store
	offer   func(Change) bool
	reset   func(Change)
	closed  func()
}

// SubscribeSink installs a trusted nonblocking projection of notifications. The
// callbacks must not perform I/O or reenter this store: they execute under its
// lock, just like bounded channel sends. Capacity and resync accounting remain
// shared with ordinary subscriptions. Initial has the same atomic watermark.
func (s *Store) SubscribeSink(offer func(Change) bool, reset func(Change), closed func()) (*Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if offer == nil || reset == nil || closed == nil {
		return nil, ErrInvalid
	}
	if len(s.subscribers) >= s.config.MaxSubscribers {
		s.status.CapacityRejections++
		return nil, ErrCapacity
	}
	sub := &Subscription{Initial: Change{Snapshot: s.snapshotLocked(), Active: s.activeLocked()}, store: s, offer: offer, reset: reset, closed: closed}
	s.subscribers[sub] = struct{}{}
	return sub, nil
}

func (s *Store) Subscribe() (*Subscription, error) {
	events := make(chan Change, s.config.SubscriptionBuffer)
	offer := func(change Change) bool {
		select {
		case events <- change:
			return true
		default:
			return false
		}
	}
	reset := func(change Change) {
		for {
			select {
			case <-events:
			default:
				events <- change
				return
			}
		}
	}
	sub, err := s.SubscribeSink(offer, reset, func() { close(events) })
	if err != nil {
		return nil, err
	}
	sub.events, sub.Events = events, events
	return sub, nil
}

func (sub *Subscription) Close() {
	s := sub.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.subscribers[sub]; exists {
		delete(s.subscribers, sub)
		sub.closed()
	}
}

func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	removed := make([]Removal, 0, len(s.rules))
	for _, value := range s.rules {
		removed = append(removed, Removal{Rule: cloneRule(value.rule), Reason: RemovedSession})
	}
	s.rules = make(map[string]entry)
	s.status.Ready = false
	s.closed = true
	change := s.changeLocked(removed)
	for sub := range s.subscribers {
		sub.closed()
		delete(s.subscribers, sub)
	}
	s.mu.Unlock()
	s.observe(change)
	return nil
}

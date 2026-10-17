package mediarules

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

type entry struct {
	rule       Rule
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
	config.Domains = append([]mediaadmission.DomainID(nil), config.Domains...)
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
func (s *Store) ApplySnapshot(control Control, revision Revision, rules []Rule) error {
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
func (s *Store) ApplyDelta(control Control, revision Revision, upserts []Rule, removals []string) error {
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
		if rule.Revision != revision {
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
	all := make([]Rule, 0, len(s.rules)+len(upserts))
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

func (s *Store) prepareLocked(rules []Rule, revision Revision) (map[string]entry, error) {
	if len(rules) > s.config.MaxRules {
		return nil, ErrCapacity
	}
	now, tick := s.effectiveTimeLocked()
	next := make(map[string]entry, len(rules))
	bytes, endpoints := 0, 0
	for _, rule := range rules {
		if err := s.validateRule(rule, revision, now); err != nil {
			return nil, fmt.Errorf("media rule %q: %w", rule.ID, err)
		}
		if old, exists := s.rules[rule.ID]; exists && sameOwner(old.rule, rule) {
			if rule.Revision < old.rule.Revision || rule.Call.SelectionRevision < old.rule.Call.SelectionRevision || (rule.Revision == old.rule.Revision && !equalRule(old.rule, rule)) {
				return nil, fmt.Errorf("media rule %q: %w", rule.ID, ErrRevision)
			}
		}
		if _, exists := next[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate media rule: %w", ErrInvalid)
		}
		size := ruleBytes(rule)
		if size > s.config.MaxBytes-bytes || len(rule.Endpoints) > s.config.MaxEndpoints-endpoints {
			return nil, ErrCapacity
		}
		bytes += size
		endpoints += len(rule.Endpoints)
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

func (s *Store) validateRule(rule Rule, revision Revision, now time.Time) error {
	if rule.ID == "" || rule.Session != s.control.session || rule.Revision == 0 || rule.Revision > revision || rule.Call.CallID == "" || rule.Call.Lifetime.Session == 0 || rule.Call.Lifetime.Generation == 0 || rule.Call.SelectionRevision == 0 || len(rule.Scope) == 0 || len(rule.Endpoints) == 0 || rule.NotBefore.IsZero() || !rule.ExpiresAt.After(rule.NotBefore) {
		return ErrInvalid
	}
	if len(rule.Endpoints) > s.config.MaxEndpointsPerRule || len(rule.Scope) > s.config.MaxEndpoints || len(rule.Call.FilterIDs) > s.config.MaxRules || ruleBytes(rule) > s.config.MaxBytes {
		return ErrCapacity
	}
	if rule.ExpiresAt.Sub(rule.NotBefore) > s.config.MaxLifetime || rule.NotBefore.Sub(now) > s.config.MaxLifetime {
		return fmt.Errorf("lifetime exceeds configured maximum: %w", ErrInvalid)
	}
	// An expired snapshot is not allowed to re-arm capture. An existing entry
	// that expired between deltas is harmless and is removed by Sweep.
	if !rule.ExpiresAt.Add(-s.config.ClockUncertainty).After(now) {
		if _, exists := s.rules[rule.ID]; !exists {
			return fmt.Errorf("rule already expired: %w", ErrInvalid)
		}
	}
	applicable := s.config.HunterID == ""
	for _, scope := range rule.Scope {
		if scope.HunterID == "" {
			return ErrScope
		}
		if scope.HunterID == s.config.HunterID && s.allowedDomain(scope.Domain) {
			applicable = true
		}
	}
	if !applicable {
		return ErrScope
	}
	seen := make(map[mediaadmission.EndpointKey]struct{}, len(rule.Endpoints))
	for _, endpoint := range rule.Endpoints {
		if err := endpoint.Key.Validate(); err != nil {
			return fmt.Errorf("endpoint: %w: %w", ErrInvalid, err)
		}
		if endpoint.Kind > RTPAndRTCP {
			return ErrInvalid
		}
		if _, duplicate := seen[endpoint.Key]; duplicate {
			return ErrInvalid
		}
		seen[endpoint.Key] = struct{}{}
		matched := false
		for _, scope := range rule.Scope {
			if scope.Domain == endpoint.Key.Domain && (s.config.HunterID == "" || scope.HunterID == s.config.HunterID) {
				matched = s.config.HunterID == "" || s.allowedDomain(scope.Domain)
			}
		}
		if !matched {
			return ErrScope
		}
	}
	return nil
}

func (s *Store) allowedDomain(domain mediaadmission.DomainID) bool {
	for _, allowed := range s.config.Domains {
		if allowed == domain {
			return true
		}
	}
	return false
}

func sameOwner(a, b Rule) bool {
	return a.Session == b.Session && a.Call.Lifetime == b.Call.Lifetime && a.Call.CallID == b.Call.CallID
}

func equalRule(a, b Rule) bool {
	return a.ID == b.ID && a.Session == b.Session && a.Revision == b.Revision &&
		a.Call.Lifetime == b.Call.Lifetime && a.Call.CallID == b.Call.CallID &&
		a.Call.FromTag == b.Call.FromTag && a.Call.ToTag == b.Call.ToTag &&
		a.Call.SelectionRevision == b.Call.SelectionRevision && a.Call.CapturePolicyRevision == b.Call.CapturePolicyRevision &&
		slices.Equal(a.Call.FilterIDs, b.Call.FilterIDs) && slices.Equal(a.Scope, b.Scope) &&
		slices.Equal(a.Endpoints, b.Endpoints) && a.NotBefore.Equal(b.NotBefore) && a.ExpiresAt.Equal(b.ExpiresAt)
}

func cloneRule(rule Rule) Rule {
	rule.Scope = append([]Scope(nil), rule.Scope...)
	rule.Endpoints = append([]Endpoint(nil), rule.Endpoints...)
	rule.Call.FilterIDs = append([]string(nil), rule.Call.FilterIDs...)
	return rule
}

// ruleBytes charges fixed bookkeeping and all variable-sized retained fields,
// including references, rather than only the wire payload length.
func ruleBytes(rule Rule) int {
	bytes := 256 + len(rule.ID) + len(rule.Session.ProcessorID) + len(rule.Call.CallID) + len(rule.Call.FromTag) + len(rule.Call.ToTag) + len(rule.Endpoints)*64
	for _, scope := range rule.Scope {
		bytes += 32 + len(scope.HunterID)
	}
	for _, id := range rule.Call.FilterIDs {
		bytes += 16 + len(id)
	}
	return bytes
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

func (s *Store) activeLocked() []Rule {
	if !s.status.Ready || s.closed {
		return nil
	}
	now, tick := s.effectiveTimeLocked()
	var active []Rule
	for _, value := range s.rules {
		if tick >= value.start && tick < value.end && !now.Before(value.rule.NotBefore.Add(s.config.ClockUncertainty)) && now.Before(value.rule.ExpiresAt.Add(-s.config.ClockUncertainty)) {
			active = append(active, cloneRule(value.rule))
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })
	return active
}

func (s *Store) ActiveRules() []Rule {
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
		s.status.Endpoints += len(value.rule.Endpoints)
	}
	s.status.Subscribers = len(s.subscribers)
}

func (s *Store) changeLocked(removed []Removal) Change {
	s.status.Sequence++
	s.recountLocked()
	change := Change{Snapshot: s.snapshotLocked(), Active: s.activeLocked(), Removed: removed}
	for sub := range s.subscribers {
		select {
		case sub.events <- cloneChange(change):
		default:
			// Discard the entire incomplete history, leaving one unambiguous
			// resynchronization marker and then EOF.
			draining := true
			for draining {
				select {
				case <-sub.events:
				default:
					draining = false
				}
			}
			sub.events <- Change{Snapshot: Snapshot{Session: s.status.Session, Revision: s.status.Revision, Sequence: s.status.Sequence}, ResyncRequired: true}
			close(sub.events)
			delete(s.subscribers, sub)
			s.status.Resyncs++
		}
	}
	return change
}

func cloneChange(change Change) Change {
	change.Rules = append([]Rule(nil), change.Rules...)
	for i := range change.Rules {
		change.Rules[i] = cloneRule(change.Rules[i])
	}
	change.Active = append([]Rule(nil), change.Active...)
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
		s.config.Observer.OnMediaRulesChanged(change)
	}
}

type Subscription struct {
	// Initial and Events share a watermark established under the store lock.
	Initial Change
	Events  <-chan Change
	events  chan Change
	store   *Store
}

func (s *Store) Subscribe() (*Subscription, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if len(s.subscribers) >= s.config.MaxSubscribers {
		return nil, ErrCapacity
	}
	events := make(chan Change, s.config.SubscriptionBuffer)
	sub := &Subscription{Initial: Change{Snapshot: s.snapshotLocked(), Active: s.activeLocked()}, Events: events, events: events, store: s}
	s.subscribers[sub] = struct{}{}
	return sub, nil
}

func (sub *Subscription) Close() {
	s := sub.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.subscribers[sub]; exists {
		delete(s.subscribers, sub)
		close(sub.events)
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
		close(sub.events)
		delete(s.subscribers, sub)
	}
	s.mu.Unlock()
	s.observe(change)
	return nil
}

type owner struct {
	lifetime callregistry.Lifetime
	callID   string
}

// Resolve uses exact endpoints in one observation domain. When both endpoints
// have known owners, only their intersection can resolve a call. Shared or
// contradictory ownership remains ambiguous; no most-recent-writer heuristic is
// used. This is attribution evidence, not independent output authorization.
func (s *Store) Resolve(source, destination mediaadmission.EndpointKey) Resolution {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source.Validate() != nil || destination.Validate() != nil || source.Domain != destination.Domain {
		return Resolution{}
	}
	left, right := make(map[owner]CallAssociation), make(map[owner]CallAssociation)
	for _, rule := range s.activeLocked() {
		key := owner{lifetime: rule.Call.Lifetime, callID: rule.Call.CallID}
		for _, endpoint := range rule.Endpoints {
			if endpoint.Key == source {
				left[key] = rule.Call
			}
			if endpoint.Key == destination {
				right[key] = rule.Call
			}
		}
	}
	if len(left) != 0 && len(right) != 0 {
		intersection := make(map[owner]CallAssociation)
		for key, association := range left {
			if _, ok := right[key]; ok {
				intersection[key] = association
			}
		}
		if len(intersection) == 0 {
			return Resolution{Ambiguous: true}
		}
		return resolveOwners(intersection)
	}
	if len(left) != 0 {
		return resolveOwners(left)
	}
	return resolveOwners(right)
}

func resolveOwners(owners map[owner]CallAssociation) Resolution {
	if len(owners) > 1 {
		return Resolution{Ambiguous: true}
	}
	for _, association := range owners {
		return Resolution{Call: association, Resolved: true}
	}
	return Resolution{}
}

// ResolveDialog requires nonempty exact dialog tags and handles reverse SIP
// direction. Initial/early dialogs without both verified tags cannot be matched
// by Call-ID alone. The processor still validates the message and transaction.
func (s *Store) ResolveDialog(callID, fromTag, toTag string) Resolution {
	return s.resolveDialog(nil, callID, fromTag, toTag)
}

// ResolveDialogInDomain additionally requires a rule scoped to this observation
// domain and configured hunter. Equal tags in another domain cannot select SIP.
func (s *Store) ResolveDialogInDomain(domain mediaadmission.DomainID, callID, fromTag, toTag string) Resolution {
	return s.resolveDialog(&domain, callID, fromTag, toTag)
}

func (s *Store) resolveDialog(domain *mediaadmission.DomainID, callID, fromTag, toTag string) Resolution {
	if callID == "" || fromTag == "" || toTag == "" {
		return Resolution{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	owners := make(map[owner]CallAssociation)
	for _, rule := range s.activeLocked() {
		if domain != nil {
			scoped := false
			for _, scope := range rule.Scope {
				if scope.Domain == *domain && (s.config.HunterID == "" || scope.HunterID == s.config.HunterID) {
					scoped = true
					break
				}
			}
			if !scoped {
				continue
			}
		}
		call := rule.Call
		if call.CallID == callID && ((call.FromTag == fromTag && call.ToTag == toTag) || (call.FromTag == toTag && call.ToTag == fromTag)) {
			owners[owner{lifetime: call.Lifetime, callID: call.CallID}] = call
		}
	}
	return resolveOwners(owners)
}

// IsResyncError reports errors requiring a complete snapshot rather than retrying
// an individual delta. Invalid rules/capacity failures remain visible to callers.
func IsResyncError(err error) bool {
	return errors.Is(err, ErrRevision) || errors.Is(err, ErrNotReady) || errors.Is(err, ErrSession)
}

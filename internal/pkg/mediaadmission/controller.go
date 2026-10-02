package mediaadmission

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

type ownerState struct {
	domain    DomainID
	endpoints map[EndpointKey]struct{}
	rejected  bool
}
type scopeState struct {
	selectors         []netip.Prefix
	noFilters         bool
	selectorsDirty    bool
	selectorsRejected bool
	status            ScopeStatus
	desired           map[EndpointKey]int
	installed         map[EndpointKey]struct{}
	unknownDesired    bool
	openSince         time.Time
	openTotal         time.Duration
}

// Controller serializes all backend operations with desired-state changes. No
// asynchronous update queue can overflow or replay a retired owner's mutation.
// Backend calls must be bounded/cancelable and may not call back into Controller.
type Controller struct {
	mu        sync.Mutex
	config    Config
	backend   Backend
	session   uint64
	nextOwner uint64
	owners    map[OwnerID]*ownerState
	scopes    map[DomainID]*scopeState
	closed    bool
}

func NewController(ctx context.Context, config Config, backend Backend) (*Controller, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	c := &Controller{config: config, backend: backend, owners: make(map[OwnerID]*ownerState), scopes: make(map[DomainID]*scopeState)}
	if !config.Enabled {
		return c, nil
	}
	if backend == nil {
		return nil, errors.New("enabled media admission requires a backend")
	}
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("create admission session identity: %w", err)
	}
	c.session = binary.LittleEndian.Uint64(seed[:])
	if c.session == 0 {
		c.session = 1
	}
	for _, domain := range config.Domains() {
		s := &scopeState{status: ScopeStatus{Domain: domain, State: StateInitializing}, desired: make(map[EndpointKey]int), installed: make(map[EndpointKey]struct{})}
		c.scopes[domain] = s
		// New sessions must not inherit pinned/stale entries from a former capture.
		existing, err := backend.ListEndpoints(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("initialize admission domain %d: %w", domain, err)
		}
		for _, key := range existing {
			if key.Domain != domain {
				return nil, errors.New("backend enumerated a foreign domain")
			}
			if err := backend.DeleteEndpoint(ctx, key); err != nil {
				return nil, fmt.Errorf("clear admission domain %d: %w", domain, err)
			}
		}
		if err := c.control(ctx, s, c.normalMode(), 0); err != nil {
			return nil, fmt.Errorf("initialize admission control %d: %w", domain, err)
		}
		s.status.State = c.normalState()
	}
	return c, nil
}

func (c *Controller) normalMode() KernelMode {
	if c.config.Mode == ModeShadow {
		return KernelShadow
	}
	return KernelEnforce
}
func (c *Controller) normalState() State {
	if c.config.Mode == ModeShadow {
		return StateShadow
	}
	return StateEnforcing
}
func (c *Controller) scope(domain DomainID) (*scopeState, error) {
	if c.closed {
		return nil, ErrClosed
	}
	if !c.config.Enabled {
		return nil, ErrDisabled
	}
	s, ok := c.scopes[domain]
	if !ok {
		return nil, ErrUnknownDomain
	}
	return s, nil
}

// BeginOwner is called exactly once per selected authoritative lifetime. The
// returned token must be retained by its adapter; CallID is diagnostic only.
func (c *Controller) BeginOwner(domain DomainID, callID string) (OwnerID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.scope(domain)
	if err != nil {
		return OwnerID{}, err
	}
	if callID == "" || len(callID) > 4096 {
		return OwnerID{}, errors.New("invalid admission Call-ID")
	}
	if len(c.owners) >= c.config.OwnerCapacity {
		s.unknownDesired = true
		return OwnerID{}, c.fail(s, ErrCapacity)
	}
	c.nextOwner++
	if c.nextOwner == 0 {
		return OwnerID{}, errors.New("admission owner generation exhausted")
	}
	id := OwnerID{Session: c.session, Generation: c.nextOwner, CallID: callID}
	c.owners[id] = &ownerState{domain: domain, endpoints: make(map[EndpointKey]struct{})}
	return id, nil
}

func (c *Controller) normalizedSet(domain DomainID, keys []EndpointKey) (map[EndpointKey]struct{}, error) {
	result := make(map[EndpointKey]struct{})
	for _, key := range keys {
		if key.Domain != domain {
			return nil, ErrUnknownDomain
		}
		if err := key.Validate(); err != nil {
			return nil, err
		}
		result[key] = struct{}{}
		if len(result) > c.config.MaxEndpointsPerOwner {
			return nil, ErrCapacity
		}
	}
	return result, nil
}

func (c *Controller) UpdateOwner(ctx context.Context, domain DomainID, id OwnerID, keys []EndpointKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.scope(domain)
	if err != nil {
		return err
	}
	owner, ok := c.owners[id]
	if !ok || owner.domain != domain {
		s.status.StaleUpdates++
		return ErrStaleOwner
	}
	next, err := c.normalizedSet(domain, keys)
	if err != nil {
		owner.rejected = true
		return c.fail(s, err)
	}
	count := len(s.desired)
	for key := range owner.endpoints {
		if _, keep := next[key]; !keep && s.desired[key] == 1 {
			count--
		}
	}
	for key := range next {
		if s.desired[key] == 0 {
			count++
		}
	}
	if c.totalDesired()-len(s.desired)+count > c.config.EndpointCapacity {
		owner.rejected = true
		return c.fail(s, ErrCapacity)
	}
	changed := !sameSet(owner.endpoints, next)
	if changed {
		c.removeDesired(s, owner.endpoints)
		for key := range next {
			s.desired[key]++
		}
		owner.endpoints = next
		s.status.DesiredGeneration++
	}
	owner.rejected = false
	if !changed && s.status.State == c.normalState() {
		return nil
	}
	return c.sync(ctx, s, false)
}

func (c *Controller) EndOwner(ctx context.Context, domain DomainID, id OwnerID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.scope(domain)
	if err != nil {
		return err
	}
	owner, ok := c.owners[id]
	if !ok || owner.domain != domain {
		s.status.StaleUpdates++
		return ErrStaleOwner
	}
	c.removeDesired(s, owner.endpoints)
	delete(c.owners, id)
	s.status.DesiredGeneration++
	return c.sync(ctx, s, false)
}
func (c *Controller) removeDesired(s *scopeState, keys map[EndpointKey]struct{}) {
	for key := range keys {
		if s.desired[key] <= 1 {
			delete(s.desired, key)
		} else {
			s.desired[key]--
		}
	}
}
func (c *Controller) totalDesired() int {
	n := 0
	for _, s := range c.scopes {
		n += len(s.desired)
	}
	return n
}
func sameSet(a, b map[EndpointKey]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}

// MarkUnsynchronized reports an update lost outside the serialized controller.
// Recovery is blocked until ReplaceDesired confirms a complete owner snapshot.
func (c *Controller) MarkUnsynchronized(domain DomainID, reason error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.scope(domain)
	if err != nil {
		return err
	}
	s.unknownDesired = true
	if reason == nil {
		reason = errors.New("admission observation lost")
	}
	return c.fail(s, reason)
}

type OwnerEndpoints struct {
	Owner     OwnerID
	Endpoints []EndpointKey
}

// ReplaceDesired is an explicit complete snapshot for one domain after external
// observation loss. Tokens must already be active. Omitted owners are retired.
func (c *Controller) ReplaceDesired(ctx context.Context, domain DomainID, snapshot []OwnerEndpoints) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.scope(domain)
	if err != nil {
		return err
	}
	next := make(map[OwnerID]map[EndpointKey]struct{})
	counts := make(map[EndpointKey]int)
	for _, item := range snapshot {
		owner, ok := c.owners[item.Owner]
		if !ok || owner.domain != domain {
			return ErrStaleOwner
		}
		if _, exists := next[item.Owner]; exists {
			return errors.New("duplicate owner in admission snapshot")
		}
		keys, err := c.normalizedSet(domain, item.Endpoints)
		if err != nil {
			return c.fail(s, err)
		}
		next[item.Owner] = keys
		for key := range keys {
			counts[key]++
		}
	}
	if c.totalDesired()-len(s.desired)+len(counts) > c.config.EndpointCapacity {
		return c.fail(s, ErrCapacity)
	}
	for id, owner := range c.owners {
		if owner.domain != domain {
			continue
		}
		keys, keep := next[id]
		if !keep {
			delete(c.owners, id)
		} else {
			owner.endpoints = keys
			owner.rejected = false
		}
	}
	s.desired = counts
	s.unknownDesired = false
	s.status.DesiredGeneration++
	return c.sync(ctx, s, true)
}

func (c *Controller) Reconcile(ctx context.Context, domain DomainID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.scope(domain)
	if err != nil {
		return err
	}
	return c.sync(ctx, s, true)
}

func (c *Controller) incomplete(s *scopeState) bool {
	if s.unknownDesired || s.selectorsRejected {
		return true
	}
	for _, owner := range c.owners {
		if owner.domain == s.status.Domain && owner.rejected {
			return true
		}
	}
	return false
}

func (c *Controller) sync(ctx context.Context, s *scopeState, enumerate bool) error {
	recovering := s.status.State != c.normalState()
	if recovering {
		s.status.State = StateRecovery
		enumerate = true
	}
	if enumerate {
		keys, err := c.backend.ListEndpoints(ctx, s.status.Domain)
		if err != nil {
			return c.fail(s, fmt.Errorf("enumerate admission endpoints: %w", err))
		}
		installed := make(map[EndpointKey]struct{}, len(keys))
		for _, key := range keys {
			if key.Domain != s.status.Domain {
				return c.fail(s, errors.New("backend enumerated a foreign domain"))
			}
			if err := key.Validate(); err != nil {
				return c.fail(s, err)
			}
			installed[key] = struct{}{}
		}
		s.installed = installed
	}
	if s.selectorsDirty {
		backend, ok := c.backend.(SelectorBackend)
		if !ok {
			return c.fail(s, errors.New("admission backend does not support independent selectors"))
		}
		if err := backend.ReplaceSelectors(ctx, s.status.Domain, append([]netip.Prefix(nil), s.selectors...), s.noFilters); err != nil {
			return c.fail(s, fmt.Errorf("replace independent admission selectors: %w", err))
		}
		s.selectorsDirty = false
	}
	// Delete first so replacing an endpoint can succeed at full capacity.
	for key := range s.installed {
		if s.desired[key] > 0 {
			continue
		}
		if err := c.backend.DeleteEndpoint(ctx, key); err != nil {
			return c.fail(s, fmt.Errorf("delete admission endpoint: %w", err))
		}
		delete(s.installed, key)
	}
	for key := range s.desired {
		if _, ok := s.installed[key]; ok {
			continue
		}
		if err := c.backend.PutEndpoint(ctx, key); err != nil {
			return c.fail(s, fmt.Errorf("install admission endpoint: %w", err))
		}
		s.installed[key] = struct{}{}
	}
	if c.incomplete(s) {
		return c.fail(s, errors.New("complete eligible owner snapshot required"))
	}
	if err := c.control(ctx, s, c.normalMode(), s.status.DesiredGeneration); err != nil {
		return c.fail(s, fmt.Errorf("publish admission generation: %w", err))
	}
	recovered := !s.status.DegradedSince.IsZero()
	s.status.InstalledGeneration = s.status.DesiredGeneration
	s.status.State = c.normalState()
	s.status.Reason = ""
	s.status.DegradedSince = time.Time{}
	if recovered {
		s.status.Recoveries++
	}
	return nil
}

func (c *Controller) control(ctx context.Context, s *scopeState, mode KernelMode, generation uint64) error {
	next := Control{Mode: mode, Generation: generation}
	if err := c.backend.SetControl(ctx, s.status.Domain, next); err != nil {
		s.status.ControlErrors++
		s.status.ControlUncertain = true
		return err
	}
	now := time.Now()
	if mode == KernelOpen && s.openSince.IsZero() {
		s.openSince = now
	}
	if mode != KernelOpen && !s.openSince.IsZero() {
		s.openTotal += now.Sub(s.openSince)
		s.openSince = time.Time{}
	}
	s.status.LastConfirmed = next
	s.status.ControlUncertain = false
	return nil
}

func (c *Controller) fail(s *scopeState, cause error) error {
	s.status.UpdateErrors++
	s.status.Reason = cause.Error()
	if s.status.DegradedSince.IsZero() {
		s.status.DegradedSince = time.Now()
	}
	mode := c.normalMode()
	state := StateDegradedClosed
	if c.config.FailurePolicy == FailureOpen {
		mode = KernelOpen
		state = StateDegradedOpen
	}
	// A canceled packet/owner operation must still be able to establish the
	// failure policy. Keep this independent control operation strictly bounded.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.control(ctx, s, mode, s.status.LastConfirmed.Generation); err != nil {
		s.status.State = StateControlFailed
		return errors.Join(cause, fmt.Errorf("establish admission failure policy: %w", err))
	}
	s.status.State = state
	return cause
}

func (c *Controller) Status() []ScopeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.config.Enabled {
		return []ScopeStatus{{State: StateDisabled}}
	}
	result := make([]ScopeStatus, 0, len(c.scopes))
	for domain, s := range c.scopes {
		st := s.status
		st.DesiredEndpoints = len(s.desired)
		st.InstalledEndpoints = len(s.installed)
		for _, owner := range c.owners {
			if owner.domain == domain {
				st.Owners++
				if owner.rejected {
					st.PendingUpdates++
				}
			}
		}
		for key := range s.desired {
			if _, ok := s.installed[key]; !ok {
				st.PendingUpdates++
			}
		}
		for key := range s.installed {
			if s.desired[key] == 0 {
				st.PendingUpdates++
			}
		}
		if s.unknownDesired {
			st.PendingUpdates++
		}
		if s.selectorsDirty || s.selectorsRejected {
			st.PendingUpdates++
		}
		if st.DesiredGeneration != st.InstalledGeneration || st.ControlUncertain {
			st.PendingUpdates++
		}
		st.OpenDuration = s.openTotal
		if !s.openSince.IsZero() {
			st.OpenDuration += time.Since(s.openSince)
		}
		result = append(result, st)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Domain < result[j].Domain })
	return result
}

// Close retires desired ownership and attempts complete deletion. The capture
// session still owns attachment/maps; it must close them even when cleanup fails.
func (c *Controller) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	var errs []error
	c.owners = make(map[OwnerID]*ownerState)
	for _, s := range c.scopes {
		s.desired = make(map[EndpointKey]int)
		s.unknownDesired = false
		s.status.DesiredGeneration++
		if err := c.sync(ctx, s, true); err != nil {
			errs = append(errs, err)
		}
		s.status.State = StateClosed
	}
	c.closed = true
	return errors.Join(errs...)
}

// ReplaceSelectors serializes independent selector publication with call
// admission. An interrupted replacement remains desired and is retried before
// any later reconciliation can restore enforcement. The backend must replace
// the complete selector set for this scope and preserve explicit restrictions.
func (c *Controller) ReplaceSelectors(ctx context.Context, domain DomainID, prefixes []netip.Prefix, noFilters bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.scope(domain)
	if err != nil {
		return err
	}
	if len(prefixes) > c.config.EndpointCapacity {
		s.selectorsRejected = true
		return c.fail(s, ErrCapacity)
	}
	next := make([]netip.Prefix, 0, len(prefixes))
	seen := make(map[netip.Prefix]bool)
	for _, prefix := range prefixes {
		if !prefix.IsValid() || prefix.Addr().Zone() != "" {
			s.selectorsRejected = true
			return c.fail(s, errors.New("invalid independent admission prefix"))
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				s.selectorsRejected = true
				return c.fail(s, errors.New("mapped IPv4 prefix exceeds address family"))
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			next = append(next, prefix)
			seen[prefix] = true
		}
	}
	s.selectorsRejected = false
	s.selectors = next
	s.noFilters = noFilters
	s.selectorsDirty = true
	s.status.DesiredGeneration++
	// Keep the configured degraded behavior through multi-map replacement, even
	// though no failure has happened yet. Status records recovery/publication.
	mode := c.normalMode()
	if c.config.FailurePolicy == FailureOpen {
		mode = KernelOpen
	}
	if err := c.control(ctx, s, mode, s.status.LastConfirmed.Generation); err != nil {
		return c.fail(s, fmt.Errorf("begin selector publication: %w", err))
	}
	s.status.State = StateRecovery
	return c.sync(ctx, s, true)
}

package mediarules

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu      sync.Mutex
	wall    time.Time
	elapsed time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

func (c *fakeClock) Elapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.elapsed
}

func (c *fakeClock) advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(duration)
	c.elapsed += duration
}

func (c *fakeClock) changeWall(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(duration)
}

func testConfig() (Config, *fakeClock) {
	clock := &fakeClock{wall: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	return Config{
		ProcessorID: "processor", HunterID: "hunter-a", Domains: []mediaadmission.DomainID{1, 2},
		MaxRules: 8, MaxBytes: 32 * 1024, MaxEndpoints: 16, MaxEndpointsPerRule: 4,
		MaxSubscribers: 2, SubscriptionBuffer: 2, MaxLifetime: time.Minute, Clock: clock,
	}, clock
}

func newTestStore(t *testing.T) (*Store, Control, *fakeClock) {
	t.Helper()
	config, clock := testConfig()
	store, err := New(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	control, err := store.StartSession("processor", Session{ProcessorID: "processor", Generation: 1})
	require.NoError(t, err)
	return store, control, clock
}

func endpoint(addr string, port uint16) Endpoint {
	return Endpoint{Key: mediaadmission.EndpointKey{Domain: 1, Addr: netip.MustParseAddr(addr), Port: port}, Kind: RTPAndRTCP}
}

func testRule(clock *fakeClock, id string) Rule {
	return Rule{
		ID: id, Session: Session{ProcessorID: "processor", Generation: 1}, Revision: 1,
		Call: CallAssociation{
			Lifetime: callregistry.Lifetime{Session: 10, Generation: 1}, CallID: "call@example.invalid",
			FromTag: "alice", ToTag: "bob", SelectionRevision: 3, FilterIDs: []string{"selected-filter"},
		},
		Scope:     []Scope{{HunterID: "hunter-a", Domain: 1}},
		Endpoints: []Endpoint{endpoint("192.0.2.1", 40000), endpoint("2001:db8::2", 50000)},
		NotBefore: clock.Now(), ExpiresAt: clock.Now().Add(10 * time.Second),
	}
}

func TestSnapshotsAreAtomicAndOwned(t *testing.T) {
	store, control, clock := newTestStore(t)
	rule := testRule(clock, "r1")
	require.ErrorIs(t, store.ApplyDelta(control, 1, []Rule{rule}, nil), ErrNotReady)
	require.Empty(t, store.ActiveRules())
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	before := store.Snapshot()
	bad := testRule(clock, "invalid")
	bad.Endpoints[0].Key.Port = 0
	require.ErrorIs(t, store.ApplySnapshot(control, 2, []Rule{rule, bad}), ErrInvalid)
	require.Equal(t, before, store.Snapshot(), "a failed complete snapshot cannot expose its valid prefix")
	rule.Endpoints[0].Key.Port = 1111
	rule.Call.FilterIDs[0] = "mutated"
	before.Rules[0].Scope[0].HunterID = "mutated"
	current := store.ActiveRules()
	require.Equal(t, uint16(40000), current[0].Endpoints[0].Key.Port)
	require.Equal(t, "selected-filter", current[0].Call.FilterIDs[0])
	require.Equal(t, "hunter-a", current[0].Scope[0].HunterID)
}

func TestSessionAuthorityAndReconnect(t *testing.T) {
	store, oldControl, clock := newTestStore(t)
	rule := testRule(clock, "r1")
	require.NoError(t, store.ApplySnapshot(oldControl, 5, []Rule{rule}))
	_, err := store.StartSession("untrusted", rule.Session)
	require.ErrorIs(t, err, ErrAuthority)
	require.Len(t, store.ActiveRules(), 1, "untrusted peer cannot invalidate trusted state")
	_, err = store.StartSession("processor", Session{ProcessorID: "other", Generation: 1})
	require.ErrorIs(t, err, ErrAuthority)
	control, err := store.StartSession("processor", rule.Session)
	require.NoError(t, err)
	require.False(t, store.Status().Ready)
	require.Empty(t, store.ActiveRules(), "reconnecting requires a fresh snapshot")
	require.ErrorIs(t, store.ApplySnapshot(oldControl, 6, []Rule{rule}), ErrSession)
	require.ErrorIs(t, store.ApplySnapshot(control, 4, []Rule{rule}), ErrRevision)
	control, err = store.StartSession("processor", rule.Session)
	require.NoError(t, err)
	require.ErrorIs(t, store.ApplySnapshot(control, 4, []Rule{rule}), ErrRevision, "repeated reconnects cannot erase the current-session watermark")
	require.NoError(t, store.ApplySnapshot(control, 5, []Rule{rule}))
	newSession := Session{ProcessorID: "processor", Generation: 2}
	control, err = store.StartSession("processor", newSession)
	require.NoError(t, err)
	require.ErrorIs(t, store.ApplySnapshot(control, 1, []Rule{rule}), ErrInvalid)
	rule.Session = newSession
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
}

func TestOrderedDeltasAndRemoval(t *testing.T) {
	store, control, clock := newTestStore(t)
	rule := testRule(clock, "r1")
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	updated := cloneRule(rule)
	updated.Revision = 2
	updated.Endpoints[0].Key.Port = 45000
	require.ErrorIs(t, store.ApplyDelta(control, 3, []Rule{updated}, nil), ErrRevision)
	require.ErrorIs(t, store.ApplyDelta(control, 2, []Rule{rule}, nil), ErrRevision)
	require.NoError(t, store.ApplyDelta(control, 2, []Rule{updated}, nil))
	require.ErrorIs(t, store.ApplyDelta(control, 2, []Rule{updated}, nil), ErrRevision)
	require.False(t, store.Resolve(rule.Endpoints[0].Key, endpoint("192.0.2.99", 50000).Key).Resolved)
	require.True(t, store.Resolve(updated.Endpoints[0].Key, endpoint("192.0.2.99", 50000).Key).Resolved)
	require.NoError(t, store.ApplyDelta(control, 3, nil, []string{"r1"}))
	require.Empty(t, store.ActiveRules())
	require.ErrorIs(t, store.ApplyDelta(control, 4, []Rule{updated}, nil), ErrRevision, "old upserts cannot resurrect removed rules")
	updated.Revision = 4
	require.ErrorIs(t, store.ApplyDelta(control, 4, []Rule{updated}, []string{"r1"}), ErrInvalid)
	updated.Call.Lifetime.Generation++
	require.NoError(t, store.ApplyDelta(control, 4, []Rule{updated}, nil), "the authoritative publisher may select a new lifetime after explicit removal")
	stale := cloneRule(updated)
	stale.Revision = 3
	require.ErrorIs(t, store.ApplySnapshot(control, 5, []Rule{stale}), ErrRevision, "a later snapshot cannot roll back an existing rule")
	stale.Revision = 4
	stale.Endpoints[0].Key.Port++
	require.ErrorIs(t, store.ApplySnapshot(control, 5, []Rule{stale}), ErrRevision, "a rule revision identifies immutable contents")
	stale.Revision = 5
	stale.Call.SelectionRevision--
	require.ErrorIs(t, store.ApplySnapshot(control, 5, []Rule{stale}), ErrRevision, "new rule revisions cannot revive older selection evidence")
}

func TestMonotonicExpiryAndReconnectDoNotExtendRules(t *testing.T) {
	store, control, clock := newTestStore(t)
	rule := testRule(clock, "r1")
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	clock.advance(8 * time.Second)
	clock.changeWall(-time.Hour)
	control, err := store.StartSession("processor", rule.Session)
	require.NoError(t, err)
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	require.Len(t, store.ActiveRules(), 1)
	clock.advance(2 * time.Second)
	require.Empty(t, store.ActiveRules(), "userspace expiry does not wait for maintenance or backend removal")
	require.Empty(t, store.Snapshot().Rules, "new subscribers must not receive expired rules while waiting for maintenance")
	require.False(t, store.Resolve(rule.Endpoints[0].Key, rule.Endpoints[1].Key).Resolved)
	require.False(t, store.ResolveDialog(rule.Call.CallID, "alice", "bob").Resolved)
	require.NoError(t, store.Sweep())
	require.Empty(t, store.Snapshot().Rules)
	require.Equal(t, uint64(1), store.Status().Expired)
	newRule := testRule(clock, "expired")
	newRule.NotBefore, newRule.ExpiresAt = rule.NotBefore, rule.ExpiresAt
	require.ErrorIs(t, store.ApplySnapshot(control, 2, []Rule{newRule}), ErrInvalid)
}

func TestControlTokensAreBoundToStore(t *testing.T) {
	first, firstControl, firstClock := newTestStore(t)
	second, secondControl, secondClock := newTestStore(t)
	require.ErrorIs(t, first.ApplySnapshot(secondControl, 1, []Rule{testRule(firstClock, "r")}), ErrSession)
	require.ErrorIs(t, second.ApplySnapshot(firstControl, 1, []Rule{testRule(secondClock, "r")}), ErrSession)
}

func TestNotBeforeClockUncertaintyAndForwardCorrection(t *testing.T) {
	config, clock := testConfig()
	config.ClockUncertainty = time.Second
	store, err := New(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	rule := testRule(clock, "r1")
	rule.NotBefore = clock.Now().Add(2 * time.Second)
	control, err := store.StartSession("processor", rule.Session)
	require.NoError(t, err)
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	require.Empty(t, store.ActiveRules())
	clock.advance(2 * time.Second)
	require.Empty(t, store.ActiveRules())
	clock.advance(time.Second)
	require.Len(t, store.ActiveRules(), 1)
	require.NoError(t, store.Sweep())
	clock.changeWall(time.Hour)
	require.Empty(t, store.ActiveRules(), "absolute expiry also fails closed after a forward clock correction")
	require.NoError(t, store.Sweep())
	require.Equal(t, uint64(1), store.Status().Expired)
}

func TestExactEndpointOwnershipAndDialogAssociation(t *testing.T) {
	store, control, clock := newTestStore(t)
	first := testRule(clock, "first")
	second := testRule(clock, "second")
	second.Call.Lifetime.Generation++
	second.Call.ToTag = "fork"
	second.Endpoints[1] = endpoint("192.0.2.3", 50002)
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{first, second}))
	unknown := endpoint("192.0.2.99", 12345).Key
	require.True(t, store.Resolve(first.Endpoints[0].Key, unknown).Ambiguous)
	resolved := store.Resolve(first.Endpoints[0].Key, first.Endpoints[1].Key)
	require.True(t, resolved.Resolved)
	require.Equal(t, first.Call.Lifetime, resolved.Call.Lifetime)
	resolved.Call.FilterIDs[0] = "mutated"
	require.Equal(t, "selected-filter", store.Resolve(first.Endpoints[0].Key, first.Endpoints[1].Key).Call.FilterIDs[0])
	wrongDomain := first.Endpoints[0].Key
	wrongDomain.Domain = 2
	require.False(t, store.Resolve(wrongDomain, unknown).Resolved)
	require.False(t, store.ResolveDialog(first.Call.CallID, "", "").Resolved)
	require.True(t, store.ResolveDialog(first.Call.CallID, "bob", "alice").Resolved)
	require.Equal(t, second.Call.Lifetime, store.ResolveDialog(first.Call.CallID, "alice", "fork").Call.Lifetime)
	first.Endpoints = []Endpoint{endpoint("192.0.2.10", 40000)}
	second.Endpoints = []Endpoint{endpoint("192.0.2.11", 40000)}
	first.Revision, second.Revision = 2, 2
	require.NoError(t, store.ApplySnapshot(control, 2, []Rule{first, second}))
	require.True(t, store.Resolve(first.Endpoints[0].Key, second.Endpoints[0].Key).Ambiguous, "contradictory exact ownership must not pick the most recent call")
}

func TestRuleValidationAndScope(t *testing.T) {
	tests := map[string]struct {
		change func(*Rule)
		err    error
	}{
		"empty lifetime":             {func(r *Rule) { r.Call.Lifetime = callregistry.Lifetime{} }, ErrInvalid},
		"missing selection revision": {func(r *Rule) { r.Call.SelectionRevision = 0 }, ErrInvalid},
		"wrong source":               {func(r *Rule) { r.Scope[0].HunterID = "hunter-b" }, ErrScope},
		"unmapped domain":            {func(r *Rule) { r.Endpoints[0].Key.Domain = 2 }, ErrScope},
		"invalid IP":                 {func(r *Rule) { r.Endpoints[0].Key.Addr = netip.Addr{} }, ErrInvalid},
		"zero port":                  {func(r *Rule) { r.Endpoints[0].Key.Port = 0 }, ErrInvalid},
		"mapped IPv4":                {func(r *Rule) { r.Endpoints[0].Key.Addr = netip.MustParseAddr("::ffff:192.0.2.1") }, ErrInvalid},
		"duplicate endpoint":         {func(r *Rule) { r.Endpoints[1] = r.Endpoints[0] }, ErrInvalid},
		"unknown media":              {func(r *Rule) { r.Endpoints[0].Kind = 100 }, ErrInvalid},
		"excess lifetime":            {func(r *Rule) { r.ExpiresAt = r.NotBefore.Add(time.Hour) }, ErrInvalid},
		"reversed lifetime":          {func(r *Rule) { r.ExpiresAt = r.NotBefore }, ErrInvalid},
		"empty scope":                {func(r *Rule) { r.Scope = nil }, ErrInvalid},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			store, control, clock := newTestStore(t)
			rule := testRule(clock, "r1")
			test.change(&rule)
			require.ErrorIs(t, store.ApplySnapshot(control, 1, []Rule{rule}), test.err)
			require.False(t, store.Status().Ready)
		})
	}
}

func TestCapacityBoundsAreAtomic(t *testing.T) {
	for _, limit := range []string{"rules", "bytes", "endpoints", "per-rule"} {
		t.Run(limit, func(t *testing.T) {
			config, clock := testConfig()
			first, second := testRule(clock, "first"), testRule(clock, "second")
			switch limit {
			case "rules":
				config.MaxRules = 1
			case "bytes":
				config.MaxBytes = ruleBytes(first) + ruleBytes(second) - 1
			case "endpoints":
				config.MaxEndpoints = 3
			case "per-rule":
				config.MaxEndpointsPerRule = 1
			}
			store, err := New(config)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, store.Close()) })
			control, err := store.StartSession("processor", first.Session)
			require.NoError(t, err)
			require.ErrorIs(t, store.ApplySnapshot(control, 1, []Rule{first, second}), ErrCapacity)
			require.Empty(t, store.Snapshot().Rules)
		})
	}
}

func TestSubscriptionWatermarkOverflowAndCapacity(t *testing.T) {
	store, control, clock := newTestStore(t)
	rule := testRule(clock, "r1")
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	sub, err := store.Subscribe()
	require.NoError(t, err)
	require.Equal(t, Revision(1), sub.Initial.Revision)
	require.Len(t, sub.Initial.Active, 1)
	second, err := store.Subscribe()
	require.NoError(t, err)
	_, err = store.Subscribe()
	require.ErrorIs(t, err, ErrCapacity)
	second.Close()
	for revision := Revision(2); revision <= 4; revision++ {
		rule.Revision = revision
		require.NoError(t, store.ApplyDelta(control, revision, []Rule{rule}, nil))
	}
	event, ok := <-sub.Events
	require.True(t, ok)
	require.True(t, event.ResyncRequired)
	require.Equal(t, Revision(4), event.Revision)
	_, ok = <-sub.Events
	require.False(t, ok)
	require.Equal(t, uint64(1), store.Status().Resyncs)
	newSub, err := store.Subscribe()
	require.NoError(t, err)
	defer newSub.Close()
	require.Equal(t, Revision(4), newSub.Initial.Revision)
	rule.Revision = 5
	require.NoError(t, store.ApplyDelta(control, 5, []Rule{rule}, nil))
	event = <-newSub.Events
	require.Greater(t, event.Sequence, newSub.Initial.Sequence)
	require.Equal(t, Revision(5), event.Revision)
}

type observerFunc func(Change)

func (f observerFunc) OnMediaRulesChanged(change Change) { f(change) }

func TestObserverRemovalExpiryAndReentrancy(t *testing.T) {
	config, clock := testConfig()
	var store *Store
	var changes []Change
	config.Observer = observerFunc(func(change Change) {
		changes = append(changes, change)
		if store != nil {
			_ = store.Status()
		}
	})
	var err error
	store, err = New(config)
	require.NoError(t, err)
	control, err := store.StartSession("processor", Session{ProcessorID: "processor", Generation: 1})
	require.NoError(t, err)
	rule := testRule(clock, "r1")
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	clock.advance(10 * time.Second)
	require.NoError(t, store.Sweep())
	last := changes[len(changes)-1]
	require.Empty(t, last.Active)
	require.Len(t, last.Removed, 1)
	require.Equal(t, RemovedExpired, last.Removed[0].Reason)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.ErrorIs(t, store.Sweep(), ErrClosed)
	_, err = store.Subscribe()
	require.ErrorIs(t, err, ErrClosed)
}

func TestPublisherCanRetainMultipleExplicitScopes(t *testing.T) {
	config, clock := testConfig()
	config.HunterID, config.Domains = "", nil
	store, err := New(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	rule := testRule(clock, "r1")
	rule.Scope = append(rule.Scope, Scope{HunterID: "hunter-b", Domain: 2})
	control, err := store.StartSession("processor", rule.Session)
	require.NoError(t, err)
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	require.Len(t, store.Snapshot().Rules[0].Scope, 2)
}

func TestConcurrentLookupSubscriptionAndUpdates(t *testing.T) {
	store, control, clock := newTestStore(t)
	rule := testRule(clock, "r1")
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Go(func() {
			for n := 0; n < 100; n++ {
				store.Resolve(rule.Endpoints[0].Key, rule.Endpoints[1].Key)
				store.ResolveDialog(rule.Call.CallID, "alice", "bob")
				sub, err := store.Subscribe()
				if err == nil {
					select {
					case <-sub.Events:
					default:
					}
					sub.Close()
				}
			}
		})
	}
	for revision := Revision(2); revision < 100; revision++ {
		updated := cloneRule(rule)
		updated.Revision = revision
		require.NoError(t, store.ApplyDelta(control, revision, []Rule{updated}, nil))
	}
	workers.Wait()
}

func TestDialogResolutionRequiresObservationDomain(t *testing.T) {
	store, control, clock := newTestStore(t)
	rule := testRule(clock, "dialog")
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	require.True(t, store.ResolveDialogInDomain(1, rule.Call.CallID, "alice", "bob").Resolved)
	require.True(t, store.ResolveDialogInDomain(1, rule.Call.CallID, "bob", "alice").Resolved)
	require.False(t, store.ResolveDialogInDomain(2, rule.Call.CallID, "alice", "bob").Resolved)
	require.False(t, store.ResolveDialogInDomain(1, rule.Call.CallID, "alice", "").Resolved)
	clock.advance(11 * time.Second)
	require.False(t, store.ResolveDialogInDomain(1, rule.Call.CallID, "alice", "bob").Resolved)
}

func TestGrantResolutionRetainsImmutableExactProofAndRejectsConflictingSelection(t *testing.T) {
	store, control, clock := newTestStore(t)
	first := testRule(clock, "a")
	first.Call.CapturePolicyRevision = 7
	first.Call.SelectionGrants = []SelectionRef{{ID: "opaque", Revision: 3}}
	first.CaptureSignature = []byte("signature")
	second := cloneRule(first)
	second.ID = "b"
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{second, first}))
	resolved := store.Resolve(first.Endpoints[0].Key, first.Endpoints[1].Key)
	require.True(t, resolved.Resolved)
	require.NotNil(t, resolved.Rule)
	require.Equal(t, "a", resolved.Rule.ID)
	resolved.Rule.Call.SelectionGrants[0].ID = "mutated"
	resolved.Rule.CaptureSignature[0] = 'x'
	require.Equal(t, "opaque", store.Resolve(first.Endpoints[0].Key, first.Endpoints[1].Key).Rule.Call.SelectionGrants[0].ID)
	second.Revision = 2
	second.Call.SelectionGrants[0].Revision++
	require.NoError(t, store.ApplyDelta(control, 2, []Rule{second}, nil))
	require.True(t, store.Resolve(first.Endpoints[0].Key, first.Endpoints[1].Key).Ambiguous)
}

func TestCompatibilityFacadeUsesOnlySharedCommittedState(t *testing.T) {
	store, control, clock := newTestStore(t)
	rule := testRule(clock, "shared")
	require.NoError(t, store.ApplySnapshot(control, 1, []Rule{rule}))
	binding := store.Core().ActiveRules()[0]
	require.Equal(t, rule.Call.CallID, binding.Subject.ID)
	// A generic publication is immediately visible through the compatibility
	// facade; there is no independently renewed legacy lifecycle registry.
	binding.Revision = 2
	require.NoError(t, store.Core().ApplyDelta(control, 2, []core.Binding{binding}, nil))
	require.Equal(t, Revision(2), store.ActiveRules()[0].Revision)
	require.NoError(t, store.Core().ApplyDelta(control, 3, nil, []string{rule.ID}))
	require.Empty(t, store.ActiveRules())
	require.False(t, store.Resolve(rule.Endpoints[0].Key, rule.Endpoints[1].Key).Resolved)
}

func TestGenericCompleteBindingCannotExposeForeignSourceDomainThroughFacade(t *testing.T) {
	store, control, clock := newTestStore(t)
	rule := testRule(clock, "full")
	rule.Scope = append(rule.Scope, Scope{HunterID: "other", Domain: 2})
	remote := rule.Endpoints[0]
	remote.Key.Domain = 2
	rule.Endpoints = append(rule.Endpoints, remote)
	require.NoError(t, store.Core().ApplySnapshot(control, 1, []core.Binding{ToBinding(rule)}))
	unknown := endpoint("192.0.2.99", 1111).Key
	require.True(t, store.Resolve(rule.Endpoints[0].Key, unknown).Resolved)
	unknown.Domain = 2
	require.False(t, store.Resolve(remote.Key, unknown).Resolved)
}

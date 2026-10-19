package learnedrules

import (
	"errors"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testClock struct {
	mu   sync.Mutex
	wall time.Time
	tick time.Duration
}

func (c *testClock) Now() time.Time         { c.mu.Lock(); defer c.mu.Unlock(); return c.wall }
func (c *testClock) Elapsed() time.Duration { c.mu.Lock(); defer c.mu.Unlock(); return c.tick }
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
	c.tick += d
}

func diagnosticAdapter(id string) Adapter {
	return Adapter{ID: id, Version: 1, Validate: func(b Binding) error {
		if string(b.Context) != "diagnostic/v1" || len(b.Intents) != 1 || b.Intents[0].ID != "operator-request" {
			return ErrInvalid
		}
		return nil
	}, Authorize: func(Binding) error { return nil }}
}

func setup(t *testing.T) (*Store, Control, *testClock) {
	t.Helper()
	c := &testClock{wall: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)}
	r, err := NewRegistry(diagnosticAdapter("diagnostic"), diagnosticAdapter("other"))
	require.NoError(t, err)
	s, err := New(Config{ProcessorID: "central", HunterID: "edge", Domains: []DomainID{7}, MaxRules: 8, MaxBytes: 32768, MaxEndpoints: 16, MaxEndpointsPerRule: 4, MaxSubscribers: 2, SubscriptionBuffer: 1, MaxLifetime: time.Minute, Clock: c, Registry: r})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	control, err := s.StartSession("central", Session{"central", 1})
	require.NoError(t, err)
	return s, control, c
}

func binding(c *testClock, id string) Binding {
	return Binding{ID: id, Revision: 25, Session: Session{"central", 1}, AdapterID: "diagnostic", ContextVersion: 1, Subject: Subject{"request", "activation-1"}, AttributionContext: "investigation", Intents: []IntentRef{{"operator-request", 1}}, Scope: []Scope{{"edge", 7}}, Selectors: []Selector{{Domain: 7, Address: netip.MustParseAddr("192.0.2.1"), Port: 444, Protocol: TCP, Direction: Source}}, Context: []byte("diagnostic/v1"), NotBefore: c.Now(), ExpiresAt: c.Now().Add(10 * time.Second)}
}

func testPacket() Packet {
	return Packet{Domain: 7, Protocol: TCP, Source: Endpoint{netip.MustParseAddr("192.0.2.1"), 444}, Destination: Endpoint{netip.MustParseAddr("198.51.100.1"), 500}}
}

func TestIndependentRevisionsAndOwnedAtomicReplacement(t *testing.T) {
	s, control, c := setup(t)
	b := binding(c, "b")
	require.NoError(t, s.ApplySnapshot(control, 1, []Binding{b}))
	b.Context[0] = 'x'
	b.Selectors[0].Port = 1
	require.Equal(t, "diagnostic/v1", string(s.ActiveRules()[0].Context))
	require.Len(t, s.Match(testPacket(), 4).Bindings, 1)
	bad := binding(c, "bad")
	bad.AdapterID = "unknown"
	require.ErrorIs(t, s.ApplySnapshot(control, 2, []Binding{binding(c, "b"), bad}), ErrUnsupported)
	require.Equal(t, Revision(1), s.Status().Revision)
	next := binding(c, "b")
	next.Revision = 26
	next.Subject.Incarnation = "activation-2"
	require.ErrorIs(t, s.ApplyDelta(control, 2, []Binding{next}, nil), ErrRevision)
	require.NoError(t, s.ApplySnapshot(control, 2, []Binding{next}))
	require.Equal(t, "activation-2", s.Match(testPacket(), 4).Bindings[0].Subject.Incarnation)
}

func TestEndpointDirectionProtocolAndCandidateOverflow(t *testing.T) {
	s, control, c := setup(t)
	b := binding(c, "a")
	other := binding(c, "b")
	other.AdapterID = "other"
	other.AttributionContext = "other-context"
	require.NoError(t, s.ApplySnapshot(control, 1, []Binding{b, other}))
	result := s.Match(testPacket(), 1)
	require.True(t, result.Overflow)
	require.Empty(t, result.Bindings)
	require.Len(t, s.Match(testPacket(), 2).Bindings, 2)
	p := testPacket()
	p.Protocol = UDP
	require.Empty(t, s.Match(p, 2).Bindings)
	p = testPacket()
	p.Domain = 8
	require.Empty(t, s.Match(p, 2).Bindings)
	p = testPacket()
	p.Source, p.Destination = p.Destination, p.Source
	require.Empty(t, s.Match(p, 2).Bindings)
	b.Revision++
	b.Selectors[0].Direction = Either
	require.NoError(t, s.ApplySnapshot(control, 2, []Binding{b}))
	require.Len(t, s.Match(p, 2).Bindings, 1)
	b.Revision++
	b.Selectors[0].Address = netip.MustParseAddr("2001:db8::1")
	require.NoError(t, s.ApplySnapshot(control, 3, []Binding{b}))
	p.Destination.Address = netip.MustParseAddr("2001:db8::1")
	require.Len(t, s.Match(p, 2).Bindings, 1)
}

func TestExpiryReconnectRollbackAndWithdrawal(t *testing.T) {
	s, control, c := setup(t)
	b := binding(c, "b")
	require.NoError(t, s.ApplySnapshot(control, 1, []Binding{b}))
	c.advance(9 * time.Second)
	newControl, err := s.StartSession("central", Session{"central", 1})
	require.NoError(t, err)
	require.Empty(t, s.Match(testPacket(), 2).Bindings)
	require.ErrorIs(t, s.ApplySnapshot(control, 2, []Binding{b}), ErrSession)
	require.NoError(t, s.ApplySnapshot(newControl, 1, []Binding{b}))
	c.mu.Lock()
	c.wall = c.wall.Add(-time.Hour)
	c.mu.Unlock()
	c.advance(time.Second)
	require.Empty(t, s.Match(testPacket(), 2).Bindings)
	require.NoError(t, s.Sweep())
	require.Empty(t, s.ActiveRules())
	require.Error(t, s.ApplySnapshot(newControl, 2, []Binding{b}))
}

func TestSubscriptionOverflowRequiresCompleteResync(t *testing.T) {
	s, control, c := setup(t)
	sub, err := s.Subscribe()
	require.NoError(t, err)
	defer sub.Close()
	require.NoError(t, s.ApplySnapshot(control, 1, []Binding{binding(c, "b")}))
	require.NoError(t, s.ApplyDelta(control, 2, nil, []string{"b"}))
	change, ok := <-sub.Events
	require.True(t, ok)
	require.True(t, change.ResyncRequired)
	_, ok = <-sub.Events
	require.False(t, ok)
	require.Equal(t, uint64(1), s.Status().Resyncs)
}

func TestIntentRevocationAndQualifierCannotBecomeWildcard(t *testing.T) {
	a := diagnosticAdapter("diagnostic")
	allowed := true
	a.Authorize = func(Binding) error {
		if !allowed {
			return ErrAuthority
		}
		return nil
	}
	a.Qualifiers = []Qualifier{{"content", 1}}
	a.Qualify = func(_ Binding, _ Selector, p Packet) bool { return string(p.Payload) == "selected" }
	r, err := NewRegistry(a)
	require.NoError(t, err)
	s, control, c := setup(t)
	s.config.Registry = r
	b := binding(c, "b")
	b.Selectors[0].Qualifier = Qualifier{"content", 1}
	require.NoError(t, s.ApplySnapshot(control, 1, []Binding{b}))
	p := testPacket()
	require.Empty(t, s.Match(p, 2).Bindings)
	p.Payload = []byte("selected")
	require.Len(t, s.Match(p, 2).Bindings, 1)
	allowed = false
	require.Empty(t, s.Match(p, 2).Bindings)
	allowed = true
	b.Revision++
	b.Selectors[0].Qualifier.Version = 2
	require.ErrorIs(t, s.ApplySnapshot(control, 2, []Binding{b}), ErrUnsupported)
	require.False(t, errors.Is(ErrUnsupported, ErrAuthority))
}

func TestCoreDependenciesAreProtocolNeutral(t *testing.T) {
	for _, tags := range []string{"all", "all,li"} {
		cmd := exec.Command("go", "list", "-tags", tags, "-deps", "github.com/endorses/lippycat/internal/pkg/learnedrules")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
		for _, dep := range strings.Fields(string(output)) {
			for _, forbidden := range []string{"internal/pkg/sip", "internal/pkg/voip", "internal/pkg/callregistry", "internal/pkg/callselection", "internal/pkg/li", "api/gen/management"} {
				require.False(t, strings.HasPrefix(dep, "github.com/endorses/lippycat/"+forbidden), dep)
			}
		}
	}
}

func TestPublisherSourceScopePrecedesCandidateLimit(t *testing.T) {
	source, _, clock := setup(t)
	config := source.Configuration()
	config.HunterID = ""
	publisher, err := New(config)
	require.NoError(t, err)
	defer func() { require.NoError(t, publisher.Close()) }()
	control, err := publisher.StartSession("central", Session{"central", 1})
	require.NoError(t, err)
	a, b := binding(clock, "a"), binding(clock, "b")
	b.Scope = []Scope{{HunterID: "other-edge", Domain: 7}}
	require.NoError(t, publisher.ApplySnapshot(control, 1, []Binding{a, b}))
	require.True(t, publisher.Match(testPacket(), 1).Overflow, "a global publisher match contains both independent source realms")
	for _, sourceID := range []string{"edge", "other-edge"} {
		matches := publisher.MatchForSource(sourceID, testPacket(), 1)
		require.False(t, matches.Overflow, "unrelated source bindings cannot exhaust the local candidate bound")
		require.Len(t, matches.Bindings, 1)
		require.Equal(t, sourceID, matches.Bindings[0].Scope[0].HunterID)
	}
	require.Empty(t, publisher.MatchForSource("unknown", testPacket(), 1).Bindings)
	require.Empty(t, publisher.MatchForSource("", testPacket(), 1).Bindings)
	c := binding(clock, "c")
	require.NoError(t, publisher.ApplySnapshot(control, 2, []Binding{a, b, c}))
	require.True(t, publisher.MatchForSource("edge", testPacket(), 1).Overflow, "all eligible owners still count against the bound")
}

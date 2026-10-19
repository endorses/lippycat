package admissionadapter

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

type mapBackend struct {
	mu      sync.Mutex
	entries map[mediaadmission.EndpointKey]struct{}
	fail    bool
}

func (b *mapBackend) PutEndpoint(_ context.Context, k mediaadmission.EndpointKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return errors.New("backend unavailable")
	}
	b.entries[k] = struct{}{}
	return nil
}
func (b *mapBackend) DeleteEndpoint(_ context.Context, k mediaadmission.EndpointKey) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fail {
		return errors.New("backend unavailable")
	}
	delete(b.entries, k)
	return nil
}
func (b *mapBackend) ListEndpoints(_ context.Context, d mediaadmission.DomainID) ([]mediaadmission.EndpointKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var keys []mediaadmission.EndpointKey
	for key := range b.entries {
		if key.Domain == d {
			keys = append(keys, key)
		}
	}
	return keys, nil
}
func (*mapBackend) SetControl(context.Context, mediaadmission.DomainID, mediaadmission.Control) error {
	return nil
}

func fixture(t *testing.T, configure func(*mediaadmission.Config)) (*Projection, *mapBackend, *mediaadmission.Controller) {
	t.Helper()
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.FailurePolicy = mediaadmission.FailureClosed
	if configure != nil {
		configure(&cfg)
	}
	backend := &mapBackend{entries: make(map[mediaadmission.EndpointKey]struct{})}
	controller, err := mediaadmission.NewController(t.Context(), cfg, backend)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, controller.Close(context.Background())) })
	projection, err := New(t.Context(), controller, []mediaadmission.DomainID{0}, nil)
	require.NoError(t, err)
	return projection, backend, controller
}

func binding(adapter, subject, incarnation string, port uint16) learnedrules.Binding {
	return learnedrules.Binding{Session: learnedrules.Session{ProcessorID: "authority", Generation: 567}, AdapterID: adapter, ContextVersion: 1,
		Subject:   learnedrules.Subject{ID: subject, Incarnation: incarnation},
		Selectors: []learnedrules.Selector{{Address: netip.MustParseAddr("192.0.2.1"), Port: port, Protocol: learnedrules.UDP}}}
}

func apply(p *Projection, sequence uint64, bindings ...learnedrules.Binding) {
	p.OnLearnedRulesChanged(learnedrules.Change{Snapshot: learnedrules.Snapshot{Ready: true, Sequence: sequence}, Active: bindings})
}

func TestProjectionUsesLocalOwnersAndPreservesSharedEndpoints(t *testing.T) {
	p, backend, controller := fixture(t, nil)
	first, second := binding("diagnostic", "request-a", "one", 45000), binding("service-membership", "service-b", "two", 45000)
	apply(p, 1, first, second)
	require.True(t, p.Ready(1))
	require.Len(t, backend.entries, 1)
	require.Len(t, p.owners, 2)
	require.Equal(t, 2, controller.Status()[0].Owners)
	for key, token := range p.owners {
		require.NotEqual(t, key.Session.Generation, token.Session)
		require.NotZero(t, token.Session)
		require.Equal(t, key.Subject.ID, token.Label)
	}
	apply(p, 2, second)
	require.True(t, p.Ready(2))
	require.Len(t, backend.entries, 1)
	require.Len(t, p.owners, 1)
	apply(p, 3)
	require.True(t, p.Ready(3))
	require.Empty(t, backend.entries)
	apply(p, 2, first)
	require.Empty(t, backend.entries)
	require.Empty(t, p.owners)
}

func TestProjectionLogicalBindingsShareOneSubjectOwner(t *testing.T) {
	p, backend, _ := fixture(t, nil)
	first, second := binding("diagnostic", "request", "one", 45000), binding("diagnostic", "request", "one", 46000)
	first.ID, second.ID = "binding-a", "binding-b"
	apply(p, 1, first, second)
	require.Len(t, p.owners, 1)
	require.Len(t, backend.entries, 2)
	apply(p, 2, second)
	require.True(t, p.Ready(2))
	require.Len(t, p.owners, 1)
	require.Len(t, backend.entries, 1)
	require.Contains(t, backend.entries, mediaadmission.EndpointKey{Addr: netip.MustParseAddr("192.0.2.1"), Port: 46000})
}

func TestProjectionSubjectReuseAndEpochMintNewTokens(t *testing.T) {
	p, _, _ := fixture(t, nil)
	first := binding("diagnostic", "request", "one", 45000)
	apply(p, 1, first)
	var previous mediaadmission.OwnerID
	for _, token := range p.owners {
		previous = token
	}
	second := first
	second.Subject.Incarnation = "two"
	apply(p, 2, second)
	for _, token := range p.owners {
		require.NotEqual(t, previous, token)
		previous = token
	}
	second.Session.Generation++
	apply(p, 3, second)
	for _, token := range p.owners {
		require.NotEqual(t, previous, token)
	}
	require.Len(t, p.owners, 1)
}

func TestProjectionFailureRetriesOwnedFullSnapshotAndWithdrawal(t *testing.T) {
	p, backend, _ := fixture(t, nil)
	first := binding("diagnostic", "request", "one", 45000)
	backend.fail = true
	apply(p, 1, first)
	require.False(t, p.Ready(1))
	require.Error(t, p.Error())
	// The observer must retain its own selector state across backend retry.
	first.Selectors[0].Port = 46000
	backend.fail = false
	require.NoError(t, p.Retry())
	require.True(t, p.Ready(1))
	require.Contains(t, backend.entries, mediaadmission.EndpointKey{Addr: netip.MustParseAddr("192.0.2.1"), Port: 45000})
	backend.fail = true
	apply(p, 2)
	require.False(t, p.Ready(2))
	backend.fail = false
	require.NoError(t, p.Retry())
	require.True(t, p.Ready(2))
	require.Empty(t, backend.entries)
}

func TestProjectionInvalidationRetiresCandidates(t *testing.T) {
	p, backend, _ := fixture(t, nil)
	apply(p, 1, binding("diagnostic", "request", "one", 45000))
	p.OnLearnedRulesChanged(learnedrules.Change{Snapshot: learnedrules.Snapshot{Sequence: 2, Ready: false}})
	require.False(t, p.Ready(2))
	require.Empty(t, backend.entries)
}

func TestProjectionPendingReservationRetainedAndRecovered(t *testing.T) {
	p, backend, _ := fixture(t, func(c *mediaadmission.Config) { c.OwnerCapacity = 1; c.PendingDialogCapacity = 1 })
	first, second := binding("diagnostic", "request-a", "one", 45000), binding("diagnostic", "request-b", "two", 46000)
	apply(p, 1, first, second)
	require.False(t, p.Ready(1))
	require.Len(t, p.owners, 2)
	// Repeated retries reuse the same bounded tokens, including the reservation.
	tokens := make(map[ownerKey]mediaadmission.OwnerID)
	for key, token := range p.owners {
		tokens[key] = token
	}
	require.Error(t, p.Retry())
	require.Equal(t, tokens, p.owners)
	apply(p, 2, second)
	require.True(t, p.Ready(2))
	require.Len(t, p.owners, 1)
	require.Len(t, backend.entries, 1)
}

func TestProjectionLostObservationRecoveredByCompleteSnapshot(t *testing.T) {
	p, backend, _ := fixture(t, func(c *mediaadmission.Config) { c.OwnerCapacity = 1; c.PendingDialogCapacity = 1 })
	first, second, third := binding("diagnostic", "request-a", "one", 45000), binding("diagnostic", "request-b", "two", 46000), binding("diagnostic", "request-c", "three", 47000)
	apply(p, 1, first, second, third)
	require.False(t, p.Ready(1))
	require.Len(t, p.owners, 2)
	apply(p, 2, third)
	require.True(t, p.Ready(2))
	require.Len(t, backend.entries, 1)
	require.Len(t, p.owners, 1)
}

func TestProjectionRejectsUnmanagedDomainsAndMalformedSelectors(t *testing.T) {
	p, backend, _ := fixture(t, nil)
	first := binding("diagnostic", "request", "one", 45000)
	first.Selectors[0].Domain = 99
	apply(p, 1, first)
	require.ErrorIs(t, p.Error(), learnedrules.ErrScope)
	require.False(t, p.Ready(1))
	require.Empty(t, p.owners)
	require.Empty(t, backend.entries)
	first.Selectors[0].Domain = 0
	first.Selectors[0].Protocol = 0
	apply(p, 2, first)
	require.ErrorIs(t, p.Error(), learnedrules.ErrInvalid)
	require.False(t, p.Ready(2))
	require.Empty(t, p.owners)
}

func TestProjectionCandidateAdmissionDoesNotInterpretProtocolOrDirection(t *testing.T) {
	p, backend, _ := fixture(t, nil)
	udp := binding("diagnostic", "udp-request", "one", 45000)
	tcp := binding("diagnostic", "tcp-request", "one", 45000)
	tcp.Selectors[0].Protocol = learnedrules.TCP
	tcp.Selectors[0].Direction = learnedrules.Destination
	apply(p, 1, udp, tcp)
	require.True(t, p.Ready(1)) // candidate backend only; matcher retains exact semantics
	require.Len(t, backend.entries, 1)
	require.Len(t, p.owners, 2)
}

func sourceFixture(t *testing.T, sourceID string, domain mediaadmission.DomainID) (*Projection, *mapBackend) {
	t.Helper()
	_, backend, controller := fixture(t, func(c *mediaadmission.Config) {
		c.InterfaceDomains = map[string]mediaadmission.DomainID{"capture0": domain}
	})
	p, err := NewForSource(t.Context(), controller, sourceID, []mediaadmission.DomainID{domain}, nil)
	require.NoError(t, err)
	return p, backend
}

func fullBinding() learnedrules.Binding {
	b := binding("diagnostic", "request", "one", 45000)
	b.Scope = []learnedrules.Scope{{HunterID: "source-a", Domain: 10}, {HunterID: "source-b", Domain: 20}}
	b.Selectors[0].Domain = 10
	b.Selectors = append(b.Selectors, learnedrules.Selector{Domain: 20, Address: netip.MustParseAddr("192.0.2.2"), Port: 46000, Protocol: learnedrules.UDP})
	return b
}

func TestSourceProjectionInstallsOnlyItsLegOfImmutableFullBinding(t *testing.T) {
	a, backendA := sourceFixture(t, "source-a", 10)
	b, backendB := sourceFixture(t, "source-b", 20)
	complete := fullBinding()
	original := learnedrules.CloneBinding(complete)
	apply(a, 1, complete)
	apply(b, 1, complete)
	require.True(t, a.Ready(1))
	require.True(t, b.Ready(1))
	require.Len(t, backendA.entries, 1)
	require.Contains(t, backendA.entries, mediaadmission.EndpointKey{Domain: 10, Addr: netip.MustParseAddr("192.0.2.1"), Port: 45000})
	require.Len(t, backendB.entries, 1)
	require.Contains(t, backendB.entries, mediaadmission.EndpointKey{Domain: 20, Addr: netip.MustParseAddr("192.0.2.2"), Port: 46000})
	require.Equal(t, original, complete, "per-source installation never narrows the immutable definition")
	require.Len(t, a.change.Active[0].Selectors, 2)
	require.Len(t, a.change.Active[0].Scope, 2)
}

func TestSourceProjectionRejectsAnotherPeersSameNumberedDomain(t *testing.T) {
	p, backend := sourceFixture(t, "source-a", 10)
	complete := fullBinding()
	apply(p, 1, complete)
	require.Len(t, backend.entries, 1)
	foreign := binding("diagnostic", "other-request", "one", 47000)
	foreign.Scope = []learnedrules.Scope{{HunterID: "source-b", Domain: 10}}
	foreign.Selectors[0].Domain = 10
	apply(p, 2, foreign)
	require.True(t, p.Ready(2), "foreign-only bindings install no local candidate entries")
	require.Empty(t, backend.entries)
	require.Empty(t, p.owners)
}

func TestSourceProjectionValidatesForeignSelectorsBeforeSkipping(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*learnedrules.Binding)
		want   error
	}{
		{"unscoped-domain", func(b *learnedrules.Binding) { b.Selectors[1].Domain = 99 }, learnedrules.ErrScope},
		{"malformed-foreign-endpoint", func(b *learnedrules.Binding) { b.Selectors[1].Port = 0 }, learnedrules.ErrInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, backend := sourceFixture(t, "source-a", 10)
			complete := fullBinding()
			test.mutate(&complete)
			apply(p, 1, complete)
			require.ErrorIs(t, p.Error(), test.want)
			require.False(t, p.Ready(1))
			require.Empty(t, p.owners)
			require.Empty(t, backend.entries)
		})
	}
}

func TestSourceProjectionRetryOwnsFullScope(t *testing.T) {
	p, backend := sourceFixture(t, "source-a", 10)
	complete := fullBinding()
	backend.fail = true
	apply(p, 1, complete)
	require.False(t, p.Ready(1))
	complete.Scope[0].HunterID = "source-b"
	complete.Selectors[0].Port = 47000
	backend.fail = false
	require.NoError(t, p.Retry())
	require.True(t, p.Ready(1))
	require.Len(t, backend.entries, 1)
	require.Contains(t, backend.entries, mediaadmission.EndpointKey{Domain: 10, Addr: netip.MustParseAddr("192.0.2.1"), Port: 45000})
}

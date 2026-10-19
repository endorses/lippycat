package admissionadapter

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
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

func projectionFixture(t *testing.T) (*Projection, *mapBackend, *mediarules.Store, mediarules.Control) {
	t.Helper()
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.FailurePolicy = mediaadmission.FailureClosed
	backend := &mapBackend{entries: make(map[mediaadmission.EndpointKey]struct{})}
	controller, err := mediaadmission.NewController(t.Context(), cfg, backend)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, controller.Close(context.Background())) })
	projection, err := New(t.Context(), controller, []mediaadmission.DomainID{0}, nil)
	require.NoError(t, err)
	settings, err := (mediarules.Settings{}).Normalize()
	require.NoError(t, err)
	store, err := mediarules.New(settings.StoreConfig("processor", "hunter", []mediaadmission.DomainID{0}, projection))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	control, err := store.StartSession("processor", mediarules.Session{ProcessorID: "processor", Generation: 1})
	require.NoError(t, err)
	return projection, backend, store, control
}
func projectionRule(id string, generation uint64) mediarules.Rule {
	now := time.Now()
	return mediarules.Rule{ID: id, Session: mediarules.Session{ProcessorID: "processor", Generation: 1}, Revision: 1, Call: mediarules.CallAssociation{Lifetime: callregistry.Lifetime{Session: 567, Generation: generation}, CallID: "shared-call", SelectionRevision: 1}, Scope: []mediarules.Scope{{HunterID: "hunter", Domain: 0}}, Endpoints: []mediarules.Endpoint{{Key: mediaadmission.EndpointKey{Addr: netip.MustParseAddr("192.0.2.1"), Port: 45000}, Kind: mediarules.RTP}}, NotBefore: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}
}

func TestProjectionUsesLocalOwnersAndPreservesSharedEndpoints(t *testing.T) {
	p, backend, store, control := projectionFixture(t)
	first, second := projectionRule("first", 1), projectionRule("second", 2)
	require.NoError(t, store.ApplySnapshot(control, 1, []mediarules.Rule{first, second}))
	require.True(t, p.Ready(store.Status().Sequence))
	require.Len(t, backend.entries, 1)

	require.NoError(t, store.ApplyDelta(control, 2, nil, []string{"first"}))
	require.True(t, p.Ready(store.Status().Sequence))
	require.Len(t, backend.entries, 1)
	require.NoError(t, store.ApplyDelta(control, 3, nil, []string{"second"}))
	require.True(t, p.Ready(store.Status().Sequence))
	require.Empty(t, backend.entries)
	// Delayed observer callbacks cannot resurrect the retired lifetime.
	p.OnMediaRulesChanged(mediarules.Change{Snapshot: mediarules.Snapshot{Ready: true, Sequence: 2}, Active: []mediarules.Rule{first}})
	require.Empty(t, backend.entries)
}
func TestProjectionFailureRetriesFullSnapshotAndWithdrawal(t *testing.T) {
	p, backend, store, control := projectionFixture(t)
	backend.fail = true
	require.NoError(t, store.ApplySnapshot(control, 1, []mediarules.Rule{projectionRule("first", 1)}))
	require.False(t, p.Ready(store.Status().Sequence))
	require.Error(t, p.Error())
	backend.fail = false
	require.NoError(t, p.Retry())
	require.True(t, p.Ready(store.Status().Sequence))
	require.Len(t, backend.entries, 1)
	backend.fail = true
	require.NoError(t, store.ApplyDelta(control, 2, nil, []string{"first"}))
	require.False(t, p.Ready(store.Status().Sequence))
	backend.fail = false
	require.NoError(t, p.Retry())
	require.True(t, p.Ready(store.Status().Sequence))
	require.Empty(t, backend.entries)
}
func TestProjectionSessionInvalidationRetiresMedia(t *testing.T) {
	p, backend, store, control := projectionFixture(t)
	require.NoError(t, store.ApplySnapshot(control, 1, []mediarules.Rule{projectionRule("first", 1)}))
	require.Len(t, backend.entries, 1)
	_, err := store.StartSession("processor", store.Status().Session)
	require.NoError(t, err)
	require.False(t, p.Ready(store.Status().Sequence))
	require.Empty(t, backend.entries)
}

func TestSourceProjectionCompatibilityRetainsFullMediaBinding(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.FailurePolicy = mediaadmission.FailureClosed
	backend := &mapBackend{entries: make(map[mediaadmission.EndpointKey]struct{})}
	controller, err := mediaadmission.NewController(t.Context(), cfg, backend)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, controller.Close(context.Background())) })
	p, err := NewForSource(t.Context(), controller, "hunter", []mediaadmission.DomainID{0}, nil)
	require.NoError(t, err)
	rule := projectionRule("selected", 1)
	rule.Scope = append(rule.Scope, mediarules.Scope{HunterID: "other-hunter", Domain: 20})
	rule.Endpoints = append(rule.Endpoints, mediarules.Endpoint{Key: mediaadmission.EndpointKey{Domain: 20, Addr: netip.MustParseAddr("192.0.2.2"), Port: 46000}, Kind: mediarules.RTP})
	p.OnMediaRulesChanged(mediarules.Change{Snapshot: mediarules.Snapshot{Ready: true, Sequence: 1}, Active: []mediarules.Rule{rule}})
	require.True(t, p.Ready(1))
	require.Len(t, backend.entries, 1)
	require.Contains(t, backend.entries, rule.Endpoints[0].Key)
	require.Len(t, rule.Endpoints, 2)
}

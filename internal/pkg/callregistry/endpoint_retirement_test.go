package callregistry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEndpointRetirementRequiresLiveLifetime(t *testing.T) {
	c := New(Config{MaxCalls: 1, MaxEndpointsPerCall: 2})
	require.True(t, c.Upsert(Call{CallID: "same"}))
	old, _ := c.Call("same")
	require.True(t, c.Remove("same", EndCompleted))
	require.True(t, c.Upsert(Call{CallID: "same"}))
	current, _ := c.Call("same")
	require.True(t, c.TryAssociateEndpoint("same", "192.0.2.1:9000"))
	for _, lifetime := range []Lifetime{{}, old.Lifetime, {Session: current.Lifetime.Session}, {Generation: current.Lifetime.Generation}} {
		require.False(t, c.TryDissociateEndpointsForLifetime("same", lifetime, []string{"192.0.2.1:9000"}))
	}
	require.False(t, c.TryDissociateEndpointsForLifetime("missing", current.Lifetime, nil))
	require.Equal(t, []string{"192.0.2.1:9000"}, c.EndpointsForCall("same"))
	c.Close()
	require.False(t, c.TryDissociateEndpointsForLifetime("same", current.Lifetime, nil))
}

func TestEndpointRetirementPreservesSharedOwnersAndReleasesCapacity(t *testing.T) {
	c := New(Config{MaxCalls: 2, MaxEndpointsPerCall: 2, MaxEndpointAssociations: 3})
	require.True(t, c.Upsert(Call{CallID: "one"}))
	require.True(t, c.Upsert(Call{CallID: "two"}))
	one, _ := c.Call("one")
	two, _ := c.Call("two")
	const shared = "192.0.2.1:9000"
	const private = "192.0.2.1:9002"
	require.True(t, c.TryAssociateEndpoint("one", shared))
	require.True(t, c.TryAssociateEndpoint("two", shared))
	require.True(t, c.TryAssociateEndpoint("two", private))
	require.False(t, c.TryAssociateEndpoint("one", "192.0.2.2:9000"))
	require.True(t, c.TryDissociateEndpointsForLifetime("two", two.Lifetime, []string{shared, shared, "absent"}))
	require.Equal(t, []string{"one"}, c.CallIDsForEndpoint(shared))
	winner, ok := c.MostRecentCallIDForEndpoint(shared)
	require.True(t, ok)
	require.Equal(t, "one", winner)
	require.Equal(t, []string{private}, c.EndpointsForCall("two"))
	require.Equal(t, 2, c.EndpointAssociationCount())
	require.True(t, c.TryAssociateEndpoint("one", "192.0.2.2:9000"))
	require.True(t, c.TryDissociateEndpointsForLifetime("one", one.Lifetime, []string{shared}))
	require.Empty(t, c.CallIDsForEndpoint(shared))
	_, ok = c.MostRecentCallIDForEndpoint(shared)
	require.False(t, ok)
	require.NotContains(t, c.endpointCalls, shared)
	require.NotContains(t, c.endpointWinner, shared)
	require.True(t, c.TryDissociateEndpointsForLifetime("two", two.Lifetime, []string{private}))
	require.NotContains(t, c.callEndpoints, "two")
	require.True(t, c.TryAssociateEndpoint("two", "192.0.2.3:9000"))
}

func TestEndpointRetirementNotifiesOnlyChangesOutsideLock(t *testing.T) {
	lifecycle := &recordingObserver{}
	c := New(Config{MaxCalls: 1, MaxEndpointsPerCall: 2, Observers: []LifecycleObserver{lifecycle}})
	require.True(t, c.Upsert(Call{CallID: "one", State: "answered", LastUpdated: time.Unix(1, 0)}))
	c.Pin("one")
	before, _ := c.Call("one")
	require.True(t, c.TryAssociateEndpoint("one", "192.0.2.1:9000"))
	require.True(t, c.TryAssociateEndpoint("one", "192.0.2.1:9002"))
	var observations []EndpointObservation
	c.AddEndpointObserver(endpointObserverFunc(func(o EndpointObservation) {
		// These methods acquire the registry lock, proving callback reentrancy.
		current, ok := c.Call(o.Call.CallID)
		require.True(t, ok)
		require.Equal(t, before, current)
		require.ElementsMatch(t, o.Endpoints, c.EndpointsForCall(o.Call.CallID))
		require.True(t, c.IsPinned("one"))
		observations = append(observations, o)
	}))
	c.AddEndpointObserver(endpointObserverFunc(func(o EndpointObservation) {
		if len(o.Endpoints) > 0 {
			o.Endpoints[0] = "mutated"
		}
	}))
	require.True(t, c.TryDissociateEndpointsForLifetime("one", before.Lifetime, []string{"192.0.2.1:9000"}))
	require.Len(t, observations, 1)
	require.Equal(t, []string{"192.0.2.1:9002"}, observations[0].Endpoints)
	require.True(t, c.TryDissociateEndpointsForLifetime("one", before.Lifetime, []string{"192.0.2.1:9000", "absent"}))
	require.True(t, c.TryDissociateEndpointsForLifetime("one", before.Lifetime, nil))
	require.Len(t, observations, 1)
	require.True(t, c.TryDissociateEndpointsForLifetime("one", before.Lifetime, []string{"192.0.2.1:9002"}))
	require.Len(t, observations, 2)
	require.Empty(t, observations[1].Endpoints)
	require.Greater(t, observations[1].Revision, observations[0].Revision)
	require.Equal(t, before, observations[1].Call)
	require.Equal(t, []string{"one"}, lifecycle.starts)
	require.Empty(t, lifecycle.ends)
	require.Equal(t, 1, c.ActiveCallCount())
	require.Equal(t, 0, c.EndpointAssociationCount())
	require.True(t, c.IsPinned("one"))
}

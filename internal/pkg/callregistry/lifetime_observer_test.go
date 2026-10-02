package callregistry

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type endpointObserverFunc func(EndpointObservation)

func (f endpointObserverFunc) OnEndpointsChanged(o EndpointObservation) { f(o) }

func TestLifetimeIndependentOfRecencyAndReuse(t *testing.T) {
	c := New(Config{MaxCalls: 2})
	require.True(t, c.Upsert(Call{CallID: "same"}))
	first, _ := c.Call("same")
	require.NotZero(t, first.Lifetime.Session)
	require.NotZero(t, first.Lifetime.Generation)
	c.Touch("same", time.Now())
	c.Upsert(Call{CallID: "same", State: "answered", Lifetime: Lifetime{999, 999}})
	updated, _ := c.Call("same")
	require.Equal(t, first.Lifetime, updated.Lifetime)
	c.Clear()
	c.Upsert(Call{CallID: "same"})
	reused, _ := c.Call("same")
	require.Equal(t, first.Lifetime.Session, reused.Lifetime.Session)
	require.Greater(t, reused.Lifetime.Generation, first.Lifetime.Generation)
	other := New(Config{MaxCalls: 1})
	other.Upsert(Call{CallID: "same"})
	otherCall, _ := other.Call("same")
	require.NotEqual(t, reused.Lifetime.Session, otherCall.Lifetime.Session)
}

func TestEndpointSnapshotsAcceptedOnlyOwnedAndReentrant(t *testing.T) {
	c := New(Config{MaxCalls: 2, MaxEndpointsPerCall: 1, MaxEndpointAssociations: 1})
	c.Upsert(Call{CallID: "a"})
	c.Upsert(Call{CallID: "b"})
	var observations []EndpointObservation
	c.AddEndpointObserver(endpointObserverFunc(func(o EndpointObservation) {
		// Reentering must not deadlock; every delivered slice belongs to its recipient.
		_, ok := c.Call(o.Call.CallID)
		require.True(t, ok)
		observations = append(observations, o)
	}))
	c.AddEndpointObserver(endpointObserverFunc(func(o EndpointObservation) {
		if len(o.Endpoints) > 0 {
			o.Endpoints[0] = "corrupted"
		}
	}))
	require.True(t, c.TryAssociateEndpoint("a", "10.0.0.1:9000"))
	require.True(t, c.TryAssociateEndpoint("a", "10.0.0.1:9000"))
	require.False(t, c.TryAssociateEndpoint("a", "10.0.0.1:9002"))
	require.False(t, c.TryAssociateEndpoint("b", "10.0.0.2:9000"))
	require.Len(t, observations, 1)
	require.Equal(t, []string{"10.0.0.1:9000"}, observations[0].Endpoints)
	c.DissociateEndpoints("a")
	require.Len(t, observations, 2)
	require.Empty(t, observations[1].Endpoints)
	require.Greater(t, observations[1].Revision, observations[0].Revision)
	require.Equal(t, observations[0].Call.Lifetime, observations[1].Call.Lifetime)
	require.True(t, c.TryAssociateEndpoint("b", "10.0.0.2:9000"))
}

func TestPromotionCannotAssociateReusedLifetime(t *testing.T) {
	c := New(Config{MaxCalls: 1, MaxEndpointsPerCall: 2})
	c.Upsert(Call{CallID: "reused"})
	old, _ := c.Call("reused")
	c.Remove("reused", EndCompleted)
	c.Upsert(Call{CallID: "reused"})
	require.False(t, c.TryAssociateEndpointForLifetime("reused", old.Lifetime, "10.0.0.1:9000"))
	current, _ := c.Call("reused")
	require.True(t, c.TryAssociateEndpointForLifetime("reused", current.Lifetime, "10.0.0.2:9000"))
	snapshot, ok := c.EndpointSnapshot("reused")
	require.True(t, ok)
	require.Equal(t, current, snapshot.Call)
	require.Equal(t, []string{"10.0.0.2:9000"}, snapshot.Endpoints)
}

package callregistry

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolveMediaEndpoints(t *testing.T) {
	registry := New(Config{MaxCalls: 8, MaxEndpointsPerCall: 4})
	now := time.Now()
	for _, id := range []string{"call-a", "call-b", "call-c"} {
		require.True(t, registry.Upsert(Call{CallID: id, LastUpdated: now}))
	}
	registry.AssociateEndpoint("call-a", "192.0.2.1:10000")
	registry.AssociateEndpoint("call-a", "192.0.2.2:20000")
	registry.AssociateEndpoint("call-b", "192.0.2.1:10000")
	registry.AssociateEndpoint("call-b", "192.0.2.3:30000")
	registry.AssociateEndpoint("call-c", "192.0.2.4:40000")

	tests := []struct {
		name        string
		source      string
		destination string
		want        MediaResolution
	}{
		{"unique two-sided intersection", "192.0.2.1:10000", "192.0.2.2:20000", MediaResolution{Status: MediaResolved, CallID: "call-a"}},
		{"unique one-sided owner", "192.0.2.4:40000", "192.0.2.99:9", MediaResolution{Status: MediaResolved, CallID: "call-c"}},
		{"empty result", "192.0.2.98:8", "192.0.2.99:9", MediaResolution{Status: MediaUnresolved}},
		{"shared endpoint ambiguity", "192.0.2.1:10000", "192.0.2.99:9", MediaResolution{Status: MediaAmbiguous}},
		{"contradictory endpoints", "192.0.2.2:20000", "192.0.2.3:30000", MediaResolution{Status: MediaUnresolved}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, registry.ResolveMediaEndpoints(test.source, test.destination))
		})
	}
}

func TestResolveMediaEndpointsRemovalAndReuse(t *testing.T) {
	registry := New(Config{MaxCalls: 4, MaxEndpointsPerCall: 2})
	registry.Upsert(Call{CallID: "old"})
	registry.AssociateEndpoint("old", "192.0.2.1:10000")
	require.Equal(t, MediaResolution{Status: MediaResolved, CallID: "old"}, registry.ResolveMediaEndpoints("192.0.2.1:10000", ""))

	require.True(t, registry.Remove("old", EndCompleted))
	require.Equal(t, MediaResolution{Status: MediaUnresolved}, registry.ResolveMediaEndpoints("192.0.2.1:10000", ""))

	registry.Upsert(Call{CallID: "new"})
	registry.AssociateEndpoint("new", "192.0.2.1:10000")
	require.Equal(t, MediaResolution{Status: MediaResolved, CallID: "new"}, registry.ResolveMediaEndpoints("192.0.2.1:10000", ""))
}

func TestCallIDsForEndpointReturnsSnapshot(t *testing.T) {
	registry := New(Config{MaxCalls: 2, MaxEndpointsPerCall: 1})
	registry.Upsert(Call{CallID: "call-a"})
	registry.AssociateEndpoint("call-a", "192.0.2.1:10000")

	owners := registry.CallIDsForEndpoint("192.0.2.1:10000")
	owners[0] = "mutated"
	require.Equal(t, []string{"call-a"}, registry.CallIDsForEndpoint("192.0.2.1:10000"))
}

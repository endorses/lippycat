//go:build li

package li

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDestinationRevisionSurvivesEndpointReversionAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf-a.example", Port: 443, X2Enabled: true}))
	initial, err := m.GetDestination(did)
	require.NoError(t, err)
	original := DestinationDeliveryGeneration(initial)
	for _, address := range []string{"mdf-b.example", "mdf-a.example"} {
		require.NoError(t, m.ModifyDestination(did, &Destination{DID: did, Address: address, Port: 443, X2Enabled: true}))
		current, err := m.GetDestination(did)
		require.NoError(t, err)
		require.NotEqual(t, original, DestinationDeliveryGeneration(current), "reverting an endpoint must not reauthorize old held product")
	}
	current, err := m.GetDestination(did)
	require.NoError(t, err)
	require.Equal(t, uint64(2), current.DeliveryRevision)
	generation := DestinationDeliveryGeneration(current)
	restarted := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
	require.NoError(t, restarted.restorePersistedState())
	restored, err := restarted.GetDestination(did)
	require.NoError(t, err)
	require.Equal(t, generation, DestinationDeliveryGeneration(restored))
	// Startup ADMF synchronization supplies no local revision; the registry must
	// preserve it for unchanged delivery definitions and descriptive updates.
	require.NoError(t, restarted.registry.ModifyDestination(did, &Destination{DID: did, Address: current.Address, Port: current.Port, X2Enabled: true, Description: "updated label"}))
	restored, err = restarted.GetDestination(did)
	require.NoError(t, err)
	require.Equal(t, generation, DestinationDeliveryGeneration(restored))
}

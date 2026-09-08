//go:build li

package li

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestDestinationPersistencePrecedesDeliveryPublication(t *testing.T) {
	for _, operation := range []string{"create", "modify", "remove", "sync_create", "sync_modify"} {
		t.Run(operation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			did := uuid.New()
			creating := operation == "create" || operation == "sync_create"
			var previous *Destination
			if !creating {
				require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf-a.example", Port: 443, X2Enabled: true}))
				var err error
				previous, err = m.GetDestination(did)
				require.NoError(t, err)
			}
			published := 0
			verifyPublication := func(dest *Destination) {
				published++
				// Delivery callbacks must observe the already durable definition.
				state, err := loadPersistedState(path)
				require.NoError(t, err)
				require.NotNil(t, state)
				if dest == nil {
					require.Empty(t, state.Destinations)
					return
				}
				require.Len(t, state.Destinations, 1)
				saved := state.Destinations[0]
				require.Equal(t, dest.Address, saved.Address)
				require.True(t, dest.CreatedAt.Equal(saved.CreatedAt))
				require.Equal(t, dest.DeliveryRevision, saved.DeliveryRevision)
			}
			// Count failure-path publication without requiring a valid checkpoint.
			m.SetDestinationCreatedCallback(func(*Destination) { published++ })
			m.SetDestinationModifiedCallback(func(*Destination) { published++ })
			m.SetDestinationRemovedCallback(func(uuid.UUID) { published++ })
			apply := func() error {
				dest := &Destination{DID: did, Address: "mdf-b.example", Port: 443, X2Enabled: true}
				switch operation {
				case "create":
					return m.CreateDestination(dest)
				case "modify":
					return m.ModifyDestination(did, dest)
				case "remove":
					return m.RemoveDestination(did)
				default:
					return m.syncDestination(dest)
				}
			}
			// A directory cannot be replaced by the atomic state-file rename.
			m.config.StateFile = t.TempDir()
			require.Error(t, apply())
			require.Zero(t, published, "unsaved destination identities must not reach delivery")
			current, err := m.GetDestination(did)
			if creating {
				require.ErrorIs(t, err, ErrDestinationNotFound)
			} else {
				require.NoError(t, err)
				require.Equal(t, previous, current, "failed update must restore the canonical definition")
			}
			m.config.StateFile = path
			m.SetDestinationCreatedCallback(verifyPublication)
			m.SetDestinationModifiedCallback(verifyPublication)
			m.SetDestinationRemovedCallback(func(uuid.UUID) { verifyPublication(nil) })
			require.NoError(t, apply())
			require.Equal(t, 1, published)
		})
	}
}

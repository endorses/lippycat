//go:build li

package li

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPersistenceRequiresDirectorySyncBeforeActivation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	did, xid := uuid.New(), uuid.New()
	m := newStateTestManager(t, ManagerConfig{Enabled: true, StateFile: path}, nil)
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 9443}))
	original, err := os.ReadFile(path)
	require.NoError(t, err)

	// Directory descriptors are now retained for the ownership lifetime. Inject
	// a definite failure at the storage boundary rather than changing pathname
	// permissions after that descriptor has already been securely opened.
	store := m.stateStore.(*EncryptedStateStore)
	store.write = func(string, []byte) (securestore.Outcome, error) {
		return securestore.NotCommitted, errors.New("injected directory sync prerequisite failure")
	}
	err = m.ActivateTask(&InterceptTask{
		XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}},
		DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2andX3,
	})
	require.ErrorContains(t, err, "directory sync prerequisite failure")
	require.Zero(t, m.FilterCount(), "uncheckpointed activation must not enforce")
	_, err = m.GetTaskDetails(xid)
	require.Error(t, err, "failed activation must roll back")
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, current, "known directory-open failure must preserve prior state")
}

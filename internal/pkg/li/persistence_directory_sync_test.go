//go:build li

package li

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPersistenceRequiresDirectorySyncBeforeActivation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory read permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	did, xid := uuid.New(), uuid.New()
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 9443}))
	original, err := os.ReadFile(path)
	require.NoError(t, err)

	// A write/search-only directory permits temporary files and rename, while
	// preventing the read-only directory open required for its final fsync.
	require.NoError(t, os.Chmod(dir, 0300))
	t.Cleanup(func() { require.NoError(t, os.Chmod(dir, 0700)) })
	err = m.ActivateTask(&InterceptTask{
		XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}},
		DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2andX3,
	})
	require.ErrorContains(t, err, "open LI state directory for sync")
	require.Zero(t, m.FilterCount(), "uncheckpointed activation must not enforce")
	_, err = m.GetTaskDetails(xid)
	require.Error(t, err, "failed activation must roll back")
	current, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, current, "known directory-open failure must preserve prior state")
}

//go:build li

package li

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPhase6PersistenceRestoresPendingWithoutArming(t *testing.T) {
	path := filepath.Join(t.TempDir(), "li-state.json")
	did, xid := uuid.New(), uuid.New()
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 9443}))
	require.NoError(t, m.ActivateTask(&InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2andX3, StartTime: time.Now().Add(time.Hour)}))
	require.Equal(t, 0, m.FilterCount())

	restarted := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
	require.NoError(t, restarted.restorePersistedState())
	task, err := restarted.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, TaskStatusPending, task.Status)
	require.Equal(t, 0, restarted.FilterCount())
	require.NotZero(t, task.ActivationGeneration)
}

func TestPhase6PersistenceDoesNotRestoreExpiredOrUnconfirmedActive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "li-state.json")
	did := uuid.New()
	require.NoError(t, writePersistedState(path, &persistedState{
		Destinations: []*persistedDestination{{DID: did, Address: "mdf.example", Port: 9443}},
		Tasks: []*InterceptTask{
			{XID: uuid.New(), Status: TaskStatusActive, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "a@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only, EndTime: time.Now().Add(time.Hour)},
			{XID: uuid.New(), Status: TaskStatusPending, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "b@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only, StartTime: time.Now().Add(-2 * time.Hour), EndTime: time.Now().Add(-time.Hour)},
		},
	}))
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
	require.NoError(t, m.restorePersistedState())
	require.Equal(t, 0, m.TaskCount(), "active needs ADMF confirmation and expired state stays disarmed")
}

func TestPhase6PersistenceCorruptionFailsClosedAndUsesRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "li-state.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0600))
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
	require.ErrorContains(t, m.Start(), "interception remains disarmed")
	require.Equal(t, 0, m.FilterCount())

	require.NoError(t, writePersistedState(path, &persistedState{}))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

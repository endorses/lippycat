//go:build li

package li

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPersistenceRestoresTasksAfterDestinationRemoval(t *testing.T) {
	for _, status := range []TaskStatus{TaskStatusDeactivated, TaskStatusFailed, TaskStatusPending} {
		t.Run(status.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			did, xid := uuid.New(), uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 9443}))
			task := &InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only}
			if status == TaskStatusPending {
				task.StartTime = time.Now().Add(time.Hour)
			}
			require.NoError(t, m.ActivateTask(task))
			switch status {
			case TaskStatusDeactivated:
				require.NoError(t, m.DeactivateTask(xid))
			case TaskStatusFailed:
				require.NoError(t, m.registry.MarkTaskFailed(xid, "test fault"))
			}
			before, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.NoError(t, m.RemoveDestination(did))
			restarted := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			require.NoError(t, restarted.restorePersistedState())
			restored, err := restarted.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, status, restored.Status)
			require.Equal(t, before.ActivationGeneration, restored.ActivationGeneration)
			require.Equal(t, before.DestinationIDs, restored.DestinationIDs)
			require.Zero(t, restarted.FilterCount())
			require.False(t, restarted.ReplayTaskAuthorized(xid, restored.ActivationGeneration))
			if status == TaskStatusPending {
				// Advance the pending boundary without sleeping; missing destinations must
				// fail promotion on both the original owner and the restarted owner.
				for _, owner := range []*Manager{m, restarted} {
					owner.registry.mu.Lock()
					owner.registry.tasks[xid].StartTime = time.Now().Add(-time.Second)
					owner.registry.mu.Unlock()
					owner.promotePendingTasks()
					failed, err := owner.GetTaskDetails(xid)
					require.NoError(t, err)
					require.Equal(t, TaskStatusFailed, failed.Status)
					require.Contains(t, failed.LastError, ErrDestinationNotFound.Error())
					require.Zero(t, owner.FilterCount())
				}
			}
		})
	}
}

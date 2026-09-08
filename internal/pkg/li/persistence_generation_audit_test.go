//go:build li

package li

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPersistedGenerationSurvivesTaskRemoval(t *testing.T) {
	for _, mode := range []string{"expired_legacy", "purged", "unconfirmed"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			xid, did := uuid.New(), uuid.New()
			task := &InterceptTask{XID: xid, ActivationGeneration: 7, Status: TaskStatusActive, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only}
			if mode == "expired_legacy" {
				task.EndTime = time.Now().Add(-time.Hour)
			}
			if mode == "purged" {
				task.Status = TaskStatusDeactivated
				task.DeactivatedAt = time.Now().Add(-time.Hour)
			}
			require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}, Destinations: []*persistedDestination{{DID: did, Address: "mdf.example", Port: 9443}}}))
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			require.NoError(t, m.restorePersistedState())
			if mode == "purged" {
				require.Equal(t, 1, m.registry.PurgeDeactivatedTasks(0))
			}
			require.Zero(t, m.TaskCount())
			require.NoError(t, m.persistState()) // Includes the startup checkpoint before ADMF confirmation.
			restarted := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			require.NoError(t, restarted.restorePersistedState())
			task.EndTime = time.Time{}
			require.NoError(t, restarted.ActivateTask(task))
			active, err := restarted.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Greater(t, active.ActivationGeneration, uint64(7), "old journal generation must never identify a new activation")
		})
	}
}

func TestPersistedActiveGenerationContinuity(t *testing.T) {
	for _, watermark := range []uint64{7, 9} {
		t.Run(fmt.Sprint(watermark), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			xid, did := uuid.New(), uuid.New()
			task := &InterceptTask{XID: xid, ActivationGeneration: 7, Status: TaskStatusActive, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only}
			require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}, Generations: map[uuid.UUID]uint64{xid: watermark}, Destinations: []*persistedDestination{{DID: did, Address: "mdf.example", Port: 9443}}}))
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path}, nil)
			require.NoError(t, m.restorePersistedState())
			require.NoError(t, m.activateStartupTask(task))
			active, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			expected := watermark + 1
			if watermark == 7 {
				expected = 7
			}
			require.Equal(t, expected, active.ActivationGeneration)
		})
	}
}

func TestTaskGenerationExhaustionRejectsActivation(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	xid, did := uuid.New(), uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 9443}))
	m.registry.seedGeneration(xid, ^uint64(0))
	require.ErrorContains(t, m.ActivateTask(&InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only}), "generation exhausted")
	require.Zero(t, m.TaskCount())
}

func TestTaskGenerationPersistenceFailureStaysDisarmed(t *testing.T) {
	for _, modify := range []bool{false, true} {
		t.Run(fmt.Sprint(modify), func(t *testing.T) {
			m := NewManager(ManagerConfig{Enabled: true}, nil)
			xid, did := uuid.New(), uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 9443}))
			task := &InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "alice@example"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only}
			if modify {
				require.NoError(t, m.ActivateTask(task))
			}
			m.config.StateFile = t.TempDir() // Atomic rename cannot replace a directory.
			if modify {
				targets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: "bob@example"}}
				require.Error(t, m.ModifyTask(xid, &TaskModification{Targets: &targets}))
				current, err := m.GetTaskDetails(xid)
				require.NoError(t, err)
				require.Equal(t, uint64(1), current.ActivationGeneration)
				require.Equal(t, task.Targets, current.Targets)
			} else {
				require.Error(t, m.ActivateTask(task))
				require.Zero(t, m.TaskCount())
				require.Zero(t, m.FilterCount())
			}
		})
	}
}

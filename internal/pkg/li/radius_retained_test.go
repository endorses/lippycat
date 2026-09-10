//go:build li

package li

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRADIUSRetainedLegacyNAIRestoresInactive(t *testing.T) {
	for _, status := range []TaskStatus{TaskStatusDeactivated, TaskStatusFailed} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeNAI, Value: "legacy account"}}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2andX3, Status: status, ActivationGeneration: 7}
			id := fmt.Sprintf("li-%s-0", task.XID)
			store := newStubFilterStore(id)
			path := filepath.Join(t.TempDir(), "state.json")
			require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}}))
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path, FilterPusher: store}, nil)
			require.NoError(t, m.restorePersistedState())
			require.False(t, store.has(id))
			restored, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, task, restored)
			_, ok := m.AcquireTaskAdmission(task.XID, 7)
			require.False(t, ok)
			require.False(t, m.ReplayTaskAuthorized(task.XID, 7))
			require.Error(t, m.ActivateTask(task), "legacy definition cannot arm")
			corrected := *task
			corrected.DeliveryType = DeliveryX2Only
			corrected.RADIUSScope = radius.ScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}
			corrected.Targets = []TargetIdentity{{Type: TargetTypeNAI, Value: "alice@example.test"}}
			require.Error(t, m.ActivateTask(&corrected), "retained identity/status policy still applies; reprovision with a new XID")
			current, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, task, current)
		})
	}
}

func TestRADIUSRetainedLegacyNAIExceptionIsNarrow(t *testing.T) {
	for _, change := range []func(*InterceptTask){
		func(t *InterceptTask) { t.Status = TaskStatusPending },
		func(t *InterceptTask) { t.RADIUSScope.ProfileRevision = "partial" },
		func(t *InterceptTask) {
			t.Targets = append(t.Targets, TargetIdentity{Type: TargetTypeRADIUSAttribute, Value: "broken"})
		},
		func(t *InterceptTask) { t.XID = uuid.Nil },
		func(t *InterceptTask) { t.Targets[0].Value = "" },
		func(t *InterceptTask) { t.DestinationIDs = nil },
		func(t *InterceptTask) { t.DeliveryType = 99 },
	} {
		task := &InterceptTask{XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeNAI, Value: "alice"}}, DestinationIDs: []uuid.UUID{uuid.New()}, DeliveryType: DeliveryX2andX3, Status: TaskStatusDeactivated}
		change(task)
		require.Error(t, NewRegistry(nil).restoreNonEnforcingTask(task))
	}
}

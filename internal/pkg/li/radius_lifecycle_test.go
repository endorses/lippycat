//go:build li

package li

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestRADIUSRestartWithdrawsLegacyFiltersAndRevokesGeneration(t *testing.T) {
	for _, status := range []TaskStatus{TaskStatusActive, TaskStatusPending, TaskStatusSuspended} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			xid, did := uuid.New(), uuid.New()
			canonical := fmt.Sprintf("li-%s-0", xid)
			legacy := fmt.Sprintf("li-%s-0", xid.String()[:8])
			store := newStubFilterStore(canonical, legacy, "ordinary")
			path := filepath.Join(t.TempDir(), "state.json")
			old := &InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeNAI, Value: "alice@example.test"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only, Status: status, ActivationGeneration: 7}
			require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{old}, Destinations: []*persistedDestination{{DID: did, Address: "mdf.example", Port: 9443, X2Enabled: true, ProtocolType: "X2Only"}}}))
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path, FilterPusher: store, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator-a", ProfileRevision: "v1"}}, nil)
			require.NoError(t, m.restorePersistedState())
			require.Zero(t, m.TaskCount())
			require.False(t, store.has(canonical))
			require.False(t, store.has(legacy))
			require.True(t, store.has("ordinary"))
			require.False(t, m.ReplayTaskAuthorized(xid, 7))
			current := *old
			current.Status = TaskStatusActive
			m.bindRADIUSDeployment(&current)
			require.NoError(t, m.activateStartupTask(&current))
			active, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, uint64(8), active.ActivationGeneration)
			_, ok := m.AcquireTaskAdmission(xid, 7)
			require.False(t, ok)
			require.False(t, m.ReplayTaskAuthorized(xid, 7))
			require.Len(t, m.filters.GetFiltersForXID(xid), 1)
			group, ok := m.filters.LookupRADIUSGroup(canonical)
			require.True(t, ok)
			require.NotNil(t, group)
		})
	}
}

func TestRADIUSReconcileMigratesActiveNAIAndRejectsUnsupportedPolicy(t *testing.T) {
	for _, delivery := range []DeliveryType{DeliveryX2Only, DeliveryX2andX3} {
		t.Run(fmt.Sprint(delivery), func(t *testing.T) {
			m := NewManager(ManagerConfig{Enabled: true, RADIUSScope: radius.ScopeBinding{OperatorScope: "operator-a", ProfileRevision: "v1"}}, nil)
			xid, did := uuid.New(), uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 9443, X2Enabled: true, ProtocolType: "X2Only"}))
			// Model the registry left by the obsolete NAI-to-SIP implementation.
			old := &InterceptTask{XID: xid, Targets: []TargetIdentity{{Type: TargetTypeNAI, Value: "alice@example.test"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: delivery, Status: TaskStatusActive, ActivatedAt: time.Now(), ActivationGeneration: 3}
			m.registry.tasks[xid] = old
			m.registry.seedGeneration(xid, 3)
			corrected := *old
			m.bindRADIUSDeployment(&corrected)
			handled, err := m.reconcileRADIUSTask(&corrected)
			require.True(t, handled)
			current, getErr := m.GetTaskDetails(xid)
			require.NoError(t, getErr)
			if delivery == DeliveryX2Only {
				require.NoError(t, err)
				require.Equal(t, uint64(4), current.ActivationGeneration)
				require.Equal(t, corrected.RADIUSScope, current.RADIUSScope)
				require.Len(t, m.filters.GetFiltersForXID(xid), 1)
			} else {
				require.Error(t, err)
				require.False(t, current.IsActive())
			}
		})
	}
}

func TestRADIUSMalformedReplacementRevokesTask(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	task := radiusTargetTask()
	did := task.DestinationIDs[0]
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, ProtocolType: "X2Only"}))
	require.NoError(t, m.ActivateTask(task))
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.NoError(t, m.rejectRADIUSReplacement(task.XID, fmt.Errorf("invalid AVP length")))
	_, ok := m.AcquireTaskAdmission(task.XID, current.ActivationGeneration)
	require.False(t, ok)
	require.Zero(t, m.FilterCount())
}

func TestRADIUSLegacyMigrationRequiresFilterInventory(t *testing.T) {
	task := radiusTargetTask()
	task.RADIUSScope = radius.ScopeBinding{}
	task.Status = TaskStatusActive
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}}))
	// This minimal pusher deliberately has no inventory API.
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path, FilterPusher: &mockFilterPusher{}}, nil)
	require.ErrorContains(t, m.restorePersistedState(), "filter lister")
	require.Zero(t, m.TaskCount())
}

func TestRADIUSReconciliationFailedReplacementNeverRetainsOldAdmission(t *testing.T) {
	for _, reason := range []string{"unknown destination", "start time"} {
		t.Run(reason, func(t *testing.T) {
			m := NewManager(ManagerConfig{Enabled: true}, nil)
			task := radiusTargetTask()
			did := task.DestinationIDs[0]
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, ProtocolType: "X2Only"}))
			require.NoError(t, m.ActivateTask(task))
			old, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			replacement := *old
			if reason == "unknown destination" {
				replacement.DestinationIDs = []uuid.UUID{uuid.New()}
			} else {
				replacement.StartTime = time.Now().Add(time.Hour)
			}
			handled, err := m.reconcileRADIUSTask(&replacement)
			require.True(t, handled)
			require.Error(t, err)
			_, ok := m.AcquireTaskAdmission(task.XID, old.ActivationGeneration)
			require.False(t, ok)
			require.Zero(t, m.FilterCount())
		})
	}
}

//go:build li

package li

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func phase2Manager(t *testing.T) (*Manager, *transactionalPusher, uuid.UUID) {
	t.Helper()
	pusher := newTransactionalPusher()
	m := NewManager(ManagerConfig{Enabled: true, FilterPusher: pusher}, nil)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443}))
	return m, pusher, did
}

func phase2Task(did uuid.UUID) *InterceptTask {
	return &InterceptTask{
		XID: uuid.New(), Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:target@example.com"}},
		DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2Only,
	}
}

func TestPhase2PendingPromotionAndPreStartDeactivation(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	task.StartTime = time.Now().Add(time.Hour)
	require.NoError(t, m.ActivateTask(task))
	got, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, TaskStatusPending, got.Status)
	assert.Empty(t, pusher.installed)

	require.NoError(t, m.DeactivateTask(task.XID))
	m.promotePendingTasks()
	assert.Empty(t, pusher.installed)
}

func TestPhase2PromotionInstallsFiltersAtBoundary(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	task.StartTime = time.Now().Add(20 * time.Millisecond)
	require.NoError(t, m.ActivateTask(task))
	assert.Empty(t, pusher.installed)
	time.Sleep(25 * time.Millisecond)
	m.promotePendingTasks()
	got, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, TaskStatusActive, got.Status)
	assert.Len(t, pusher.installed, 1)
}

func TestPhase2ExpiryWithdrawsFilters(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	task.EndTime = time.Now().Add(20 * time.Millisecond)
	task.ImplicitDeactivationAllowed = true
	require.NoError(t, m.ActivateTask(task))
	require.Len(t, pusher.installed, 1)
	time.Sleep(25 * time.Millisecond)
	m.registry.checkExpiredTasks()
	got, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, TaskStatusDeactivated, got.Status)
	assert.Empty(t, pusher.installed)
}

func TestPhase3ReactivationOfDeactivatedTaskFailsClosed(t *testing.T) {
	m, _, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))
	require.NoError(t, m.DeactivateTask(task.XID))
	before, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	replacement := phase2Task(did)
	replacement.XID = task.XID
	replacement.Targets[0].Value = "sip:replacement@example.com"
	require.ErrorIs(t, m.ActivateTask(replacement), ErrTaskDefinitionConflict)
	got, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	assert.Equal(t, before, got)
}

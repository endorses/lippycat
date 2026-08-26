//go:build li

package li

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerReactivatesDeactivatedTaskThroughActivationTransaction(t *testing.T) {
	m, pusher, originalDID := phase2Manager(t)
	replacementDID := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: replacementDID, Address: "renewed.example", Port: 443}))
	task := phase2Task(originalDID)
	task.Targets = append(task.Targets, TargetIdentity{Type: TargetTypeTELURI, Value: "tel:+15551234567"})
	require.NoError(t, m.ActivateTask(task))
	require.NoError(t, m.DeactivateTask(task.XID))
	tombstone := mustTask(t, m.registry, task.XID)
	require.Empty(t, pusher.installed)

	replacement := cloneInterceptTask(task)
	replacement.Targets = []TargetIdentity{task.Targets[1], task.Targets[0], task.Targets[1]}
	replacement.DestinationIDs = []uuid.UUID{replacementDID}
	replacement.EndTime = time.Now().Add(2 * time.Hour).UTC()
	replacement.ImplicitDeactivationAllowed = true
	require.NoError(t, m.ActivateTask(replacement))

	got := mustTask(t, m.registry, task.XID)
	assert.Equal(t, TaskStatusActive, got.Status)
	assert.Equal(t, tombstone.ActivationGeneration+1, got.ActivationGeneration)
	assert.Equal(t, replacement.DestinationIDs, got.DestinationIDs)
	assert.Equal(t, replacement.EndTime, got.EndTime)
	assert.True(t, got.ImplicitDeactivationAllowed)
	assert.Len(t, pusher.installed, len(replacement.Targets))
	require.Len(t, m.registry.auditHistory[task.XID], 1)
	assert.Equal(t, *tombstone, m.registry.auditHistory[task.XID][0])
	assert.NotContains(t, m.registry.rollbackTask, task.XID)
}

func TestManagerReactivationIdentityConflictHasNoSideEffects(t *testing.T) {
	mutations := map[string]func(*InterceptTask){
		"target type":  func(v *InterceptTask) { v.Targets[0].Type = TargetTypeTELURI },
		"target value": func(v *InterceptTask) { v.Targets[0].Value = "sip:other@example.com" },
		"added target": func(v *InterceptTask) {
			v.Targets = append(v.Targets, TargetIdentity{Type: TargetTypeUsername, Value: "other"})
		},
		"removed target": func(v *InterceptTask) {
			v.Targets = nil
		},
		"delivery type": func(v *InterceptTask) { v.DeliveryType = DeliveryX3Only },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m, pusher, did := phase2Manager(t)
			task := phase2Task(did)
			require.NoError(t, m.ActivateTask(task))
			require.NoError(t, m.DeactivateTask(task.XID))
			before := mustTask(t, m.registry, task.XID)
			generationBefore := m.registry.generations[task.XID]
			replacement := cloneInterceptTask(task)
			mutate(replacement)

			err := m.ActivateTask(replacement)
			require.ErrorIs(t, err, ErrReactivationIdentityConflict)
			assert.Equal(t, before, mustTask(t, m.registry, task.XID))
			assert.Equal(t, generationBefore, m.registry.generations[task.XID])
			assert.Empty(t, m.registry.auditHistory[task.XID])
			assert.NotContains(t, m.registry.rollbackTask, task.XID)
			assert.Empty(t, m.filters.GetFiltersForXID(task.XID))
			assert.Empty(t, pusher.installed)
		})
	}
}

func TestManagerReactivationFilterFailureRestoresTombstone(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))
	require.NoError(t, m.DeactivateTask(task.XID))
	tombstone := mustTask(t, m.registry, task.XID)
	pusher.failUpdateCall = pusher.updateCalls + 1

	err := m.ActivateTask(cloneInterceptTask(task))
	require.Error(t, err)
	assert.Equal(t, tombstone, mustTask(t, m.registry, task.XID))
	assert.Empty(t, m.registry.auditHistory[task.XID])
	assert.NotContains(t, m.registry.rollbackTask, task.XID)
	assert.Empty(t, m.filters.GetFiltersForXID(task.XID))
	assert.Empty(t, pusher.installed)
}

func TestManagerUnknownLifecycleStateFailsClosed(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))
	m.registry.mu.Lock()
	m.registry.tasks[task.XID].Status = TaskStatus(255)
	m.registry.mu.Unlock()
	before := mustTask(t, m.registry, task.XID)

	require.ErrorIs(t, m.ActivateTask(cloneInterceptTask(task)), ErrTaskDefinitionConflict)
	assert.Equal(t, before, mustTask(t, m.registry, task.XID))
	assert.Len(t, pusher.installed, len(task.Targets))
}

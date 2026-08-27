//go:build li

package li

import (
	"errors"
	"os"
	"sync"
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

func TestManagerReactivationCommitFailureRestoresTombstone(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))
	require.NoError(t, m.DeactivateTask(task.XID))
	tombstone := mustTask(t, m.registry, task.XID)
	m.commitActivation = func(uuid.UUID, time.Time) error { return errors.New("injected commit failure") }

	err := m.ActivateTask(cloneInterceptTask(task))
	require.ErrorContains(t, err, "injected commit failure")
	assert.Equal(t, tombstone, mustTask(t, m.registry, task.XID))
	assert.Empty(t, m.registry.auditHistory[task.XID])
	assert.NotContains(t, m.registry.rollbackTask, task.XID)
	assert.Empty(t, m.filters.GetFiltersForXID(task.XID))
	assert.Empty(t, pusher.installed)
}

func TestManagerConcurrentDuplicateReactivationCommitsOnce(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))
	require.NoError(t, m.DeactivateTask(task.XID))
	pusher.updateCalls = 0

	const attempts = 16
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- m.ActivateTask(cloneInterceptTask(task))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	got := mustTask(t, m.registry, task.XID)
	assert.Equal(t, TaskStatusActive, got.Status)
	assert.Equal(t, uint64(2), got.ActivationGeneration)
	assert.Equal(t, len(task.Targets), pusher.updateCalls)
	assert.Len(t, m.registry.auditHistory[task.XID], 1)
}

func TestManagerReactivationAfterDurableRestore(t *testing.T) {
	stateFile := t.TempDir() + "/li-state.json"
	m1, _, dids := newIdempotencyManager(t, stateFile)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m1.ActivateTask(task))
	require.NoError(t, m1.DeactivateTask(task.XID))

	pusher := newTransactionalPusher()
	m2 := NewManager(ManagerConfig{Enabled: true, FilterPusher: pusher, StateFile: stateFile}, nil)
	require.NoError(t, m2.restorePersistedState())
	tombstone := mustTask(t, m2.registry, task.XID)
	require.Equal(t, TaskStatusDeactivated, tombstone.Status)
	require.NoError(t, m2.ActivateTask(cloneInterceptTask(task)))
	active := mustTask(t, m2.registry, task.XID)
	assert.Equal(t, TaskStatusActive, active.Status)
	assert.Equal(t, tombstone.ActivationGeneration+1, active.ActivationGeneration)
	assert.Len(t, pusher.installed, len(task.Targets))

	require.NoError(t, m2.DeactivateTask(task.XID))
	beforeTask := mustTask(t, m2.registry, task.XID)
	beforeState, err := os.ReadFile(stateFile)
	require.NoError(t, err)
	conflict := cloneInterceptTask(task)
	conflict.Targets[0].Value = "sip:changed@example"
	require.ErrorIs(t, m2.ActivateTask(conflict), ErrReactivationIdentityConflict)
	afterState, err := os.ReadFile(stateFile)
	require.NoError(t, err)
	assert.Equal(t, beforeTask, mustTask(t, m2.registry, task.XID))
	assert.Equal(t, beforeState, afterState)
}

func TestManagerInvalidReactivationLeavesPersistenceUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(*Manager, *InterceptTask)
		wantErr error
	}{
		{
			name: "missing destination",
			prepare: func(_ *Manager, task *InterceptTask) {
				task.DestinationIDs = []uuid.UUID{uuid.New()}
			},
			wantErr: ErrDestinationNotFound,
		},
		{
			name: "incompatible destination",
			prepare: func(m *Manager, task *InterceptTask) {
				did := uuid.New()
				require.NoError(t, m.CreateDestination(&Destination{
					DID: did, Address: "x3.example", Port: 443, X3Enabled: true, ProtocolType: "X3Only",
				}))
				task.DestinationIDs = []uuid.UUID{did}
			},
			wantErr: ErrUnsupportedDeliveryCombination,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stateFile := t.TempDir() + "/li-state.json"
			pusher := newTransactionalPusher()
			m := NewManager(ManagerConfig{Enabled: true, FilterPusher: pusher, StateFile: stateFile}, nil)
			did := uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{
				DID: did, Address: "x2.example", Port: 443, X2Enabled: true, ProtocolType: "X2Only",
			}))
			task := phase2Task(did)
			require.NoError(t, m.ActivateTask(task))
			require.NoError(t, m.DeactivateTask(task.XID))
			replacement := cloneInterceptTask(task)
			tc.prepare(m, replacement)
			beforeTask := mustTask(t, m.registry, task.XID)
			beforeState, err := os.ReadFile(stateFile)
			require.NoError(t, err)

			require.ErrorIs(t, m.ActivateTask(replacement), tc.wantErr)
			afterState, err := os.ReadFile(stateFile)
			require.NoError(t, err)
			assert.Equal(t, beforeTask, mustTask(t, m.registry, task.XID))
			assert.Equal(t, beforeState, afterState)
			assert.Empty(t, m.registry.auditHistory[task.XID])
			assert.NotContains(t, m.registry.rollbackTask, task.XID)
			assert.Empty(t, m.filters.GetFiltersForXID(task.XID))
		})
	}
}

func TestManagerConcurrentDeactivateAndReactivationSerializes(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))

	start := make(chan struct{})
	errs := make(chan error, 2)
	go func() { <-start; errs <- m.DeactivateTask(task.XID) }()
	go func() { <-start; errs <- m.ActivateTask(cloneInterceptTask(task)) }()
	close(start)
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)

	// If the idempotent activation won the lock first, the deactivation won
	// second. Finish with one explicit reactivation in that valid ordering.
	if mustTask(t, m.registry, task.XID).Status == TaskStatusDeactivated {
		require.NoError(t, m.ActivateTask(cloneInterceptTask(task)))
	}
	got := mustTask(t, m.registry, task.XID)
	assert.Equal(t, TaskStatusActive, got.Status)
	assert.Equal(t, uint64(2), got.ActivationGeneration)
	assert.Len(t, m.registry.auditHistory[task.XID], 1)
	assert.NotContains(t, m.registry.rollbackTask, task.XID)
	assert.Len(t, pusher.installed, len(task.Targets))
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

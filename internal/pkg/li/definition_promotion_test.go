//go:build li

package li

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func promoteDefinitionForTest(m *Manager, task *InterceptTask) error {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.promoteTaskDefinitionLocked(task)
}

func TestDefinitionPromotionFillsStartAndClosesOldGeneration(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory"
		if persistent {
			name = "persistent"
		}
		t.Run(name, func(t *testing.T) {
			var m *Manager
			var dids []uuid.UUID
			if persistent {
				m, _, _, dids = administrativeTransactionManager(t)
			} else {
				m, _, dids = newIdempotencyManager(t, "")
			}
			initial := idempotencyTask(uuid.New(), dids, time.Time{})
			require.NoError(t, m.ActivateTask(initial))
			previous, err := m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			var revoked uint64
			m.SetTaskModifiedCallback(func(old *InterceptTask) { revoked = old.ActivationGeneration })
			full := cloneInterceptTask(initial)
			full.StartTime = time.Now().Add(time.Hour).UTC()
			require.NoError(t, promoteDefinitionForTest(m, full))
			current, err := m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusPending, current.Status)
			require.Equal(t, full.StartTime, current.StartTime)
			require.Greater(t, current.ActivationGeneration, previous.ActivationGeneration)
			require.Equal(t, previous.ActivationGeneration, revoked)
			require.Empty(t, m.filters.GetFiltersForXID(initial.XID))
			if persistent {
				state := readManagerStateTest(t, m)
				require.Len(t, state.Tasks, 1)
				require.Equal(t, current.StartTime, state.Tasks[0].StartTime)
				require.Equal(t, current.ActivationGeneration, state.Tasks[0].ActivationGeneration)
			}
		})
	}
}

func TestDefinitionPromotionValidationAndFilterRollback(t *testing.T) {
	m, pusher, dids := newIdempotencyManager(t, "")
	initial := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(initial))
	previous, err := m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	ids := m.filters.GetFiltersForXID(initial.XID)
	invalid := cloneInterceptTask(initial)
	invalid.StartTime = time.Now().Add(-time.Hour).UTC()
	invalid.DestinationIDs = []uuid.UUID{uuid.New()}
	pusher.reset()
	require.ErrorIs(t, promoteDefinitionForTest(m, invalid), ErrDestinationNotFound)
	require.Empty(t, pusher.updates)
	require.Empty(t, pusher.deletes)
	current, err := m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	require.Equal(t, previous, current)
	full := cloneInterceptTask(initial)
	full.StartTime = time.Now().Add(-time.Hour).UTC()
	full.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:replacement@example.test"}}
	pusher.failNext = true
	require.Error(t, promoteDefinitionForTest(m, full))
	current, err = m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	require.Equal(t, previous, current)
	require.Equal(t, ids, m.filters.GetFiltersForXID(initial.XID))
}

func TestModifyTaskNarrowWindowRevokesButExtensionPreserves(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		name := "memory"
		if persistent {
			name = "persistent"
		}
		t.Run(name, func(t *testing.T) {
			var m *Manager
			var dids []uuid.UUID
			if persistent {
				m, _, _, dids = administrativeTransactionManager(t)
			} else {
				m, _, dids = newIdempotencyManager(t, "")
			}
			initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
			require.NoError(t, m.ActivateTask(initial))
			before, err := m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			end := initial.EndTime.Add(-time.Hour)
			require.NoError(t, m.ModifyTask(initial.XID, &TaskModification{EndTime: &end}))
			narrowed, err := m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			require.Greater(t, narrowed.ActivationGeneration, before.ActivationGeneration)
			end = initial.EndTime.Add(time.Hour)
			require.NoError(t, m.ModifyTask(initial.XID, &TaskModification{EndTime: &end}))
			extended, err := m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			require.Equal(t, narrowed.ActivationGeneration, extended.ActivationGeneration)
		})
	}
}

func TestDefinitionPromotionPendingToActiveRetainsGeneration(t *testing.T) {
	m, _, _, dids := administrativeTransactionManager(t)
	initial := idempotencyTask(uuid.New(), dids, time.Now().Add(time.Hour).UTC())
	require.NoError(t, m.ActivateTask(initial))
	previous, err := m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	require.Empty(t, m.filters.GetFiltersForXID(initial.XID))
	full := cloneInterceptTask(initial)
	full.StartTime = time.Now().Add(-time.Hour).UTC()
	require.NoError(t, promoteDefinitionForTest(m, full))
	current, err := m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusActive, current.Status)
	require.Equal(t, previous.ActivationGeneration, current.ActivationGeneration)
	require.NotEmpty(t, m.filters.GetFiltersForXID(initial.XID))
}

func TestDefinitionPromotionPersistentFilterFailureClosesAdmission(t *testing.T) {
	m, pusher, revoker, dids := administrativeTransactionManager(t)
	initial := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(initial))
	previous, err := m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	full := cloneInterceptTask(initial)
	full.StartTime = time.Now().Add(-time.Hour).UTC()
	full.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:replacement@example.test"}}
	pusher.failNext = true
	require.Error(t, promoteDefinitionForTest(m, full))
	current, err := m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusFailed, current.Status)
	require.NotNil(t, m.stateFault.Load())
	require.NotEmpty(t, revoker.committed)
	_, admitted := m.AcquireTaskAdmission(initial.XID, previous.ActivationGeneration)
	require.False(t, admitted)
	_, admitted = m.AcquireTaskAdmission(initial.XID, current.ActivationGeneration)
	require.False(t, admitted)
	require.Empty(t, m.filters.GetFiltersForXID(initial.XID))
}

func TestDefinitionPromotionRevokesBufferedGenerationBeforePolicy(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	initial := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(initial))
	previous, err := m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	full := cloneInterceptTask(initial)
	full.StartTime = time.Now().Add(-time.Hour).UTC()
	full.EndTime = time.Now().Add(time.Hour).UTC()
	revoked := false
	revoker.commit = func(controls []*StateRevocation) (securestore.Outcome, error) {
		require.Len(t, controls, 1)
		require.Equal(t, StateRevokeTask, controls[0].Scope)
		require.Equal(t, initial.XID, *controls[0].XID)
		require.Equal(t, previous.ActivationGeneration, *controls[0].TaskGeneration)
		live, err := m.GetTaskDetails(initial.XID)
		require.NoError(t, err)
		require.Equal(t, TaskStatusSuspended, live.Status)
		state, err := m.stateStore.Load()
		require.NoError(t, err)
		require.NotEmpty(t, state.Revocations)
		require.Greater(t, state.Generations[initial.XID], previous.ActivationGeneration)
		revoked = true
		return securestore.Committed, nil
	}
	m.SetCommittedTaskCallback(func(task *InterceptTask) {
		require.True(t, revoked, "new authorization must publish after buffered generation revocation")
		require.Greater(t, task.ActivationGeneration, previous.ActivationGeneration)
	})
	require.NoError(t, promoteDefinitionForTest(m, full))
	require.True(t, revoked)
	_, admitted := m.AcquireTaskAdmission(initial.XID, previous.ActivationGeneration)
	require.False(t, admitted)
}

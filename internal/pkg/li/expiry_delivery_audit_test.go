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

func TestTaskAdmissionEnforcesExpiryBeforeRegistrySweep(t *testing.T) {
	m, _, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))
	active, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	for _, implicit := range []bool{true, false} {
		// Keep the stored status active to model admission between expiry sweeps.
		m.registry.mu.Lock()
		m.registry.tasks[task.XID].EndTime = time.Now().Add(-time.Second)
		m.registry.tasks[task.XID].ImplicitDeactivationAllowed = implicit
		m.registry.mu.Unlock()
		admission, allowed := m.AcquireTaskAdmission(task.XID, active.ActivationGeneration)
		admission.Release()
		require.Equal(t, !implicit, allowed, "admission must respect the task's implicit-deactivation policy")
	}
}

func TestExpiryRevokesDeliveryDespiteCleanupFailure(t *testing.T) {
	for _, fault := range []string{"filter_withdrawal", "state_checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			pusher := newTransactionalPusher()
			var revoked []*InterceptTask
			m := NewManager(ManagerConfig{Enabled: true, FilterPusher: pusher}, func(task *InterceptTask, reason DeactivationReason) {
				require.Equal(t, DeactivationReasonExpired, reason)
				revoked = append(revoked, task)
			})
			did := uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			task := phase2Task(did)
			task.DeliveryType = DeliveryX2andX3
			task.ImplicitDeactivationAllowed = true
			require.NoError(t, m.ActivateTask(task))
			active, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			if fault == "filter_withdrawal" {
				pusher.failDeletes[m.filters.GetFiltersForXID(task.XID)[0]] = true
			} else {
				blocker := filepath.Join(t.TempDir(), "not-a-directory")
				require.NoError(t, os.WriteFile(blocker, nil, 0600))
				m.config.StateFile = filepath.Join(blocker, "state.json")
			}
			// Set the boundary directly so the regression does not depend on sleeps.
			m.registry.mu.Lock()
			m.registry.tasks[task.XID].EndTime = time.Now().Add(-time.Second)
			m.registry.mu.Unlock()
			m.registry.checkExpiredTasks()
			require.Len(t, revoked, 1, "expiry must revoke queued delivery even when cleanup fails")
			require.Equal(t, active.ActivationGeneration, revoked[0].ActivationGeneration)
			admission, allowed := m.AcquireTaskAdmission(task.XID, active.ActivationGeneration)
			admission.Release()
			require.False(t, allowed)
		})
	}
}

func TestStaleExpiryPreservesReactivatedGeneration(t *testing.T) {
	m, pusher, did := phase2Manager(t)
	task := phase2Task(did)
	task.ImplicitDeactivationAllowed = true
	require.NoError(t, m.ActivateTask(task))
	original, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	callback := m.registry.onDeactivation
	m.registry.onDeactivation = func(expired *InterceptTask, reason DeactivationReason) {
		if reason != DeactivationReasonExpired {
			callback(expired, reason)
			return
		}
		// Reproduce lifecycle changes after the checker's snapshot but before
		// its callback acquires the manager's admission barrier.
		require.NoError(t, m.DeactivateTask(task.XID))
		require.NoError(t, m.ActivateTask(task))
		callback(expired, reason)
	}
	m.registry.mu.Lock()
	m.registry.tasks[task.XID].EndTime = time.Now().Add(-time.Second)
	m.registry.mu.Unlock()
	m.registry.checkExpiredTasks()
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Greater(t, current.ActivationGeneration, original.ActivationGeneration)
	require.Equal(t, TaskStatusActive, current.Status)
	require.Len(t, pusher.installed, 1, "stale expiry must not withdraw the replacement's filters")
}

func TestExpiryCallbackRetainsLifecycleBarrier(t *testing.T) {
	var m *Manager
	called := false
	m = NewManager(ManagerConfig{Enabled: true}, func(_ *InterceptTask, reason DeactivationReason) {
		require.Equal(t, DeactivationReasonExpired, reason)
		called = true
		unlocked := m.lifecycleMu.TryLock()
		if unlocked {
			m.lifecycleMu.Unlock()
		}
		require.False(t, unlocked, "reactivation must wait until generation cleanup completes")
	})
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	task := phase2Task(did)
	task.ImplicitDeactivationAllowed = true
	require.NoError(t, m.ActivateTask(task))
	m.registry.mu.Lock()
	m.registry.tasks[task.XID].EndTime = time.Now().Add(-time.Second)
	m.registry.mu.Unlock()
	m.registry.checkExpiredTasks()
	require.True(t, called)
}

func TestStaleExpiryFinalizationPreservesSuspendedReplacement(t *testing.T) {
	m, _, did := phase2Manager(t)
	task := phase2Task(did)
	require.NoError(t, m.ActivateTask(task))
	previous, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.NoError(t, m.DeactivateTask(task.XID))
	require.NoError(t, m.ActivateTask(task))
	m.registry.mu.Lock()
	m.registry.tasks[task.XID].Status = TaskStatusSuspended
	m.registry.mu.Unlock()
	require.NoError(t, m.registry.finishExpiration(task.XID, previous.ActivationGeneration))
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusSuspended, current.Status)
}

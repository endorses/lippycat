//go:build li

package li

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStrictCandidateRetainsKnownFieldsAcrossPartialSnapshots(t *testing.T) {
	for _, field := range []string{"window", "implicit_false", "implicit_true"} {
		t.Run(field, func(t *testing.T) {
			cfg := ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state"), ADMFCompleteTaskContract: true}
			m := newStateTestManager(t, cfg, nil)
			xid, did := uuid.New(), uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			partial := convergenceDetails(xid, did, false)
			if field == "window" {
				partial = convergenceDetails(xid, did, true)
				end := schema.QualifiedMicrosecondDateTime("2090-01-01T00:00:00Z")
				partial.TaskDetails.ListOfMediationDetails.MediationDetails[0].EndTime = &end
				partial.TaskDetails.ImplicitDeactivationAllowed = nil
				partial.TaskDetails.ListOfMediationDetails.MediationDetails[0].StartTime = nil
			} else {
				flag := field == "implicit_true"
				partial.TaskDetails.ImplicitDeactivationAllowed = &flag
			}
			first := applyConvergence(t, m, partial)
			require.False(t, first.Completeness.Complete())
			before := cloneInterceptTask(m.persistenceCandidates[xid])
			applyConvergence(t, m, convergenceDetails(xid, did, false))
			require.Equal(t, before, m.persistenceCandidates[xid])
			require.Zero(t, m.FilterCount())
			m.Stop()
			next := newStateTestManager(t, cfg, nil)
			require.NoError(t, next.restorePersistedState())
			applyConvergence(t, next, convergenceDetails(xid, did, false))
			held := next.persistenceCandidates[xid]
			require.Equal(t, before.StartTime, held.StartTime)
			require.Equal(t, before.EndTime, held.EndTime)
			require.Equal(t, before.ImplicitDeactivationAllowed, held.ImplicitDeactivationAllowed)
			require.Equal(t, before.Definition.Completeness, held.Definition.Completeness)
			require.True(t, held.Definition.Candidate)
			require.Zero(t, next.FilterCount())
			_, err := next.GetTaskDetails(xid)
			require.ErrorIs(t, err, ErrTaskNotFound)
		})
	}
}

func TestRestoredPushConflictNarrowsAndExactPullCannotResolve(t *testing.T) {
	cfg := ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state")}
	m := newStateTestManager(t, cfg, nil)
	xid, did := uuid.New(), uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	full := convergenceDetails(xid, did, true)
	converted, err := ConvertSnapshotTask(full)
	require.NoError(t, err)
	push := cloneInterceptTask(converted.Task)
	push.Definition = TaskDefinitionState{}
	require.NoError(t, m.ActivateTask(push))
	original, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	m.Stop()
	next := newStateTestManager(t, cfg, nil)
	require.NoError(t, next.restorePersistedState())
	stale := convergenceDetails(xid, did, true)
	end := schema.QualifiedMicrosecondDateTime("2090-01-01T00:00:00Z")
	stale.TaskDetails.ListOfMediationDetails.MediationDetails[0].EndTime = &end
	applyConvergence(t, next, stale)
	held, err := next.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, 1, next.FilterCount())
	require.Equal(t, time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC), held.EndTime)
	require.Equal(t, DefinitionPush, held.Definition.Source)
	require.True(t, held.Definition.Conflict)
	require.EqualValues(t, 1, next.Stats().Definitions.Conflicts)
	require.False(t, next.ReplayTaskAuthorized(xid, original.ActivationGeneration))
	applyConvergence(t, next, full)
	current, err := next.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, DefinitionPush, current.Definition.Source)
	require.True(t, current.Definition.Conflict)
	require.Greater(t, current.ActivationGeneration, original.ActivationGeneration)
	require.False(t, next.ReplayTaskAuthorized(xid, original.ActivationGeneration))
	require.Equal(t, 1, next.FilterCount())
	// Later pulls still cannot replace the confirmed push.
	applyConvergence(t, next, stale)
	current, err = next.GetTaskDetails(xid)
	require.NoError(t, err)
	require.True(t, equivalentTaskDefinition(held, current))
	require.True(t, current.Definition.Conflict)
}

func TestRestoredPendingCompatibilityPartialAllowsScheduledActivation(t *testing.T) {
	cfg := ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state"), LifecycleInterval: time.Hour}
	m := newStateTestManager(t, cfg, nil)
	xid, did := uuid.New(), uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	partial := convergenceDetails(xid, did, true)
	start := schema.QualifiedMicrosecondDateTime(time.Now().Add(500 * time.Millisecond).UTC().Format(time.RFC3339Nano))
	partial.TaskDetails.ListOfMediationDetails.MediationDetails[0].StartTime = &start
	partial.TaskDetails.ImplicitDeactivationAllowed = nil
	applyConvergence(t, m, partial)
	old, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, TaskStatusPending, old.Status)
	m.Stop()
	next := newStateTestManager(t, cfg, nil)
	require.NoError(t, next.restorePersistedState())
	require.True(t, next.pendingNeedsConfirmation(xid))
	applyConvergence(t, next, convergenceDetails(xid, did, false))
	current, err := next.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, old.StartTime, current.StartTime)
	require.Equal(t, TaskStatusPending, current.Status)
	require.False(t, next.pendingNeedsConfirmation(xid))
	require.False(t, next.ReplayTaskAuthorized(xid, old.ActivationGeneration))
	require.Eventually(t, func() bool {
		next.promotePendingTasks()
		task, err := next.GetTaskDetails(xid)
		return err == nil && task.Status == TaskStatusActive
	}, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, next.FilterCount())
}

func TestStrictTransitionRejectsUnknownRestoredPendingTask(t *testing.T) {
	cfg := ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state")}
	m := newStateTestManager(t, cfg, nil)
	xid, did := uuid.New(), uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	partial := convergenceDetails(xid, did, true)
	start := schema.QualifiedMicrosecondDateTime(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	partial.TaskDetails.ListOfMediationDetails.MediationDetails[0].StartTime = &start
	partial.TaskDetails.ImplicitDeactivationAllowed = nil
	converted, err := ConvertSnapshotTask(partial)
	require.NoError(t, err)
	// Legacy state can have a future start without a known complete window.
	converted.Task.Definition.Completeness.End = false
	require.NoError(t, m.ActivateTask(converted.Task))
	m.Stop()
	cfg.ADMFCompleteTaskContract = true
	next := newStateTestManager(t, cfg, nil)
	require.ErrorContains(t, next.Start(), "repairing persisted incomplete")
	require.Nil(t, next.x1ServerCancel)
	require.Nil(t, next.registry.expirationTicker)
	require.Zero(t, next.FilterCount())
}

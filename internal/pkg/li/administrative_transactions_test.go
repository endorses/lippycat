//go:build li

package li

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type administrativeTestRevoker struct {
	prepare   func(RevocationRequest) ([]*StateRevocation, error)
	commit    func([]*StateRevocation) (securestore.Outcome, error)
	requests  []RevocationRequest
	committed [][]*StateRevocation
}

func (r *administrativeTestRevoker) Prepare(req RevocationRequest) ([]*StateRevocation, error) {
	r.requests = append(r.requests, req)
	if r.prepare != nil {
		return r.prepare(req)
	}
	c := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: req.StateIncarnation, RevokedAt: NewStateTimestamp(time.Now())}
	if req.Task != nil {
		c.Scope = StateRevokeTask
		c.XID = statePtr(req.Task.XID)
		c.TaskGeneration = statePtr(req.Task.ActivationGeneration)
	} else {
		c.Scope = StateRevokeDestination
		c.DID = statePtr(req.Destination.DID)
		c.DestinationGeneration = statePtr(req.DestinationGeneration)
	}
	return []*StateRevocation{c}, nil
}
func (r *administrativeTestRevoker) Commit(c []*StateRevocation) (securestore.Outcome, error) {
	r.committed = append(r.committed, c)
	if r.commit != nil {
		return r.commit(c)
	}
	return securestore.Committed, nil
}
func administrativeTransactionManager(t *testing.T) (*Manager, *mockFilterPusher, *administrativeTestRevoker, []uuid.UUID) {
	t.Helper()
	pusher := &mockFilterPusher{}
	m := newStateTestManager(t, ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state.enc"), FilterPusher: pusher, LifecycleInterval: time.Hour}, nil)
	revoker := &administrativeTestRevoker{}
	require.NoError(t, m.PrepareAdministrativeStorage())
	require.NoError(t, m.SetDurableRevoker(revoker))
	dids := []uuid.UUID{uuid.New(), uuid.New()}
	for _, did := range dids {
		require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, X3Enabled: true}))
	}
	return m, pusher, revoker, dids
}
func restartAdministrativeTestManager(t *testing.T, m *Manager, revoker *administrativeTestRevoker) *Manager {
	t.Helper()
	cfg := m.Config()
	m.Stop()
	restarted := NewManager(cfg, nil)
	t.Cleanup(restarted.Stop)
	require.NoError(t, restarted.PrepareAdministrativeStorage())
	if revoker != nil {
		require.NoError(t, restarted.SetDurableRevoker(revoker))
	}
	require.NoError(t, restarted.restorePersistedState())
	return restarted
}

func TestAdministrativePreflightDoesNotPublishOrClean(t *testing.T) {
	m, pusher, _, dids := administrativeTransactionManager(t)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	cfg := m.Config()
	incarnation := m.StateIncarnation()
	m.Stop()
	pusher.reset()
	reopened := NewManager(cfg, nil)
	t.Cleanup(reopened.Stop)
	require.NoError(t, reopened.PrepareAdministrativeStorage())
	require.NoError(t, reopened.PrepareAdministrativeStorage())
	require.Equal(t, incarnation, reopened.StateIncarnation())
	require.Zero(t, reopened.TaskCount())
	require.Empty(t, reopened.ListDestinations())
	require.Empty(t, pusher.deletes)
	require.False(t, reopened.administrativeAdmissionReady())
	_, err := OpenStateStore(cfg.StateFile, cfg.StateKeys)
	require.ErrorIs(t, err, securestore.ErrLocked)
	require.NoError(t, reopened.restorePersistedState())
	require.NotEmpty(t, pusher.deletes)
	require.Zero(t, reopened.ActiveTaskCount())
}

func TestAdministrativeTaskReservationPrecedesFiltersAndConsumesFailedGeneration(t *testing.T) {
	for _, stage := range []int{1, 2, 3} {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			m, pusher, _, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			writes := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				writes++
				if writes == stage {
					return securestore.NotCommitted, errors.New("injected checkpoint failure")
				}
				return write(name, data)
			}
			err := m.ActivateTask(task)
			require.Error(t, err)
			_, ok := m.AcquireTaskAdmission(task.XID, 1)
			require.False(t, ok)
			if stage == 1 {
				require.Equal(t, securestore.NotCommitted, securestore.OutcomeOf(err))
				require.Empty(t, pusher.updates)
				require.Zero(t, m.registry.generations[task.XID])
				require.Nil(t, m.stateFault.Load())
				store.write = write
				require.NoError(t, m.ActivateTask(task))
				return
			}
			require.NotEmpty(t, pusher.updates)
			require.Equal(t, uint64(1), m.registry.generations[task.XID])
			require.ErrorIs(t, m.ActivateTask(task), ErrAdministrativeFault)
			restarted := restartAdministrativeTestManager(t, m, nil)
			closed, err := restarted.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusFailed, closed.Status)
			require.Equal(t, uint64(1), closed.ActivationGeneration)
			require.Empty(t, restarted.GetActiveTasks())
			require.Empty(t, restarted.stateCleanup)
			require.NoError(t, restarted.DeactivateTask(task.XID))
			require.NoError(t, restarted.ActivateTask(task))
			fresh, err := restarted.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, uint64(2), fresh.ActivationGeneration)
		})
	}
}

func TestAdministrativeRevocationsAreRecordedBeforeCommitAndRetriedIdentically(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	revoker.commit = func(controls []*StateRevocation) (securestore.Outcome, error) {
		snapshot, err := m.stateStore.Load()
		require.NoError(t, err)
		for _, c := range controls {
			found := false
			for _, persisted := range snapshot.Revocations {
				if persisted.ControlID == c.ControlID {
					require.Equal(t, c, persisted)
					found = true
				}
			}
			require.True(t, found)
		}
		return securestore.NotCommitted, errors.New("injected journal rejection")
	}
	require.Error(t, m.DeactivateTask(task.XID))
	require.Empty(t, m.GetActiveTasks())
	require.Len(t, revoker.committed, 1)
	first := revoker.committed[0]
	revoker.commit = nil
	restarted := restartAdministrativeTestManager(t, m, revoker)
	require.Len(t, revoker.committed, 2)
	require.Equal(t, first, revoker.committed[1])
	require.Len(t, revoker.requests, 1, "recovery must not invent another plan")
	closed, err := restarted.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusDeactivated, closed.Status)
	require.NoError(t, restarted.DeactivateTask(task.XID))
	require.Len(t, revoker.committed, 2)
}

func TestAdministrativeDestinationRemovalWithdrawsAllMembershipsAndRecovers(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "retry"}[fail], func(t *testing.T) {
			m, pusher, revoker, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			require.NoError(t, m.ActivateTask(task))
			before, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			if fail {
				pusher.failNext = true
				require.Error(t, m.RemoveDestination(dids[0]))
				require.Empty(t, m.GetActiveTasks())
				m = restartAdministrativeTestManager(t, m, revoker)
			} else {
				require.NoError(t, m.RemoveDestination(dids[0]))
			}
			closed, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusDeactivated, closed.Status)
			require.Equal(t, before.DestinationIDs, closed.DestinationIDs)
			require.Equal(t, before.ActivationGeneration, closed.ActivationGeneration)
			_, err = m.GetDestination(dids[0])
			require.ErrorIs(t, err, ErrDestinationNotFound)
			_, err = m.GetDestination(dids[1])
			require.NoError(t, err)
			require.Zero(t, m.FilterCount())
			require.Empty(t, m.stateCleanup)
			snapshot, err := m.stateStore.Load()
			require.NoError(t, err)
			require.NoError(t, ValidateStateSnapshot(snapshot))
			require.Equal(t, before.ActivationGeneration, snapshot.Generations[task.XID])
			for _, i := range snapshot.Intents {
				require.Equal(t, StateFinished, i.Phase)
			}
		})
	}
}

func TestAdministrativeOversizedRevocationPlanHasNoEffects(t *testing.T) {
	m, pusher, revoker, dids := administrativeTransactionManager(t)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	before := readManagerStateTest(t, m)
	pusher.reset()
	revoker.prepare = func(req RevocationRequest) ([]*StateRevocation, error) {
		return make([]*StateRevocation, maxStateReferences+1), nil
	}
	require.Error(t, m.RemoveDestination(dids[0]))
	require.Empty(t, pusher.deletes)
	require.Empty(t, revoker.committed)
	require.Equal(t, before, readManagerStateTest(t, m))
	require.Len(t, m.GetActiveTasks(), 1)
}

func TestAdministrativeLegacyPendingZeroModification(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "fault"}[fail], func(t *testing.T) {
			path, keys, _ := stateStoreFixture(t)
			snapshot := emptyStateFixture()
			did := uuid.New()
			task := idempotencyTask(uuid.New(), []uuid.UUID{did}, time.Now().Add(time.Hour).UTC())
			task.Status = TaskStatusPending
			snapshot.Tasks = []*InterceptTask{task}
			snapshot.Generations[task.XID] = 0
			snapshot.Destinations = []*StateDestination{{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, X3Enabled: true, CreatedAt: time.Now().UTC()}}
			_, err := InitStateStore(path, keys, snapshot)
			require.NoError(t, err)
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path, StateKeys: keys}, nil)
			t.Cleanup(m.Stop)
			revoker := &administrativeTestRevoker{}
			require.NoError(t, m.SetDurableRevoker(revoker))
			require.NoError(t, m.restorePersistedState())
			if fail {
				store := m.stateStore.(*EncryptedStateStore)
				write := store.write
				calls := 0
				store.write = func(name string, data []byte) (securestore.Outcome, error) {
					calls++
					if calls == 2 {
						return securestore.NotCommitted, errors.New("injected")
					}
					return write(name, data)
				}
			}
			targets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:changed@example"}}
			err = m.ModifyTask(task.XID, &TaskModification{Targets: &targets})
			require.Empty(t, revoker.requests, "generation zero never prepares a revocation")
			require.Equal(t, uint64(1), m.registry.generations[task.XID])
			if fail {
				require.Error(t, err)
				m = restartAdministrativeTestManager(t, m, revoker)
				closed, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.Equal(t, TaskStatusFailed, closed.Status)
				require.Empty(t, m.GetActiveTasks())
			} else {
				require.NoError(t, err)
				current, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.Equal(t, uint64(1), current.ActivationGeneration)
				require.Equal(t, TaskStatusPending, current.Status)
			}
		})
	}
}

func TestAdministrativeDestinationCheckpointRecoveryPreservesReservedIdentity(t *testing.T) {
	for _, stage := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			previous, err := m.GetDestination(dids[0])
			require.NoError(t, err)
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			calls := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				calls++
				if calls == stage {
					return securestore.NotCommitted, errors.New("injected destination checkpoint failure")
				}
				return write(name, data)
			}
			candidate := *previous
			candidate.Address = "replacement.example"
			require.Error(t, m.ModifyDestination(previous.DID, &candidate))
			if stage == 1 {
				require.Empty(t, revoker.committed)
				current, err := m.GetDestination(previous.DID)
				require.NoError(t, err)
				require.Equal(t, previous, current)
				require.Nil(t, m.stateFault.Load())
				return
			}
			require.NotNil(t, m.stateFault.Load())
			restarted := restartAdministrativeTestManager(t, m, revoker)
			current, err := restarted.GetDestination(previous.DID)
			require.NoError(t, err)
			require.Equal(t, candidate.Address, current.Address)
			require.Equal(t, previous.DeliveryRevision+1, current.DeliveryRevision)
			require.Equal(t, previous.CreatedAt, current.CreatedAt)
			require.Empty(t, restarted.GetActiveTasks())
			current.Description = "metadata only"
			generation := DestinationDeliveryGeneration(current)
			before := len(revoker.requests)
			require.NoError(t, restarted.ModifyDestination(current.DID, current))
			require.Len(t, revoker.requests, before)
			got, err := restarted.GetDestination(current.DID)
			require.NoError(t, err)
			require.Equal(t, generation, DestinationDeliveryGeneration(got))
		})
	}
}

func TestAdministrativeModificationCheckpointNeverRestoresRevokedGeneration(t *testing.T) {
	for _, stage := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			require.NoError(t, m.ActivateTask(task))
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			calls := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				calls++
				if calls == stage {
					return securestore.NotCommitted, errors.New("injected modification checkpoint failure")
				}
				return write(name, data)
			}
			targets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:replacement@example"}}
			require.Error(t, m.ModifyTask(task.XID, &TaskModification{Targets: &targets}))
			if stage == 1 {
				require.Len(t, m.GetActiveTasks(), 1)
				require.Equal(t, uint64(1), m.registry.generations[task.XID])
				require.Empty(t, revoker.committed)
				return
			}
			require.Empty(t, m.GetActiveTasks())
			require.Equal(t, uint64(2), m.registry.generations[task.XID])
			restarted := restartAdministrativeTestManager(t, m, revoker)
			closed, err := restarted.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusFailed, closed.Status)
			require.Equal(t, uint64(2), closed.ActivationGeneration)
			require.Equal(t, uint64(1), *revoker.committed[len(revoker.committed)-1][0].TaskGeneration)
		})
	}
}

func TestAdministrativePendingPromotionCheckpointRemainsClosed(t *testing.T) {
	for _, stage := range []int{1, 2, 3} {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Now().Add(time.Hour).UTC())
			require.NoError(t, m.ActivateTask(task))
			m.registry.mu.Lock()
			m.registry.tasks[task.XID].StartTime = time.Now().Add(-time.Second).UTC()
			m.registry.mu.Unlock()
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			calls := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				calls++
				if calls == stage {
					return securestore.NotCommitted, errors.New("injected promotion checkpoint failure")
				}
				return write(name, data)
			}
			m.promotePendingTasks()
			require.Empty(t, m.GetActiveTasks())
			require.Equal(t, uint64(1), m.registry.generations[task.XID])
			restarted := restartAdministrativeTestManager(t, m, revoker)
			closed, err := restarted.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusFailed, closed.Status)
			require.Equal(t, uint64(1), closed.ActivationGeneration)
		})
	}
}

func TestAdministrativeCleanupAndPurgePreserveObligations(t *testing.T) {
	m, pusher, revoker, dids := administrativeTransactionManager(t)
	ids := []string{"li-12345678-0", "li-" + uuid.NewString() + "-2"}
	pusher.failNext = true
	m.adminMu.Lock()
	_, err := m.cleanupPersistentFiltersLocked(ids)
	m.adminMu.Unlock()
	require.Error(t, err)
	snapshot, err := m.stateStore.Load()
	require.NoError(t, err)
	intent := snapshot.Intents[len(snapshot.Intents)-1]
	require.Equal(t, StateCleanup, intent.Kind)
	require.Nil(t, intent.XID)
	require.Nil(t, intent.DID)
	require.Equal(t, ids, intent.CleanupFilterIDs)
	m = restartAdministrativeTestManager(t, m, revoker)
	require.Subset(t, pusher.deletes, ids)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	require.NoError(t, m.DeactivateTask(task.XID))
	snapshot, err = m.stateStore.Load()
	require.NoError(t, err)
	controls := snapshot.Revocations
	count, err := m.PurgeDeactivatedTasksWithError(0)
	require.NoError(t, err)
	require.Zero(t, count, "retained controls keep their administrative task subject")
	snapshot, err = m.stateStore.Load()
	require.NoError(t, err)
	require.Equal(t, uint64(1), snapshot.Generations[task.XID])
	require.Equal(t, controls, snapshot.Revocations)
	_, err = m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	m.adminMu.Lock()
	_, err = m.cleanupPersistentFiltersLocked([]string{"ordinary-filter"})
	m.adminMu.Unlock()
	require.Error(t, err)
}

func TestAdministrativeSerializationWaitsForCompletePriorTransaction(t *testing.T) {
	m, _, _, dids := administrativeTransactionManager(t)
	first := idempotencyTask(uuid.New(), dids, time.Time{})
	second := idempotencyTask(uuid.New(), dids, time.Time{})
	store := m.stateStore.(*EncryptedStateStore)
	write := store.write
	calls := 0
	entered, release := make(chan struct{}), make(chan struct{})
	store.write = func(name string, data []byte) (securestore.Outcome, error) {
		calls++
		if calls == 3 {
			close(entered)
			<-release
		}
		return write(name, data)
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- m.ActivateTask(first) }()
	<-entered
	secondDone := make(chan error, 1)
	go func() { secondDone <- m.ActivateTask(second) }()
	require.Zero(t, m.TaskCount(), "final snapshot has not committed either candidate")
	select {
	case err := <-secondDone:
		t.Fatalf("second mutation escaped serialization: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-firstDone)
	require.NoError(t, <-secondDone)
	snapshot, err := store.Load()
	require.NoError(t, err)
	require.Len(t, snapshot.Tasks, 2)
	for _, intent := range snapshot.Intents {
		require.Equal(t, StateFinished, intent.Phase)
	}
}

func TestAdministrativeUncertainRevocationRequiresRecovery(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	revoker.commit = func([]*StateRevocation) (securestore.Outcome, error) {
		return securestore.Uncertain, errors.New("injected uncertain journal boundary")
	}
	err := m.DeactivateTask(task.XID)
	require.Error(t, err)
	require.Equal(t, securestore.Uncertain, securestore.OutcomeOf(err))
	require.Empty(t, m.GetActiveTasks())
	require.ErrorIs(t, m.DeactivateTask(task.XID), ErrAdministrativeFault)
	controls := revoker.committed[0]
	revoker.commit = nil
	m = restartAdministrativeTestManager(t, m, revoker)
	require.Equal(t, controls, revoker.committed[1])
	closed, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusDeactivated, closed.Status)
	require.NoError(t, m.ActivateTask(task))
	require.Len(t, m.registry.auditHistory[task.XID], 1)
	require.Equal(t, *closed, m.registry.auditHistory[task.XID][0])
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Greater(t, current.ActivationGeneration, closed.ActivationGeneration)
}

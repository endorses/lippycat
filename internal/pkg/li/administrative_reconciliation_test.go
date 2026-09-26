//go:build li

package li

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestAdministrativeRestoredPendingRequiresFreshActivation(t *testing.T) {
	for _, future := range []bool{false, true} {
		t.Run(fmt.Sprint(future), func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Now().Add(time.Hour).UTC())
			require.NoError(t, m.ActivateTask(task))
			snapshot := readManagerStateTest(t, m)
			if !future {
				snapshot.Tasks[0].StartTime = time.Now().Add(-time.Second).UTC()
			}
			_, err := m.stateStore.Save(snapshot)
			require.NoError(t, err)
			m = restartAdministrativeTestManager(t, m, revoker)
			require.True(t, m.pendingNeedsConfirmation(task.XID))
			require.NotContains(t, m.persistedActive, task.XID)
			m.promotePendingTasks()
			require.Empty(t, m.GetActiveTasks())
			implicit := false
			require.NoError(t, m.ModifyTask(task.XID, &TaskModification{ImplicitDeactivationAllowed: &implicit}))
			require.True(t, m.pendingNeedsConfirmation(task.XID))
			current, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			if future {
				m.registry.mu.Lock()
				m.registry.tasks[task.XID].StartTime = time.Now().Add(-time.Second).UTC()
				m.registry.mu.Unlock()
				m.promotePendingTasks()
				require.Empty(t, m.GetActiveTasks())
			}
			require.NoError(t, m.ActivateTask(current))
			require.False(t, m.pendingNeedsConfirmation(task.XID))
			fresh, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, uint64(2), fresh.ActivationGeneration)
			require.False(t, m.ReplayTaskAuthorized(task.XID, 1))
			if future {
				require.Equal(t, TaskStatusPending, fresh.Status)
			} else {
				require.Equal(t, TaskStatusActive, fresh.Status)
			}
		})
	}
}

func TestAdministrativePendingCannotOutrunUnavailableADMF(t *testing.T) {
	for _, mode := range []string{"absent", "failed", "unsupported", "blocked"} {
		t.Run(mode, func(t *testing.T) {
			m, _, _, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Now().Add(time.Hour).UTC())
			require.NoError(t, m.ActivateTask(task))
			snapshot := readManagerStateTest(t, m)
			snapshot.Tasks[0].StartTime = time.Now().Add(-time.Second).UTC()
			_, err := m.stateStore.Save(snapshot)
			require.NoError(t, err)
			cfg := m.Config()
			m.Stop()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			if mode != "absent" {
				server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						t.Errorf("read ADMF request: %v", err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if !strings.Contains(string(body), "GetAllDetailsRequest") {
						w.WriteHeader(http.StatusOK)
						return
					}
					if mode == "blocked" {
						once.Do(func() { close(entered) })
						<-release
					}
					if mode == "unsupported" {
						if _, err := io.WriteString(w, `<X1Response xmlns="http://uri.etsi.org/03221/X1/2017/10"><errorResponse><requestMessageType>GetAllDetailsRequest</requestMessageType><errorInformation><errorCode>7</errorCode><errorDescription>Unsupported operation</errorDescription></errorInformation></errorResponse></X1Response>`); err != nil {
							t.Errorf("write ADMF response: %v", err)
						}
					} else {
						w.WriteHeader(http.StatusServiceUnavailable)
					}
				})
				cfg.ADMFEndpoint = server.URL
				cfg.SyncOnStartup = true
				cfg.SyncTimeout = time.Second
			}
			cfg.LifecycleInterval = time.Millisecond
			restarted := NewManager(cfg, nil)
			t.Cleanup(restarted.Stop)
			done := make(chan error, 1)
			go func() { done <- restarted.Start() }()
			if mode == "blocked" {
				<-entered
				time.Sleep(10 * time.Millisecond)
				require.Empty(t, restarted.GetActiveTasks())
				require.True(t, restarted.pendingNeedsConfirmation(task.XID))
				close(release)
			}
			require.NoError(t, <-done)
			restarted.promotePendingTasks()
			require.Empty(t, restarted.GetActiveTasks())
			require.Zero(t, restarted.FilterCount())
		})
	}
}

func TestAdministrativeWithdrawalPlanningFailuresCloseActualCallers(t *testing.T) {
	for _, caller := range []string{"deactivate", "fail", "expiry", "radius_reject", "radius_reconcile"} {
		t.Run(caller, func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			if caller == "radius_reject" || caller == "radius_reconcile" {
				task = radiusTargetTask()
				task.DestinationIDs = dids[:1]
				require.NoError(t, m.ModifyDestination(dids[0], &Destination{DID: dids[0], Address: "mdf.example", Port: 443, X2Enabled: true, ProtocolType: "X2Only"}))
				revoker.requests = nil
				revoker.committed = nil
			}
			require.NoError(t, m.ActivateTask(task))
			current, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			before := readManagerStateTest(t, m).Revocations
			revoker.prepare = func(RevocationRequest) ([]*StateRevocation, error) {
				return nil, errors.New("injected planning rejection")
			}
			switch caller {
			case "deactivate":
				err = m.DeactivateTask(task.XID)
			case "fail":
				err = m.MarkTaskFailed(task.XID, "fault")
			case "expiry":
				m.expireAdministrativeTask(current)
				err = m.administrativeError()
			case "radius_reject":
				err = m.rejectRADIUSReplacement(task.XID, errors.New("invalid replacement"))
			case "radius_reconcile":
				replacement := cloneInterceptTask(current)
				replacement.StartTime = time.Now().Add(time.Hour).UTC()
				_, err = m.reconcileRADIUSTask(replacement)
			}
			require.Error(t, err)
			admission, ok := m.AcquireTaskAdmission(task.XID, current.ActivationGeneration)
			if ok {
				admission.Release()
			}
			require.False(t, ok)
			require.Empty(t, revoker.committed)
			require.Equal(t, before, readManagerStateTest(t, m).Revocations, "failed Prepare never invents a control")
		})
	}
}

func TestAdministrativeMalformedWithdrawalPlansRemainClosed(t *testing.T) {
	for _, mode := range []string{"oversized", "wrong_scope", "duplicate"} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fail=%v", mode, fail), func(t *testing.T) {
				m, _, revoker, dids := administrativeTransactionManager(t)
				task := idempotencyTask(uuid.New(), dids, time.Time{})
				require.NoError(t, m.ActivateTask(task))
				revoker.prepare = func(req RevocationRequest) ([]*StateRevocation, error) {
					if mode == "oversized" {
						return make([]*StateRevocation, maxStateReferences+1), nil
					}
					control := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: req.StateIncarnation, Scope: StateRevokeTask, XID: &task.XID, TaskGeneration: statePtr(uint64(1)), RevokedAt: NewStateTimestamp(time.Now())}
					if mode == "duplicate" {
						return []*StateRevocation{control, control}, nil
					}
					control.Scope = StateRevokeCall
					control.DID, control.DestinationGeneration = &dids[0], statePtr(uint64(1))
					control.CallIncarnation, control.CallGeneration = statePtr(uuid.New()), statePtr(uint64(1))
					return []*StateRevocation{control}, nil
				}
				var err error
				if fail {
					err = m.MarkTaskFailed(task.XID, "fault")
				} else {
					err = m.DeactivateTask(task.XID)
				}
				require.Error(t, err)
				require.Equal(t, securestore.NotCommitted, securestore.OutcomeOf(err))
				require.Empty(t, m.GetActiveTasks())
				require.Empty(t, revoker.committed)
				require.Empty(t, readManagerStateTest(t, m).Revocations)
			})
		}
	}
}

func TestAdministrativeConcurrentEquivalentActivationAndStopBoundary(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(fmt.Sprintf("stop=%v", stop), func(t *testing.T) {
			m, pusher, revoker, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			entered, release := make(chan struct{}), make(chan struct{})
			calls := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				calls++
				if calls == 3 {
					close(entered)
					<-release
				}
				return write(name, data)
			}
			first, second := make(chan error, 1), make(chan error, 1)
			go func() { first <- m.ActivateTask(task) }()
			<-entered
			go func() {
				if stop {
					m.Stop()
					second <- nil
				} else {
					second <- m.ActivateTask(cloneInterceptTask(task))
				}
			}()
			select {
			case err := <-second:
				t.Fatalf("operation escaped pending final commit: %v", err)
			case <-time.After(10 * time.Millisecond):
			}
			close(release)
			firstErr := <-first
			require.NoError(t, <-second)
			require.NoError(t, firstErr)
			require.Equal(t, 3, calls)
			require.Len(t, pusher.updates, len(task.Targets))
			m = restartAdministrativeTestManager(t, m, revoker)
			require.Equal(t, uint64(1), m.persistedActive[task.XID].ActivationGeneration)
			require.Empty(t, m.GetActiveTasks())
		})
	}
}

func TestAdministrativePersistentExpiryAndFailureCallbackBeforeIncompleteCleanup(t *testing.T) {
	for _, caller := range []string{"expiry", "failure"} {
		t.Run(caller, func(t *testing.T) {
			m, pusher, revoker, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			require.NoError(t, m.ActivateTask(task))
			current, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			callbacks := 0
			m.registry.onDeactivation = func(closed *InterceptTask, reason DeactivationReason) {
				callbacks++
				require.False(t, closed.IsActive())
				snapshot, err := m.stateStore.Load()
				require.NoError(t, err)
				require.NotEmpty(t, snapshot.Revocations)
				require.Equal(t, StateReserved, snapshot.Intents[len(snapshot.Intents)-1].Phase)
			}
			pusher.failNext = true
			if caller == "expiry" {
				m.expireAdministrativeTask(current)
			} else {
				require.Error(t, m.MarkTaskFailed(task.XID, "fault"))
			}
			require.Equal(t, 1, callbacks)
			require.Empty(t, m.GetActiveTasks())
			m = restartAdministrativeTestManager(t, m, revoker)
			closed, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.False(t, closed.IsActive())
			require.Empty(t, m.stateCleanup)
		})
	}
}

func TestAdministrativeLegacyZeroReactivationInterruptedRepresentation(t *testing.T) {
	for _, stage := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			task.Status = TaskStatusDeactivated
			task.DeactivatedAt = time.Now().UTC()
			snapshot := readManagerStateTest(t, m)
			snapshot.Tasks = append(snapshot.Tasks, task)
			snapshot.Generations[task.XID] = 0
			_, err := m.stateStore.Save(snapshot)
			require.NoError(t, err)
			m = restartAdministrativeTestManager(t, m, revoker)
			if stage != 0 {
				store := m.stateStore.(*EncryptedStateStore)
				write := store.write
				calls := 0
				store.write = func(name string, data []byte) (securestore.Outcome, error) {
					calls++
					if calls == stage {
						return securestore.NotCommitted, errors.New("injected")
					}
					return write(name, data)
				}
			}
			err = m.ActivateTask(task)
			require.Empty(t, revoker.requests)
			if stage == 0 {
				require.NoError(t, err)
				current, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.Equal(t, uint64(1), current.ActivationGeneration)
			} else {
				require.Error(t, err)
				m = restartAdministrativeTestManager(t, m, revoker)
				current, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				if stage == 1 {
					require.Equal(t, uint64(0), current.ActivationGeneration)
					require.Equal(t, TaskStatusDeactivated, current.Status)
				} else {
					require.Equal(t, uint64(1), current.ActivationGeneration)
					require.Equal(t, TaskStatusFailed, current.Status)
				}
			}
		})
	}
}

func TestAdministrativeInterruptedMetadataUpdateStaysUnconfirmed(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			start := time.Time{}
			if pending {
				start = time.Now().Add(time.Hour).UTC()
			}
			task := idempotencyTask(uuid.New(), dids, start)
			require.NoError(t, m.ActivateTask(task))
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			calls := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				calls++
				if calls == 2 {
					return securestore.NotCommitted, errors.New("final metadata checkpoint")
				}
				return write(name, data)
			}
			end := task.EndTime.Add(time.Hour)
			require.Error(t, m.ModifyTask(task.XID, &TaskModification{EndTime: &end}))
			require.Empty(t, revoker.requests)
			m = restartAdministrativeTestManager(t, m, revoker)
			require.Empty(t, m.GetActiveTasks())
			require.False(t, m.ReplayTaskAuthorized(task.XID, 1))
			snapshot := readManagerStateTest(t, m)
			require.Equal(t, end, snapshot.Tasks[0].EndTime)
			require.Equal(t, uint64(1), snapshot.Tasks[0].ActivationGeneration)
			if pending {
				require.True(t, m.pendingNeedsConfirmation(task.XID))
				m.promotePendingTasks()
				require.Empty(t, m.GetActiveTasks())
			} else {
				require.Contains(t, m.persistedActive, task.XID)
			}
		})
	}
}

func TestAdministrativeGroupedRemovalResumesRemainingTaskAndEndpoint(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	first := idempotencyTask(uuid.New(), dids, time.Time{})
	second := idempotencyTask(uuid.New(), dids[:1], time.Time{})
	require.NoError(t, m.ActivateTask(first))
	require.NoError(t, m.ActivateTask(second))
	calls := 0
	revoker.commit = func([]*StateRevocation) (securestore.Outcome, error) {
		calls++
		if calls == 2 {
			return securestore.Uncertain, errors.New("second task boundary")
		}
		return securestore.Committed, nil
	}
	require.Error(t, m.RemoveDestination(dids[0]))
	require.Empty(t, m.GetActiveTasks())
	snapshot := readManagerStateTest(t, m)
	require.Len(t, snapshot.Revocations, 3)
	original := snapshot.Revocations
	revoker.commit = nil
	m = restartAdministrativeTestManager(t, m, revoker)
	m = restartAdministrativeTestManager(t, m, revoker)
	for _, task := range []*InterceptTask{first, second} {
		closed, err := m.GetTaskDetails(task.XID)
		require.NoError(t, err)
		require.Equal(t, TaskStatusDeactivated, closed.Status)
		require.Equal(t, uint64(1), closed.ActivationGeneration)
	}
	_, err := m.GetDestination(dids[0])
	require.ErrorIs(t, err, ErrDestinationNotFound)
	require.Equal(t, original, readManagerStateTest(t, m).Revocations)
	require.Len(t, revoker.requests, 3, "restart never replans controls")
}

func TestAdministrativePurgeInterruptedAndCleanupIneligible(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	revoker.prepare = func(RevocationRequest) ([]*StateRevocation, error) { return nil, nil }
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	require.NoError(t, m.DeactivateTask(task.XID))
	m.stateCleanup[task.XID] = []string{fmt.Sprintf("li-%s-0", task.XID)}
	count, err := m.PurgeDeactivatedTasksWithError(0)
	require.NoError(t, err)
	require.Zero(t, count)
	delete(m.stateCleanup, task.XID)
	store := m.stateStore.(*EncryptedStateStore)
	write := store.write
	calls := 0
	store.write = func(name string, data []byte) (securestore.Outcome, error) {
		calls++
		if calls == 2 {
			return securestore.NotCommitted, errors.New("purge final checkpoint")
		}
		return write(name, data)
	}
	count, err = m.PurgeDeactivatedTasksWithError(0)
	require.Error(t, err)
	require.Zero(t, count)
	m = restartAdministrativeTestManager(t, m, revoker)
	_, err = m.GetTaskDetails(task.XID)
	require.ErrorIs(t, err, ErrTaskNotFound)
	require.Equal(t, uint64(1), m.registry.generations[task.XID])
	require.NoError(t, m.ActivateTask(task))
	m = restartAdministrativeTestManager(t, m, revoker)
	require.Equal(t, uint64(2), m.persistedActive[task.XID].ActivationGeneration, "finished historical purge cannot erase recreated identity")
}

func TestAdministrativeCommittedCleanupWarningPreservesPublication(t *testing.T) {
	for _, kind := range []string{"task", "destination"} {
		t.Run(kind, func(t *testing.T) {
			m, _, _, dids := administrativeTransactionManager(t)
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			calls := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				calls++
				out, err := write(name, data)
				if err == nil && calls == 3 {
					return securestore.Committed, errors.New("postcommit cleanup warning")
				}
				return out, err
			}
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			did := uuid.New()
			var err error
			published := false
			if kind == "task" {
				err = m.ActivateTask(task)
				require.Len(t, m.GetActiveTasks(), 1)
			} else {
				m.SetDestinationCreatedCallback(func(d *Destination) {
					published = true
					snapshot, err := m.stateStore.Load()
					require.NoError(t, err)
					found := false
					for _, saved := range snapshot.Destinations {
						if saved.DID == d.DID {
							found = true
						}
					}
					require.True(t, found)
				})
				err = m.CreateDestination(&Destination{DID: did, Address: "new.example", Port: 443})
				require.True(t, published)
			}
			require.Error(t, err)
			require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
			require.Nil(t, m.stateFault.Load())
			m = restartAdministrativeTestManager(t, m, nil)
			if kind == "task" {
				require.Contains(t, m.persistedActive, task.XID)
			} else {
				_, err = m.GetDestination(did)
				require.NoError(t, err)
			}
		})
	}
}

func TestAdministrativeUnconfirmedPendingRelevantModificationDoesNotPromote(t *testing.T) {
	m, pusher, revoker, dids := administrativeTransactionManager(t)
	task := idempotencyTask(uuid.New(), dids, time.Now().Add(time.Hour).UTC())
	require.NoError(t, m.ActivateTask(task))
	snapshot := readManagerStateTest(t, m)
	snapshot.Tasks[0].StartTime = time.Now().Add(-time.Second).UTC()
	_, err := m.stateStore.Save(snapshot)
	require.NoError(t, err)
	m = restartAdministrativeTestManager(t, m, revoker)
	pusher.reset()
	targets := []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:changed@example"}}
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{Targets: &targets}))
	require.True(t, m.pendingNeedsConfirmation(task.XID))
	m.promotePendingTasks()
	require.Empty(t, m.GetActiveTasks())
	require.Empty(t, pusher.updates)
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusPending, current.Status)
	require.Equal(t, uint64(2), current.ActivationGeneration)
	require.NoError(t, m.ActivateTask(current))
	fresh, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, uint64(3), fresh.ActivationGeneration)
	require.Equal(t, TaskStatusActive, fresh.Status)
}

func TestAdministrativeLegacyZeroReactivationRetainsHigherWatermark(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	task.Status = TaskStatusDeactivated
	task.DeactivatedAt = time.Now().UTC()
	snapshot := readManagerStateTest(t, m)
	snapshot.Tasks = append(snapshot.Tasks, task)
	snapshot.Generations[task.XID] = 7
	_, err := m.stateStore.Save(snapshot)
	require.NoError(t, err)
	m = restartAdministrativeTestManager(t, m, revoker)
	require.NoError(t, m.ActivateTask(task))
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, uint64(8), current.ActivationGeneration)
}

//go:build li

package li

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestConflictDisarmedRejectsEveryModification(t *testing.T) {
	for _, mode := range []string{"memory", "persistent", "restored"} {
		for _, reason := range []string{"expired", "empty_window", "no_common_targets", "no_confirmed_destinations", "no_common_delivery"} {
			t.Run(mode+"/"+reason, func(t *testing.T) {
				var m *Manager
				var dids []uuid.UUID
				if mode == "memory" {
					m, _, dids = newIdempotencyManager(t, "")
				} else {
					m, _, _, dids = administrativeTransactionManager(t)
				}
				task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				if reason == "no_common_delivery" {
					task.DeliveryType = DeliveryX2Only
				}
				require.NoError(t, m.ActivateTask(task))
				original, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				in := conflictSnapshot(original)
				switch reason {
				case "expired":
					in.Task.EndTime = time.Now().Add(-time.Minute)
				case "empty_window":
					in.Task.StartTime = original.EndTime.Add(time.Hour)
					in.Task.EndTime = in.Task.StartTime.Add(time.Hour)
				case "no_common_targets":
					in.Task.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:other@example"}}
				case "no_confirmed_destinations":
					in.Task.DestinationIDs = []uuid.UUID{uuid.New()}
				case "no_common_delivery":
					in.Task.DeliveryType = DeliveryX3Only
				}
				require.NoError(t, m.applySnapshotDefinition(in))
				if mode == "restored" {
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
					require.NoError(t, m.applySnapshotDefinition(in))
				}
				before, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.Equal(t, reason, before.Definition.ConflictReason)
				end := original.EndTime.Add(time.Hour)
				targets := []x1.TargetIdentity{{Type: x1.TargetTypeSIPURI, Value: "sip:alice@example"}}
				delivery := x1.DeliveryX2andX3
				implicit := true
				for _, mod := range []*x1.TaskModification{
					{EndTime: &end}, {}, {Targets: &targets, DestinationIDs: &dids, DeliveryType: &delivery, EndTime: &end, ImplicitDeactivationAllowed: &implicit},
				} {
					require.ErrorIs(t, m.ModifyTaskX1(task.XID, mod), x1.ErrModifyNotAllowed)
					after, err := m.GetTaskDetails(task.XID)
					require.NoError(t, err)
					require.Equal(t, before, after)
					require.Empty(t, m.filters.GetFiltersForXID(task.XID))
					_, admitted := m.AcquireTaskAdmission(task.XID, before.ActivationGeneration)
					require.False(t, admitted)
					require.False(t, m.ReplayTaskAuthorized(task.XID, original.ActivationGeneration))
					m.conflictReportMu.Lock()
					report := m.conflictReports[task.XID]
					m.conflictReportMu.Unlock()
					require.NotNil(t, report)
				}
				require.ErrorIs(t, m.ModifyTask(task.XID, nil), ErrModifyNotAllowed)
				require.ErrorIs(t, m.promoteTaskDefinitionLocked(original), ErrModifyNotAllowed)
				if mode != "memory" {
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
					require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(original)))
					after, err := m.GetTaskDetails(task.XID)
					require.NoError(t, err)
					require.True(t, after.Definition.ConflictDisarmed)
					require.Empty(t, m.filters.GetFiltersForXID(task.XID))
					require.ErrorIs(t, m.ModifyTaskX1(task.XID, &x1.TaskModification{EndTime: &end}), x1.ErrModifyNotAllowed)
				}
			})
		}
	}
}

func TestRetainedReactivationRequiresCompleteDefinition(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("persistent=%t/strict=%t", persistent, strict), func(t *testing.T) {
				var m *Manager
				var dids []uuid.UUID
				if persistent {
					m, _, _, dids = administrativeTransactionManager(t)
				} else {
					m, _, dids = newIdempotencyManager(t, "")
				}
				m.config.ADMFCompleteTaskContract = strict
				task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				require.NoError(t, m.ActivateTask(task))
				active, err := m.GetTaskDetailsX1(task.XID)
				require.NoError(t, err)
				require.NoError(t, m.DeactivateTask(task.XID))
				tombstone, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				for _, presence := range []*x1.TaskDefinitionPresence{{}, {Mediation: true, Start: true}, {Mediation: true, End: true}, {Start: true, End: true}} {
					replacement := *active
					replacement.DefinitionPresence = presence
					require.ErrorIs(t, m.ActivateTaskX1(&replacement), x1.ErrInvalidTask)
					after, err := m.GetTaskDetails(task.XID)
					require.NoError(t, err)
					require.Equal(t, tombstone, after)
					require.Empty(t, m.filters.GetFiltersForXID(task.XID))
					require.Equal(t, tombstone.ActivationGeneration, m.registry.generations[task.XID])
				}
				// A known open end and omitted optional implicit flag are complete.
				active.EndTime = time.Time{}
				active.ImplicitDeactivationAllowed = false
				active.DefinitionPresence = &x1.TaskDefinitionPresence{Mediation: true, Start: true, End: true}
				require.NoError(t, m.ActivateTaskX1(active))
				after, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.Greater(t, after.ActivationGeneration, tombstone.ActivationGeneration)
				require.True(t, after.Definition.Completeness.Complete())
				// Equivalent active retries retain their existing read-only behavior even
				// when the client omits the presence information on the retry.
				active.DefinitionPresence = &x1.TaskDefinitionPresence{}
				require.NoError(t, m.ActivateTaskX1(active))
				retried, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.Equal(t, after, retried)
			})
		}
	}
}

func TestConflictRecoveryLifecycleRetainsIdentity(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		for _, changedIdentity := range []bool{false, true} {
			t.Run(fmt.Sprintf("persistent=%t/changedIdentity=%t", persistent, changedIdentity), func(t *testing.T) {
				var m *Manager
				var dids []uuid.UUID
				if persistent {
					m, _, _, dids = administrativeTransactionManager(t)
				} else {
					m, _, dids = newIdempotencyManager(t, "")
				}
				initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				require.NoError(t, m.ActivateTask(initial))
				original, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				in := conflictSnapshot(original)
				in.Task.StartTime = time.Now().Add(time.Hour).UTC()
				if changedIdentity {
					in.Task.Targets = in.Task.Targets[:1]
					in.Task.DeliveryType = DeliveryX2Only
				}
				require.NoError(t, m.applySnapshotDefinition(in))
				narrowed, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				require.NoError(t, m.DeactivateTask(initial.XID))
				m.conflictReportMu.Lock()
				report := m.conflictReports[initial.XID]
				m.conflictReportMu.Unlock()
				require.Nil(t, report)
				if persistent {
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
				}
				tombstone, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				replacement := cloneInterceptTask(original)
				replacement.StartTime = time.Now().Add(-time.Minute).UTC()
				replacement.DestinationIDs = dids[1:]
				replacement.Definition = authoritativeDefinition(replacement)
				if changedIdentity {
					require.ErrorIs(t, m.ActivateTask(replacement), ErrReactivationIdentityConflict)
					require.Equal(t, tombstone, mustTask(t, m.registry, initial.XID))
					replacement.XID = uuid.New()
				}
				require.NoError(t, m.ActivateTask(replacement))
				recovered, err := m.GetTaskDetails(replacement.XID)
				require.NoError(t, err)
				require.Equal(t, TaskStatusActive, recovered.Status)
				require.Equal(t, replacement.StartTime, recovered.StartTime)
				require.Equal(t, replacement.DestinationIDs, recovered.DestinationIDs)
				if !changedIdentity {
					require.Greater(t, recovered.ActivationGeneration, narrowed.ActivationGeneration)
				} else {
					require.Equal(t, tombstone, mustTask(t, m.registry, initial.XID))
				}
				require.False(t, m.ReplayTaskAuthorized(initial.XID, original.ActivationGeneration))
				require.False(t, m.ReplayTaskAuthorized(initial.XID, narrowed.ActivationGeneration))
				if persistent {
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
					require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(recovered)))
					require.True(t, m.ReplayTaskAuthorized(replacement.XID, recovered.ActivationGeneration))
					require.False(t, m.ReplayTaskAuthorized(initial.XID, original.ActivationGeneration))
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
					require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(recovered)))
					require.True(t, m.ReplayTaskAuthorized(replacement.XID, recovered.ActivationGeneration))
				}
			})
		}
	}
}

func TestNonemptyConflictRenewalRetainsEffectiveScope(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprint(persistent), func(t *testing.T) {
			var m *Manager
			var dids []uuid.UUID
			if persistent {
				m, _, _, dids = administrativeTransactionManager(t)
			} else {
				m, _, dids = newIdempotencyManager(t, "")
			}
			initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
			require.NoError(t, m.ActivateTask(initial))
			original, err := m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			in := conflictSnapshot(original)
			in.Task.Targets = in.Task.Targets[:1]
			in.Task.DestinationIDs = in.Task.DestinationIDs[:1]
			in.Task.DeliveryType = DeliveryX2Only
			in.Task.EndTime = original.EndTime.Add(-time.Hour)
			require.NoError(t, m.applySnapshotDefinition(in))
			narrowed, err := m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			// Omitted window retains both the cutoff and the implicit expiry policy.
			require.ErrorIs(t, m.ModifyTaskX1(initial.XID, &x1.TaskModification{}), x1.ErrModifyNotAllowed)
			// An explicit same-value field can resolve the conflict.
			delivery := x1.DeliveryX2Only
			require.NoError(t, m.ModifyTaskX1(initial.XID, &x1.TaskModification{DeliveryType: &delivery}))
			current, err := m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			require.True(t, equivalentTaskDefinition(narrowed, current))
			end := narrowed.EndTime.Add(time.Minute)
			require.NoError(t, m.ModifyTaskX1(initial.XID, &x1.TaskModification{EndTime: &end}))
			current, err = m.GetTaskDetails(initial.XID)
			require.NoError(t, err)
			require.Equal(t, narrowed.Targets, current.Targets)
			require.Equal(t, narrowed.DestinationIDs, current.DestinationIDs)
			require.Equal(t, narrowed.DeliveryType, current.DeliveryType)
			require.Equal(t, narrowed.StartTime, current.StartTime)
			require.Equal(t, narrowed.ImplicitDeactivationAllowed, current.ImplicitDeactivationAllowed)
			require.False(t, m.ReplayTaskAuthorized(initial.XID, original.ActivationGeneration))
		})
	}
}

func TestConflictRecoveryInterruptedLifecycleRemainsClosed(t *testing.T) {
	for _, operation := range []string{"deactivate", "reactivate"} {
		for _, stage := range []int{1, 2, 3} {
			t.Run(fmt.Sprintf("%s/checkpoint=%d", operation, stage), func(t *testing.T) {
				m, _, revoker, dids := administrativeTransactionManager(t)
				task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				require.NoError(t, m.ActivateTask(task))
				original, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				in := conflictSnapshot(original)
				in.Task.Targets = nil
				require.NoError(t, m.applySnapshotDefinition(in))
				disarmed, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				if operation == "reactivate" {
					require.NoError(t, m.DeactivateTask(task.XID))
				}
				store := m.stateStore.(*EncryptedStateStore)
				write := store.write
				calls := 0
				store.write = func(name string, data []byte) (securestore.Outcome, error) {
					calls++
					if calls == stage {
						return securestore.NotCommitted, errors.New("injected lifecycle checkpoint failure")
					}
					return write(name, data)
				}
				if operation == "deactivate" {
					err = m.DeactivateTask(task.XID)
				} else {
					err = m.ActivateTask(task)
				}
				require.Error(t, err)
				consumed := m.registry.generations[task.XID]
				_, admitted := m.AcquireTaskAdmission(task.XID, original.ActivationGeneration)
				require.False(t, admitted)
				require.False(t, m.ReplayTaskAuthorized(task.XID, original.ActivationGeneration))
				// Restart finishes durable withdrawal, or abandons interrupted activation.
				m = restartAdministrativeTestManager(t, m, revoker)
				restored, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.NotEqual(t, TaskStatusActive, restored.Status)
				require.NotEqual(t, TaskStatusPending, restored.Status)
				require.Empty(t, m.filters.GetFiltersForXID(task.XID))
				require.GreaterOrEqual(t, m.registry.generations[task.XID], consumed)
				require.False(t, m.ReplayTaskAuthorized(task.XID, original.ActivationGeneration))
				for _, intent := range readManagerStateTest(t, m).Intents {
					require.Equal(t, StateFinished, intent.Phase)
				}
				require.NoError(t, m.DeactivateTask(task.XID))
				require.NoError(t, m.ActivateTask(task))
				recovered, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.Greater(t, recovered.ActivationGeneration, consumed)
				require.Greater(t, recovered.ActivationGeneration, disarmed.ActivationGeneration)
				require.False(t, m.ReplayTaskAuthorized(task.XID, original.ActivationGeneration))
			})
		}
	}
}

func TestCompatibilityFirstActivationRemainsIncompleteButReactivationDoesNot(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprint(persistent), func(t *testing.T) {
			var m *Manager
			var dids []uuid.UUID
			if persistent {
				m, _, _, dids = administrativeTransactionManager(t)
			} else {
				m, _, dids = newIdempotencyManager(t, "")
			}
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			task.Definition = TaskDefinitionState{Source: DefinitionPush}
			require.NoError(t, m.ActivateTask(task))
			active, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.False(t, active.Definition.Completeness.Complete())
			require.Equal(t, TaskStatusActive, active.Status)
			require.NoError(t, m.ActivateTask(task))
			retried, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, active, retried)
			require.NoError(t, m.DeactivateTask(task.XID))
			require.ErrorIs(t, m.ActivateTask(task), ErrInvalidTask)
			after, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusDeactivated, after.Status)
			require.Empty(t, m.filters.GetFiltersForXID(task.XID))
		})
	}
}

func TestElapsedTerminalTaskRetainsRecoveryContractAcrossRestart(t *testing.T) {
	for _, status := range []TaskStatus{TaskStatusDeactivated, TaskStatusFailed} {
		t.Run(status.String(), func(t *testing.T) {
			m, _, _, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Now().Add(-2*time.Hour).UTC())
			require.NoError(t, m.ActivateTask(task))
			if status == TaskStatusFailed {
				require.NoError(t, m.MarkTaskFailed(task.XID, "synthetic terminal failure"))
			} else {
				require.NoError(t, m.DeactivateTask(task.XID))
			}
			// Model the old authorization cutoff passing while the owner is
			// stopped, without sleeping on wall-clock expiry in a regression.
			state := readManagerStateTest(t, m)
			require.Len(t, state.Tasks, 1)
			state.Tasks[0].EndTime = time.Now().Add(-time.Hour).UTC()
			_, err := m.stateStore.Save(state)
			require.NoError(t, err)
			for range 2 {
				m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
				retained, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err, "an elapsed cutoff cannot hide a terminal tombstone")
				require.Equal(t, status, retained.Status)
				require.NotContains(t, m.persistedActive, task.XID)
				require.NotContains(t, m.persistenceCandidates, task.XID)
				complete := cloneInterceptTask(task)
				complete.Definition = authoritativeDefinition(complete)
				incomplete := cloneInterceptTask(complete)
				incomplete.Definition.Completeness = DefinitionCompleteness{}
				changed := cloneInterceptTask(complete)
				changed.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:replacement@example.invalid"}}
				if status == TaskStatusFailed {
					require.ErrorIs(t, m.ActivateTask(incomplete), ErrTaskDefinitionConflict)
					require.ErrorIs(t, m.ActivateTask(changed), ErrTaskDefinitionConflict)
				} else {
					require.ErrorIs(t, m.ActivateTask(incomplete), ErrInvalidTask)
					require.ErrorIs(t, m.ActivateTask(changed), ErrReactivationIdentityConflict)
				}
				require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(complete)))
				require.Equal(t, retained, mustTask(t, m.registry, task.XID))
				require.Empty(t, m.filters.GetFiltersForXID(task.XID))
				require.False(t, m.ReplayTaskAuthorized(task.XID, retained.ActivationGeneration))
			}
			retained := mustTask(t, m.registry, task.XID)
			require.NoError(t, m.DeactivateTask(task.XID))
			replacement := cloneInterceptTask(task)
			replacement.Definition = authoritativeDefinition(replacement)
			require.NoError(t, m.ActivateTask(replacement))
			fresh := mustTask(t, m.registry, task.XID)
			require.Equal(t, TaskStatusActive, fresh.Status)
			require.Greater(t, fresh.ActivationGeneration, retained.ActivationGeneration)
			require.False(t, m.ReplayTaskAuthorized(task.XID, retained.ActivationGeneration))
		})
	}
}

// The report worker is deliberately not started: drive its acknowledgment and
// retry state directly so request rejection can be checked without timer races.
func TestNarrowedConflictRejectsEmptyModificationWithoutSideEffects(t *testing.T) {
	for _, mode := range []string{"memory", "persistent", "restored"} {
		for _, status := range []TaskStatus{TaskStatusActive, TaskStatusPending} {
			for _, acknowledged := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/acknowledged=%t", mode, status, acknowledged), func(t *testing.T) {
					var m *Manager
					var pusher *mockFilterPusher
					var dids []uuid.UUID
					var revoker *administrativeTestRevoker
					if mode == "memory" {
						m, pusher, dids = newIdempotencyManager(t, "")
					} else {
						m, pusher, revoker, dids = administrativeTransactionManager(t)
					}
					initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
					require.NoError(t, m.ActivateTask(initial))
					original := mustTask(t, m.registry, initial.XID)
					in := conflictSnapshot(original)
					in.Task.Targets = in.Task.Targets[:1]
					in.Task.DestinationIDs = in.Task.DestinationIDs[:1]
					in.Task.DeliveryType = DeliveryX2Only
					if status == TaskStatusPending {
						in.Task.StartTime = time.Now().Add(time.Hour).UTC()
					}
					if mode == "restored" {
						m = restartAdministrativeTestManager(t, m, revoker)
					}
					require.NoError(t, m.applySnapshotDefinition(in))
					before := mustTask(t, m.registry, initial.XID)
					require.Equal(t, status, before.Status)
					require.True(t, before.Definition.Conflict)
					require.False(t, before.Definition.ConflictDisarmed)
					filters := m.filters.GetFiltersForXID(initial.XID)
					report := m.conflictReports[initial.XID]
					require.NotNil(t, report)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					report.cancel = cancel
					report.acknowledged = acknowledged
					report.failureLogged = true
					report.deferRetry(time.Now())
					report.deferRetry(report.retryAt)
					retryAt, retryDelay := report.retryAt, report.retryDelay
					reportTask := cloneInterceptTask(report.task)
					callbacks := 0
					m.SetTaskModifiedCallback(func(*InterceptTask) { callbacks++ })
					m.SetTaskConflictCallback(func(*InterceptTask) error { callbacks++; return nil })
					m.SetCommittedTaskCallback(func(*InterceptTask) { callbacks++ })
					pusher.reset()
					writes := 0
					var persisted *StateSnapshot
					if mode != "memory" {
						persisted = readManagerStateTest(t, m)
						revoker.requests, revoker.committed = nil, nil
						store := m.stateStore.(*EncryptedStateStore)
						write := store.write
						store.write = func(name string, data []byte) (securestore.Outcome, error) {
							writes++
							return write(name, data)
						}
					}
					for _, request := range []string{"direct", "metadata_only", "x1"} {
						switch request {
						case "direct":
							require.ErrorIs(t, m.ModifyTask(initial.XID, &TaskModification{}), ErrModifyNotAllowed)
						case "metadata_only":
							require.ErrorIs(t, m.ModifyTask(initial.XID, &TaskModification{definition: &TaskDefinitionState{Source: DefinitionPush}}), ErrModifyNotAllowed)
						case "x1":
							require.ErrorIs(t, m.ModifyTaskX1(initial.XID, &x1.TaskModification{}), x1.ErrModifyNotAllowed)
						}
						require.Equal(t, before, mustTask(t, m.registry, initial.XID), request)
						require.Equal(t, filters, m.filters.GetFiltersForXID(initial.XID), request)
						for generation, expected := range map[uint64]bool{original.ActivationGeneration: false, before.ActivationGeneration: status == TaskStatusActive} {
							admission, admitted := m.AcquireTaskAdmission(initial.XID, generation)
							admission.Release()
							require.Equal(t, expected, admitted, request)
							require.False(t, m.ReplayTaskAuthorized(initial.XID, generation), request)
						}
						require.Same(t, report, m.conflictReports[initial.XID], request)
						require.Equal(t, reportTask, report.task, request)
						require.Equal(t, acknowledged, report.acknowledged, request)
						require.Equal(t, retryAt, report.retryAt, request)
						require.Equal(t, retryDelay, report.retryDelay, request)
						require.True(t, report.failureLogged, request)
						require.NoError(t, ctx.Err(), request)
					}
					require.ErrorIs(t, m.ModifyTask(initial.XID, nil), ErrInvalidTask)
					require.Equal(t, before, mustTask(t, m.registry, initial.XID))
					require.Zero(t, callbacks)
					require.Zero(t, writes)
					require.Empty(t, pusher.updates)
					require.Empty(t, pusher.deletes)
					if mode != "memory" {
						require.Empty(t, revoker.requests)
						require.Empty(t, revoker.committed)
						require.Equal(t, persisted, readManagerStateTest(t, m))
						m = restartAdministrativeTestManager(t, m, revoker)
						retained := readManagerStateTest(t, m)
						require.Len(t, retained.Tasks, 1)
						require.True(t, retained.Tasks[0].Definition.Conflict)
						require.True(t, equivalentTaskDefinition(before, retained.Tasks[0]))
						require.Equal(t, before.ActivationGeneration, retained.Tasks[0].ActivationGeneration)
						// Restoration alone does not arm historical tasks or restore
						// process-local reporting; reconciliation starts a new episode.
						require.Empty(t, m.conflictReports)
						require.NoError(t, m.applySnapshotDefinition(in))
						restored := mustTask(t, m.registry, initial.XID)
						require.Equal(t, status, restored.Status)
						require.True(t, restored.Definition.Conflict)
						require.True(t, equivalentTaskDefinition(before, restored))
						restoredReport := m.conflictReports[initial.XID]
						require.NotNil(t, restoredReport)
						require.NotSame(t, report, restoredReport)
						require.False(t, restoredReport.acknowledged)
						require.Zero(t, restoredReport.retryDelay)
						require.True(t, restoredReport.retryAt.IsZero())
					}
				})
			}
		}
	}
}

func TestNarrowedConflictExplicitModificationPresence(t *testing.T) {
	cases := []struct {
		name    string
		modify  func(*InterceptTask) *TaskModification
		invalid bool
	}{
		{name: "same_targets", modify: func(task *InterceptTask) *TaskModification { return &TaskModification{Targets: &task.Targets} }},
		{name: "same_destinations", modify: func(task *InterceptTask) *TaskModification {
			return &TaskModification{DestinationIDs: &task.DestinationIDs}
		}},
		{name: "same_delivery", modify: func(task *InterceptTask) *TaskModification {
			return &TaskModification{DeliveryType: &task.DeliveryType}
		}},
		{name: "same_end", modify: func(task *InterceptTask) *TaskModification { return &TaskModification{EndTime: &task.EndTime} }},
		{name: "same_implicit", modify: func(task *InterceptTask) *TaskModification {
			return &TaskModification{ImplicitDeactivationAllowed: &task.ImplicitDeactivationAllowed}
		}},
		{name: "renew_end", modify: func(task *InterceptTask) *TaskModification {
			end := task.EndTime.Add(time.Hour)
			return &TaskModification{EndTime: &end}
		}},
		{name: "false_implicit", modify: func(*InterceptTask) *TaskModification {
			value := false
			return &TaskModification{ImplicitDeactivationAllowed: &value}
		}},
		{name: "open_end", modify: func(*InterceptTask) *TaskModification { return &TaskModification{EndTime: new(time.Time)} }},
		{name: "empty_targets", invalid: true, modify: func(*InterceptTask) *TaskModification { return &TaskModification{Targets: &[]TargetIdentity{}} }},
		{name: "empty_destinations", invalid: true, modify: func(*InterceptTask) *TaskModification { return &TaskModification{DestinationIDs: &[]uuid.UUID{}} }},
		{name: "invalid_delivery", invalid: true, modify: func(*InterceptTask) *TaskModification { return &TaskModification{DeliveryType: new(DeliveryType)} }},
		{name: "end_before_start", invalid: true, modify: func(task *InterceptTask) *TaskModification {
			end := task.StartTime.Add(-time.Second)
			return &TaskModification{EndTime: &end}
		}},
	}
	for _, persistent := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("persistent=%t/%s", persistent, tc.name), func(t *testing.T) {
				var m *Manager
				var dids []uuid.UUID
				if persistent {
					m, _, _, dids = administrativeTransactionManager(t)
				} else {
					m, _, dids = newIdempotencyManager(t, "")
				}
				initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				require.NoError(t, m.ActivateTask(initial))
				in := conflictSnapshot(mustTask(t, m.registry, initial.XID))
				in.Task.Targets = in.Task.Targets[:1]
				in.Task.DestinationIDs = in.Task.DestinationIDs[:1]
				in.Task.DeliveryType = DeliveryX2Only
				require.NoError(t, m.applySnapshotDefinition(in))
				before := mustTask(t, m.registry, initial.XID)
				mod := tc.modify(cloneInterceptTask(before))
				err := m.ModifyTask(initial.XID, mod)
				after := mustTask(t, m.registry, initial.XID)
				if tc.invalid {
					require.ErrorIs(t, err, ErrInvalidTask)
					require.Equal(t, before, after)
					require.NotNil(t, m.conflictReports[initial.XID])
					return
				}
				require.NoError(t, err)
				require.False(t, after.Definition.Conflict)
				require.Nil(t, m.conflictReports[initial.XID])
				require.Greater(t, after.ActivationGeneration, before.ActivationGeneration)
				require.Equal(t, before.Targets, after.Targets)
				require.Equal(t, before.DestinationIDs, after.DestinationIDs)
				require.Equal(t, before.DeliveryType, after.DeliveryType)
				require.Equal(t, before.StartTime, after.StartTime)
				if mod.EndTime != nil {
					require.Equal(t, *mod.EndTime, after.EndTime)
				} else {
					require.Equal(t, before.EndTime, after.EndTime)
				}
				if mod.ImplicitDeactivationAllowed != nil {
					require.Equal(t, *mod.ImplicitDeactivationAllowed, after.ImplicitDeactivationAllowed)
				} else {
					require.Equal(t, before.ImplicitDeactivationAllowed, after.ImplicitDeactivationAllowed)
				}
			})
		}
	}
}

func TestEmptyModificationPreservesNonconflictingAndRADIUSBehavior(t *testing.T) {
	for _, radiusTask := range []bool{false, true} {
		t.Run(fmt.Sprintf("radius=%t", radiusTask), func(t *testing.T) {
			m, _, dids := newIdempotencyManager(t, "")
			task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
			if radiusTask {
				task = radiusTargetTask()
				require.NoError(t, m.CreateDestination(&Destination{DID: task.DestinationIDs[0], Address: "mdf.example", Port: 5001, ProtocolType: "X2Only", X2Enabled: true}))
			}
			require.NoError(t, m.ActivateTask(task))
			before := mustTask(t, m.registry, task.XID)
			require.ErrorIs(t, m.ModifyTask(task.XID, nil), ErrInvalidTask)
			require.Equal(t, before, mustTask(t, m.registry, task.XID))
			require.NoError(t, m.ModifyTask(task.XID, &TaskModification{}))
			require.Equal(t, before, mustTask(t, m.registry, task.XID))
			require.NoError(t, m.ModifyTaskX1(task.XID, &x1.TaskModification{}))
			require.Equal(t, before, mustTask(t, m.registry, task.XID))
		})
	}
}

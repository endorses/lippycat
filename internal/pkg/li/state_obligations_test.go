//go:build li

package li

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestStateObligationCleanupOwnershipBeforeRestoreEffects(t *testing.T) {
	for _, place := range []string{"root", "intent"} {
		t.Run(place, func(t *testing.T) {
			for _, id := range []string{"ordinary-filter", "li-nothexzz-0", "li-" + uuid.NewString() + "-0"} {
				t.Run(id, func(t *testing.T) {
					store, path, keys := openInitializedState(t)
					snapshot, err := store.Load()
					require.NoError(t, err)
					xid := snapshot.Tasks[0].XID
					if place == "root" {
						snapshot.CleanupNeeded[xid] = []string{id}
					} else {
						snapshot.Intents = []*StateIntent{{OperationID: uuid.New(), Kind: StateCleanup, StateIncarnation: snapshot.Incarnation, XID: &xid, Phase: StateReserved, CleanupFilterIDs: []string{id}, RevocationIDs: []uuid.UUID{}}}
					}
					require.ErrorIs(t, ValidateStateSnapshot(snapshot), ErrStateSnapshot)
					raw, err := json.Marshal(snapshot)
					require.NoError(t, err)
					sealed, err := store.writer.Seal(securestore.AdministrativeState, securestore.Binding{Store: [16]byte(snapshot.Incarnation), Object: stateSnapshotObject}, raw)
					require.NoError(t, err)
					_, err = store.write(store.name, sealed)
					require.NoError(t, err)
					require.NoError(t, store.Close())
					filters := newStubFilterStore(id, "ordinary-filter")
					m := NewManager(ManagerConfig{Enabled: true, StateFile: path, StateKeys: keys, FilterPusher: filters}, nil)
					t.Cleanup(m.Stop)
					require.ErrorIs(t, m.restorePersistedState(), ErrStateSnapshot)
					require.True(t, filters.has(id))
					require.True(t, filters.has("ordinary-filter"))
					require.Zero(t, m.TaskCount())
				})
			}
		})
	}
	s := emptyStateFixture()
	xid := uuid.New()
	s.CleanupNeeded[xid] = []string{"li-" + xid.String() + "-0", "li-" + xid.String()[:8] + "-legacy"}
	require.NoError(t, ValidateStateSnapshot(s))
}

func TestStateObligationKindAndScopeLinksMatchLivePlans(t *testing.T) {
	revoking := map[StateIntentKind]bool{StateTaskModify: true, StateTaskDeactivate: true, StateTaskExpire: true, StateTaskFail: true, StateDestinationModify: true, StateDestinationRemove: true}
	kinds := []StateIntentKind{StateTaskActivate, StateTaskReactivate, StateTaskPromote, StateTaskConfirm, StateTaskModify, StateTaskUpdate, StateTaskDeactivate, StateTaskExpire, StateTaskFail, StateDestinationCreate, StateDestinationModify, StateDestinationUpdate, StateDestinationRemove, StatePurge}
	for _, kind := range kinds {
		for _, scope := range []StateRevocationScope{StateRevokeTask, StateRevokeDestination, StateRevokeCall} {
			t.Run(string(kind)+"/"+string(scope), func(t *testing.T) {
				s, i := stateIntentFixture(t, kind)
				xid := s.Tasks[0].XID
				did := s.Destinations[0].DID
				control := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: s.Incarnation, Scope: scope, RevokedAt: NewStateTimestamp(s.WrittenAt)}
				if scope != StateRevokeDestination {
					control.XID = statePtr(xid)
					control.TaskGeneration = statePtr(uint64(3))
				}
				if scope != StateRevokeTask {
					control.DID = statePtr(did)
					d := s.Destinations[0]
					control.DestinationGeneration = statePtr(DestinationDeliveryGeneration(&Destination{DID: d.DID, Address: d.Address, Port: d.Port, X2Enabled: d.X2Enabled, X3Enabled: d.X3Enabled, ProtocolType: d.ProtocolType, CreatedAt: d.CreatedAt, DeliveryRevision: d.DeliveryRevision}))
				}
				if scope == StateRevokeCall {
					control.CallIncarnation = statePtr(uuid.New())
					control.CallGeneration = statePtr(uint64(1))
				}
				s.Revocations = []*StateRevocation{control}
				i.RevocationIDs = []uuid.UUID{control.ControlID}
				allowed := revoking[kind] && ((i.XID != nil && scope == StateRevokeTask) || (i.DID != nil && scope == StateRevokeDestination))
				encoded, err := MarshalStateSnapshot(s)
				if allowed {
					require.NoError(t, err)
					_, err = UnmarshalStateSnapshot(encoded)
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, ErrStateSnapshot)
					raw, err := json.Marshal(s)
					require.NoError(t, err)
					_, err = UnmarshalStateSnapshot(raw)
					require.ErrorIs(t, err, ErrStateSnapshot)
				}
			})
		}
	}
}

func destinationObligationFixture(kind StateIntentKind, phase StateIntentPhase, revision uint64) (*StateSnapshot, *StateIntent, *StateRevocation) {
	s := emptyStateFixture()
	d := &Destination{DID: uuid.New(), Address: "old.example", Port: 443, X2Enabled: true, X3Enabled: true, CreatedAt: s.WrittenAt, DeliveryRevision: revision}
	s.Destinations = []*StateDestination{stateDestination(d)}
	i := &StateIntent{OperationID: uuid.New(), Kind: kind, StateIncarnation: s.Incarnation, DID: &d.DID, PreviousGeneration: revision, Phase: phase, CleanupFilterIDs: []string{}, RevocationIDs: []uuid.UUID{}}
	if kind == StateDestinationModify {
		candidate := *d
		candidate.Address = "new.example"
		candidate.DeliveryRevision++
		i.CandidateDestination, i.ReservedGeneration = stateDestination(&candidate), candidate.DeliveryRevision
	}
	c := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: s.Incarnation, Scope: StateRevokeDestination, DID: &d.DID, DestinationGeneration: statePtr(DestinationDeliveryGeneration(d)), RevokedAt: NewStateTimestamp(s.WrittenAt)}
	i.RevocationIDs = []uuid.UUID{c.ControlID}
	s.Intents, s.Revocations = []*StateIntent{i}, []*StateRevocation{c}
	return s, i, c
}

func TestStateObligationUnfinishedDestinationControlsBindPriorIdentity(t *testing.T) {
	for _, kind := range []StateIntentKind{StateDestinationModify, StateDestinationRemove} {
		for _, phase := range []StateIntentPhase{StateReserved, StateRevocationCommitted, StatePolicyCommitted} {
			for _, revision := range []uint64{0, 5} {
				for _, mode := range []string{"valid", "missing_root", "wrong_root", "stale_revision", "wrong_hash", "new_incarnation", "changed_endpoint"} {
					t.Run(fmt.Sprintf("%s/%s/%d/%s", kind, phase, revision, mode), func(t *testing.T) {
						s, _, control := destinationObligationFixture(kind, phase, revision)
						switch mode {
						case "missing_root":
							s.Destinations = []*StateDestination{}
						case "wrong_root":
							s.Destinations[0].DID = uuid.New()
						case "stale_revision":
							s.Destinations[0].DeliveryRevision++
						case "wrong_hash":
							*control.DestinationGeneration = (*control.DestinationGeneration % 100) + 1
						case "new_incarnation":
							s.Destinations[0].CreatedAt = s.WrittenAt.Add(time.Second)
						case "changed_endpoint":
							s.Destinations[0].Address = "different.example"
						}
						raw, err := json.Marshal(s)
						require.NoError(t, err)
						_, decodeErr := UnmarshalStateSnapshot(raw)
						_, saveErr := MarshalStateSnapshot(s)
						if mode == "valid" {
							require.NoError(t, decodeErr)
							require.NoError(t, saveErr)
						} else {
							require.ErrorIs(t, decodeErr, ErrStateSnapshot)
							require.ErrorIs(t, saveErr, ErrStateSnapshot)
						}
					})
				}
			}
		}
	}
}

func TestStateObligationDestinationBindingBeforeRecoveryAndHistoricalInertness(t *testing.T) {
	for _, kind := range []StateIntentKind{StateDestinationModify, StateDestinationRemove} {
		for _, mode := range []string{"unfinished_wrong_hash", "finished_absent", "finished_recreated"} {
			t.Run(string(kind)+"/"+mode, func(t *testing.T) {
				store, path, keys := openInitializedState(t)
				s, intent, control := destinationObligationFixture(kind, StateReserved, 0)
				s.Incarnation = uuid.UUID(store.StoreID())
				intent.StateIncarnation, control.StateIncarnation = s.Incarnation, s.Incarnation
				if mode == "unfinished_wrong_hash" {
					*control.DestinationGeneration = (*control.DestinationGeneration % 100) + 1
				} else {
					intent.Phase = StateFinished
					if mode == "finished_absent" {
						s.Destinations = []*StateDestination{}
					} else {
						s.Destinations[0].CreatedAt = s.WrittenAt.Add(time.Second)
						s.Destinations[0].Address = "recreated.example"
						s.Destinations[0].DeliveryRevision = 42
					}
					require.NoError(t, ValidateStateSnapshot(s))
				}
				raw, err := json.Marshal(s)
				require.NoError(t, err)
				sealed, err := store.writer.Seal(securestore.AdministrativeState, securestore.Binding{Store: [16]byte(s.Incarnation), Object: stateSnapshotObject}, raw)
				require.NoError(t, err)
				_, err = store.write(store.name, sealed)
				require.NoError(t, err)
				require.NoError(t, store.Close())
				revoker := &administrativeTestRevoker{}
				filters := newStubFilterStore("ordinary-filter")
				m := NewManager(ManagerConfig{Enabled: true, StateFile: path, StateKeys: keys, FilterPusher: filters}, nil)
				t.Cleanup(m.Stop)
				require.NoError(t, m.SetDurableRevoker(revoker))
				err = m.restorePersistedState()
				if mode == "unfinished_wrong_hash" {
					require.ErrorIs(t, err, ErrStateSnapshot)
					require.Empty(t, m.ListDestinations())
				} else {
					require.NoError(t, err)
					require.Len(t, m.ListDestinations(), len(s.Destinations))
					if mode == "finished_recreated" {
						d, err := m.GetDestination(*intent.DID)
						require.NoError(t, err)
						require.Equal(t, "recreated.example", d.Address)
						require.Equal(t, uint64(42), d.DeliveryRevision)
					}
				}
				require.Empty(t, revoker.requests)
				require.Empty(t, revoker.committed, "invalid or finished historical controls cannot cause recovery effects")
				require.True(t, filters.has("ordinary-filter"))
			})
		}
	}
}

func TestStateObligationPurgeExactRetainedIdentity(t *testing.T) {
	for name, change := range map[string]func(*StateSnapshot, *StateIntent){
		"destination": func(s *StateSnapshot, i *StateIntent) { i.XID = nil; i.DID = statePtr(s.Destinations[0].DID) },
		"active":      func(s *StateSnapshot, i *StateIntent) { s.Tasks[0].Status = TaskStatusActive },
		"pending":     func(s *StateSnapshot, i *StateIntent) { s.Tasks[0].Status = TaskStatusPending },
		"newer": func(s *StateSnapshot, i *StateIntent) {
			s.Tasks[0].ActivationGeneration++
			s.Generations[s.Tasks[0].XID]++
		},
		"missing":      func(s *StateSnapshot, i *StateIntent) { s.Tasks = s.Tasks[1:] },
		"no timestamp": func(s *StateSnapshot, i *StateIntent) { s.Tasks[0].DeactivatedAt = s.Tasks[0].StartTime },
		"cleanup": func(s *StateSnapshot, i *StateIntent) {
			s.CleanupNeeded[*i.XID] = []string{"li-" + i.XID.String() + "-0"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, i := stateIntentFixture(t, StatePurge)
			if name == "no timestamp" {
				s.Tasks[0].StartTime = time.Time{}
			}
			change(s, i)
			require.ErrorIs(t, ValidateStateSnapshot(s), ErrStateSnapshot)
		})
	}
	s, i := stateIntentFixture(t, StatePurge)
	i.Phase = StateFinished
	s.Tasks[0].Status = TaskStatusActive
	s.Tasks[0].ActivationGeneration++
	s.Generations[s.Tasks[0].XID]++
	require.NoError(t, ValidateStateSnapshot(s), "historical finished purge must not bind a newer live definition")
}

func TestStateObligationPurgeRetainsTaskAndCallControls(t *testing.T) {
	for _, scope := range []StateRevocationScope{StateRevokeTask, StateRevokeCall} {
		t.Run(string(scope), func(t *testing.T) {
			s, i := stateIntentFixture(t, StatePurge)
			control := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: s.Incarnation, Scope: scope, XID: i.XID, TaskGeneration: statePtr(i.PreviousGeneration), RevokedAt: NewStateTimestamp(s.WrittenAt)}
			if scope == StateRevokeCall {
				control.DID = statePtr(s.Destinations[0].DID)
				control.DestinationGeneration = statePtr(uint64(17))
				control.CallIncarnation = statePtr(uuid.New())
				control.CallGeneration = statePtr(uint64(1))
			}
			s.Revocations = []*StateRevocation{control}
			raw, err := json.Marshal(s)
			require.NoError(t, err)
			_, err = UnmarshalStateSnapshot(raw)
			require.ErrorIs(t, err, ErrStateSnapshot)
			i.Phase = StateFinished
			require.NoError(t, ValidateStateSnapshot(s), "finished intents describe history")

			m, _, _, dids := administrativeTransactionManager(t)
			task := idempotencyTask(uuid.New(), dids, time.Time{})
			require.NoError(t, m.ActivateTask(task))
			require.NoError(t, m.DeactivateTask(task.XID))
			control.StateIncarnation = m.stateID
			control.XID = &task.XID
			control.TaskGeneration = statePtr(uint64(1))
			m.stateRevocations = append(m.stateRevocations, control)
			count, err := m.PurgeDeactivatedTasksWithError(0)
			require.NoError(t, err)
			require.Zero(t, count, "retained controls prevent producer admission")
			_, err = m.GetTaskDetails(task.XID)
			require.NoError(t, err)
		})
	}
}

// The list is normative input, deliberately independent of stateJSONSchema.
func TestStateObligationRequiredFieldPresenceAndTypes(t *testing.T) {
	s, i := stateIntentFixture(t, StateTaskModify)
	c := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: s.Incarnation, Scope: StateRevokeTask, XID: i.XID, TaskGeneration: statePtr(i.PreviousGeneration), RevokedAt: NewStateTimestamp(s.WrittenAt)}
	s.Revocations = []*StateRevocation{c}
	i.RevocationIDs = []uuid.UUID{c.ControlID}
	encoded, err := MarshalStateSnapshot(s)
	require.NoError(t, err)
	families := map[string][]string{
		"":                         strings.Fields("version written_at incarnation tasks destinations cleanup_needed generations intents revocations"),
		"tasks.0":                  strings.Fields("XID Targets DestinationIDs DeliveryType Status"),
		"tasks.0.Targets.0":        strings.Fields("Type Value"),
		"destinations.0":           strings.Fields("did address port x2_enabled x3_enabled created_at"),
		"intents.0":                strings.Fields("operation_id kind state_incarnation xid did previous_generation reserved_generation phase candidate_task candidate_destination cleanup_filter_ids revocation_ids failed"),
		"revocations.0":            strings.Fields("version control_id journal_uuid state_incarnation scope xid task_generation did destination_generation call_incarnation call_generation covered_record_highwater covered_admission_highwater revoked_at"),
		"revocations.0.revoked_at": strings.Fields("seconds nanos"),
	}
	for path, fields := range families {
		for _, field := range fields {
			for _, mode := range []string{"absent", "wrong_type", "null"} {
				t.Run(path+"/"+field+"/"+mode, func(t *testing.T) {
					d := json.NewDecoder(bytes.NewReader(encoded))
					d.UseNumber()
					var tree map[string]any
					require.NoError(t, d.Decode(&tree))
					var node any = tree
					if path != "" {
						for _, part := range strings.Split(path, ".") {
							if list, ok := node.([]any); ok {
								index, err := strconv.Atoi(part)
								require.NoError(t, err)
								node = list[index]
							} else {
								node = node.(map[string]any)[part]
							}
						}
					}
					object := node.(map[string]any)
					nullable := object[field] == nil
					if mode == "absent" {
						delete(object, field)
					} else if mode == "null" {
						object[field] = nil
					} else {
						switch object[field].(type) {
						case string:
							object[field] = false
						case bool:
							object[field] = "wrong"
						default:
							object[field] = "wrong"
						}
					}
					raw, err := json.Marshal(tree)
					require.NoError(t, err)
					_, err = UnmarshalStateSnapshot(raw)
					if mode == "null" && nullable {
						require.NoError(t, err)
					} else {
						require.ErrorIs(t, err, ErrStateSnapshot)
					}
				})
			}
		}
	}
}

func TestStateObligationHookPlansAreDetachedAndMalformedRejected(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	intent, err := m.taskIntentLocked(StateTaskDeactivate, current, nil)
	require.NoError(t, err)
	original := &StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: uuid.New(), StateIncarnation: m.StateIncarnation(), Scope: StateRevokeTask, XID: statePtr(task.XID), TaskGeneration: statePtr(uint64(1)), RevokedAt: NewStateTimestamp(current.ActivatedAt)}
	revoker.prepare = func(RevocationRequest) ([]*StateRevocation, error) { return []*StateRevocation{original}, nil }
	plan, err := m.prepareRevocationsLocked(intent, current, nil)
	require.NoError(t, err)
	*original.XID = uuid.New()
	*original.TaskGeneration = 99
	require.Equal(t, task.XID, *plan[0].XID)
	require.Equal(t, uint64(1), *plan[0].TaskGeneration)
	revoker.commit = func(cs []*StateRevocation) (securestore.Outcome, error) {
		*cs[0].XID = uuid.New()
		*cs[0].TaskGeneration = 7
		return securestore.Committed, nil
	}
	_, err = m.commitRevocationsLocked(plan)
	require.NoError(t, err)
	require.Equal(t, task.XID, *plan[0].XID)
	require.Equal(t, uint64(1), *plan[0].TaskGeneration)
	for _, mode := range []string{"duplicate_id", "duplicate_journal", "wrong_task", "wrong_generation", "call_scope", "wrong_store"} {
		t.Run(mode, func(t *testing.T) {
			a := cloneStateRevocation(plan[0])
			b := cloneStateRevocation(plan[0])
			b.ControlID = uuid.New()
			b.JournalUUID = uuid.New()
			controls := []*StateRevocation{a}
			switch mode {
			case "duplicate_id":
				b.ControlID = a.ControlID
				controls = append(controls, b)
			case "duplicate_journal":
				b.JournalUUID = a.JournalUUID
				controls = append(controls, b)
			case "wrong_task":
				*a.XID = uuid.New()
			case "wrong_generation":
				*a.TaskGeneration = 2
			case "call_scope":
				a.Scope = StateRevokeCall
				a.DID = statePtr(dids[0])
				a.DestinationGeneration = statePtr(uint64(1))
				a.CallIncarnation = statePtr(uuid.New())
				a.CallGeneration = statePtr(uint64(1))
			case "wrong_store":
				a.StateIncarnation = uuid.New()
			}
			revoker.prepare = func(RevocationRequest) ([]*StateRevocation, error) { return controls, nil }
			_, err := m.prepareRevocationsLocked(intent, current, nil)
			require.Error(t, err)
		})
	}
	m.durableRevoker = nil
	_, err = m.commitRevocationsLocked(plan)
	require.Error(t, err)
	require.Equal(t, fmt.Sprint(task.XID), plan[0].XID.String())
}

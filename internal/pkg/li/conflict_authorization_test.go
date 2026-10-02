//go:build li

package li

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func conflictSnapshot(task *InterceptTask) *SnapshotTask {
	task = cloneInterceptTask(task)
	task.Definition.Source = DefinitionPull
	return &SnapshotTask{Task: task, Completeness: task.Definition.Completeness}
}

func TestConflictAuthorizationMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*InterceptTask, *InterceptTask, *SnapshotTask)
		reason string
		check  func(*testing.T, *InterceptTask, *InterceptTask)
	}{
		{name: "shorter_cutoff", mutate: func(h, s *InterceptTask, _ *SnapshotTask) { s.EndTime = h.EndTime.Add(-time.Hour) }, check: func(t *testing.T, h, c *InterceptTask) { require.Equal(t, h.EndTime.Add(-time.Hour), c.EndTime) }},
		{name: "expired", mutate: func(h, s *InterceptTask, _ *SnapshotTask) { s.EndTime = time.Now().Add(-time.Minute) }, reason: "expired"},
		{name: "future_start", mutate: func(h, s *InterceptTask, _ *SnapshotTask) { s.StartTime = time.Now().Add(time.Hour) }, check: func(t *testing.T, h, c *InterceptTask) { require.Equal(t, TaskStatusPending, c.Status) }},
		{name: "empty_window", mutate: func(h, s *InterceptTask, _ *SnapshotTask) {
			s.StartTime = h.EndTime.Add(time.Hour)
			s.EndTime = h.EndTime.Add(2 * time.Hour)
		}, reason: "empty_window"},
		{name: "one_target", mutate: func(h, s *InterceptTask, _ *SnapshotTask) { s.Targets = s.Targets[:1] }, check: func(t *testing.T, h, c *InterceptTask) { require.Len(t, c.Targets, 1) }},
		{name: "no_targets", mutate: func(h, s *InterceptTask, _ *SnapshotTask) {
			s.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:other@example"}}
		}, reason: "no_common_targets"},
		{name: "task_destination_removed_but_global", mutate: func(h, s *InterceptTask, _ *SnapshotTask) { s.DestinationIDs = s.DestinationIDs[:1] }, check: func(t *testing.T, h, c *InterceptTask) { require.Equal(t, h.DestinationIDs[:1], c.DestinationIDs) }},
		{name: "retained_destination_unconfirmed", mutate: func(h, s *InterceptTask, in *SnapshotTask) {
			s.DestinationIDs = s.DestinationIDs[:1]
			in.confirmedDestinations = map[uuid.UUID]bool{h.DestinationIDs[1]: true}
		}, reason: "no_confirmed_destinations"},
		{name: "one_confirmation_fails", mutate: func(h, s *InterceptTask, in *SnapshotTask) {
			in.confirmedDestinations = map[uuid.UUID]bool{h.DestinationIDs[1]: true}
			s.EndTime = s.EndTime.Add(time.Hour)
		}, check: func(t *testing.T, h, c *InterceptTask) { require.Equal(t, h.DestinationIDs[1:], c.DestinationIDs) }},
		{name: "no_destination", mutate: func(h, s *InterceptTask, _ *SnapshotTask) { s.DestinationIDs = []uuid.UUID{uuid.New()} }, reason: "no_confirmed_destinations"},
		{name: "x2", mutate: func(h, s *InterceptTask, _ *SnapshotTask) { s.DeliveryType = DeliveryX2Only }, check: func(t *testing.T, h, c *InterceptTask) { require.Equal(t, DeliveryX2Only, c.DeliveryType) }},
		{name: "x3", mutate: func(h, s *InterceptTask, _ *SnapshotTask) { s.DeliveryType = DeliveryX3Only }, check: func(t *testing.T, h, c *InterceptTask) { require.Equal(t, DeliveryX3Only, c.DeliveryType) }},
		{name: "wider", mutate: func(h, s *InterceptTask, _ *SnapshotTask) {
			s.StartTime = h.StartTime.Add(-time.Hour)
			s.EndTime = h.EndTime.Add(time.Hour)
			s.Targets = append(s.Targets, TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:extra@example"})
			s.DestinationIDs = append(s.DestinationIDs, uuid.New())
		}, check: func(t *testing.T, h, c *InterceptTask) { require.True(t, equivalentTaskDefinition(h, c)) }},
		{name: "mixed", mutate: func(h, s *InterceptTask, _ *SnapshotTask) {
			s.EndTime = h.EndTime.Add(time.Hour)
			s.Targets = s.Targets[:1]
			s.DeliveryType = DeliveryX2Only
		}, check: func(t *testing.T, h, c *InterceptTask) {
			require.Equal(t, h.EndTime, c.EndTime)
			require.Len(t, c.Targets, 1)
			require.Equal(t, DeliveryX2Only, c.DeliveryType)
		}},
	}
	for _, mode := range []string{"live_memory", "live_persistent", "restored"} {
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				var m *Manager
				var dids []uuid.UUID
				if mode == "live_memory" {
					m, _, dids = newIdempotencyManager(t, "")
				} else {
					m, _, _, dids = administrativeTransactionManager(t)
				}
				task := idempotencyTask(uuid.New(), dids, time.Now().Add(-2*time.Hour).UTC())
				require.NoError(t, m.ActivateTask(task))
				held, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				in := conflictSnapshot(held)
				tc.mutate(held, in.Task, in)
				if mode == "restored" {
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
				}
				var revoked uint64
				m.SetTaskModifiedCallback(func(old *InterceptTask) { revoked = old.ActivationGeneration })
				var productRevocations int
				m.SetTaskConflictCallback(func(*InterceptTask) error { productRevocations++; return nil })
				require.NoError(t, m.applySnapshotDefinition(in))
				current, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.True(t, current.Definition.Conflict)
				require.Equal(t, DefinitionPush, current.Definition.Source)
				require.False(t, m.ReplayTaskAuthorized(task.XID, held.ActivationGeneration))
				if tc.reason != "" {
					require.True(t, current.Definition.ConflictDisarmed)
					require.Equal(t, tc.reason, current.Definition.ConflictReason)
					require.Equal(t, TaskStatusSuspended, current.Status)
					require.Empty(t, m.filters.GetFiltersForXID(task.XID))
				} else {
					tc.check(t, held, current)
					require.False(t, current.Definition.ConflictDisarmed)
					if current.Status == TaskStatusActive {
						require.Len(t, m.filters.GetFiltersForXID(task.XID), len(current.Targets))
					} else {
						require.Empty(t, m.filters.GetFiltersForXID(task.XID))
					}
				}
				if tc.reason != "" || !equivalentDeliveryDefinition(held, current) || authorizationWindowNarrows(held, current) {
					require.Greater(t, current.ActivationGeneration, held.ActivationGeneration)
					require.Equal(t, held.ActivationGeneration, revoked)
					_, ok := m.AcquireTaskAdmission(task.XID, held.ActivationGeneration)
					require.False(t, ok)
				}
				if mode != "restored" && tc.name == "wider" {
					require.Zero(t, productRevocations, "unchanged live scope must keep its delivery generation eligible")
					require.Equal(t, held.ActivationGeneration, current.ActivationGeneration)
				}
				// Widening back to the original definition cannot undo any restriction.
				require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(held)))
				again, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.True(t, equivalentTaskDefinition(current, again))
				require.Equal(t, current.ActivationGeneration, again.ActivationGeneration)
				require.True(t, again.Definition.Conflict)
				if mode != "live_memory" {
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
					require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(held)))
					after, err := m.GetTaskDetails(task.XID)
					require.NoError(t, err)
					require.True(t, equivalentTaskDefinition(current, after))
					require.Equal(t, current.Definition.ConflictDisarmed, after.Definition.ConflictDisarmed)
					require.False(t, m.ReplayTaskAuthorized(task.XID, current.ActivationGeneration))
				}
			})
		}
	}
}

func TestConflictEffectiveCutoffsAndCanonicalTargets(t *testing.T) {
	now := time.Now().UTC()
	for _, mode := range []string{"live_memory", "live_persistent", "restored"} {
		for _, variant := range []string{"held_nominal", "snapshot_nominal", "equal_held_nominal", "equal_snapshot_nominal", "both_unbounded", "disjoint_delivery", "legacy_number"} {
			t.Run(mode+"/"+variant, func(t *testing.T) {
				var m *Manager
				var dids []uuid.UUID
				if mode == "live_memory" {
					m, _, dids = newIdempotencyManager(t, "")
				} else {
					m, _, _, dids = administrativeTransactionManager(t)
				}
				h := idempotencyTask(uuid.New(), dids, now.Add(-time.Hour))
				h.EndTime = now.Add(4 * time.Hour)
				s := cloneInterceptTask(h)
				switch variant {
				case "held_nominal":
					h.ImplicitDeactivationAllowed = false
					h.EndTime = now.Add(time.Hour)
				case "snapshot_nominal":
					s.ImplicitDeactivationAllowed = false
					s.EndTime = now.Add(time.Hour)
				case "equal_held_nominal":
					h.ImplicitDeactivationAllowed = false
				case "equal_snapshot_nominal":
					s.ImplicitDeactivationAllowed = false
				case "both_unbounded":
					h.ImplicitDeactivationAllowed = false
					s.ImplicitDeactivationAllowed = false
					s.EndTime = now.Add(time.Hour)
				case "disjoint_delivery":
					h.DeliveryType = DeliveryX2Only
					s.DeliveryType = DeliveryX3Only
				case "legacy_number":
					h.Targets = []TargetIdentity{{Type: TargetTypeTELURI, Value: "15551234567"}}
					s.Targets = []TargetIdentity{{Type: TargetTypeE164, Value: "15551234567"}}
					s.EndTime = s.EndTime.Add(-time.Hour)
				}
				require.NoError(t, m.ActivateTask(h))
				before, err := m.GetTaskDetails(h.XID)
				require.NoError(t, err)
				s.Definition = authoritativeDefinition(s)
				if mode == "restored" {
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
				}
				require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(s)))
				c, err := m.GetTaskDetails(h.XID)
				require.NoError(t, err)
				switch variant {
				case "both_unbounded":
					require.True(t, TaskAuthorizationCutoff(c).IsZero())
					require.False(t, c.ImplicitDeactivationAllowed)
				case "disjoint_delivery":
					require.True(t, c.Definition.ConflictDisarmed)
					require.Empty(t, m.filters.GetFiltersForXID(h.XID))
				case "legacy_number":
					require.Equal(t, TargetTypeE164, c.Targets[0].Type)
				default:
					require.Equal(t, now.Add(4*time.Hour), TaskAuthorizationCutoff(c))
					require.True(t, c.ImplicitDeactivationAllowed)
				}
				if variant == "held_nominal" || variant == "equal_held_nominal" {
					require.Greater(t, c.ActivationGeneration, before.ActivationGeneration)
				}
			})
		}
	}
}

func TestConflictResolutionRequiresExplicitMutationAndFreshGeneration(t *testing.T) {
	for _, disarm := range []bool{false, true} {
		for _, restore := range []bool{false, true} {
			t.Run(fmt.Sprintf("disarm=%t/restore=%t", disarm, restore), func(t *testing.T) {
				m, _, _, dids := administrativeTransactionManager(t)
				initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				require.NoError(t, m.ActivateTask(initial))
				original, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				in := conflictSnapshot(original)
				if disarm {
					in.Task.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:unrelated@example"}}
				} else {
					in.Task.DestinationIDs = in.Task.DestinationIDs[:1]
				}
				require.NoError(t, m.applySnapshotDefinition(in))
				conflict, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				if restore {
					m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
					require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(conflict)))
				}
				current, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				require.True(t, current.Definition.Conflict)
				// An authenticated mutation may accept the retained effective definition.
				require.NoError(t, m.ModifyTaskX1(initial.XID, &x1.TaskModification{DeliveryType: ptrX1Delivery(x1.DeliveryX2andX3)}))
				resolved, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				require.False(t, resolved.Definition.Conflict)
				require.False(t, resolved.Definition.ConflictDisarmed)
				require.Empty(t, resolved.LastError)
				require.Equal(t, TaskStatusActive, resolved.Status)
				require.Greater(t, resolved.ActivationGeneration, conflict.ActivationGeneration)
				require.False(t, m.ReplayTaskAuthorized(initial.XID, original.ActivationGeneration))
				require.False(t, m.ReplayTaskAuthorized(initial.XID, conflict.ActivationGeneration))
				m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
				require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(resolved)))
				require.True(t, m.ReplayTaskAuthorized(initial.XID, resolved.ActivationGeneration))
				require.False(t, m.ReplayTaskAuthorized(initial.XID, conflict.ActivationGeneration))
			})
		}
	}
}

func ptrX1Delivery(v x1.DeliveryType) *x1.DeliveryType { return &v }

func TestConflictNarrowingFailuresCloseAdmission(t *testing.T) {
	for _, disarm := range []bool{false, true} {
		for _, failure := range []string{"memory_filter", "persistent_filter", "reserve", "revoke", "policy", "finish"} {
			t.Run(fmt.Sprintf("disarm=%t/%s", disarm, failure), func(t *testing.T) {
				var m *Manager
				var pusher *mockFilterPusher
				var dids []uuid.UUID
				if failure == "memory_filter" {
					m, pusher, dids = newIdempotencyManager(t, "")
				} else {
					m, pusher, _, dids = administrativeTransactionManager(t)
				}
				initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				require.NoError(t, m.ActivateTask(initial))
				old, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				in := conflictSnapshot(old)
				in.Task.Targets = in.Task.Targets[:1]
				if disarm {
					in.Task.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:unrelated@example"}}
				}
				if strings.HasSuffix(failure, "filter") {
					if disarm {
						pusher.failNext = true
					} else {
						pusher.failNext = true
					}
				} else {
					store := m.stateStore.(*EncryptedStateStore)
					write := store.write
					calls := 0
					stage := map[string]int{"reserve": 1, "revoke": 2, "policy": 3, "finish": 4}[failure]
					store.write = func(name string, data []byte) (securestore.Outcome, error) {
						calls++
						if calls == stage {
							return securestore.NotCommitted, errors.New("injected narrowing checkpoint failure")
						}
						return write(name, data)
					}
					t.Cleanup(func() { store.write = write })
				}
				require.Error(t, m.applySnapshotDefinition(in))
				require.NotNil(t, m.stateFault.Load())
				_, ok := m.AcquireTaskAdmission(initial.XID, old.ActivationGeneration)
				require.False(t, ok)
				current, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				_, ok = m.AcquireTaskAdmission(initial.XID, current.ActivationGeneration)
				require.False(t, ok)
				require.False(t, m.ReplayTaskAuthorized(initial.XID, old.ActivationGeneration))
			})
		}
	}
}

func TestConflictWaitsForExistingPacketAdmission(t *testing.T) {
	m, _, dids := newIdempotencyManager(t, "")
	initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
	require.NoError(t, m.ActivateTask(initial))
	old, err := m.GetTaskDetails(initial.XID)
	require.NoError(t, err)
	release, ok := m.AcquireTaskAdmission(initial.XID, old.ActivationGeneration)
	require.True(t, ok)
	in := conflictSnapshot(old)
	in.Task.DeliveryType = DeliveryX2Only
	done := make(chan error, 1)
	go func() { done <- m.applySnapshotDefinition(in) }()
	// Observe the administrative lock held before testing that the lifecycle
	// writer remains blocked by the packet admission read lease.
	require.Eventually(t, func() bool {
		if m.adminMu.TryLock() {
			m.adminMu.Unlock()
			return false
		}
		return true
	}, time.Second, time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("narrowing passed active admission: %v", err)
	default:
	}
	release.Release()
	require.NoError(t, <-done)
	_, ok = m.AcquireTaskAdmission(initial.XID, old.ActivationGeneration)
	require.False(t, ok)
}

func TestConflictStateCodecCompatibleOptionalFields(t *testing.T) {
	m, _, _, dids := administrativeTransactionManager(t)
	initial := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(initial))
	state := readManagerStateTest(t, m)
	encoded, err := MarshalStateSnapshot(state)
	require.NoError(t, err)
	// The previous version omitted these optional fields entirely.
	require.Contains(t, string(encoded), `,"ConflictDisarmed":false,"ConflictReason":""`)
	encoded = bytes.ReplaceAll(encoded, []byte(`,"ConflictDisarmed":false,"ConflictReason":""`), nil)
	require.NotContains(t, string(encoded), "ConflictDisarmed")
	require.NotContains(t, string(encoded), "ConflictReason")
	restored, err := UnmarshalStateSnapshot(encoded)
	require.NoError(t, err)
	require.False(t, restored.Tasks[0].Definition.ConflictDisarmed)
	in := conflictSnapshot(state.Tasks[0])
	in.Task.DeliveryType = DeliveryX2Only
	require.NoError(t, m.applySnapshotDefinition(in))
	narrowed := readManagerStateTest(t, m)
	data, err := MarshalStateSnapshot(narrowed)
	require.NoError(t, err)
	again, err := UnmarshalStateSnapshot(data)
	require.NoError(t, err)
	require.True(t, again.Tasks[0].Definition.Conflict)
	require.Equal(t, "common_scope", again.Tasks[0].Definition.ConflictReason)
}

func TestConflictDeactivationAndFreshActivation(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(fmt.Sprint(persistent), func(t *testing.T) {
			var m *Manager
			var dids []uuid.UUID
			if persistent {
				m, _, _, dids = administrativeTransactionManager(t)
			} else {
				m, _, dids = newIdempotencyManager(t, "")
			}
			task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
			require.NoError(t, m.ActivateTask(task))
			original, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			in := conflictSnapshot(original)
			in.Task.Targets = nil
			require.NoError(t, m.applySnapshotDefinition(in))
			disarmed, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.True(t, disarmed.Definition.ConflictDisarmed)
			require.NoError(t, m.DeactivateTask(task.XID))
			if persistent {
				m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
			}
			closed, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusDeactivated, closed.Status)
			require.False(t, closed.Definition.ConflictDisarmed)
			require.False(t, closed.Definition.Conflict)
			require.NoError(t, m.applySnapshotDefinition(in))
			require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(original)))
			afterPull, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusDeactivated, afterPull.Status)
			require.Nil(t, m.stateFault.Load())
			require.Empty(t, m.filters.GetFiltersForXID(task.XID))
			require.NoError(t, m.ActivateTask(task))
			active, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, TaskStatusActive, active.Status)
			require.Greater(t, active.ActivationGeneration, disarmed.ActivationGeneration)
		})
	}
}

func TestConflictRepeatedSnapshotDoesNotRewritePolicy(t *testing.T) {
	m, pusher, _, dids := administrativeTransactionManager(t)
	task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
	require.NoError(t, m.ActivateTask(task))
	original, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	in := conflictSnapshot(original)
	in.Task.DeliveryType = DeliveryX2Only
	require.NoError(t, m.applySnapshotDefinition(in))
	before, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	pusher.reset()
	store := m.stateStore.(*EncryptedStateStore)
	write := store.write
	writes := 0
	store.write = func(name string, data []byte) (securestore.Outcome, error) { writes++; return write(name, data) }
	defer func() { store.write = write }()
	for range 3 {
		require.NoError(t, m.applySnapshotDefinition(in))
		require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(before)))
	}
	require.Zero(t, writes)
	require.Empty(t, pusher.updates)
	require.Empty(t, pusher.deletes)
	after, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestConflictResolverDoesNotInferSelectorOverlap(t *testing.T) {
	now := time.Now().UTC()
	held := idempotencyTask(uuid.New(), []uuid.UUID{uuid.New()}, now.Add(-time.Hour))
	held.Definition = authoritativeDefinition(held)
	for _, pair := range [][2]TargetIdentity{
		{{Type: TargetTypeIPv4CIDR, Value: "192.0.2.0/24"}, {Type: TargetTypeIPv4Address, Value: "192.0.2.1"}},
		{{Type: TargetTypeSIPURI, Value: "sip:a@example"}, {Type: TargetTypeSIPURI, Value: "a@example"}},
		{{Type: TargetTypeTELURI, Value: "tel:+15551234567"}, {Type: TargetTypeE164, Value: "15551234567"}},
	} {
		held.Targets = []TargetIdentity{pair[0]}
		snapshot := cloneInterceptTask(held)
		snapshot.Targets = []TargetIdentity{pair[1]}
		common, reason := resolveConflictAuthorization(held, snapshot, nil, now)
		require.Nil(t, common)
		require.Equal(t, "no_common_targets", reason)
	}
}

func TestConflictTransportRevocationFailureClosesAdmission(t *testing.T) {
	m, _, dids := newIdempotencyManager(t, "")
	task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
	require.NoError(t, m.ActivateTask(task))
	old, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	revokeErr := errors.New("transport owner did not terminate")
	calls := 0
	m.SetTaskConflictCallback(func(task *InterceptTask) error {
		calls++
		require.Equal(t, old.ActivationGeneration, task.ActivationGeneration)
		return revokeErr
	})
	in := conflictSnapshot(old)
	in.Task.DeliveryType = DeliveryX2Only
	require.ErrorIs(t, m.applySnapshotDefinition(in), revokeErr)
	require.Equal(t, 1, calls)
	require.NotNil(t, m.stateFault.Load())
	require.Empty(t, m.filters.GetFiltersForXID(task.XID))
	_, ok := m.AcquireTaskAdmission(task.XID, old.ActivationGeneration)
	require.False(t, ok)
}

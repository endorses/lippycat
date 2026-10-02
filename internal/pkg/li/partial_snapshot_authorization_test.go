//go:build li

package li

import (
	"encoding/xml"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// partialAuthorizationSnapshot exercises wire omission rather than assigning
// zero times to an otherwise complete internal definition.
func partialAuthorizationSnapshot(t *testing.T, task *InterceptTask) *SnapshotTask {
	t.Helper()
	var targets []schema.TargetIdentifier
	for _, target := range task.Targets {
		switch target.Type {
		case TargetTypeSIPURI:
			value := schema.SIPURI(target.Value)
			targets = append(targets, schema.TargetIdentifier{SipUri: &value})
		case TargetTypeTELURI:
			value := schema.TELURI(target.Value)
			targets = append(targets, schema.TargetIdentifier{TelUri: &value})
		case TargetTypeE164:
			value := schema.InternationalE164(target.Value)
			targets = append(targets, schema.TargetIdentifier{E164Number: &value})
		default:
			t.Fatalf("unexpected target type %v", target.Type)
		}
	}
	details := makeTaskResponseDetails(task.XID, task.DestinationIDs, targets)
	details.TaskDetails.DeliveryType = task.DeliveryType.String()
	details.TaskDetails.ImplicitDeactivationAllowed = nil
	wire, err := xml.Marshal(details)
	require.NoError(t, err)
	require.NotContains(t, string(wire), "ListOfMediationDetails")
	var parsed schema.TaskResponseDetails
	require.NoError(t, xml.Unmarshal(wire, &parsed))
	in, err := ConvertSnapshotTask(&parsed)
	require.NoError(t, err)
	require.False(t, in.Completeness.Complete())
	return in
}

func TestPartialSnapshotAuthorizationAcrossLifecycles(t *testing.T) {
	for _, mode := range []string{"memory", "persistent", "restored", "restored_pending"} {
		for _, strict := range []bool{false, true} {
			for _, implicit := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/strict=%t/implicit=%t", mode, strict, implicit), func(t *testing.T) {
					var m *Manager
					var dids []uuid.UUID
					if mode == "memory" {
						m, _, dids = newIdempotencyManager(t, "")
					} else {
						m, _, _, dids = administrativeTransactionManager(t)
					}
					m.config.ADMFCompleteTaskContract = strict
					initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
					initial.ImplicitDeactivationAllowed = implicit
					if mode == "restored_pending" {
						initial.StartTime = time.Now().Add(time.Hour).UTC()
					}
					require.NoError(t, m.ActivateTask(initial))
					held, err := m.GetTaskDetails(initial.XID)
					require.NoError(t, err)
					supplied := cloneInterceptTask(held)
					supplied.Targets, supplied.DestinationIDs = supplied.Targets[:1], supplied.DestinationIDs[:1]
					supplied.DeliveryType = DeliveryX2Only
					in := partialAuthorizationSnapshot(t, supplied)
					in.confirmedDestinations = map[uuid.UUID]bool{dids[0]: true, dids[1]: true}
					if mode == "restored" || mode == "restored_pending" {
						m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
					}
					var revoked []uint64
					m.SetTaskConflictCallback(func(old *InterceptTask) error {
						revoked = append(revoked, old.ActivationGeneration)
						return nil
					})
					require.NoError(t, m.applySnapshotDefinition(in))
					current, err := m.GetTaskDetails(initial.XID)
					require.NoError(t, err)
					require.Equal(t, supplied.Targets, current.Targets)
					require.Equal(t, supplied.DestinationIDs, current.DestinationIDs)
					require.Equal(t, DeliveryX2Only, current.DeliveryType)
					require.Equal(t, held.StartTime, current.StartTime)
					require.Equal(t, held.EndTime, current.EndTime)
					require.Equal(t, held.ImplicitDeactivationAllowed, current.ImplicitDeactivationAllowed)
					require.Equal(t, held.Definition.Completeness, current.Definition.Completeness)
					require.True(t, current.Definition.Conflict)
					require.Greater(t, current.ActivationGeneration, held.ActivationGeneration)
					require.Contains(t, revoked, held.ActivationGeneration)
					_, err = m.GetDestination(dids[1])
					require.NoError(t, err, "removed task destination remains globally configured")
					_, admitted := m.AcquireTaskAdmission(initial.XID, held.ActivationGeneration)
					require.False(t, admitted)
					require.False(t, m.ReplayTaskAuthorized(initial.XID, held.ActivationGeneration))
					if strict && (mode == "restored" || mode == "restored_pending") {
						require.True(t, m.pendingNeedsConfirmation(initial.XID))
						m.promotePendingTasks()
						require.Empty(t, m.filters.GetFiltersForXID(initial.XID))
					} else if mode == "restored_pending" {
						require.Empty(t, m.filters.GetFiltersForXID(initial.XID))
					} else {
						require.Len(t, m.filters.GetFiltersForXID(initial.XID), 1)
					}
					for _, poll := range []*SnapshotTask{in, partialAuthorizationSnapshot(t, held)} {
						require.NoError(t, m.applySnapshotDefinition(poll))
						again, err := m.GetTaskDetails(initial.XID)
						require.NoError(t, err)
						require.True(t, equivalentTaskDefinition(current, again))
						require.Equal(t, current.ActivationGeneration, again.ActivationGeneration)
					}
					if mode != "memory" {
						m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
						require.NoError(t, m.applySnapshotDefinition(in))
						after, err := m.GetTaskDetails(initial.XID)
						require.NoError(t, err)
						require.True(t, equivalentTaskDefinition(current, after))
						require.False(t, m.ReplayTaskAuthorized(initial.XID, current.ActivationGeneration))
						if strict {
							require.Empty(t, m.filters.GetFiltersForXID(initial.XID))
						}
					}
					// Complete confirmation may admit current scope, but cannot
					// restore the removed target, DID or X3 authorization.
					require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(held)))
					final, err := m.GetTaskDetails(initial.XID)
					require.NoError(t, err)
					require.True(t, equivalentTaskDefinition(current, final))
					require.False(t, m.pendingNeedsConfirmation(initial.XID))
				})
			}
		}
	}
}

func TestPartialSnapshotMandatoryDimensionMatrix(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, variant := range []string{"equal", "wider", "canonical", "unconfirmed", "one_confirmed", "no_targets", "no_destinations", "no_delivery"} {
			t.Run(fmt.Sprintf("strict=%t/%s", strict, variant), func(t *testing.T) {
				m, _, dids := newIdempotencyManager(t, "")
				m.config.ADMFCompleteTaskContract = strict
				initial := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				if variant == "canonical" {
					initial.Targets = []TargetIdentity{{Type: TargetTypeTELURI, Value: "15551234567"}}
				}
				if variant == "no_delivery" {
					initial.DeliveryType = DeliveryX2Only
				}
				require.NoError(t, m.ActivateTask(initial))
				held, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				supplied := cloneInterceptTask(held)
				switch variant {
				case "wider":
					supplied.Targets = append(supplied.Targets, TargetIdentity{Type: TargetTypeSIPURI, Value: "sip:extra@example"})
					supplied.DestinationIDs = append(supplied.DestinationIDs, uuid.New())
				case "canonical":
					supplied.Targets[0].Type = TargetTypeE164
				case "no_targets":
					supplied.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:other@example"}}
				case "no_destinations":
					supplied.DestinationIDs = []uuid.UUID{uuid.New()}
				case "no_delivery":
					supplied.DeliveryType = DeliveryX3Only
				}
				in := partialAuthorizationSnapshot(t, supplied)
				if variant == "unconfirmed" {
					in.confirmedDestinations = map[uuid.UUID]bool{}
				} else if variant == "one_confirmed" {
					in.confirmedDestinations = map[uuid.UUID]bool{dids[1]: true}
				}
				require.NoError(t, m.applySnapshotDefinition(in))
				current, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				switch variant {
				case "equal", "canonical", "wider":
					require.True(t, equivalentTaskDefinition(held, current))
					require.Equal(t, held.ActivationGeneration, current.ActivationGeneration)
					require.Equal(t, variant == "wider", current.Definition.Conflict)
				case "one_confirmed":
					require.Equal(t, dids[1:], current.DestinationIDs)
					require.False(t, current.Definition.ConflictDisarmed)
				default:
					require.True(t, current.Definition.ConflictDisarmed)
					require.Empty(t, m.filters.GetFiltersForXID(initial.XID))
					_, admitted := m.AcquireTaskAdmission(initial.XID, current.ActivationGeneration)
					require.False(t, admitted)
				}
				require.NoError(t, m.applySnapshotDefinition(in))
				again, err := m.GetTaskDetails(initial.XID)
				require.NoError(t, err)
				require.Equal(t, current.ActivationGeneration, again.ActivationGeneration)
			})
		}
	}
}

func TestPartialSnapshotStrictCandidateRemainsUnarmed(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		for _, disarm := range []bool{false, true} {
			t.Run(fmt.Sprintf("persistent=%t/disarm=%t", persistent, disarm), func(t *testing.T) {
				var m *Manager
				var dids []uuid.UUID
				if persistent {
					m, _, _, dids = administrativeTransactionManager(t)
				} else {
					m, _, dids = newIdempotencyManager(t, "")
				}
				m.config.ADMFCompleteTaskContract = true
				task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
				first := partialAuthorizationSnapshot(t, task)
				require.NoError(t, m.applySnapshotDefinition(first))
				narrow := cloneInterceptTask(task)
				narrow.Targets = narrow.Targets[:1]
				narrow.DestinationIDs = narrow.DestinationIDs[:1]
				narrow.DeliveryType = DeliveryX2Only
				if disarm {
					narrow.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:other@example"}}
				}
				in := partialAuthorizationSnapshot(t, narrow)
				for i := 0; i < 3; i++ {
					require.NoError(t, m.applySnapshotDefinition(in))
					require.Empty(t, m.filters.GetFiltersForXID(task.XID))
					require.False(t, m.ReplayTaskAuthorized(task.XID, 1))
					if disarm {
						held, err := m.GetTaskDetails(task.XID)
						require.NoError(t, err)
						require.True(t, held.Definition.ConflictDisarmed)
						require.Nil(t, m.persistenceCandidates[task.XID])
					} else {
						held := m.persistenceCandidates[task.XID]
						require.NotNil(t, held)
						require.True(t, held.Definition.Candidate)
						require.False(t, held.Definition.Completeness.Complete())
						require.Equal(t, narrow.Targets, held.Targets)
						require.Equal(t, narrow.DestinationIDs, held.DestinationIDs)
						require.Equal(t, narrow.DeliveryType, held.DeliveryType)
					}
					if persistent {
						m = restartAdministrativeTestManager(t, m, &administrativeTestRevoker{})
					}
				}
				if !disarm {
					task.Definition = authoritativeDefinition(task)
					require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(task)))
					current, err := m.GetTaskDetails(task.XID)
					require.NoError(t, err)
					require.True(t, current.Definition.Completeness.Complete())
					require.False(t, current.Definition.Candidate)
					require.Nil(t, m.persistenceCandidates[task.XID])
					require.Equal(t, narrow.Targets, current.Targets)
					require.Len(t, m.filters.GetFiltersForXID(task.XID), 1)
				}
			})
		}
	}
}

func TestPartialSnapshotPullScopeStaysUnknownAndCannotWiden(t *testing.T) {
	m, _, dids := newIdempotencyManager(t, "")
	task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour).UTC())
	require.NoError(t, m.applySnapshotDefinition(partialAuthorizationSnapshot(t, task)))
	held, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, DefinitionPull, held.Definition.Source)
	narrow := cloneInterceptTask(task)
	narrow.Targets, narrow.DestinationIDs = narrow.Targets[:1], narrow.DestinationIDs[:1]
	narrow.DeliveryType = DeliveryX2Only
	require.NoError(t, m.applySnapshotDefinition(partialAuthorizationSnapshot(t, narrow)))
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.False(t, current.Definition.Completeness.Complete())
	require.True(t, current.StartTime.IsZero())
	require.True(t, current.EndTime.IsZero())
	require.False(t, current.ImplicitDeactivationAllowed)
	require.Equal(t, narrow.Targets, current.Targets)
	require.Equal(t, narrow.DestinationIDs, current.DestinationIDs)
	require.Equal(t, narrow.DeliveryType, current.DeliveryType)
	require.NoError(t, m.applySnapshotDefinition(partialAuthorizationSnapshot(t, task)))
	again, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, current.ActivationGeneration, again.ActivationGeneration)
	require.True(t, equivalentTaskDefinition(current, again))
	task.Definition = authoritativeDefinition(task)
	require.NoError(t, m.applySnapshotDefinition(conflictSnapshot(task)))
	complete, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.True(t, complete.Definition.Completeness.Complete())
	require.Equal(t, narrow.Targets, complete.Targets)
	require.Equal(t, narrow.DestinationIDs, complete.DestinationIDs)
	require.Equal(t, narrow.DeliveryType, complete.DeliveryType)
	require.Equal(t, task.StartTime, complete.StartTime)
	require.Equal(t, task.EndTime, complete.EndTime)
	require.False(t, m.ReplayTaskAuthorized(task.XID, held.ActivationGeneration))
}

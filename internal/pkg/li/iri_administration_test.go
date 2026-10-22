//go:build li

package li

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func iriAdministrativeObjects() (iripolicy.Object, iripolicy.Object) {
	rule := iripolicy.Object{ID: uuid.New(), Rule: &iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{{Owner: "ETSI", Name: "IRIEvents", Value: "All"}}}}, Action: iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: "NotDelivered"}}}
	policy := iripolicy.Object{ID: uuid.New(), Policy: &iripolicy.Policy{Rules: []iripolicy.RuleReference{{Order: 1, ObjectID: rule.ID}}}}
	return rule, policy
}

func provisionIRIPolicy(t *testing.T, m *Manager) (iripolicy.Object, iripolicy.Object) {
	t.Helper()
	rule, policy := iriAdministrativeObjects()
	require.NoError(t, m.CreateGenericObject(rule))
	require.NoError(t, m.CreateGenericObject(policy))
	return rule, policy
}

func requireObjectCode(t *testing.T, err error, code int) {
	t.Helper()
	var objectErr *x1.ObjectError
	require.ErrorAs(t, err, &objectErr)
	require.Equal(t, code, objectErr.Code)
}

func TestIRIPolicyAdministrativeCRUDAndDetachedAuthority(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, X3Enabled: true}))
	rule, policy := provisionIRIPolicy(t, m)
	requireObjectCode(t, m.CreateGenericObject(rule), x1.ErrorCodeObjectAlreadyExists)
	requireObjectCode(t, m.DeleteGenericObject(rule.ID), x1.ErrorCodeDeleteObject)
	task := idempotencyTask(uuid.New(), []uuid.UUID{did}, time.Time{})
	task.IRIPolicyReferences = []uuid.UUID{policy.ID}
	require.NoError(t, m.ActivateTask(task))
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	deliver, err := m.EvaluateIRIPolicy(current.XID, current.ActivationGeneration, iripolicy.Facts{})
	require.NoError(t, err)
	require.False(t, deliver)
	copyObject, err := m.GetGenericObject(rule.ID)
	require.NoError(t, err)
	copyObject.Rule.Action.Value = "Delivered"
	current.IRIPolicyReferences[0] = uuid.New()
	for id := range current.IRIPolicySourceGenerations {
		current.IRIPolicySourceGenerations[id] = 999
	}
	current, err = m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	deliver, err = m.EvaluateIRIPolicy(current.XID, current.ActivationGeneration, iripolicy.Facts{})
	require.NoError(t, err)
	require.False(t, deliver)
	requireObjectCode(t, m.DeleteGenericObject(policy.ID), x1.ErrorCodeDeleteObject)
	requireObjectCode(t, m.DeleteAllGenericObjects(), x1.ErrorCodeDeleteAllObjects)
	var revoked []uint64
	m.SetOnIRIPolicyChanged(func(previous *InterceptTask) error {
		revoked = append(revoked, previous.ActivationGeneration)
		return nil
	})
	require.NoError(t, m.ModifyGenericObject(copyObject))
	updated, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Greater(t, updated.ActivationGeneration, current.ActivationGeneration)
	require.Equal(t, []uint64{current.ActivationGeneration}, revoked)
	deliver, err = m.EvaluateIRIPolicy(updated.XID, updated.ActivationGeneration, iripolicy.Facts{})
	require.NoError(t, err)
	require.True(t, deliver)
	deliver, err = m.EvaluateIRIPolicy(updated.XID, current.ActivationGeneration, iripolicy.Facts{})
	require.Error(t, err)
	require.False(t, deliver)
	refs := []uuid.UUID{}
	require.NoError(t, m.ModifyTask(task.XID, &TaskModification{IRIPolicyReferences: &refs}))
	require.Len(t, revoked, 2)
	require.NoError(t, m.DeleteAllGenericObjects())
	require.Empty(t, m.iriObjects)
}

func TestIRIPolicyManagerOwnsCapabilityProfile(t *testing.T) {
	entry := iripolicy.DictionaryEntry{Owner: "DE", Name: "IRIEvents", Value: "synthetic-event"}
	profile := iripolicy.Profile{Events: []iripolicy.DictionaryEntry{entry}}
	m := NewManager(ManagerConfig{Enabled: true, IRIProfile: profile}, nil)
	t.Cleanup(m.Stop)
	profile.Events[0].Value = "changed-by-caller"
	returned := m.Config()
	returned.IRIProfile.Events[0].Value = "changed-through-getter"
	rule := iripolicy.Object{ID: uuid.New(), Rule: &iripolicy.Rule{Criteria: []iripolicy.Criterion{{Events: []iripolicy.DictionaryEntry{entry}}}, Action: iripolicy.DictionaryEntry{Owner: "ETSI", Name: "IRIAction", Value: "NotDelivered"}}}
	require.NoError(t, m.CreateGenericObject(rule))
	require.Equal(t, entry, m.Config().IRIProfile.Events[0])
}

func TestIRIPolicySharedUpdateReservesAndRevokesTogether(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	rule, policy := provisionIRIPolicy(t, m)
	var tasks []*InterceptTask
	for range 2 {
		task := idempotencyTask(uuid.New(), dids, time.Time{})
		task.IRIPolicyReferences = []uuid.UUID{policy.ID}
		require.NoError(t, m.ActivateTask(task))
		held, err := m.GetTaskDetails(task.XID)
		require.NoError(t, err)
		tasks = append(tasks, held)
	}
	store := m.stateStore.(*EncryptedStateStore)
	write := store.write
	writes := 0
	store.write = func(name string, data []byte) (securestore.Outcome, error) { writes++; return write(name, data) }
	var revoked []uuid.UUID
	m.SetOnIRIPolicyChanged(func(previous *InterceptTask) error {
		revoked = append(revoked, previous.XID)
		// Both reservations are already durable while neither new definition is live.
		state, err := m.stateStore.Load()
		require.NoError(t, err)
		var unfinished int
		for _, intent := range state.Intents {
			if intent.Phase != StateFinished {
				unfinished++
				require.True(t, intent.IncludeX2)
			}
		}
		require.Equal(t, 2, unfinished)
		for _, task := range tasks {
			held, err := m.GetTaskDetails(task.XID)
			require.NoError(t, err)
			require.Equal(t, task.ActivationGeneration, held.ActivationGeneration)
			require.Equal(t, TaskStatusSuspended, held.Status)
		}
		return nil
	})
	rule.Rule.Action.Value = "Delivered"
	require.NoError(t, m.ModifyGenericObject(rule))
	require.Equal(t, 2, writes)
	require.Len(t, revoked, 2)
	require.Len(t, revoker.requests, 2)
	for _, request := range revoker.requests {
		require.True(t, request.IncludeX2)
	}
	state, err := m.stateStore.Load()
	require.NoError(t, err)
	for _, task := range tasks {
		held, err := m.GetTaskDetails(task.XID)
		require.NoError(t, err)
		require.Equal(t, task.ActivationGeneration+1, held.ActivationGeneration)
		require.Equal(t, uint64(2), held.IRIPolicySourceGenerations[rule.ID])
	}
	for _, intent := range state.Intents {
		require.Equal(t, StateFinished, intent.Phase)
	}
}

func TestIRIPolicyGroupedCheckpointFailuresAndRecovery(t *testing.T) {
	for _, stage := range []int{1, 2} {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			rule, policy := provisionIRIPolicy(t, m)
			var tasks []*InterceptTask
			for range 2 {
				task := idempotencyTask(uuid.New(), dids, time.Time{})
				task.IRIPolicyReferences = []uuid.UUID{policy.ID}
				require.NoError(t, m.ActivateTask(task))
				held, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				tasks = append(tasks, held)
			}
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			writes := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				writes++
				if writes == stage {
					return securestore.NotCommitted, errors.New("injected policy checkpoint failure")
				}
				return write(name, data)
			}
			rule.Rule.Action.Value = "Delivered"
			require.Error(t, m.ModifyGenericObject(rule))
			stored, err := m.GetGenericObject(rule.ID)
			require.NoError(t, err)
			require.Equal(t, "NotDelivered", stored.Rule.Action.Value)
			if stage == 1 {
				require.Len(t, revoker.requests, 2, "preparation is side-effect free")
				require.Empty(t, revoker.committed)
				for _, task := range tasks {
					held, err := m.GetTaskDetails(task.XID)
					require.NoError(t, err)
					require.Equal(t, task.ActivationGeneration, held.ActivationGeneration)
					require.Equal(t, TaskStatusActive, held.Status)
				}
				return
			}
			restarted := restartAdministrativeTestManager(t, m, revoker)
			for _, task := range tasks {
				held, err := restarted.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.Equal(t, TaskStatusFailed, held.Status)
				_, ok := restarted.AcquireTaskAdmission(task.XID, held.ActivationGeneration)
				require.False(t, ok)
			}
			stored, err = restarted.GetGenericObject(rule.ID)
			require.NoError(t, err)
			require.Equal(t, "NotDelivered", stored.Rule.Action.Value)
		})
	}
}

func TestIRIPolicyUncertainGroupNeverPublishesMixedAuthority(t *testing.T) {
	for _, stage := range []int{1, 2} {
		t.Run(string(rune('0'+stage)), func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			rule, policy := provisionIRIPolicy(t, m)
			var tasks []*InterceptTask
			for range 2 {
				task := idempotencyTask(uuid.New(), dids, time.Time{})
				task.IRIPolicyReferences = []uuid.UUID{policy.ID}
				require.NoError(t, m.ActivateTask(task))
				held, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				tasks = append(tasks, held)
			}
			store := m.stateStore.(*EncryptedStateStore)
			write := store.write
			writes := 0
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				writes++
				out, err := write(name, data)
				if err == nil && writes == stage {
					return securestore.Uncertain, errors.New("injected ambiguous policy checkpoint")
				}
				return out, err
			}
			rule.Rule.Action.Value = "Delivered"
			require.Error(t, m.ModifyGenericObject(rule))
			require.False(t, m.administrativeAdmissionReady())
			for _, task := range tasks {
				_, ok := m.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
				require.False(t, ok)
			}
			restarted := restartAdministrativeTestManager(t, m, revoker)
			require.Zero(t, restarted.ActiveTaskCount())
			require.Zero(t, restarted.IRIPolicyStats().ConfirmedObjects)
			stored, err := restarted.GetGenericObject(rule.ID)
			require.NoError(t, err)
			if stage == 1 {
				require.Equal(t, "NotDelivered", stored.Rule.Action.Value)
				for _, task := range tasks {
					held, err := restarted.GetTaskDetails(task.XID)
					require.NoError(t, err)
					require.Equal(t, TaskStatusFailed, held.Status)
				}
			} else {
				require.Equal(t, "Delivered", stored.Rule.Action.Value)
				for _, task := range tasks {
					candidate := restarted.persistedActive[task.XID]
					require.NotNil(t, candidate)
					require.Equal(t, task.ActivationGeneration+1, candidate.ActivationGeneration)
					require.Equal(t, uint64(2), candidate.IRIPolicySourceGenerations[rule.ID])
				}
			}
		})
	}
}

func TestIRIPolicyCommittedCheckpointErrorPublishesCommittedGraph(t *testing.T) {
	m, _, _, dids := administrativeTransactionManager(t)
	rule, policy := provisionIRIPolicy(t, m)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	task.IRIPolicyReferences = []uuid.UUID{policy.ID}
	require.NoError(t, m.ActivateTask(task))
	old, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	store := m.stateStore.(*EncryptedStateStore)
	write := store.write
	writes := 0
	store.write = func(name string, data []byte) (securestore.Outcome, error) {
		writes++
		out, err := write(name, data)
		if err == nil && writes == 2 {
			return securestore.Committed, errors.New("injected committed checkpoint diagnostic")
		}
		return out, err
	}
	rule.Rule.Action.Value = "Delivered"
	err = m.ModifyGenericObject(rule)
	require.Error(t, err)
	require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
	require.True(t, m.administrativeAdmissionReady())
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, old.ActivationGeneration+1, current.ActivationGeneration)
	deliver, err := m.EvaluateIRIPolicy(task.XID, current.ActivationGeneration, iripolicy.Facts{})
	require.NoError(t, err)
	require.True(t, deliver)
}

func TestIRIPolicyRestartProfileChangeRevokesPriorGeneration(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	m.config.IRIPolicyProfileRevision = strings.Repeat("a", 64)
	rule, policy := provisionIRIPolicy(t, m)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	task.IRIPolicyReferences = []uuid.UUID{policy.ID}
	require.NoError(t, m.ActivateTask(task))
	old, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	cfg := m.Config()
	m.Stop()
	cfg.IRIPolicyProfileRevision = strings.Repeat("b", 64)
	restarted := NewManager(cfg, nil)
	t.Cleanup(restarted.Stop)
	require.NoError(t, restarted.PrepareAdministrativeStorage())
	require.NoError(t, restarted.SetDurableRevoker(revoker))
	require.NoError(t, restarted.restorePersistedState())
	require.True(t, restarted.applyIRIObjectSnapshot(&schema.GetAllDetailsResponse{ListOfGenericObjectResponseDetails: iriSnapshotObjects(rule, policy)}, newADMFSnapshot()))
	var canceled uint64
	restarted.SetOnIRIPolicyChanged(func(previous *InterceptTask) error { canceled = previous.ActivationGeneration; return nil })
	require.NoError(t, restarted.activateStartupTask(task))
	current, err := restarted.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, old.ActivationGeneration+1, current.ActivationGeneration)
	require.Equal(t, cfg.IRIPolicyProfileRevision, current.IRIPolicyProfileRevision)
	require.Equal(t, old.ActivationGeneration, canceled)
	require.True(t, revoker.requests[len(revoker.requests)-1].IncludeX2)
	require.False(t, restarted.ReplayTaskAuthorized(task.XID, old.ActivationGeneration))
}

func TestIRIPolicyConflictingTaskListsCannotUseOneListAsIntersection(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443, X2Enabled: true, X3Enabled: true}))
	_, policy := provisionIRIPolicy(t, m)
	task := idempotencyTask(uuid.New(), []uuid.UUID{did}, time.Time{})
	task.IRIPolicyReferences = []uuid.UUID{policy.ID}
	require.NoError(t, m.ActivateTask(task))
	held, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	incoming := cloneInterceptTask(held)
	incoming.IRIPolicyReferences = nil
	incoming.IRIPolicySourceGenerations = nil
	incoming.IRIPolicyProfileRevision = ""
	common, reason := resolveConflictAuthorization(held, incoming, nil, time.Now())
	require.Nil(t, common)
	require.Equal(t, "no_common_iri_policy", reason)
}

func iriSnapshotObjects(objects ...iripolicy.Object) *schema.ListOfGenericObjectResponseDetails {
	list := &schema.ListOfGenericObjectResponseDetails{}
	for _, object := range objects {
		id := schema.UUID(object.ID.String())
		value := iripolicy.CloneObject(object)
		list.GenericObjectResponseDetails = append(list.GenericObjectResponseDetails, &schema.GenericObjectResponseDetails{Object: &schema.GenericObject{ObjectId: &id, IRIObject: &value}})
	}
	return list
}

func TestIRIPolicyRestoreRequiresSameSnapshotGraphConfirmation(t *testing.T) {
	m, _, revoker, dids := administrativeTransactionManager(t)
	rule, policy := provisionIRIPolicy(t, m)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	task.IRIPolicyReferences = []uuid.UUID{policy.ID}
	require.NoError(t, m.ActivateTask(task))
	held, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	restarted := restartAdministrativeTestManager(t, m, revoker)
	require.Zero(t, restarted.IRIPolicyStats().ConfirmedObjects)
	require.Error(t, restarted.ActivateTask(task))
	require.False(t, restarted.ReplayTaskAuthorized(task.XID, held.ActivationGeneration))
	response := &schema.GetAllDetailsResponse{ListOfGenericObjectResponseDetails: iriSnapshotObjects(rule, policy)}
	snapshot := newADMFSnapshot()
	require.True(t, restarted.applyIRIObjectSnapshot(response, snapshot))
	require.Equal(t, 2, restarted.IRIPolicyStats().ConfirmedObjects)
	require.NoError(t, restarted.activateStartupTask(task))
	current, err := restarted.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, held.ActivationGeneration, current.ActivationGeneration)
	// A subsequent incomplete object list revokes both products and never proves absence.
	snapshot = newADMFSnapshot()
	require.False(t, restarted.applyIRIObjectSnapshot(&schema.GetAllDetailsResponse{}, snapshot))
	require.True(t, snapshot.iriMembershipUncertain)
	current, err = restarted.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusFailed, current.Status)
	require.True(t, revoker.requests[len(revoker.requests)-1].IncludeX2)
}

func TestIRIPolicyStateV2MigrationAndStrictGraph(t *testing.T) {
	state := emptyStateFixture()
	encoded, err := MarshalStateSnapshot(state)
	require.NoError(t, err)
	old := bytes.Replace(encoded, []byte(`"version":3`), []byte(`"version":2`), 1)
	old = bytes.Replace(old, []byte(`,"generic_objects":null`), nil, 1)
	migrated, err := UnmarshalStateSnapshot(old)
	require.NoError(t, err)
	require.Equal(t, StateSchemaVersion, migrated.Version)
	require.Empty(t, migrated.GenericObjects)
	rule, policy := iriAdministrativeObjects()
	rule.Generation = 1
	policy.Generation = 1
	state.GenericObjects = []iripolicy.Object{rule, policy}
	encoded, err = MarshalStateSnapshot(state)
	require.NoError(t, err)
	decoded, err := UnmarshalStateSnapshot(encoded)
	require.NoError(t, err)
	require.Equal(t, state, decoded)
	_, err = UnmarshalStateSnapshot(bytes.Replace(encoded, []byte(`"version":3`), []byte(`"version":2`), 1))
	require.ErrorIs(t, err, ErrStateSnapshot)
	state.GenericObjects[0].Generation = 0
	require.ErrorIs(t, ValidateStateSnapshot(state), ErrStateSnapshot)
}

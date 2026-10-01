//go:build li

package li

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPersistenceLegacyStateFixture(t *testing.T) {
	fixture := filepath.Join("testdata", "legacy_state_v1.json")
	state, err := loadPersistedState(fixture)
	require.NoError(t, err)
	require.NotNil(t, state)
	require.Equal(t, 1, state.Version)
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	require.Equal(t, at, state.WrittenAt)
	xid := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	did := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	radiusID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	pendingID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	retainedID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	failedID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	expiredID := uuid.MustParse("77777777-7777-4777-8777-777777777777")
	watermarkID := uuid.MustParse("88888888-8888-4888-8888-888888888888")
	removedDID := uuid.MustParse("99999999-9999-4999-8999-999999999999")
	require.Len(t, state.Tasks, 6)
	require.Equal(t, &InterceptTask{
		XID: xid, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:fixture-1@example.invalid"}},
		DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2andX3,
		ImplicitDeactivationAllowed: true, Status: TaskStatusActive,
		ActivatedAt: at, ActivationGeneration: 3,
	}, state.Tasks[0])
	require.Equal(t, radiusID, state.Tasks[1].XID)
	require.Equal(t, radius.ScopeBinding{OperatorScope: "fixture-operator/nas", ProfileRevision: "fixture-v1", OriginNodeID: "fixture-edge-a", SourceID: "fixture-eth0"}, state.Tasks[1].RADIUSScope)
	require.Equal(t, radius.MACProfileUppercaseHyphen, state.Tasks[1].RADIUSMACProfile)
	require.Equal(t, []TargetIdentity{{Type: TargetTypeNAI, Value: "Fixture@example.invalid"}, {Type: TargetTypeMACAddress, Value: "020000000001"}, {Type: TargetTypeRADIUSAttribute, Value: "570361"}}, state.Tasks[1].Targets)
	require.Equal(t, DeliveryX2Only, state.Tasks[1].DeliveryType)
	require.Equal(t, uint64(31), state.Tasks[1].ActivationGeneration)
	require.Equal(t, TaskStatusPending, state.Tasks[2].Status)
	require.Equal(t, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), state.Tasks[2].StartTime)
	require.Equal(t, TaskStatusDeactivated, state.Tasks[3].Status)
	require.Equal(t, at, state.Tasks[3].DeactivatedAt)
	require.Equal(t, TaskStatusFailed, state.Tasks[4].Status)
	require.Equal(t, "synthetic destination removed", state.Tasks[4].LastError)
	require.Equal(t, time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), state.Tasks[5].EndTime)
	for _, task := range state.Tasks[2:5] {
		require.Equal(t, []uuid.UUID{removedDID}, task.DestinationIDs)
	}
	require.Equal(t, []*persistedDestination{{DID: did, Address: "mdf.example.invalid", Port: 9443, X2Enabled: true, X3Enabled: true, ProtocolType: "X2andX3", Description: "Synthetic MDF destination", CreatedAt: at, DeliveryRevision: 5}}, state.Destinations)
	require.Equal(t, map[uuid.UUID]uint64{xid: 3, radiusID: 31, pendingID: 4, retainedID: 8, failedID: 9, watermarkID: 21}, state.Generations)
	expectedCleanup := map[uuid.UUID][]string{
		xid:         {"li-11111111-1111-4111-8111-111111111111-0"},
		radiusID:    {"li-33333333-3333-4333-8333-333333333333-0", "li-33333333-legacy"},
		retainedID:  {"li-55555555-5555-4555-8555-555555555555-0"},
		watermarkID: {"li-88888888-8888-4888-8888-888888888888-0"},
	}
	require.Equal(t, expectedCleanup, state.Cleanup)

	// Exercise startup, not only JSON decoding: active candidates stay disarmed,
	// retained/pending identities survive absent destinations, cleanup is retried,
	// and both explicit and task-only generation high-water marks are restored.
	data, err := os.ReadFile(fixture)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	pusher := &mockFilterPusher{}
	m := newStateTestManager(t, ManagerConfig{Enabled: true, StateFile: path, FilterPusher: pusher}, nil)
	require.NoError(t, m.restorePersistedState())
	require.Zero(t, m.ActiveTaskCount())
	require.Zero(t, m.FilterCount())
	require.Empty(t, pusher.updates)
	require.Len(t, m.persistedActive, 2)
	// Missing legacy presence is migrated conservatively, without authority.
	for _, task := range state.Tasks {
		if !IsRADIUSTask(task) {
			task.Definition = TaskDefinitionState{Source: DefinitionRestore, Restored: true, Completeness: DefinitionCompleteness{
				Mediation: !task.StartTime.IsZero(), Start: !task.StartTime.IsZero(), End: !task.EndTime.IsZero(), EndProvided: !task.EndTime.IsZero(), Implicit: task.ImplicitDeactivationAllowed,
			}}
		}
	}
	require.Equal(t, state.Tasks[0], m.persistedActive[xid])
	require.Equal(t, state.Tasks[1], m.persistedActive[radiusID])
	for _, task := range state.Tasks[2:5] {
		restored, err := m.GetTaskDetails(task.XID)
		require.NoError(t, err)
		require.Equal(t, task, restored)
	}
	_, err = m.GetTaskDetails(expiredID)
	require.ErrorIs(t, err, ErrTaskNotFound)
	_, err = m.GetDestination(removedDID)
	require.ErrorIs(t, err, ErrDestinationNotFound)
	destination, err := m.GetDestination(did)
	require.NoError(t, err)
	require.Equal(t, uint64(5), destination.DeliveryRevision)
	require.Equal(t, "X2andX3", destination.ProtocolType)
	watermarks := map[uuid.UUID]uint64{xid: 3, radiusID: 31, pendingID: 4, retainedID: 8, failedID: 9, expiredID: 13, watermarkID: 21}
	require.Equal(t, watermarks, m.registry.generations)
	for id, generation := range watermarks {
		require.False(t, m.ReplayTaskAuthorized(id, generation), "a file cannot authorize replay")
	}
	var cleanupIDs []string
	for _, ids := range expectedCleanup {
		cleanupIDs = append(cleanupIDs, ids...)
	}
	require.ElementsMatch(t, cleanupIDs, pusher.deletes)
}

//go:build li

package li

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func convergenceDetails(xid, did uuid.UUID, complete bool) *schema.TaskResponseDetails {
	target := schema.SIPURI("sip:synthetic@example.invalid")
	td := makeTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}})
	if complete {
		start := schema.QualifiedMicrosecondDateTime("2020-01-01T00:00:00.000000Z")
		td.TaskDetails.ListOfMediationDetails = &schema.ListOfMediationDetails{MediationDetails: []*schema.MediationDetails{{StartTime: &start}}}
	} else {
		td.TaskDetails.ImplicitDeactivationAllowed = nil
	}
	return td
}

func applyConvergence(t *testing.T, m *Manager, td *schema.TaskResponseDetails) *SnapshotTask {
	t.Helper()
	in, err := ConvertSnapshotTask(td)
	require.NoError(t, err)
	require.NoError(t, m.applySnapshotDefinition(in))
	return in
}

func TestSnapshotDefinitionPresence(t *testing.T) {
	xid, did := uuid.New(), uuid.New()
	partial, err := ConvertSnapshotTask(convergenceDetails(xid, did, false))
	require.NoError(t, err)
	require.False(t, partial.Completeness.Complete())
	require.False(t, partial.Completeness.End)
	full, err := ConvertSnapshotTask(convergenceDetails(xid, did, true))
	require.NoError(t, err)
	require.True(t, full.Completeness.Complete())
	require.True(t, full.Completeness.End)
	require.False(t, full.Completeness.EndProvided)
	for _, kind := range []string{"empty_list", "empty_start", "inconsistent", "end_before_start"} {
		t.Run(kind, func(t *testing.T) {
			td := convergenceDetails(xid, did, true)
			switch kind {
			case "empty_list":
				td.TaskDetails.ListOfMediationDetails.MediationDetails = nil
			case "empty_start":
				v := schema.QualifiedMicrosecondDateTime("")
				td.TaskDetails.ListOfMediationDetails.MediationDetails[0].StartTime = &v
			case "inconsistent":
				td.TaskDetails.ListOfMediationDetails.MediationDetails = append(td.TaskDetails.ListOfMediationDetails.MediationDetails, &schema.MediationDetails{})
			case "end_before_start":
				v := schema.QualifiedMicrosecondDateTime("2019-01-01T00:00:00Z")
				td.TaskDetails.ListOfMediationDetails.MediationDetails[0].EndTime = &v
			}
			_, err := ConvertSnapshotTask(td)
			require.Error(t, err)
		})
	}
}

func TestDefinitionConvergenceModesAndFullPush(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			m := NewManager(ManagerConfig{Enabled: true, ADMFCompleteTaskContract: strict}, nil)
			did, xid := uuid.New(), uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			applyConvergence(t, m, convergenceDetails(xid, did, false))
			stats := m.Stats().Definitions
			require.EqualValues(t, 1, stats.Incomplete)
			require.EqualValues(t, 1, stats.UnknownWindows)
			if strict {
				_, err := m.GetTaskDetails(xid)
				require.ErrorIs(t, err, ErrTaskNotFound)
				require.Zero(t, m.FilterCount())
			} else {
				require.Equal(t, 1, m.ActiveTaskCount())
				require.Equal(t, 1, m.FilterCount())
			}
			full, err := ConvertSnapshotTask(convergenceDetails(xid, did, true))
			require.NoError(t, err)
			push := &x1.Task{XID: xid, Targets: []x1.TargetIdentity{{Type: x1.TargetTypeSIPURI, Value: full.Task.Targets[0].Value}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: x1.DeliveryX2andX3, StartTime: full.Task.StartTime, ImplicitDeactivationAllowed: true}
			require.NoError(t, m.ActivateTaskX1(push))
			live, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, DefinitionPush, live.Definition.Source)
			require.True(t, live.Definition.Completeness.Complete())
			require.Equal(t, full.Task.StartTime, live.StartTime)
			require.Equal(t, 1, m.FilterCount())
			require.NoError(t, m.ActivateTaskX1(push))
			retry, _ := m.GetTaskDetails(xid)
			require.Equal(t, live.ActivationGeneration, retry.ActivationGeneration)
			// A partial response cannot erase the repaired window or boolean.
			partial := convergenceDetails(xid, did, false)
			applyConvergence(t, m, partial)
			after, _ := m.GetTaskDetails(xid)
			require.Equal(t, live, after)
			// Later stale full pulls cannot replace a pushed definition.
			changed := convergenceDetails(xid, did, true)
			end := schema.QualifiedMicrosecondDateTime("2090-01-01T00:00:00Z")
			changed.TaskDetails.ListOfMediationDetails.MediationDetails[0].EndTime = &end
			applyConvergence(t, m, changed)
			after, _ = m.GetTaskDetails(xid)
			require.Equal(t, time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC), after.EndTime)
			require.EqualValues(t, 1, m.Stats().Definitions.Conflicts)
			et := time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC)
			require.NoError(t, m.ModifyTaskX1(xid, &x1.TaskModification{EndTime: &et}))
			require.Zero(t, m.Stats().Definitions.Conflicts)
		})
	}
}

func TestDefinitionPullRepairAndRollback(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	did, xid := uuid.New(), uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	applyConvergence(t, m, convergenceDetails(xid, did, false))
	before, _ := m.GetTaskDetails(xid)
	full := convergenceDetails(xid, did, true)
	applyConvergence(t, m, full)
	live, _ := m.GetTaskDetails(xid)
	require.Greater(t, live.ActivationGeneration, before.ActivationGeneration)
	require.EqualValues(t, 1, m.Stats().Definitions.Repairs)
	_, ok := m.AcquireTaskAdmission(xid, before.ActivationGeneration)
	require.False(t, ok)
	// Destinations are validated before any filter or generation change.
	bad := convergenceDetails(xid, uuid.New(), true)
	in, err := ConvertSnapshotTask(bad)
	require.NoError(t, err)
	require.ErrorIs(t, m.applySnapshotDefinition(in), ErrDestinationNotFound)
	after, _ := m.GetTaskDetails(xid)
	require.Equal(t, live, after)
	require.Equal(t, 1, m.FilterCount())
}

func TestDefinitionCandidateRestartAndReplay(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			did, xid := uuid.New(), uuid.New()
			cfg := ManagerConfig{Enabled: true, StateFile: path, ADMFCompleteTaskContract: strict}
			m := newStateTestManager(t, cfg, nil)
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			applyConvergence(t, m, convergenceDetails(xid, did, false))
			m.Stop()
			next := newStateTestManager(t, cfg, nil)
			require.NoError(t, next.restorePersistedState())
			require.False(t, next.ReplayTaskAuthorized(xid, 1))
			require.Zero(t, next.FilterCount())
			applyConvergence(t, next, convergenceDetails(xid, did, false))
			require.False(t, next.ReplayTaskAuthorized(xid, 1))
			applyConvergence(t, next, convergenceDetails(xid, did, true))
			task, err := next.GetTaskDetails(xid)
			require.NoError(t, err)
			require.True(t, task.Definition.Completeness.Complete())
			require.False(t, next.ReplayTaskAuthorized(xid, 1), "changed start cannot reuse historical authorization")
		})
	}
}

func TestCompleteSnapshotAloneConfirmsReplayAfterPartial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	did, xid := uuid.New(), uuid.New()
	cfg := ManagerConfig{Enabled: true, StateFile: path}
	m := newStateTestManager(t, cfg, nil)
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	applyConvergence(t, m, convergenceDetails(xid, did, true))
	old, _ := m.GetTaskDetails(xid)
	m.Stop()
	next := newStateTestManager(t, cfg, nil)
	require.NoError(t, next.restorePersistedState())
	applyConvergence(t, next, convergenceDetails(xid, did, false))
	require.False(t, next.ReplayTaskAuthorized(xid, old.ActivationGeneration))
	applyConvergence(t, next, convergenceDetails(xid, did, true))
	require.True(t, next.ReplayTaskAuthorized(xid, old.ActivationGeneration))
}

func TestStrictTransitionRequiresAuthoritativeRepair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	did, xid := uuid.New(), uuid.New()
	cfg := ManagerConfig{Enabled: true, StateFile: path}
	m := newStateTestManager(t, cfg, nil)
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	applyConvergence(t, m, convergenceDetails(xid, did, false))
	m.Stop()
	cfg.ADMFCompleteTaskContract = true
	blocked := newStateTestManager(t, cfg, nil)
	require.ErrorContains(t, blocked.Start(), "repairing persisted incomplete")
	blocked.Stop()
	response := buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{convergenceDetails(xid, did, true)})
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, err := fmt.Fprint(w, response)
		require.NoError(t, err)
	})
	cfg.ADMFEndpoint = server.URL
	cfg.SyncOnStartup = true
	repaired := newStateTestManager(t, cfg, nil)
	require.NoError(t, repaired.Start())
	live, err := repaired.GetTaskDetails(xid)
	require.NoError(t, err)
	require.True(t, live.Definition.Completeness.Complete())
}

func TestMalformedKnownSnapshotPreservesListedTaskButWithdrawsOrphan(t *testing.T) {
	xid, listed, did := uuid.New(), uuid.New(), testDestDID
	bad := convergenceDetails(listed, did, true)
	bad.TaskDetails.ListOfMediationDetails = &schema.ListOfMediationDetails{}
	m := admfServing(t, nil, 1, bad)
	defer m.Stop()
	snapshotTestTask(t, m, xid, did)
	snapshotTestTask(t, m, listed, did)
	held, err := m.GetTaskDetails(listed)
	require.NoError(t, err)
	require.Error(t, m.syncStateFromADMF(context.Background()))
	task, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, TaskStatusDeactivated, task.Status, "known malformed ID does not hide independent task absence")
	retained, err := m.GetTaskDetails(listed)
	require.NoError(t, err)
	require.True(t, retained.IsActive())
	require.False(t, m.ReplayTaskAuthorized(listed, held.ActivationGeneration), "malformed definition cannot confirm replay")
}

func TestSnapshotReconcilesHeldDefinitionAndRejectsLaterStalePull(t *testing.T) {
	did, other, xid := uuid.New(), uuid.New(), uuid.New()
	full := convergenceDetails(xid, did, true)
	var response atomic.Value
	publish := func(td *schema.TaskResponseDetails) {
		response.Store(buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443), makeDestinationResponseDetails(other, "127.0.0.1", 9443)}, []*schema.TaskResponseDetails{td}))
	}
	publish(full)
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, err := fmt.Fprint(w, response.Load().(string))
		require.NoError(t, err)
	})
	m := newStateTestManager(t, ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state"), ADMFEndpoint: server.URL}, nil)
	require.NoError(t, m.syncStateFromADMF(context.Background()))
	original, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	changed := convergenceDetails(xid, other, true)
	end := schema.QualifiedMicrosecondDateTime("2090-01-01T00:00:00Z")
	changed.TaskDetails.ListOfMediationDetails.MediationDetails[0].EndTime = &end
	target := schema.SIPURI("sip:replacement@example.invalid")
	changed.TaskDetails.TargetIdentifiers.TargetIdentifier[0].SipUri = &target
	changed.TaskDetails.DeliveryType = "X2Only"
	publish(changed)
	m.reconcileWithADMF()
	repaired, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{other}, repaired.DestinationIDs)
	require.Equal(t, string(target), repaired.Targets[0].Value)
	require.Equal(t, DeliveryX2Only, repaired.DeliveryType)
	require.False(t, repaired.EndTime.IsZero())
	require.Greater(t, repaired.ActivationGeneration, original.ActivationGeneration)
	_, ok := m.AcquireTaskAdmission(xid, original.ActivationGeneration)
	require.False(t, ok)
	// Explicit push modification establishes authority. The ADMF subsequently
	// responds with its older complete definition; local receipt time is no proof.
	newEnd := time.Date(2091, 1, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, m.ModifyTaskX1(xid, &x1.TaskModification{EndTime: &newEnd}))
	m.reconcileWithADMF()
	held, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, repaired.EndTime, held.EndTime)
	require.True(t, held.Definition.Conflict)
	require.Equal(t, DefinitionPush, held.Definition.Source)
	require.EqualValues(t, 1, m.Stats().Definitions.Repairs)
}

func TestPartialRestoreCannotUseUnconfirmedRetainedDestination(t *testing.T) {
	did, other, xid := uuid.New(), uuid.New(), uuid.New()
	cfg := ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state")}
	m := newStateTestManager(t, cfg, nil)
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	applyConvergence(t, m, convergenceDetails(xid, did, true))
	m.Stop()
	next := newStateTestManager(t, cfg, nil)
	require.NoError(t, next.restorePersistedState())
	require.NoError(t, next.CreateDestination(&Destination{DID: other, Address: "127.0.0.1", Port: 9443}))
	partial, err := ConvertSnapshotTask(convergenceDetails(xid, other, false))
	require.NoError(t, err)
	partial.confirmedDestinations = map[uuid.UUID]bool{other: true}
	require.ErrorIs(t, next.applySnapshotDefinition(partial), ErrDestinationNotFound)
	require.Zero(t, next.FilterCount())
	require.False(t, next.ReplayTaskAuthorized(xid, 1))
}

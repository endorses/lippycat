//go:build li

package li

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type startupFailingPusher struct {
	*stubFilterStore
	fail atomic.Bool
}

func (p *startupFailingPusher) UpdateFilter(filter *management.Filter) error {
	if p.fail.Load() {
		return errors.New("injected filter activation failure")
	}
	return p.stubFilterStore.UpdateFilter(filter)
}

func startupResponse(t *testing.T, xid, did uuid.UUID) string {
	t.Helper()
	target := schema.SIPURI("sip:alice@example.com")
	return buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{makeCompleteTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}})})
}

func startupQuery(t *testing.T, r *http.Request) bool {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	return strings.Contains(string(body), "GetAllDetailsRequest")
}

func TestStartupSyncRetryPersistedCandidates(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		interval time.Duration
		initial  string
	}{
		{"timeout/no-periodic", 0, ""},
		{"timeout/periodic", 10 * time.Millisecond, ""},
		{"incomplete-snapshot", 0, `<GetAllDetailsResponse><neStatusDetails/><listOfTaskResponseDetails/></GetAllDetailsResponse>`},
		{"wrong-response-type", 0, `<X1Response xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><x1ResponseMessage xsi:type="GetNEStatusResponse"><neStatusDetails/></x1ResponseMessage></X1Response>`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			xid, did := uuid.New(), uuid.New()
			target := schema.SIPURI("sip:alice@example.com")
			task, err := TaskResponseDetailsToInterceptTask(makeCompleteTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}}))
			require.NoError(t, err)
			task.Status, task.ActivationGeneration = TaskStatusActive, 7
			path := filepath.Join(t.TempDir(), "state")
			require.NoError(t, writePersistedState(path, &persistedState{Tasks: []*InterceptTask{task}, Destinations: []*persistedDestination{{DID: did, Address: "unconfirmed.example", Port: 8443}}}))
			var recovered atomic.Bool
			var queries atomic.Int32
			server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				if !startupQuery(t, r) {
					w.WriteHeader(http.StatusOK)
					return
				}
				queries.Add(1)
				if !recovered.Load() {
					if scenario.initial != "" {
						_, err := fmt.Fprint(w, scenario.initial)
						require.NoError(t, err)
						return
					}
					<-r.Context().Done()
					return
				}
				_, err := fmt.Fprint(w, startupResponse(t, xid, did))
				require.NoError(t, err)
			})
			m := newStateTestManager(t, ManagerConfig{Enabled: true, StateFile: path, ADMFEndpoint: server.URL, SyncOnStartup: true, SyncTimeout: 40 * time.Millisecond, ReconcileInterval: scenario.interval}, nil)
			var delivered atomic.Int32
			m.SetPacketProcessor(func(*InterceptTask, *types.PacketDisplay) { delivered.Add(1) })
			require.NoError(t, m.Start())
			defer m.Stop()
			require.Equal(t, StartupSyncRetryableFailure, m.Stats().StartupSync.State)
			require.NotEmpty(t, m.StartupSyncStatus().LastFailure)
			require.False(t, m.ReplayTaskAuthorized(xid, 7))
			m.ProcessPacket(&types.PacketDisplay{}, []string{fmt.Sprintf("li-%s-0", xid)})
			require.Zero(t, delivered.Load(), "candidate must not authorize X2/X3 callback")
			require.Zero(t, m.ActiveTaskCount())
			m.adminMu.Lock()
			_, retained := m.persistenceCandidates[xid]
			m.adminMu.Unlock()
			require.True(t, retained, "incomplete snapshot must preserve the unconfirmed candidate")
			recovered.Store(true)
			require.Eventually(t, func() bool { return m.StartupSyncStatus().State == StartupSyncSucceeded }, 4*time.Second, 10*time.Millisecond)
			require.True(t, m.ReplayTaskAuthorized(xid, 7))
			require.NotZero(t, m.StartupSyncStatus().RecoveredAt)
			active, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			for i := 0; i < 3; i++ {
				m.reconcileWithADMF()
			}
			again, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, active.ActivationGeneration, again.ActivationGeneration)
			require.Equal(t, active.ActivatedAt, again.ActivatedAt)
			require.Equal(t, 1, m.FilterCount())
			require.Equal(t, 1, len(m.ListDestinations()))
			require.GreaterOrEqual(t, queries.Load(), int32(2))
		})
	}
}

func TestStartupSyncUnsupportedTerminal(t *testing.T) {
	for _, code := range []int{7, 1080} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var queries atomic.Int32
			server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				if !startupQuery(t, r) {
					w.WriteHeader(http.StatusOK)
					return
				}
				queries.Add(1)
				_, err := fmt.Fprintf(w, `<X1Response><errorResponse><requestMessageType>GetAllDetailsRequest</requestMessageType><errorInformation><errorCode>%d</errorCode><errorDescription>Unsupported</errorDescription></errorInformation></errorResponse></X1Response>`, code)
				require.NoError(t, err)
			})
			m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, SyncOnStartup: true, ReconcileInterval: 10 * time.Millisecond}, nil)
			require.NoError(t, m.Start())
			defer m.Stop()
			require.Equal(t, StartupSyncUnsupported, m.StartupSyncStatus().State)
			for i := 0; i < 3; i++ {
				m.reconcileWithADMF()
			}
			require.Equal(t, int32(1), queries.Load())
			require.Zero(t, m.ActiveTaskCount())
		})
	}
}

func TestStartupSyncPartialSnapshotAndUnconfirmedDestination(t *testing.T) {
	xid, did, orphan := uuid.New(), uuid.New(), uuid.New()
	target := schema.SIPURI("sip:alice@example.com")
	good := makeCompleteTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}})
	var mode atomic.Int32
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !startupQuery(t, r) {
			w.WriteHeader(http.StatusOK)
			return
		}
		var response string
		switch mode.Load() {
		case 0:
			response = buildGetAllDetailsResponseXML(nil, []*schema.TaskResponseDetails{good})
		case 1:
			response = buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{good, {}})
		default:
			response = startupResponse(t, xid, did)
		}
		_, err := fmt.Fprint(w, response)
		require.NoError(t, err)
	})
	store := newStubFilterStore()
	m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, SyncOnStartup: true, FilterPusher: store}, nil)
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "unconfirmed.example", Port: 8443}))
	require.NoError(t, m.ActivateTask(&InterceptTask{XID: orphan, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:bob@example.com"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2andX3}))
	require.True(t, m.attemptStartupSync())
	require.Equal(t, StartupSyncRetryableFailure, m.StartupSyncStatus().State)
	_, err := m.GetTaskDetails(xid)
	require.ErrorIs(t, err, ErrTaskNotFound)
	mode.Store(1)
	require.True(t, m.attemptStartupSync())
	orphanTask, err := m.GetTaskDetails(orphan)
	require.NoError(t, err)
	require.Equal(t, TaskStatusActive, orphanTask.Status, "partial snapshot must not remove possible orphan")
	mode.Store(2)
	require.False(t, m.attemptStartupSync())
	require.Equal(t, StartupSyncSucceeded, m.StartupSyncStatus().State)
	orphanTask, err = m.GetTaskDetails(orphan)
	require.NoError(t, err)
	require.Equal(t, TaskStatusDeactivated, orphanTask.Status)
	m.Stop()
}

func TestStartupSyncStopDuringRequestAndBackoff(t *testing.T) {
	for _, inRequest := range []bool{false, true} {
		t.Run(fmt.Sprint(inRequest), func(t *testing.T) {
			entered := make(chan struct{}, 1)
			server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				if !startupQuery(t, r) {
					w.WriteHeader(http.StatusOK)
					return
				}
				select {
				case entered <- struct{}{}:
				default:
				}
				<-r.Context().Done()
			})
			m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, SyncOnStartup: true, SyncTimeout: 500 * time.Millisecond}, nil)
			require.NoError(t, m.Start())
			<-entered
			if inRequest {
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("retry never entered")
				}
			}
			done := make(chan struct{})
			go func() { m.Stop(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Stop did not cancel/join startup recovery")
			}
		})
	}
}

func TestStartupSyncSerializesSnapshotWithX1AndPeriodic(t *testing.T) {
	xid, did := uuid.New(), uuid.New()
	entered, release := make(chan struct{}), make(chan struct{})
	var queries atomic.Int32
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !startupQuery(t, r) {
			w.WriteHeader(http.StatusOK)
			return
		}
		if queries.Add(1) == 1 {
			close(entered)
			<-release
		}
		_, err := fmt.Fprint(w, startupResponse(t, xid, did))
		require.NoError(t, err)
	})
	m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, SyncOnStartup: true}, nil)
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	target := schema.SIPURI("sip:alice@example.com")
	initial, err := TaskResponseDetailsToInterceptTask(makeCompleteTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}}))
	require.NoError(t, err)
	require.NoError(t, m.ActivateTask(initial))
	synced := make(chan bool, 1)
	go func() { synced <- m.attemptStartupSync() }()
	<-entered
	periodicDone := make(chan struct{})
	go func() { m.reconcileWithADMF(); close(periodicDone) }()
	x1Done := make(chan error, 1)
	go func() { x1Done <- m.DeactivateTaskX1(xid) }()
	select {
	case err := <-x1Done:
		t.Fatalf("X1 mutation overtook snapshot: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.False(t, <-synced)
	require.NoError(t, <-x1Done)
	<-periodicDone
	require.Equal(t, int32(1), queries.Load(), "periodic startup attempt must coalesce after recovery")
	task, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, TaskStatusDeactivated, task.Status)
	require.Zero(t, m.FilterCount())
	m.Stop()
}

func TestStartupSyncEntryApplicationFailuresRemainPending(t *testing.T) {
	for _, entry := range []string{"destination", "activation"} {
		t.Run(entry, func(t *testing.T) {
			xid, did := uuid.New(), uuid.New()
			var valid atomic.Bool
			server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				if !startupQuery(t, r) {
					w.WriteHeader(http.StatusOK)
					return
				}
				response := startupResponse(t, xid, did)
				if entry == "destination" && !valid.Load() {
					target := schema.SIPURI("sip:alice@example.com")
					response = buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{{}}, []*schema.TaskResponseDetails{makeCompleteTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}})})
				}
				_, err := fmt.Fprint(w, response)
				require.NoError(t, err)
			})
			pusher := &startupFailingPusher{stubFilterStore: newStubFilterStore()}
			pusher.fail.Store(entry == "activation")
			m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, SyncOnStartup: true, FilterPusher: pusher}, nil)
			require.NoError(t, m.Start())
			defer m.Stop()
			require.Equal(t, StartupSyncRetryableFailure, m.StartupSyncStatus().State)
			require.Zero(t, m.ActiveTaskCount())
			require.Zero(t, m.FilterCount())
			valid.Store(true)
			pusher.fail.Store(false)
			require.Eventually(t, func() bool { return m.StartupSyncStatus().State == StartupSyncSucceeded }, 4*time.Second, 10*time.Millisecond)
			require.Equal(t, 1, m.ActiveTaskCount())
			require.Equal(t, 1, m.FilterCount())
		})
	}
}

func TestPartialStartupDoesNotStarvePeriodicReconciliation(t *testing.T) {
	xid, did, orphan := uuid.New(), uuid.New(), uuid.New()
	var changed atomic.Bool
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !startupQuery(t, r) {
			w.WriteHeader(http.StatusOK)
			return
		}
		target := schema.SIPURI("sip:before@example.invalid")
		if changed.Load() {
			target = "sip:after@example.invalid"
		}
		good := makeCompleteTaskResponseDetails(xid, []uuid.UUID{did}, []schema.TargetIdentifier{{SipUri: &target}})
		response := buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{good, {}})
		_, err := fmt.Fprint(w, response)
		require.NoError(t, err)
	})
	m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, SyncOnStartup: true}, nil)
	defer m.Stop()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	require.NoError(t, m.ActivateTask(&InterceptTask{XID: orphan, Targets: []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:orphan@example.invalid"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: DeliveryX2andX3}))
	require.True(t, m.attemptStartupSync())
	require.True(t, m.StartupSyncStatus().partialSnapshot)
	changed.Store(true)
	m.reconcileWithADMF()
	require.EqualValues(t, 1, m.StartupSyncStatus().Attempts, "periodic reconciliation must not divert into startup retry")
	require.Equal(t, StartupSyncRetryableFailure, m.StartupSyncStatus().State)
	task, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, "sip:after@example.invalid", task.Targets[0].Value)
	retained, err := m.GetTaskDetails(orphan)
	require.NoError(t, err)
	require.Equal(t, TaskStatusActive, retained.Status, "a malformed entry must still suppress orphan removal")
}

func TestSnapshotFailureIdentifiersDoNotExposeMalformedValues(t *testing.T) {
	id := uuid.New()
	value := schema.UUID(id.String())
	td := &schema.TaskResponseDetails{TaskDetails: &schema.TaskDetails{XId: &value}}
	dd := &schema.DestinationResponseDetails{DestinationDetails: &schema.DestinationDetails{DId: &value}}
	require.Equal(t, id.String(), snapshotTaskID(td))
	require.Equal(t, id.String(), snapshotDestinationID(dd))
	value = "sip:sensitive@example.invalid"
	require.Equal(t, "unknown", snapshotTaskID(td))
	require.Equal(t, "unknown", snapshotDestinationID(dd))
	require.Equal(t, "unknown", snapshotTaskID(nil))
	require.Equal(t, "unknown", snapshotDestinationID(nil))
}

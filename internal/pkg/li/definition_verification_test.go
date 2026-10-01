//go:build li

package li

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Production ADMF open-ended definitions omit implicitDeactivationAllowed.
func productionOpenDefinition(xid, did uuid.UUID) *schema.TaskResponseDetails {
	td := convergenceDetails(xid, did, true)
	td.TaskDetails.ImplicitDeactivationAllowed = nil
	return td
}

func TestProductionOpenDefinitionStartupAndStrictTransition(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			xid, did := uuid.New(), uuid.New()
			td := productionOpenDefinition(xid, did)
			response := buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{td})
			admf := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, err := io.WriteString(w, response)
				require.NoError(t, err)
			})
			cfg := ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state"), ADMFEndpoint: admf.URL, SyncOnStartup: true, ADMFCompleteTaskContract: strict}
			m := newStateTestManager(t, cfg, nil)
			require.NoError(t, m.Start())
			task, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.True(t, task.Definition.Completeness.Complete())
			require.False(t, task.Definition.Completeness.Implicit)
			require.False(t, task.ImplicitDeactivationAllowed)
			require.Equal(t, 1, m.FilterCount())
			require.Zero(t, m.Stats().Definitions.Incomplete)
			require.EqualValues(t, 1, m.Stats().Definitions.OpenEnded)
			m.Stop()
			// Switching an already complete production-shaped definition to
			// strict mode needs no artificial implicit flag or repair.
			cfg.ADMFCompleteTaskContract = true
			next := newStateTestManager(t, cfg, nil)
			require.NoError(t, next.Start())
			restored, err := next.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, task.ActivationGeneration, restored.ActivationGeneration)
			require.True(t, next.ReplayTaskAuthorized(xid, task.ActivationGeneration))
			require.Equal(t, 1, next.FilterCount())
		})
	}
}

func TestRestoredPushRenewalConflictRemainsArmedAndReportedOnce(t *testing.T) {
	xid, did := uuid.New(), uuid.New()
	var reports atomic.Int32
	renewed := productionOpenDefinition(xid, did)
	end := schema.QualifiedMicrosecondDateTime(time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339Nano))
	renewed.TaskDetails.ListOfMediationDetails.MediationDetails[0].EndTime = &end
	implicit := true
	renewed.TaskDetails.ImplicitDeactivationAllowed = &implicit
	response := buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{renewed})
	admf := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if strings.Contains(string(body), "ReportTaskIssueRequest") {
			require.Contains(t, string(body), "retaining X1 definition")
			reports.Add(1)
			_, err = io.WriteString(w, "<ReportTaskIssueResponse/>")
		} else {
			_, err = io.WriteString(w, response)
		}
		require.NoError(t, err)
	})
	cfg := ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state")}
	first := newStateTestManager(t, cfg, nil)
	require.NoError(t, first.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	original, err := ConvertSnapshotTask(renewed)
	require.NoError(t, err)
	original.Task.EndTime = time.Now().Add(time.Hour).UTC()
	original.Task.Definition = TaskDefinitionState{}
	require.NoError(t, first.ActivateTask(original.Task))
	before, err := first.GetTaskDetails(xid)
	require.NoError(t, err)
	first.Stop()
	cfg.ADMFEndpoint, cfg.SyncOnStartup = admf.URL, true
	next := newStateTestManager(t, cfg, nil)
	require.NoError(t, next.Start())
	held, err := next.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, TaskStatusActive, held.Status)
	require.Equal(t, before.EndTime, held.EndTime)
	require.True(t, held.Definition.Conflict)
	require.Equal(t, 1, next.FilterCount())
	require.False(t, next.ReplayTaskAuthorized(xid, before.ActivationGeneration))
	require.Eventually(t, func() bool { return reports.Load() == 1 }, 3*time.Second, time.Millisecond)
	for range 3 {
		next.reconcileWithADMF()
	}
	require.EqualValues(t, 1, reports.Load())
	next.Stop()
	next = newStateTestManager(t, cfg, nil)
	require.NoError(t, next.Start())
	retained, err := next.GetTaskDetails(xid)
	require.NoError(t, err)
	require.True(t, retained.Definition.Conflict)
	require.Equal(t, before.EndTime, retained.EndTime)
	require.Equal(t, 1, next.FilterCount())
	require.EqualValues(t, 1, reports.Load(), "persisted conflicts do not report on every restart")
	require.False(t, next.ReplayTaskAuthorized(xid, before.ActivationGeneration))
	// Explicit renewal clears the conflict without granting historical replay.
	renewedEnd, err := time.Parse(time.RFC3339Nano, string(end))
	require.NoError(t, err)
	require.NoError(t, next.ModifyTaskX1(xid, &x1.TaskModification{EndTime: &renewedEnd}))
	require.Zero(t, next.Stats().Definitions.Conflicts)
	require.False(t, next.ReplayTaskAuthorized(xid, before.ActivationGeneration))
}

func TestConcurrentCompleteStaleSnapshotThenFirstPush(t *testing.T) {
	xid, did := uuid.New(), uuid.New()
	stale := productionOpenDefinition(xid, did)
	response := buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{stale})
	entered, release := make(chan struct{}), make(chan struct{})
	admf := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		if !strings.Contains(string(body), "GetAllDetailsRequest") {
			_, err = io.WriteString(w, "<X1Response/>")
			require.NoError(t, err)
			return
		}
		close(entered)
		<-release
		_, err = io.WriteString(w, response)
		require.NoError(t, err)
	})
	m := newStateTestManager(t, ManagerConfig{Enabled: true, ADMFEndpoint: admf.URL}, nil)
	pulled := make(chan error, 1)
	go func() { pulled <- m.syncStateFromADMF(context.Background()) }()
	<-entered
	pushed, pushing := make(chan error, 1), make(chan struct{})
	start := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	go func() {
		close(pushing)
		pushed <- m.ActivateTaskX1(&x1.Task{XID: xid, Targets: []x1.TargetIdentity{{Type: x1.TargetTypeSIPURI, Value: "sip:newer@example.invalid"}}, DestinationIDs: []uuid.UUID{did}, DeliveryType: x1.DeliveryX2andX3, StartTime: start, DefinitionPresence: &x1.TaskDefinitionPresence{Mediation: true, Start: true, End: true}})
	}()
	<-pushing
	close(release)
	require.NoError(t, <-pulled)
	require.NoError(t, <-pushed)
	task, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.Equal(t, DefinitionPush, task.Definition.Source)
	require.Equal(t, start, task.StartTime)
	require.Equal(t, "sip:newer@example.invalid", task.Targets[0].Value)
	require.Equal(t, 1, m.FilterCount())
	applyConvergence(t, m, stale)
	retained, err := m.GetTaskDetails(xid)
	require.NoError(t, err)
	require.True(t, equivalentTaskDefinition(task, retained))
	require.True(t, retained.Definition.Conflict)
}

func TestRawX1OpenPushAfterPartialPull(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			certDir := filepath.Join("..", "..", "..", "test", "testcerts", "li")
			certFile, keyFile := filepath.Join(certDir, "x1-server-cert.pem"), filepath.Join(certDir, "x1-server-key.pem")
			caFile := filepath.Join(certDir, "ca-cert.pem")
			clientCert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "admf-client-cert.pem"), filepath.Join(certDir, "admf-client-key.pem"))
			require.NoError(t, err)
			m := newStateTestManager(t, ManagerConfig{Enabled: true, ADMFCompleteTaskContract: strict, X1ListenAddr: "127.0.0.1:0", X1TLSCertFile: certFile, X1TLSKeyFile: keyFile, X1TLSCAFile: caFile, NEIdentifier: "test-ne"}, nil)
			require.NoError(t, m.Start())
			xid, did := uuid.New(), uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			applyConvergence(t, m, convergenceDetails(xid, did, false))
			ca, err := os.ReadFile(caFile)
			require.NoError(t, err)
			roots := x509.NewCertPool()
			require.True(t, roots.AppendCertsFromPEM(ca))
			transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{clientCert}}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			raw := fmt.Sprintf(`<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><x1RequestMessage xsi:type="ActivateTaskRequest"><admfIdentifier>test-admf</admfIdentifier><neIdentifier>test-ne</neIdentifier><version>v1.22.1</version><x1TransactionId>%s</x1TransactionId><admfTimestamp>2026-10-01T00:00:00.000000Z</admfTimestamp><taskDetails><xId>%s</xId><targetIdentifiers><targetIdentifier><sipUri>sip:synthetic@example.invalid</sipUri></targetIdentifier></targetIdentifiers><deliveryType>X2andX3</deliveryType><listOfDIDs><dId>%s</dId></listOfDIDs><listOfMediationDetails><mediationDetails><LIID>test-window</LIID><deliveryType>HI2andHI3</deliveryType><StartTime>2020-01-01T00:00:00.000000Z</StartTime></mediationDetails></listOfMediationDetails></taskDetails></x1RequestMessage></X1Request>`, uuid.New(), xid, did)
			resp, err := client.Post("https://"+m.x1Server.Addr()+"/", "application/xml", strings.NewReader(raw))
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, resp.Body.Close())
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.NotContains(t, string(body), "ErrorResponse")
			require.NotContains(t, string(body), "<errorCode>")
			task, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, DefinitionPush, task.Definition.Source)
			require.True(t, task.Definition.Completeness.Complete())
			require.False(t, task.Definition.Completeness.Implicit)
			require.False(t, task.ImplicitDeactivationAllowed)
			require.False(t, task.StartTime.IsZero())
			require.Equal(t, 1, m.FilterCount())
		})
	}
}

func TestConflictingRestoreCannotUseUnconfirmedRetainedDestination(t *testing.T) {
	xid, did, other := uuid.New(), uuid.New(), uuid.New()
	cfg := ManagerConfig{Enabled: true, StateFile: filepath.Join(t.TempDir(), "state")}
	first := newStateTestManager(t, cfg, nil)
	require.NoError(t, first.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	converted, err := ConvertSnapshotTask(productionOpenDefinition(xid, did))
	require.NoError(t, err)
	converted.Task.Definition.Source = DefinitionPush
	require.NoError(t, first.ActivateTask(converted.Task))
	old, err := first.GetTaskDetails(xid)
	require.NoError(t, err)
	first.Stop()
	next := newStateTestManager(t, cfg, nil)
	require.NoError(t, next.restorePersistedState())
	require.NoError(t, next.CreateDestination(&Destination{DID: other, Address: "127.0.0.1", Port: 9443}))
	in, err := ConvertSnapshotTask(productionOpenDefinition(xid, other))
	require.NoError(t, err)
	in.confirmedDestinations = map[uuid.UUID]bool{other: true}
	require.ErrorIs(t, next.applySnapshotDefinition(in), ErrDestinationNotFound)
	require.Zero(t, next.FilterCount())
	require.False(t, next.ReplayTaskAuthorized(xid, old.ActivationGeneration))
}

//go:build li

package li

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestConflictReportAdministrativeLifecycleCancellation(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		mode := "memory"
		if persistent {
			mode = "persistent"
		}
		for _, action := range []string{"modify", "deactivate", "expiry", "fault", "failed_modify"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				var m *Manager
				var dids []uuid.UUID
				if persistent {
					m, _, _, dids = administrativeTransactionManager(t)
				} else {
					m, _, dids = newIdempotencyManager(t, "")
				}
				t.Cleanup(m.Stop)
				task := idempotencyTask(uuid.New(), dids, time.Now().Add(-2*time.Hour).UTC())
				require.NoError(t, m.ActivateTask(task))
				held, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				entered := make(chan context.Context, 1)
				finished := make(chan struct{})
				m.conflictReportSend = func(ctx context.Context, _ uuid.UUID, _ string) error {
					entered <- ctx
					<-ctx.Done()
					close(finished)
					return ctx.Err()
				}
				incoming := conflictSnapshot(held)
				incoming.Task.Targets = incoming.Task.Targets[:1]
				require.NoError(t, m.applySnapshotDefinition(incoming))
				var reportCtx context.Context
				select {
				case reportCtx = <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("established conflict was not reported")
				}
				current, err := m.GetTaskDetails(task.XID)
				require.NoError(t, err)
				require.True(t, current.Definition.Conflict)
				switch action {
				case "modify":
					end := current.EndTime.Add(time.Hour)
					require.NoError(t, m.ModifyTask(task.XID, &TaskModification{EndTime: &end}))
				case "deactivate":
					require.NoError(t, m.DeactivateTask(task.XID))
				case "expiry":
					// Invoke the administrative expiry callback directly. Registry
					// clock eligibility is covered separately; this tests cancellation
					// at the real durable/non-durable withdrawal boundary.
					m.expireAdministrativeTask(current)
				case "fault":
					require.NoError(t, m.MarkTaskFailed(task.XID, "synthetic terminating fault"))
				case "failed_modify":
					invalidEnd := current.StartTime.Add(-time.Hour)
					require.Error(t, m.ModifyTask(task.XID, &TaskModification{EndTime: &invalidEnd}))
					require.NoError(t, reportCtx.Err(), "a rejected mutation must not cancel unresolved reporting")
					m.conflictReportMu.Lock()
					require.Len(t, m.conflictReports, 1)
					m.conflictReportMu.Unlock()
					// Prove subsequent successful withdrawal still clears the episode.
					require.NoError(t, m.DeactivateTask(task.XID))
				}
				require.ErrorIs(t, reportCtx.Err(), context.Canceled)
				select {
				case <-finished:
				case <-time.After(3 * time.Second):
					t.Fatal("withdrawal did not cancel the in-flight report")
				}
				m.conflictReportMu.Lock()
				require.Empty(t, m.conflictReports, "resolved/withdrawn tasks must not retain reporting bookkeeping")
				m.conflictReportMu.Unlock()
			})
		}
	}
}

func TestTaskDeactivationCallbackReportsMatchingX1Category(t *testing.T) {
	for _, reason := range []DeactivationReason{DeactivationReasonExpired, DeactivationReasonFault} {
		t.Run(reason.String(), func(t *testing.T) {
			types := make(chan string, 1)
			server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				var request struct {
					Message struct {
						ReportType string `xml:"taskReportType"`
					} `xml:"x1RequestMessage"`
				}
				require.NoError(t, xml.Unmarshal(body, &request))
				if request.Message.ReportType != "" {
					types <- request.Message.ReportType
				}
				w.WriteHeader(http.StatusOK) // Wrapper provides a correlated acknowledgment.
			})
			m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL}, nil)
			defer m.Stop()
			did, xid := uuid.New(), uuid.New()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			snapshotTestTask(t, m, xid, did)
			task, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			want := x1.TaskReportTypeImplicitDeactivation
			if reason == DeactivationReasonFault {
				want = x1.TaskReportTypeTerminatingFault
				require.NoError(t, m.MarkTaskFailed(xid, "synthetic terminating fault"))
			} else {
				m.expireAdministrativeTask(task)
			}
			select {
			case got := <-types:
				require.Equal(t, want, got)
			case <-time.After(3 * time.Second):
				t.Fatal("deactivation did not report to ADMF")
			}
		})
	}
}

func TestDisarmedConflictOrphanWithdrawalCancelsReporting(t *testing.T) {
	m, _, dids := newIdempotencyManager(t, "")
	t.Cleanup(m.Stop)
	m.config.ReconcileOrphanPolls = 2
	task := idempotencyTask(uuid.New(), dids, time.Now().Add(-time.Hour))
	require.NoError(t, m.ActivateTask(task))
	held, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	entered := make(chan context.Context, 1)
	m.conflictReportSend = func(ctx context.Context, _ uuid.UUID, _ string) error {
		entered <- ctx
		<-ctx.Done()
		return ctx.Err()
	}
	incoming := conflictSnapshot(held)
	incoming.Task.Targets = []TargetIdentity{{Type: TargetTypeSIPURI, Value: "sip:disjoint@example.invalid"}}
	require.NoError(t, m.applySnapshotDefinition(incoming))
	var reportCtx context.Context
	select {
	case reportCtx = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("disarmed conflict was not reported")
	}
	current, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusSuspended, current.Status)
	require.True(t, current.Definition.ConflictDisarmed)
	// Neither a recovery-time empty list nor uncertain enumeration authorizes
	// deleting the diagnostic-only task or canceling its conflict report.
	empty := newADMFSnapshot()
	require.Zero(t, m.removeOrphanedTasks(empty, true))
	require.True(t, empty.status.TaskOrphanRemovalSuppressed)
	uncertain := newADMFSnapshot()
	uncertain.taskMembershipUncertain = true
	uncertain.tasks[uuid.New()] = true
	require.Zero(t, m.removeOrphanedTasks(uncertain, true))
	require.NoError(t, reportCtx.Err())
	absent := newADMFSnapshot()
	absent.tasks[uuid.New()] = true
	require.Zero(t, m.removeOrphanedTasks(absent, true), "first reliable absence must retain the task")
	require.NoError(t, reportCtx.Err())
	require.Equal(t, 1, m.removeOrphanedTasks(absent, true))
	require.ErrorIs(t, reportCtx.Err(), context.Canceled)
	current, err = m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusDeactivated, current.Status)
	require.False(t, current.Definition.Conflict)
	require.False(t, current.Definition.ConflictDisarmed)
	require.Empty(t, current.Definition.ConflictReason)
	m.conflictReportMu.Lock()
	require.Empty(t, m.conflictReports)
	m.conflictReportMu.Unlock()
}

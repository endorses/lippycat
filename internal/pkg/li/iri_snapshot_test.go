//go:build li

package li

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func snapshotPolicyReferences(ids ...uuid.UUID) *schema.ListOfIRIPolicyReferences {
	list := &schema.ListOfIRIPolicyReferences{}
	for _, id := range ids {
		value := schema.UUID(id.String())
		list.IRIPolicyReference = append(list.IRIPolicyReference, &value)
	}
	return list
}

func TestIRIPolicySnapshotCannotAdmitMixedGraphAndTaskReferences(t *testing.T) {
	for _, restored := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "restored"}[restored], func(t *testing.T) {
			m, _, revoker, dids := administrativeTransactionManager(t)
			ruleA, policyA := provisionIRIPolicy(t, m)
			ruleB, policyB := provisionIRIPolicy(t, m)
			xid := uuid.New()
			details := convergenceDetails(xid, dids[0], true)
			details.TaskDetails.ListOfIRIPolicyReferences = snapshotPolicyReferences(policyA.ID)
			converted, err := ConvertSnapshotTask(details)
			require.NoError(t, err)
			require.NoError(t, m.ActivateTask(converted.Task))
			old, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			if restored {
				m = restartAdministrativeTestManager(t, m, revoker)
			}
			incoming := convergenceDetails(xid, dids[0], true)
			incoming.TaskDetails.ListOfIRIPolicyReferences = snapshotPolicyReferences(policyB.ID)
			ruleA.Rule.Action.Value = "Delivered" // New graph plus old A refs would incorrectly deliver.
			response := &schema.GetAllDetailsResponse{ListOfGenericObjectResponseDetails: iriSnapshotObjects(ruleA, policyA, ruleB, policyB), ListOfTaskResponseDetails: &schema.ListOfTaskResponseDetails{TaskResponseDetails: []*schema.TaskResponseDetails{incoming}}, ListOfDestinationResponseDetails: &schema.ListOfDestinationResponseDetails{DestinationResponseDetails: []*schema.DestinationResponseDetails{makeDestinationResponseDetails(dids[0], "mdf.example", 443)}}}
			observed := false
			m.iriSnapshotAppliedHook = func() {
				observed = true
				if current, getErr := m.GetTaskDetails(xid); getErr == nil {
					require.Equal(t, []uuid.UUID{policyA.ID}, current.IRIPolicyReferences, "task reconciliation has not run yet")
					admission, ok := m.AcquireTaskAdmission(xid, current.ActivationGeneration)
					if admission != nil {
						admission.Release()
					}
					require.False(t, ok)
					deliver, err := m.EvaluateIRIPolicy(xid, current.ActivationGeneration, iripolicy.Facts{})
					require.Error(t, err)
					require.False(t, deliver)
				}
				require.False(t, m.ReplayTaskAuthorized(xid, old.ActivationGeneration))
			}
			m.snapshotMu.Lock()
			snapshot, tasks, _ := m.applyADMFSnapshotEntries(response, restored)
			m.snapshotMu.Unlock()
			require.True(t, observed)
			require.Equal(t, 1, tasks)
			require.Zero(t, snapshot.status.TotalFailures)
			current, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, []uuid.UUID{policyB.ID}, current.IRIPolicyReferences)
			admission, ok := m.AcquireTaskAdmission(xid, current.ActivationGeneration)
			require.True(t, ok)
			admission.Release()
			deliver, err := m.EvaluateIRIPolicy(xid, current.ActivationGeneration, iripolicy.Facts{})
			require.NoError(t, err)
			require.False(t, deliver)
			for _, request := range revoker.requests {
				if request.Task != nil {
					require.True(t, request.IncludeX2)
				}
			}
		})
	}
}

func TestIRIPolicySnapshotBarrierPreventsPendingPromotion(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	did := uuid.New()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "mdf.example", Port: 443}))
	rule, policy := provisionIRIPolicy(t, m)
	task := idempotencyTask(uuid.New(), []uuid.UUID{did}, time.Time{})
	task.StartTime = time.Now().Add(time.Hour)
	task.IRIPolicyReferences = []uuid.UUID{policy.ID}
	require.NoError(t, m.ActivateTask(task))
	response := &schema.GetAllDetailsResponse{ListOfGenericObjectResponseDetails: iriSnapshotObjects(rule, policy)}
	blocked := m.beginIRISnapshotBarrier(response)
	// Move the scheduled boundary into the past while the snapshot is in flight.
	m.registry.mu.Lock()
	m.registry.tasks[task.XID].StartTime = time.Now().Add(-time.Second)
	m.registry.mu.Unlock()
	m.promotePendingTasks()
	held, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusPending, held.Status)
	m.finishIRISnapshotBarrier(blocked, map[uuid.UUID]bool{}, newADMFSnapshot())
	held, err = m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	require.Equal(t, TaskStatusFailed, held.Status)
}

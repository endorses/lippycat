//go:build li

package li

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func snapshotTestTask(t *testing.T, m *Manager, xid, did uuid.UUID) {
	t.Helper()
	task, err := ConvertSnapshotTask(convergenceDetails(xid, did, true))
	require.NoError(t, err)
	require.NoError(t, m.ActivateTask(task.Task))
}

func TestSnapshotMembershipIndependentOfDefinitions(t *testing.T) {
	for _, scenario := range []string{"known_bad_task", "bad_destination", "unknown_task", "duplicate_task", "duplicate_destination", "empty_tasks"} {
		t.Run(scenario, func(t *testing.T) {
			xid, orphan, did := uuid.New(), uuid.New(), uuid.New()
			tasks := []*schema.TaskResponseDetails{convergenceDetails(xid, did, true)}
			destinations := []*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}
			wantRemoved, wantSuppressed := true, false
			switch scenario {
			case "known_bad_task":
				tasks[0].TaskDetails.TargetIdentifiers = nil
			case "bad_destination":
				destinations[0].DestinationDetails.DeliveryAddress = nil
			case "unknown_task":
				tasks = append(tasks, malformedTask())
				wantRemoved, wantSuppressed = false, true
			case "duplicate_task":
				tasks = append(tasks, convergenceDetails(xid, did, true))
				wantRemoved, wantSuppressed = false, true
			case "duplicate_destination":
				destinations = append(destinations, makeDestinationResponseDetails(did, "127.0.0.2", 8443))
			case "empty_tasks":
				tasks = nil
				wantRemoved, wantSuppressed = false, true
			}
			response := buildGetAllDetailsResponseXML(destinations, tasks)
			server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, err := fmt.Fprint(w, response)
				require.NoError(t, err)
			})
			m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, ReconcileOrphanPolls: 2, FilterPusher: newStubFilterStore()}, nil)
			defer m.Stop()
			require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			snapshotTestTask(t, m, xid, did)
			snapshotTestTask(t, m, orphan, did)
			m.reconcileWithADMF()
			first, err := m.GetTaskDetails(orphan)
			require.NoError(t, err)
			require.Equal(t, TaskStatusActive, first.Status, "one absence is insufficient")
			m.reconcileWithADMF()
			current, err := m.GetTaskDetails(orphan)
			require.NoError(t, err)
			if wantRemoved {
				require.Equal(t, TaskStatusDeactivated, current.Status)
			} else {
				require.Equal(t, TaskStatusActive, current.Status)
			}
			listed, err := m.GetTaskDetails(xid)
			require.NoError(t, err)
			require.Equal(t, TaskStatusActive, listed.Status, "listed malformed tasks are not orphaned")
			status := m.SnapshotSyncStatus()
			require.Equal(t, wantSuppressed, status.TaskOrphanRemovalSuppressed)
			require.EqualValues(t, 2, status.Attempts)
			if scenario != "empty_tasks" {
				require.Positive(t, status.TotalFailures)
			}
		})
	}
}

func TestSnapshotUncertaintyBreaksConsecutiveAbsence(t *testing.T) {
	xid, orphan, did := uuid.New(), uuid.New(), uuid.New()
	var uncertain atomic.Bool
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		tasks := []*schema.TaskResponseDetails{convergenceDetails(xid, did, true)}
		if uncertain.Load() {
			tasks = append(tasks, malformedTask())
		}
		_, err := fmt.Fprint(w, buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, tasks))
		require.NoError(t, err)
	})
	m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL, ReconcileOrphanPolls: 2}, nil)
	defer m.Stop()
	require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
	snapshotTestTask(t, m, orphan, did)
	m.reconcileWithADMF()
	uncertain.Store(true)
	m.reconcileWithADMF()
	uncertain.Store(false)
	m.reconcileWithADMF()
	task, err := m.GetTaskDetails(orphan)
	require.NoError(t, err)
	require.Equal(t, TaskStatusActive, task.Status)
	m.reconcileWithADMF()
	task, err = m.GetTaskDetails(orphan)
	require.NoError(t, err)
	require.Equal(t, TaskStatusDeactivated, task.Status)
}

func TestSnapshotDestinationCleanupRetainsTaskReferences(t *testing.T) {
	for _, owner := range []string{"live", "persisted_candidate", "malformed_snapshot"} {
		t.Run(owner, func(t *testing.T) {
			m := NewManager(ManagerConfig{Enabled: true}, nil)
			defer m.Stop()
			xid, retained, listed, orphan := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			for _, did := range []uuid.UUID{retained, listed, orphan} {
				require.NoError(t, m.CreateDestination(&Destination{DID: did, Address: "127.0.0.1", Port: 8443}))
			}
			task := convergenceDetails(xid, listed, true)
			switch owner {
			case "live":
				snapshotTestTask(t, m, xid, retained)
			case "persisted_candidate":
				candidate, err := ConvertSnapshotTask(convergenceDetails(xid, retained, true))
				require.NoError(t, err)
				candidate.Task.Status = TaskStatusActive
				m.persistenceCandidates[xid] = candidate.Task
			case "malformed_snapshot":
				task = convergenceDetails(xid, retained, true)
				task.TaskDetails.TargetIdentifiers = nil
			}
			snapshot := enumerateADMFSnapshot(&schema.GetAllDetailsResponse{ListOfTaskResponseDetails: &schema.ListOfTaskResponseDetails{TaskResponseDetails: []*schema.TaskResponseDetails{task}}, ListOfDestinationResponseDetails: &schema.ListOfDestinationResponseDetails{DestinationResponseDetails: []*schema.DestinationResponseDetails{makeDestinationResponseDetails(listed, "127.0.0.1", 8443)}}})
			require.Equal(t, 1, m.removeOrphanedDestinations(snapshot))
			_, err := m.GetDestination(retained)
			require.NoError(t, err)
			_, err = m.GetDestination(orphan)
			require.ErrorIs(t, err, ErrDestinationNotFound)
			require.True(t, snapshot.status.DestinationOrphanRemovalSuppressed)
		})
	}
}

func TestSnapshotFailureStatusBoundedPrivateAndDeduplicated(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	defer m.Stop()
	var output bytes.Buffer
	logger.UseFile(&output)
	defer logger.UseStderr()
	const sensitive = "sip:private-selector@example.invalid"
	badID := schema.UUID(sensitive)
	response := &schema.GetAllDetailsResponse{ListOfTaskResponseDetails: &schema.ListOfTaskResponseDetails{}, ListOfDestinationResponseDetails: &schema.ListOfDestinationResponseDetails{}}
	for range SnapshotFailureLimit + 8 {
		response.ListOfTaskResponseDetails.TaskResponseDetails = append(response.ListOfTaskResponseDetails.TaskResponseDetails, &schema.TaskResponseDetails{TaskDetails: &schema.TaskDetails{XId: &badID}})
	}
	for range 3 {
		snapshot := enumerateADMFSnapshot(response)
		m.removeOrphanedTasks(snapshot, true)
		m.removeOrphanedDestinations(snapshot)
		m.publishSnapshotStatus(snapshot, "startup")
	}
	status := m.SnapshotSyncStatus()
	require.EqualValues(t, SnapshotFailureLimit+8, status.TaskFailures)
	require.Len(t, status.Failures, SnapshotFailureLimit)
	require.EqualValues(t, 8, status.FailuresTruncated)
	require.EqualValues(t, 2, status.WarningsSuppressed)
	require.Equal(t, 1, strings.Count(output.String(), "ADMF snapshot reconciliation incomplete"))
	data, err := json.Marshal(status)
	require.NoError(t, err)
	require.NotContains(t, string(data), sensitive)
	require.NotContains(t, output.String(), sensitive)
	require.Empty(t, status.Failures[0].UUID)
	status.Failures[0].Category = "tampered"
	require.Equal(t, "unknown_identifier", m.SnapshotSyncStatus().Failures[0].Category, "returned diagnostics cannot mutate published state")
	// A changed failure past the detail cap must still trigger a new warning.
	changed := enumerateADMFSnapshot(response)
	changed.status.TaskOrphanRemovalSuppressed = true
	changed.status.DestinationOrphanRemovalSuppressed = true
	changed.fail("snapshot", "persistence_failed", -1, uuid.Nil)
	m.publishSnapshotStatus(changed, "periodic")
	require.Equal(t, 2, strings.Count(output.String(), "ADMF snapshot reconciliation incomplete"))
	m.publishSnapshotStatus(newADMFSnapshot(), "periodic")
	require.Equal(t, 1, strings.Count(output.String(), "ADMF snapshot reconciliation recovered"))
	require.Zero(t, m.SnapshotSyncStatus().TotalFailures)
	require.Empty(t, m.SnapshotSyncStatus().Failures)
}

func TestSnapshotRequestFailuresAndMissingListsSuppressRemoval(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	defer m.Stop()
	id := uuid.New()
	m.orphanStreak[id] = 1
	m.recordSnapshotRequestFailure(fmt.Errorf("remote private payload: %w", context.DeadlineExceeded), "periodic")
	require.Empty(t, m.orphanStreak)
	status := m.SnapshotSyncStatus()
	require.Equal(t, "timeout", status.Failures[0].Category)
	require.Equal(t, -1, status.Failures[0].EntryIndex)
	require.True(t, status.TaskOrphanRemovalSuppressed)
	require.True(t, status.DestinationOrphanRemovalSuppressed)
	m.recordSnapshotRequestFailure(errors.New("private remote response"), "periodic")
	require.Equal(t, "request_failed", m.SnapshotSyncStatus().Failures[0].Category)
	m.recordSnapshotRequestFailure(fmt.Errorf("private remote content: %w", x1.ErrIncompleteGetAllDetailsResponse), "periodic")
	require.Equal(t, "incomplete_response", m.SnapshotSyncStatus().Failures[0].Category)
	snapshot := enumerateADMFSnapshot(&schema.GetAllDetailsResponse{})
	require.False(t, snapshot.tasksComplete())
	require.False(t, snapshot.destinationsComplete())
	require.EqualValues(t, 2, snapshot.status.TotalFailures)
	require.Equal(t, "missing_list", snapshot.status.Failures[0].Category)
}

func TestStartupSnapshotWarningSuppressionDoesNotStopRetries(t *testing.T) {
	xid, did := uuid.New(), uuid.New()
	var recovered atomic.Bool
	server := newTestADMFServer(t, func(w http.ResponseWriter, r *http.Request) {
		task := convergenceDetails(xid, did, true)
		if !recovered.Load() {
			task.TaskDetails.TargetIdentifiers = nil
		}
		_, err := fmt.Fprint(w, buildGetAllDetailsResponseXML([]*schema.DestinationResponseDetails{makeDestinationResponseDetails(did, "127.0.0.1", 8443)}, []*schema.TaskResponseDetails{task}))
		require.NoError(t, err)
	})
	m := NewManager(ManagerConfig{Enabled: true, ADMFEndpoint: server.URL}, nil)
	defer m.Stop()
	for range 3 {
		require.True(t, m.attemptStartupSync())
	}
	require.EqualValues(t, 3, m.StartupSyncStatus().Attempts)
	require.EqualValues(t, 3, m.SnapshotSyncStatus().Attempts)
	require.EqualValues(t, 2, m.SnapshotSyncStatus().WarningsSuppressed)
	recovered.Store(true)
	require.False(t, m.attemptStartupSync())
	require.Equal(t, StartupSyncSucceeded, m.StartupSyncStatus().State)
	require.Zero(t, m.SnapshotSyncStatus().TotalFailures)
	require.EqualValues(t, 4, m.SnapshotSyncStatus().Attempts)
	require.Equal(t, 1, m.ActiveTaskCount())
}

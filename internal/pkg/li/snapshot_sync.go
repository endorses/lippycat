//go:build li

package li

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
)

// Membership evidence is separate from definition validity. A known malformed
// entry proves its ID is present; an unknown or duplicate ID invalidates absence
// inference. Duplicate definitions are never applied in arbitrary wire order.
type admfSnapshot struct {
	tasks, destinations                                     map[uuid.UUID]bool
	duplicateTasks, duplicateDestinations                   map[uuid.UUID]bool
	taskMembershipUncertain, destinationMembershipUncertain bool
	convErrors, destinationConvErrors                       int
	rejectedTasks                                           map[uuid.UUID]int
	referencedDestinations                                  map[uuid.UUID]bool
	status                                                  SnapshotSyncStatus
	failureHash                                             hash.Hash
}

func newADMFSnapshot() *admfSnapshot {
	return &admfSnapshot{
		tasks: make(map[uuid.UUID]bool), destinations: make(map[uuid.UUID]bool),
		duplicateTasks: make(map[uuid.UUID]bool), duplicateDestinations: make(map[uuid.UUID]bool),
		rejectedTasks: make(map[uuid.UUID]int), referencedDestinations: make(map[uuid.UUID]bool),
		failureHash: sha256.New(),
	}
}

func (s *admfSnapshot) tasksComplete() bool        { return !s.taskMembershipUncertain }
func (s *admfSnapshot) destinationsComplete() bool { return !s.destinationMembershipUncertain }

// Filter sweeps additionally require successful definition application. Local
// filters for a listed but malformed definition cannot be inferred orphaned.
func (s *admfSnapshot) complete() bool {
	return s.tasksComplete() && s.destinationsComplete() && s.convErrors == 0 && s.destinationConvErrors == 0
}

func (s *admfSnapshot) fail(kind, category string, index int, id uuid.UUID) {
	failure := SnapshotFailure{Kind: kind, Category: category, EntryIndex: index}
	if id != uuid.Nil {
		failure.UUID = id.String()
	}
	s.status.TotalFailures++
	switch kind {
	case "task":
		s.convErrors++
		s.status.TaskFailures++
	case "destination":
		s.destinationConvErrors++
		s.status.DestinationFailures++
	}
	// Hash writes cannot fail. Encoding only bounded fixed categories and UUIDs
	// keeps bookkeeping independent of untrusted response text.
	_, _ = fmt.Fprintf(s.failureHash, "%s/%s/%d/%s\n", kind, category, index, failure.UUID)
	if len(s.status.Failures) < SnapshotFailureLimit {
		s.status.Failures = append(s.status.Failures, failure)
	} else {
		s.status.FailuresTruncated++
	}
}

func taskSnapshotUUID(td *schema.TaskResponseDetails) (uuid.UUID, bool) {
	if td != nil && td.TaskDetails != nil && td.TaskDetails.XId != nil {
		id, err := uuid.Parse(string(*td.TaskDetails.XId))
		return id, err == nil && id != uuid.Nil
	}
	return uuid.Nil, false
}
func destinationSnapshotUUID(dd *schema.DestinationResponseDetails) (uuid.UUID, bool) {
	if dd != nil && dd.DestinationDetails != nil && dd.DestinationDetails.DId != nil {
		id, err := uuid.Parse(string(*dd.DestinationDetails.DId))
		return id, err == nil && id != uuid.Nil
	}
	return uuid.Nil, false
}

func enumerateADMFSnapshot(resp *schema.GetAllDetailsResponse) *admfSnapshot {
	s := newADMFSnapshot()
	if resp.ListOfTaskResponseDetails == nil {
		s.taskMembershipUncertain = true
		s.fail("task", "missing_list", -1, uuid.Nil)
	} else {
		for index, td := range resp.ListOfTaskResponseDetails.TaskResponseDetails {
			id, valid := taskSnapshotUUID(td)
			if !valid {
				s.taskMembershipUncertain = true
				s.fail("task", "unknown_identifier", index, uuid.Nil)
				continue
			}
			if s.tasks[id] {
				s.taskMembershipUncertain = true
				s.duplicateTasks[id] = true
			}
			s.tasks[id] = true
			if td.TaskDetails.ListOfDIDs != nil {
				for _, value := range td.TaskDetails.ListOfDIDs.DId {
					if value != nil {
						if did, err := uuid.Parse(string(*value)); err == nil && did != uuid.Nil {
							s.referencedDestinations[did] = true
						}
					}
				}
			}
		}
	}
	if resp.ListOfDestinationResponseDetails == nil {
		s.destinationMembershipUncertain = true
		s.fail("destination", "missing_list", -1, uuid.Nil)
	} else {
		for index, dd := range resp.ListOfDestinationResponseDetails.DestinationResponseDetails {
			id, valid := destinationSnapshotUUID(dd)
			if !valid {
				s.destinationMembershipUncertain = true
				s.fail("destination", "unknown_identifier", index, uuid.Nil)
				continue
			}
			if s.destinations[id] {
				s.destinationMembershipUncertain = true
				s.duplicateDestinations[id] = true
			}
			s.destinations[id] = true
		}
	}
	return s
}

// applyADMFSnapshotEntries is shared by startup recovery and periodic repair.
// snapshotMu must be held by the caller across fetch and application.
func (m *Manager) applyADMFSnapshotEntries(resp *schema.GetAllDetailsResponse, startup bool) (*admfSnapshot, int, int) {
	snapshot := enumerateADMFSnapshot(resp)
	confirmedDestinations := make(map[uuid.UUID]bool)
	var taskCount, destCount int
	if resp.ListOfDestinationResponseDetails != nil {
		for index, dd := range resp.ListOfDestinationResponseDetails.DestinationResponseDetails {
			id, valid := destinationSnapshotUUID(dd)
			if !valid {
				continue
			}
			if snapshot.duplicateDestinations[id] {
				snapshot.fail("destination", "duplicate_identifier", index, id)
				continue
			}
			dest, err := DestinationResponseDetailsToDestination(dd)
			if err != nil {
				snapshot.fail("destination", "conversion_failed", index, id)
				continue
			}
			if err := m.syncDestination(dest); err != nil {
				snapshot.fail("destination", "application_failed", index, id)
				continue
			}
			confirmedDestinations[id] = true
			destCount++
		}
	}
	if resp.ListOfTaskResponseDetails != nil {
		for index, td := range resp.ListOfTaskResponseDetails.TaskResponseDetails {
			id, valid := taskSnapshotUUID(td)
			if !valid {
				continue
			}
			if snapshot.duplicateTasks[id] {
				snapshot.fail("task", "duplicate_identifier", index, id)
				continue
			}
			converted, err := ConvertSnapshotTask(td)
			if err != nil {
				if !startup {
					if revokeErr := m.rejectRADIUSReplacement(id, err); revokeErr != nil {
						snapshot.fail("task", "revocation_failed", index, id)
					}
				}
				snapshot.fail("task", "conversion_failed", index, id)
				continue
			}
			task := converted.Task
			converted.confirmedDestinations = confirmedDestinations
			m.bindRADIUSDeployment(task)
			radiusTask := IsRADIUSTask(task)
			radiusLifecycle := radiusTask
			if !startup && !radiusLifecycle {
				if previous, getErr := m.registry.GetTaskDetails(id); getErr == nil {
					radiusLifecycle = IsRADIUSTask(previous)
				}
			}
			if radiusLifecycle {
				confirmed := true
				for _, did := range task.DestinationIDs {
					if !confirmedDestinations[did] {
						confirmed = false
						break
					}
				}
				if !confirmed {
					snapshot.rejectedTasks[id] = len(task.Targets)
					snapshot.fail("task", "unconfirmed_destination", index, id)
					continue
				}
			}
			// The specialized lifecycle owns either side of a RADIUS replacement.
			// An unknown XID is deliberately unhandled and must fall through to
			// activation, rather than being counted as successfully reconciled.
			handled := false
			if !startup {
				handled, err = m.reconcileRADIUSTask(task)
			}
			if !handled {
				if startup && radiusTask {
					err = m.activateStartupTask(task)
				} else {
					err = m.applySnapshotDefinition(converted)
				}
			}
			if err != nil {
				if startup && errors.Is(err, ErrTaskAlreadyExists) {
					continue
				}
				snapshot.rejectedTasks[id] = len(task.Targets)
				category := "application_failed"
				if errors.Is(err, ErrDestinationNotFound) {
					category = "unconfirmed_destination"
				}
				snapshot.fail("task", category, index, id)
				continue
			}
			taskCount++
		}
	}
	return snapshot, taskCount, destCount
}

func (m *Manager) SnapshotSyncStatus() SnapshotSyncStatus {
	if status := m.snapshotStatus.Load(); status != nil {
		copy := *status
		copy.Failures = append([]SnapshotFailure(nil), status.Failures...)
		return copy
	}
	return SnapshotSyncStatus{}
}

// publishSnapshotStatus retains one bounded immutable snapshot. The complete
// failure fingerprint suppresses identical warnings even if entries beyond the
// diagnostic limit change. Retry scheduling never depends on warning emission.
func (m *Manager) publishSnapshotStatus(snapshot *admfSnapshot, source string) {
	status := snapshot.status
	previous := m.SnapshotSyncStatus()
	status.Source, status.LastAttempt, status.Attempts = source, time.Now().UTC(), previous.Attempts+1
	status.WarningsSuppressed = previous.WarningsSuppressed
	status.State = "complete"
	if status.TotalFailures > 0 {
		status.State = "partial"
	}
	status.fingerprint = sha256.Sum256([]byte(fmt.Sprintf("%x/%t/%t", snapshot.failureHash.Sum(nil), status.TaskOrphanRemovalSuppressed, status.DestinationOrphanRemovalSuppressed)))
	if status.TotalFailures > 0 || status.TaskOrphanRemovalSuppressed || status.DestinationOrphanRemovalSuppressed {
		if previous.Attempts > 0 && status.fingerprint == previous.fingerprint {
			status.WarningsSuppressed++
		} else {
			logger.Warn("ADMF snapshot reconciliation incomplete", "source", source, "task_failures", status.TaskFailures, "destination_failures", status.DestinationFailures, "failures", status.Failures, "failures_truncated", status.FailuresTruncated, "task_orphans_suppressed", status.TaskOrphanRemovalSuppressed, "destination_orphans_suppressed", status.DestinationOrphanRemovalSuppressed)
		}
	} else if previous.TotalFailures > 0 || previous.TaskOrphanRemovalSuppressed || previous.DestinationOrphanRemovalSuppressed {
		logger.Info("ADMF snapshot reconciliation recovered", "source", source)
	}
	status.Failures = append([]SnapshotFailure(nil), status.Failures...)
	m.snapshotStatus.Store(&status)
}

func (m *Manager) recordSnapshotRequestFailure(err error, source string) {
	snapshot := newADMFSnapshot()
	category := "request_failed"
	var remote *x1.ADMFError
	switch {
	case errors.Is(err, x1.ErrIncompleteGetAllDetailsResponse):
		category = "incomplete_response"
	case errors.Is(err, context.DeadlineExceeded):
		category = "timeout"
	case errors.Is(err, context.Canceled):
		category = "canceled"
	case errors.As(err, &remote):
		category = "request_rejected"
	}
	snapshot.fail("snapshot", category, -1, uuid.Nil)
	snapshot.status.TaskOrphanRemovalSuppressed = true
	snapshot.status.DestinationOrphanRemovalSuppressed = true
	m.clearOrphanStreaks()
	m.publishSnapshotStatus(snapshot, source)
}

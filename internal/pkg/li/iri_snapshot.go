//go:build li

package li

import (
	"errors"
	"maps"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/google/uuid"
)

// applyIRIObjectSnapshot uses the same response as task confirmation. A second
// query could combine task references with a graph from another ADMF revision.
// snapshotMu is held by the caller, followed here by adminMu and lifecycleMu.
func (m *Manager) applyIRIObjectSnapshot(response *schema.GetAllDetailsResponse, snapshot *admfSnapshot) bool {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	if err := m.ensureAdministrativeStateLocked(); err != nil {
		snapshot.fail("object", "application_failed", -1, uuid.Nil)
		return false
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	old, _ := m.GetGenericObjects()
	snapshot.iriRequired = len(old) > 0
	if response.ListOfTaskResponseDetails != nil {
		for _, task := range response.ListOfTaskResponseDetails.TaskResponseDetails {
			if task != nil && task.TaskDetails != nil && task.TaskDetails.ListOfIRIPolicyReferences != nil && len(task.TaskDetails.ListOfIRIPolicyReferences.IRIPolicyReference) > 0 {
				snapshot.iriRequired = true
			}
		}
	}
	list := response.ListOfGenericObjectResponseDetails
	if list == nil {
		snapshot.iriMembershipUncertain = true
		if snapshot.iriRequired {
			snapshot.fail("object", "missing_list", -1, uuid.Nil)
			m.rejectUnconfirmedIRIGraphLocked(snapshot)
		}
		return false
	}
	objects := make([]iripolicy.Object, 0, len(list.GenericObjectResponseDetails))
	seen := make(map[uuid.UUID]bool)
	oldByID := make(map[uuid.UUID]iripolicy.Object, len(old))
	for _, object := range old {
		oldByID[object.ID] = object
	}
	for index, details := range list.GenericObjectResponseDetails {
		id := uuid.Nil
		if details != nil && details.Object != nil && details.Object.ObjectId != nil {
			id, _ = uuid.Parse(string(*details.Object.ObjectId))
		}
		if id == uuid.Nil {
			snapshot.iriMembershipUncertain = true
			snapshot.fail("object", "unknown_identifier", index, uuid.Nil)
			continue
		}
		if seen[id] {
			snapshot.iriMembershipUncertain = true
			snapshot.fail("object", "duplicate_identifier", index, id)
			continue
		}
		seen[id] = true
		object, err := x1.DecodeGenericObject(details.Object)
		if err != nil {
			snapshot.fail("object", "conversion_failed", index, id)
			continue
		}
		object.Generation = 1
		if previous, ok := oldByID[id]; ok {
			object.Generation = previous.Generation
			if !iripolicy.EqualObjects(previous, object) {
				if object.Generation == ^uint64(0) {
					snapshot.fail("object", "generation_exhausted", index, id)
					continue
				}
				object.Generation++
			}
		}
		objects = append(objects, object)
	}
	snapshot.status.GenericObjectMembershipComplete = !snapshot.iriMembershipUncertain
	if snapshot.iriConvErrors != 0 || snapshot.iriMembershipUncertain {
		m.rejectUnconfirmedIRIGraphLocked(snapshot)
		return false
	}
	if err := iripolicy.ValidateObjects(objects, m.config.IRIProfile, iripolicy.Limits{}); err != nil {
		snapshot.fail("object", "invalid_graph", -1, uuid.Nil)
		m.rejectUnconfirmedIRIGraphLocked(snapshot)
		return false
	}
	var previous, candidates []*InterceptTask
	for _, task := range m.policyTasksLocked() {
		compiled, err := iripolicy.Compile(task.IRIPolicyReferences, objects, m.config.IRIProfile, iripolicy.Limits{})
		if err != nil {
			if err := m.rejectIRIPolicyTaskLocked(task); err != nil {
				snapshot.fail("object", "revocation_failed", -1, uuid.Nil)
				return false
			}
			continue
		}
		if maps.Equal(task.IRIPolicySourceGenerations, compiled.SourceGenerations()) && task.IRIPolicyProfileRevision == m.config.IRIPolicyProfileRevision {
			continue
		}
		candidate := cloneInterceptTask(task)
		candidate.IRIPolicySourceGenerations = compiled.SourceGenerations()
		candidate.IRIPolicyProfileRevision = m.config.IRIPolicyProfileRevision
		m.registry.mu.RLock()
		watermark := m.registry.generations[task.XID]
		m.registry.mu.RUnlock()
		if watermark == ^uint64(0) {
			snapshot.fail("object", "generation_exhausted", -1, uuid.Nil)
			m.rejectUnconfirmedIRIGraphLocked(snapshot)
			return false
		}
		candidate.ActivationGeneration = watermark + 1
		previous = append(previous, task)
		candidates = append(candidates, candidate)
	}
	if err := m.commitIRIGraphLocked(objects, previous, candidates, uuid.Nil, "snapshot"); err != nil {
		snapshot.fail("object", "application_failed", -1, uuid.Nil)
		return false
	}
	return true
}

func (m *Manager) policyTasksLocked() []*InterceptTask {
	var tasks []*InterceptTask
	m.registry.mu.RLock()
	defer m.registry.mu.RUnlock()
	for _, task := range m.registry.tasks {
		if len(task.IRIPolicyReferences) > 0 && (task.Status == TaskStatusActive || task.Status == TaskStatusPending || task.Status == TaskStatusSuspended) {
			tasks = append(tasks, cloneInterceptTask(task))
		}
	}
	return tasks
}

func (m *Manager) rejectIRIPolicyTaskLocked(task *InterceptTask) error {
	if m.stateStore != nil {
		return m.withdrawPersistentTaskLocked(task.XID, StateTaskFail, "IRI policy graph requires administrative confirmation", true)
	}
	if err := m.notifyIRIPolicyChanged(task); err != nil {
		m.faultAdministrative(err)
		return err
	}
	markErr := m.registry.MarkTaskFailed(task.XID, "IRI policy graph requires administrative confirmation")
	m.notifyTaskModified(task)
	return errors.Join(markErr, m.filters.RemoveFiltersForTask(task.XID))
}

func (m *Manager) rejectUnconfirmedIRIGraphLocked(snapshot *admfSnapshot) {
	m.iriMu.Lock()
	m.iriConfirmed = make(map[uuid.UUID]bool)
	m.iriCompiled = nil
	m.iriMu.Unlock()
	for _, task := range m.policyTasksLocked() {
		if err := m.rejectIRIPolicyTaskLocked(task); err != nil {
			snapshot.fail("object", "revocation_failed", -1, uuid.Nil)
			m.faultAdministrative(err)
		}
	}
}

// beginIRISnapshotBarrier closes old task admission before a graph from the
// response becomes visible. Graph publication alone cannot authorize a task
// whose policy-reference list has not yet been checked in that same response.
// Queued product needs no reversible pause: source/profile and reference changes
// durably revoke both products of each old generation before publication. This
// barrier prevents producers, replay and pending promotion from admitting the
// replacement generation until the whole same-response definition is checked.
func (m *Manager) beginIRISnapshotBarrier(response *schema.GetAllDetailsResponse) map[uuid.UUID]bool {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	if err := m.ensureAdministrativeStateLocked(); err != nil {
		return nil
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	blocked := make(map[uuid.UUID]bool)
	for _, task := range m.policyTasksLocked() {
		blocked[task.XID] = true
	}
	if list := response.ListOfTaskResponseDetails; list != nil {
		for _, details := range list.TaskResponseDetails {
			if id, valid := taskSnapshotUUID(details); valid && details.TaskDetails.ListOfIRIPolicyReferences != nil && len(details.TaskDetails.ListOfIRIPolicyReferences.IRIPolicyReference) > 0 {
				blocked[id] = true
			}
		}
	}
	m.iriMu.Lock()
	if m.iriSnapshotBlocked == nil {
		m.iriSnapshotBlocked = make(map[uuid.UUID]bool)
	}
	for id := range blocked {
		m.iriSnapshotBlocked[id] = true
	}
	m.iriMu.Unlock()
	return blocked
}

func (m *Manager) finishIRISnapshotBarrier(blocked, confirmed map[uuid.UUID]bool, snapshot *admfSnapshot) {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	for id := range blocked {
		if !confirmed[id] {
			if task, err := m.registry.GetTaskDetails(id); err == nil && (task.Status == TaskStatusActive || task.Status == TaskStatusPending || task.Status == TaskStatusSuspended) {
				if err := m.rejectIRIPolicyTaskLocked(task); err != nil {
					snapshot.fail("object", "revocation_failed", -1, uuid.Nil)
					m.faultAdministrative(err)
				}
			}
		}
	}
	if m.stateFault.Load() != nil {
		return
	}
	m.iriMu.Lock()
	for id := range blocked {
		delete(m.iriSnapshotBlocked, id)
	}
	m.iriMu.Unlock()
}

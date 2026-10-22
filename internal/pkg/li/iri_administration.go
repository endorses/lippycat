//go:build li

package li

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/endorses/lippycat/internal/pkg/li/iripolicy"
	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

type iriCompiledTask struct {
	generation uint64
	compiled   *iripolicy.Compiled
}

func cloneIRIProfile(profile iripolicy.Profile) iripolicy.Profile {
	return iripolicy.Profile{NFTypes: slices.Clone(profile.NFTypes), Events: slices.Clone(profile.Events), HandoverFormats: slices.Clone(profile.HandoverFormats)}
}

// IRIPolicyStats reports graph size without exposing provisioned definitions.
type IRIPolicyStats struct{ Objects, Policies, Rules, ConfirmedObjects int }

func (m *Manager) IRIPolicyStats() IRIPolicyStats {
	m.iriMu.RLock()
	defer m.iriMu.RUnlock()
	stats := IRIPolicyStats{Objects: len(m.iriObjects)}
	for _, object := range m.iriObjects {
		if object.Policy != nil {
			stats.Policies++
		} else {
			stats.Rules++
		}
		if m.iriConfirmed[object.ID] {
			stats.ConfirmedObjects++
		}
	}
	return stats
}

// SetOnIRIPolicyChanged withdraws both product types from the old generation.
// The callback runs with administrative and lifecycle write admission held.
func (m *Manager) SetOnIRIPolicyChanged(callback func(*InterceptTask) error) {
	m.callbackMu.Lock()
	defer m.callbackMu.Unlock()
	m.onIRIPolicyChanged = callback
}

func (m *Manager) notifyIRIPolicyChanged(task *InterceptTask) error {
	m.callbackMu.RLock()
	callback := m.onIRIPolicyChanged
	m.callbackMu.RUnlock()
	if callback != nil {
		return callback(cloneInterceptTask(task))
	}
	return nil
}

func (m *Manager) compileIRIPolicyLocked(task *InterceptTask, requireConfirmation bool) (*iripolicy.Compiled, error) {
	m.iriMu.RLock()
	defer m.iriMu.RUnlock()
	compiled, err := iripolicy.Compile(task.IRIPolicyReferences, m.iriObjects, m.config.IRIProfile, iripolicy.Limits{})
	if err != nil {
		return nil, fmt.Errorf("%w: IRI policy graph: %w", ErrInvalidTask, err)
	}
	if requireConfirmation {
		for id := range compiled.SourceGenerations() {
			if !m.iriConfirmed[id] {
				return nil, fmt.Errorf("%w: IRI policy source requires administrative confirmation", ErrInvalidTask)
			}
		}
	}
	return compiled, nil
}

func (m *Manager) bindIRIPolicyTaskLocked(task *InterceptTask) (*InterceptTask, error) {
	bound := cloneInterceptTask(task)
	if len(bound.IRIPolicyReferences) == 0 {
		bound.IRIPolicySourceGenerations = nil
		bound.IRIPolicyProfileRevision = ""
		return bound, nil
	}
	compiled, err := m.compileIRIPolicyLocked(bound, true)
	if err != nil {
		return nil, err
	}
	bound.IRIPolicySourceGenerations = compiled.SourceGenerations()
	bound.IRIPolicyProfileRevision = m.config.IRIPolicyProfileRevision
	return bound, nil
}

func (m *Manager) bindIRIPolicyModificationLocked(xid uuid.UUID, mod *TaskModification) (*TaskModification, error) {
	held, err := m.registry.GetTaskDetails(xid)
	if err != nil {
		return nil, err
	}
	if mod.IRIPolicyReferences != nil {
		held.IRIPolicyReferences = append([]uuid.UUID(nil), (*mod.IRIPolicyReferences)...)
	}
	bound, err := m.bindIRIPolicyTaskLocked(held)
	if err != nil {
		return nil, err
	}
	copyMod := *mod
	refs := bound.IRIPolicyReferences
	if mod.IRIPolicyReferences != nil || !equivalentIRIPolicyDefinition(held, bound) {
		copyMod.IRIPolicyReferences = &refs
	}
	copyMod.iriPolicySourceGenerations = bound.IRIPolicySourceGenerations
	copyMod.iriPolicyProfileRevision = bound.IRIPolicyProfileRevision
	return &copyMod, nil
}

// EvaluateIRIPolicy evaluates a currently admitted generation without acquiring
// lifecycle admission again. Its immutable compiled cache has a separate lock.
func (m *Manager) EvaluateIRIPolicy(xid uuid.UUID, generation uint64, facts iripolicy.Facts) (bool, error) {
	if !m.administrativeAdmissionReady() {
		return false, ErrAdministrativeFault
	}
	task, err := m.registry.GetTaskDetails(xid)
	if err != nil {
		return false, err
	}
	if task.ActivationGeneration != generation || task.Status != TaskStatusActive {
		return false, ErrInvalidTask
	}
	m.iriMu.RLock()
	blocked := m.iriSnapshotBlocked[xid]
	m.iriMu.RUnlock()
	if blocked {
		return false, ErrInvalidTask
	}
	if len(task.IRIPolicyReferences) == 0 {
		return true, nil
	}
	if task.IRIPolicyProfileRevision != m.config.IRIPolicyProfileRevision {
		return false, ErrInvalidTask
	}
	m.iriMu.Lock()
	defer m.iriMu.Unlock()
	cached, ok := m.iriCompiled[xid]
	if !ok || cached.generation != generation {
		compiled, err := iripolicy.Compile(task.IRIPolicyReferences, m.iriObjects, m.config.IRIProfile, iripolicy.Limits{})
		if err != nil {
			return false, err
		}
		if !maps.Equal(compiled.SourceGenerations(), task.IRIPolicySourceGenerations) {
			return false, ErrInvalidTask
		}
		for id := range compiled.SourceGenerations() {
			if !m.iriConfirmed[id] {
				return false, ErrInvalidTask
			}
		}
		if m.iriCompiled == nil {
			m.iriCompiled = make(map[uuid.UUID]iriCompiledTask)
		}
		cached = iriCompiledTask{generation, compiled}
		m.iriCompiled[xid] = cached
	}
	return cached.compiled.Evaluate(facts)
}

func iriObjectError(code int, message string) error {
	return &x1.ObjectError{Code: code, Message: message}
}

func (m *Manager) GetGenericObject(id uuid.UUID) (iripolicy.Object, error) {
	m.iriMu.RLock()
	defer m.iriMu.RUnlock()
	for _, object := range m.iriObjects {
		if object.ID == id {
			return iripolicy.CloneObject(object), nil
		}
	}
	return iripolicy.Object{}, iriObjectError(x1.ErrorCodeObjectNotFound, "generic object does not exist")
}
func (m *Manager) GetGenericObjects() ([]iripolicy.Object, error) {
	m.iriMu.RLock()
	defer m.iriMu.RUnlock()
	return iripolicy.CloneObjects(m.iriObjects), nil
}

func (m *Manager) CreateGenericObject(object iripolicy.Object) error {
	return m.changeGenericObject(object, object.ID, "create")
}
func (m *Manager) ModifyGenericObject(object iripolicy.Object) error {
	return m.changeGenericObject(object, object.ID, "modify")
}
func (m *Manager) DeleteGenericObject(id uuid.UUID) error {
	return m.changeGenericObject(iripolicy.Object{}, id, "delete")
}
func (m *Manager) DeleteAllGenericObjects() error {
	return m.changeGenericObject(iripolicy.Object{}, uuid.Nil, "delete_all")
}

func (m *Manager) changeGenericObject(object iripolicy.Object, id uuid.UUID, operation string) error {
	m.snapshotMu.Lock()
	defer m.snapshotMu.Unlock()
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	if err := m.ensureAdministrativeStateLocked(); err != nil {
		return err
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	objects, _ := m.GetGenericObjects()
	index := -1
	for n, existing := range objects {
		if existing.ID == id {
			index = n
			break
		}
	}
	if operation == "create" && index >= 0 {
		return iriObjectError(x1.ErrorCodeObjectAlreadyExists, "generic object already exists")
	}
	if (operation == "modify" || operation == "delete") && index < 0 {
		return iriObjectError(x1.ErrorCodeObjectNotFound, "generic object does not exist")
	}
	operationCode := x1.ErrorCodeCreateObject
	switch operation {
	case "modify":
		operationCode = x1.ErrorCodeModifyObject
	case "delete":
		operationCode = x1.ErrorCodeDeleteObject
	case "delete_all":
		operationCode = x1.ErrorCodeDeleteAllObjects
	}
	switch operation {
	case "create":
		object.Generation = 1
		objects = append(objects, iripolicy.CloneObject(object))
	case "modify":
		old := objects[index]
		if (old.Policy == nil) != (object.Policy == nil) {
			return iriObjectError(operationCode, "generic object type cannot change")
		}
		object.Generation = old.Generation
		if !iripolicy.EqualObjects(old, object) {
			if object.Generation == ^uint64(0) {
				return iriObjectError(operationCode, "generic object generation exhausted")
			}
			object.Generation++
		}
		objects[index] = iripolicy.CloneObject(object)
	case "delete":
		objects = slices.Delete(objects, index, index+1)
	case "delete_all":
		objects = []iripolicy.Object{}
	}
	if err := iripolicy.ValidateObjects(objects, m.config.IRIProfile, iripolicy.Limits{}); err != nil {
		return iriObjectError(operationCode, "invalid or referenced IRI policy object")
	}
	// Validate complete graph references, including policies with no current task.
	for _, entry := range objects {
		if entry.Policy != nil {
			if _, err := iripolicy.Compile([]uuid.UUID{entry.ID}, objects, m.config.IRIProfile, iripolicy.Limits{}); err != nil {
				return iriObjectError(operationCode, "generic object is referenced or graph is incomplete")
			}
		}
	}
	m.registry.mu.RLock()
	tasks := make([]*InterceptTask, 0, len(m.registry.tasks))
	for _, task := range m.registry.tasks {
		tasks = append(tasks, cloneInterceptTask(task))
	}
	m.registry.mu.RUnlock()
	var previous, candidates []*InterceptTask
	for _, task := range tasks {
		if len(task.IRIPolicyReferences) == 0 || task.Status == TaskStatusDeactivated || task.Status == TaskStatusFailed {
			continue
		}
		compiled, err := iripolicy.Compile(task.IRIPolicyReferences, objects, m.config.IRIProfile, iripolicy.Limits{})
		if err != nil {
			return iriObjectError(operationCode, "generic object is referenced by a task")
		}
		m.iriMu.RLock()
		confirmed := true
		for sourceID := range compiled.SourceGenerations() {
			if sourceID != id && !m.iriConfirmed[sourceID] {
				confirmed = false
				break
			}
		}
		m.iriMu.RUnlock()
		if !confirmed {
			return iriObjectError(operationCode, "dependent task requires confirmed policy sources")
		}
		if maps.Equal(task.IRIPolicySourceGenerations, compiled.SourceGenerations()) {
			continue
		}
		if task.Status == TaskStatusSuspended && !task.Definition.ConflictDisarmed {
			continue
		}
		candidate := cloneInterceptTask(task)
		candidate.IRIPolicySourceGenerations = compiled.SourceGenerations()
		m.registry.mu.RLock()
		watermark := m.registry.generations[task.XID]
		m.registry.mu.RUnlock()
		if watermark == ^uint64(0) {
			return iriObjectError(operationCode, "task generation exhausted")
		}
		candidate.ActivationGeneration = watermark + 1
		previous = append(previous, task)
		candidates = append(candidates, candidate)
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].ID.String() < objects[j].ID.String() })
	return m.commitIRIGraphLocked(objects, previous, candidates, id, operation)
}

func (m *Manager) commitIRIGraphLocked(objects []iripolicy.Object, previous, candidates []*InterceptTask, confirmedID uuid.UUID, operation string) error {
	var intents []*StateIntent
	var controls []*StateRevocation
	var committedErr error
	if m.stateStore != nil {
		for n, candidate := range candidates {
			if err := m.unfinishedSubjectLocked(candidate.XID, uuid.Nil); err != nil {
				return err
			}
			intent, err := m.taskIntentLocked(StateTaskModify, previous[n], candidate)
			if err != nil {
				return err
			}
			intent.IncludeX2 = true
			planned, err := m.prepareRevocationsLocked(intent, previous[n], nil)
			if err != nil {
				return err
			}
			for _, control := range planned {
				intent.RevocationIDs = append(intent.RevocationIDs, control.ControlID)
			}
			intents = append(intents, intent)
			controls = append(controls, planned...)
		}
		if len(intents) > 0 {
			if err := m.reserveAdministrativeLocked(intents, controls, false); err != nil {
				return err
			}
		}
	}
	fail := func(cause error) error {
		for n, intent := range intents {
			cause = errors.Join(cause, m.failAdministrativeTaskLocked(intent, candidates[n], cause))
		}
		if len(previous) > 0 {
			m.faultAdministrative(cause)
		}
		return cause
	}
	if len(previous) > 0 {
		m.registry.mu.Lock()
		for _, task := range previous {
			m.registry.tasks[task.XID].Status = TaskStatusSuspended
		}
		m.registry.mu.Unlock()
		if _, err := m.commitRevocationsLocked(controls); err != nil {
			return fail(err)
		}
		for _, task := range previous {
			if err := m.notifyIRIPolicyChanged(task); err != nil {
				return fail(err)
			}
			m.notifyTaskModified(task)
		}
		for _, candidate := range candidates {
			if candidate.Status == TaskStatusActive {
				if err := m.filters.UpdateFiltersForTask(candidate); err != nil {
					return fail(err)
				}
			}
		}
	}
	if m.stateStore != nil {
		snapshot := m.snapshotAdministrativeLocked()
		snapshot.GenericObjects = iripolicy.CloneObjects(objects)
		for n, intent := range intents {
			intent.Phase = StateFinished
			intent.CleanupFilterIDs = []string{}
			replaceSnapshotTask(snapshot, candidates[n])
			ids := m.filters.GetFiltersForXID(candidates[n].XID)
			if len(ids) > 0 {
				snapshot.CleanupNeeded[candidates[n].XID] = ids
			} else {
				delete(snapshot.CleanupNeeded, candidates[n].XID)
			}
		}
		out, err := m.saveAdministrativeSnapshotLocked(snapshot, false)
		if err != nil {
			if out != securestore.Committed {
				for _, intent := range intents {
					intent.Phase = StateReserved
				}
				if len(intents) > 0 {
					return fail(err)
				}
				return err
			}
			committedErr = err
		}
		m.stateCleanup = snapshot.CleanupNeeded
	}
	m.iriMu.Lock()
	m.iriObjects = iripolicy.CloneObjects(objects)
	m.iriCompiled = nil
	if m.iriConfirmed == nil {
		m.iriConfirmed = make(map[uuid.UUID]bool)
	}
	if operation == "create" || operation == "modify" {
		m.iriConfirmed[confirmedID] = true
	} else if operation == "snapshot" {
		m.iriConfirmed = make(map[uuid.UUID]bool, len(objects))
		for _, object := range objects {
			m.iriConfirmed[object.ID] = true
		}
	} else if operation == "delete_all" {
		m.iriConfirmed = make(map[uuid.UUID]bool)
	} else {
		delete(m.iriConfirmed, confirmedID)
	}
	m.iriMu.Unlock()
	m.registry.mu.Lock()
	for _, candidate := range candidates {
		m.registry.tasks[candidate.XID] = cloneInterceptTask(candidate)
		m.registry.generations[candidate.XID] = candidate.ActivationGeneration
	}
	m.registry.mu.Unlock()
	for _, candidate := range candidates {
		m.notifyCommittedTask(candidate)
	}
	return committedErr
}

func (a *managerTaskAdapter) CreateGenericObject(object iripolicy.Object) error {
	return a.m.CreateGenericObject(object)
}
func (a *managerTaskAdapter) ModifyGenericObject(object iripolicy.Object) error {
	return a.m.ModifyGenericObject(object)
}
func (a *managerTaskAdapter) DeleteGenericObject(id uuid.UUID) error {
	return a.m.DeleteGenericObject(id)
}
func (a *managerTaskAdapter) GetGenericObject(id uuid.UUID) (iripolicy.Object, error) {
	return a.m.GetGenericObject(id)
}
func (a *managerTaskAdapter) GetGenericObjects() ([]iripolicy.Object, error) {
	return a.m.GetGenericObjects()
}
func (a *managerTaskAdapter) DeleteAllGenericObjects() error { return a.m.DeleteAllGenericObjects() }

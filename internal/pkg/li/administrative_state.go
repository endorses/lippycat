//go:build li

package li

import (
	"errors"
	"os"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

var ErrAdministrativeFault = errors.New("LI administrative state requires reconciliation; admission is blocked")

type administrativeFault struct{ err error }
type administrativeIdentity struct {
	incarnation uuid.UUID
	radiusPin   string
}

type administrativeStateStore interface {
	Load() (*StateSnapshot, error)
	Save(*StateSnapshot) (securestore.Outcome, error)
	SaveControl(*StateSnapshot) (securestore.Outcome, error)
	StoreID() uuid.UUID
	Close() error
}

func (m *Manager) administrativeAdmissionReady() bool {
	return !m.stopped.Load() && m.stateFault.Load() == nil && (m.config.StateFile == "" || m.stateReady.Load())
}

func (m *Manager) administrativeError() error {
	if m.stopped.Load() {
		return os.ErrClosed
	}
	if fault := m.stateFault.Load(); fault != nil {
		return errors.Join(ErrAdministrativeFault, fault.err)
	}
	return nil
}

func (m *Manager) faultAdministrative(err error) {
	if err != nil {
		m.stateFault.CompareAndSwap(nil, &administrativeFault{err: err})
	}
}

// StateIncarnation identifies the owned encrypted administrative store. It is
// stable across restart/rotation and zero when persistence is disabled/unopened.
func (m *Manager) StateIncarnation() uuid.UUID {
	if id := m.stateIdentity.Load(); id != nil {
		return id.incarnation
	}
	return uuid.Nil
}

// RADIUSCorrelationStateFile never derives an allocator from a possibly moved
// administrative path. Missing pins fail at the allocator boundary, while
// non-RADIUS operation may use an otherwise valid unpinned snapshot.
func (m *Manager) RADIUSCorrelationStateFile() (string, error) {
	if err := m.administrativeError(); err != nil {
		return "", err
	}
	if m.config.StateFile == "" {
		return m.config.RADIUSCorrelationStateFile, nil
	}
	id := m.stateIdentity.Load()
	if !m.stateReady.Load() || id == nil || id.radiusPin == "" {
		return "", errors.New("encrypted LI state has no RADIUS correlation allocator pin")
	}
	return id.radiusPin, nil
}

// PrepareAdministrativeStorage owns and authenticates the complete document
// without publishing tasks, cleaning filters, or invoking delivery callbacks.
// Start and mutations reuse this owner and perform reconciliation separately.
func (m *Manager) PrepareAdministrativeStorage() error {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	return m.prepareAdministrativeStorageLocked()
}

func (m *Manager) prepareAdministrativeStorageLocked() error {
	if err := m.administrativeError(); err != nil {
		return err
	}
	if m.config.StateFile == "" {
		return nil
	}
	if m.stateStore != nil {
		if m.statePath != m.config.StateFile {
			return errors.New("LI administrative store path cannot change while owned")
		}
		return nil
	}
	store, err := OpenStateStore(m.config.StateFile, m.config.StateKeys)
	if err != nil {
		return err
	}
	state, err := store.Load()
	if err == nil && m.config.RADIUSCorrelationStateFile != "" && m.config.RADIUSCorrelationStateFile != state.RADIUSCorrelationStateFile {
		err = errors.New("configured RADIUS correlation allocator conflicts with encrypted state pin")
	}
	if err != nil {
		return errors.Join(err, store.Close())
	}
	m.stateStore, m.statePath, m.stateID, m.preparedState = store, m.config.StateFile, store.StoreID(), state
	m.radiusCorrelationPin = state.RADIUSCorrelationStateFile
	m.stateIdentity.Store(&administrativeIdentity{incarnation: m.stateID, radiusPin: state.RADIUSCorrelationStateFile})
	return nil
}

func (m *Manager) ensureAdministrativeStateLocked() error {
	if err := m.administrativeError(); err != nil {
		return err
	}
	if m.config.StateFile != "" && !m.stateReady.Load() {
		return m.restorePersistedStateLocked()
	}
	if m.stateStore != nil && m.statePath != m.config.StateFile {
		return errors.New("LI administrative store path cannot change while owned")
	}
	return nil
}

func (m *Manager) closeAdministrativeStateLocked() error {
	m.stateReady.Store(false)
	if m.stateStore == nil {
		return nil
	}
	err := m.stateStore.Close()
	m.stateStore = nil
	m.preparedState = nil
	return err
}

// snapshotAdministrativeLocked requires adminMu. Every registry/filter value is
// detached before store I/O; a different mutation cannot enter this snapshot.
func (m *Manager) snapshotAdministrativeLocked() *StateSnapshot {
	s := &StateSnapshot{Version: StateSchemaVersion, WrittenAt: time.Now().UTC(), Incarnation: m.stateID,
		RADIUSCorrelationStateFile: m.radiusCorrelationPin,
		Tasks:                      []*InterceptTask{}, Destinations: []*StateDestination{}, CleanupNeeded: map[uuid.UUID][]string{}, Generations: map[uuid.UUID]uint64{},
		Intents: m.stateIntents, Revocations: m.stateRevocations}
	m.registry.mu.RLock()
	for id, generation := range m.registry.generations {
		s.Generations[id] = generation
	}
	registered := make(map[uuid.UUID]bool, len(m.registry.tasks))
	for id, task := range m.registry.tasks {
		s.Tasks = append(s.Tasks, cloneInterceptTask(task))
		registered[id] = true
	}
	for _, d := range m.registry.destinations {
		s.Destinations = append(s.Destinations, &StateDestination{DID: d.DID, Address: d.Address, Port: d.Port, X2Enabled: d.X2Enabled, X3Enabled: d.X3Enabled,
			ProtocolType: d.ProtocolType, Description: d.Description, CreatedAt: d.CreatedAt, DeliveryRevision: d.DeliveryRevision})
	}
	m.registry.mu.RUnlock()
	for id, task := range m.persistedActive {
		s.Generations[id] = max(s.Generations[id], task.ActivationGeneration)
	}
	for id, task := range m.persistenceCandidates {
		if !registered[id] && s.Generations[id] == task.ActivationGeneration {
			s.Tasks = append(s.Tasks, cloneInterceptTask(task))
		}
	}
	for id, ids := range m.stateCleanup {
		s.CleanupNeeded[id] = append([]string{}, ids...)
	}
	m.filters.mu.RLock()
	for id, ids := range m.filters.xidToFilters {
		for _, filterID := range ids {
			if !containsCleanupID(s.CleanupNeeded[id], filterID) {
				s.CleanupNeeded[id] = append(s.CleanupNeeded[id], filterID)
			}
		}
	}
	m.filters.mu.RUnlock()
	return s
}

func containsCleanupID(ids []string, id string) bool {
	for _, existing := range ids {
		if existing == id {
			return true
		}
	}
	return false
}

func (m *Manager) persistStateLocked() error {
	if err := m.ensureAdministrativeStateLocked(); err != nil {
		return err
	}
	if m.stateStore == nil {
		return nil
	}
	out, err := m.stateStore.Save(m.snapshotAdministrativeLocked())
	if err == nil && out != securestore.Committed {
		err = errors.New("administrative snapshot did not commit")
	}
	if err != nil {
		// Until a coordinator classifies an operation's earlier boundaries, a
		// failed checkpoint conservatively closes admission for the whole owner.
		m.faultAdministrative(err)
		return &securestore.CommitError{Outcome: out, Op: "save administrative state", Err: err}
	}
	return nil
}

func (m *Manager) persistState() error {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	return m.persistStateLocked()
}

func (m *Manager) expireAdministrativeTask(task *InterceptTask) {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	current, err := m.registry.GetTaskDetails(task.XID)
	if err != nil || current.ActivationGeneration != task.ActivationGeneration {
		return
	}
	if m.stateStore != nil {
		if err := m.withdrawPersistentTaskLocked(task.XID, StateTaskExpire, ""); err != nil {
			m.faultAdministrative(err)
			logger.Error("LI task expiry enforcement failed", "xid", task.XID, "error", err)
		}
		return
	}
	// Expiration itself closes admission even if durable cleanup cannot finish.
	m.registry.mu.Lock()
	m.registry.tasks[task.XID].Status = TaskStatusSuspended
	m.registry.mu.Unlock()
	if err := m.completeExpiration(task); err != nil {
		logger.Error("LI task expiry enforcement failed", "xid", task.XID, "error", err)
	}
	if m.registry.onDeactivation != nil {
		m.registry.onDeactivation(task, DeactivationReasonExpired)
	}
}

//go:build li

package li

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

const persistenceSchemaVersion = 1

type persistedState struct {
	Version      int                     `json:"version"`
	WrittenAt    time.Time               `json:"written_at"`
	Tasks        []*InterceptTask        `json:"tasks"`
	Destinations []*persistedDestination `json:"destinations"`
	Cleanup      map[uuid.UUID][]string  `json:"cleanup_needed,omitempty"`
	Generations  map[uuid.UUID]uint64    `json:"generations,omitempty"`
}

// persistedDestination deliberately excludes TLSConfig and all key material.
type persistedDestination struct {
	DID              uuid.UUID `json:"did"`
	Address          string    `json:"address"`
	Port             int       `json:"port"`
	X2Enabled        bool      `json:"x2_enabled"`
	X3Enabled        bool      `json:"x3_enabled"`
	ProtocolType     string    `json:"protocol_type,omitempty"`
	Description      string    `json:"description,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	DeliveryRevision uint64    `json:"delivery_revision,omitempty"`
}

func loadPersistedState(path string) (*persistedState, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read LI state %q: %w", path, err)
	}
	var state persistedState
	if err := json.Unmarshal(b, &state); err != nil {
		return nil, fmt.Errorf("decode LI state %q: %w", path, err)
	}
	if state.Version != persistenceSchemaVersion {
		return nil, fmt.Errorf("LI state %q has unsupported schema version %d", path, state.Version)
	}
	return &state, nil
}

func writePersistedState(path string, state *persistedState) (result error) {
	state.Version, state.WrittenAt = persistenceSchemaVersion, time.Now().UTC()
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode LI state: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create LI state directory %q: %w", dir, err)
	}
	// Open before replacing state: write/search permissions alone permit the
	// rename, but cannot provide the directory handle needed to make it durable.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open LI state directory for sync: %w", err)
	}
	defer func() {
		if err := d.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("close LI state directory: %w", err))
		}
	}()
	tmp, err := os.CreateTemp(dir, ".li-state-*")
	if err != nil {
		return fmt.Errorf("create temporary LI state: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary LI state: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary LI state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary LI state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary LI state: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace LI state %q: %w", path, err)
	}
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync LI state directory: %w", err)
	}
	return nil
}

// restorePersistedState acquires ownership and authenticates a complete detached
// snapshot before publishing registry data or attempting filter cleanup.
func (m *Manager) restorePersistedState() error {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	return m.restorePersistedStateLocked()
}

func (m *Manager) restorePersistedStateLocked() (result error) {
	if m.config.StateFile == "" {
		return nil
	}
	if m.stateReady.Load() {
		return m.prepareAdministrativeStorageLocked()
	}
	if err := m.prepareAdministrativeStorageLocked(); err != nil {
		return err
	}
	store, state := m.stateStore, m.preparedState
	defer func() {
		if result != nil {
			result = errors.Join(result, m.closeAdministrativeStateLocked())
		}
	}()
	if err := m.recoverAdministrativeLocked(state); err != nil {
		return err
	}
	// Build the entire restored registry off to the side. Historical definitions
	// have already passed codec validation; activation validation is deliberately
	// not applied to retained or expired data here.
	tasks := make(map[uuid.UUID]*InterceptTask)
	destinations := make(map[uuid.UUID]*Destination)
	active := make(map[uuid.UUID]*InterceptTask)
	candidates := make(map[uuid.UUID]*InterceptTask)
	unconfirmedPending := make(map[uuid.UUID]bool)
	for _, d := range state.Destinations {
		destinations[d.DID] = &Destination{DID: d.DID, Address: d.Address, Port: d.Port, X2Enabled: d.X2Enabled, X3Enabled: d.X3Enabled,
			ProtocolType: d.ProtocolType, Description: d.Description, CreatedAt: d.CreatedAt, DeliveryRevision: d.DeliveryRevision}
	}
	now := time.Now()
	for _, task := range state.Tasks {
		if IsRADIUSTask(task) && (task.Status == TaskStatusPending || task.Status == TaskStatusActive || task.Status == TaskStatusSuspended) {
			active[task.XID], candidates[task.XID] = cloneInterceptTask(task), cloneInterceptTask(task)
			continue
		}
		if !task.EndTime.IsZero() && !now.Before(task.EndTime) {
			// Keep the complete historical definition in future snapshots without
			// treating it as a registry activation or replay confirmation.
			candidates[task.XID] = cloneInterceptTask(task)
			continue
		}
		switch task.Status {
		case TaskStatusPending, TaskStatusDeactivated, TaskStatusFailed:
			tasks[task.XID] = cloneInterceptTask(task)
			if task.Status == TaskStatusPending {
				unconfirmedPending[task.XID] = true
			}
		case TaskStatusActive, TaskStatusSuspended:
			active[task.XID], candidates[task.XID] = cloneInterceptTask(task), cloneInterceptTask(task)
		}
	}
	m.registry.mu.Lock()
	m.registry.tasks, m.registry.destinations, m.registry.generations = tasks, destinations, state.Generations
	m.registry.unconfirmedPending = unconfirmedPending
	m.registry.mu.Unlock()
	m.persistedActive, m.persistenceCandidates = active, candidates
	m.stateIntents, m.stateRevocations = state.Intents, state.Revocations
	m.stateCleanup = make(map[uuid.UUID][]string)
	m.stateStore, m.statePath, m.stateID = store, m.config.StateFile, store.StoreID()
	m.stateIdentity.Store(&administrativeIdentity{incarnation: m.stateID, radiusPin: state.RADIUSCorrelationStateFile})
	m.radiusCorrelationPin = state.RADIUSCorrelationStateFile
	m.preparedState = nil
	m.stateReady.Store(true)
	return nil
}

// ReplayTaskAuthorized requires an unchanged persisted activation confirmed by
// the startup ADMF snapshot. UUID/generation equality without that evidence is
// insufficient. Call after Start; lifecycle state is revalidated on every call.
func (m *Manager) ReplayTaskAuthorized(xid uuid.UUID, generation uint64) bool {
	if !m.administrativeAdmissionReady() {
		return false
	}
	m.mu.RLock()
	confirmed := m.replayConfirmed[xid]
	m.mu.RUnlock()
	if generation == 0 || confirmed != generation {
		return false
	}
	task, err := m.GetTaskDetails(xid)
	return err == nil && !IsRADIUSTask(task) && task.IsActive() && task.ActivationGeneration == generation && equivalentTaskDefinition(m.persistedActive[xid], task)
}

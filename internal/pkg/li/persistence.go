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
}

// persistedDestination deliberately excludes TLSConfig and all key material.
type persistedDestination struct {
	DID          uuid.UUID `json:"did"`
	Address      string    `json:"address"`
	Port         int       `json:"port"`
	X2Enabled    bool      `json:"x2_enabled"`
	X3Enabled    bool      `json:"x3_enabled"`
	ProtocolType string    `json:"protocol_type,omitempty"`
	Description  string    `json:"description,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
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

func writePersistedState(path string, state *persistedState) error {
	state.Version, state.WrittenAt = persistenceSchemaVersion, time.Now().UTC()
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode LI state: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create LI state directory %q: %w", dir, err)
	}
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
	if d, err := os.Open(dir); err == nil {
		defer d.Close()
		if err := d.Sync(); err != nil {
			return fmt.Errorf("sync LI state directory: %w", err)
		}
	}
	return nil
}

func (m *Manager) persistState() error {
	if m.config.StateFile == "" {
		return nil
	}
	state := &persistedState{Cleanup: make(map[uuid.UUID][]string)}
	m.registry.ListTasks(func(task *InterceptTask) bool {
		state.Tasks = append(state.Tasks, task)
		return true
	})
	for _, dest := range m.ListDestinations() {
		state.Destinations = append(state.Destinations, &persistedDestination{
			DID: dest.DID, Address: dest.Address, Port: dest.Port,
			X2Enabled: dest.X2Enabled, X3Enabled: dest.X3Enabled,
			ProtocolType: dest.ProtocolType, Description: dest.Description, CreatedAt: dest.CreatedAt,
		})
	}
	m.filters.mu.RLock()
	for xid, ids := range m.filters.xidToFilters {
		state.Cleanup[xid] = append([]string(nil), ids...)
	}
	m.filters.mu.RUnlock()
	return writePersistedState(m.config.StateFile, state)
}

func (m *Manager) restorePersistedState() error {
	if m.config.StateFile == "" {
		return nil
	}
	state, err := loadPersistedState(m.config.StateFile)
	if err != nil || state == nil {
		return err
	}
	for _, pd := range state.Destinations {
		if pd == nil || pd.DID == uuid.Nil || pd.Address == "" || pd.Port <= 0 || pd.Port > 65535 {
			return fmt.Errorf("invalid persisted LI destination")
		}
		if err := m.registry.restoreDestination(&Destination{DID: pd.DID, Address: pd.Address, Port: pd.Port,
			X2Enabled: pd.X2Enabled, X3Enabled: pd.X3Enabled, ProtocolType: pd.ProtocolType,
			Description: pd.Description, CreatedAt: pd.CreatedAt}); err != nil {
			return err
		}
	}
	now := time.Now()
	for _, task := range state.Tasks {
		if task == nil {
			return fmt.Errorf("nil task in persisted LI state")
		}
		if !task.EndTime.IsZero() && !now.Before(task.EndTime) {
			continue
		}
		switch task.Status {
		case TaskStatusPending:
			if err := m.registry.restorePendingTask(task); err != nil {
				return fmt.Errorf("restore pending XID %s: %w", task.XID, err)
			}
		case TaskStatusActive, TaskStatusSuspended:
			// Active state is only a candidate until a complete ADMF snapshot confirms it.
			copyTask := *task
			m.persistedActive[task.XID] = &copyTask
		}
	}
	// Retry withdrawal before any task can be armed. These IDs are safe to
	// remove because active tasks are not restored until ADMF confirmation.
	if m.config.FilterPusher != nil {
		for xid, ids := range state.Cleanup {
			for _, id := range ids {
				if err := m.config.FilterPusher.DeleteFilter(id); err != nil {
					return fmt.Errorf("resume cleanup XID %s filter %s: %w", xid, id, err)
				}
			}
		}
	}
	return nil
}

//go:build li

package li

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// newStateTestManager explicitly provisions/imports test fixtures before runtime
// construction. Production NewManager never creates a key, ledger or snapshot.
func newStateTestManager(t testing.TB, cfg ManagerConfig, callback DeactivationCallback) *Manager {
	t.Helper()
	if cfg.StateFile != "" {
		cfg.StateKeys = prepareStateTestStore(t, cfg.StateFile)
	}
	m := NewManager(cfg, callback)
	t.Cleanup(m.Stop)
	return m
}

func prepareStateTestStore(t testing.TB, path string) securestore.KeyConfig {
	t.Helper()
	parent := filepath.Dir(path)
	require.NoError(t, os.MkdirAll(parent, 0700))
	require.NoError(t, os.Chmod(parent, 0700))
	keys := securestore.KeyConfig{Active: securestore.KeyRef{ID: "state-test", File: filepath.Join(parent, "state-test.key")}}
	if _, err := os.Stat(keys.Active.File); errors.Is(err, os.ErrNotExist) {
		require.NoError(t, os.WriteFile(keys.Active.File, bytes.Repeat([]byte{0x74}, securestore.KeyBytes), 0600))
	} else {
		require.NoError(t, err)
	}
	data, err := os.ReadFile(path)
	if err == nil && bytes.HasPrefix(data, []byte("LCS1")) {
		return keys
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return keys
	} // deliberate unsafe/corrupt fixture
	s := emptyStateFixture()
	if len(data) != 0 {
		var legacy persistedState
		if json.Unmarshal(data, &legacy) != nil {
			return keys
		} // corruption test
		// Older tests omitted identities that the real writer supplied. Make
		// those fixtures explicit before the strict legacy migration boundary.
		for _, d := range legacy.Destinations {
			if d != nil && d.CreatedAt.IsZero() {
				d.CreatedAt = time.Now().UTC()
			}
		}
		for _, task := range legacy.Tasks {
			if task != nil && (task.Status == TaskStatusActive || task.Status == TaskStatusSuspended) && task.ActivationGeneration == 0 {
				task.ActivationGeneration = 1
			}
		}
		if legacy.WrittenAt.IsZero() {
			legacy.WrittenAt = time.Now().UTC()
		}
		data, err = json.Marshal(&legacy)
		require.NoError(t, err)
		s, err = DecodeLegacyStateSnapshot(data, uuid.New())
		require.NoError(t, err)
		require.NoError(t, os.Remove(path))
	}
	s.RADIUSCorrelationStateFile = path + ".radius-correlation"
	out, err := InitStateStore(path, keys, s)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	return keys
}

func readManagerStateTest(t testing.TB, m *Manager) *StateSnapshot {
	t.Helper()
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	require.NotNil(t, m.stateStore)
	s, err := m.stateStore.Load()
	require.NoError(t, err)
	return s
}

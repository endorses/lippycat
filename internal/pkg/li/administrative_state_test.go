//go:build li

package li

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestAdministrativeRADIUSAllocatorPin(t *testing.T) {
	for _, mode := range []string{"moved", "missing", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			path, keys, _ := stateStoreFixture(t)
			s := emptyStateFixture()
			pin := filepath.Join(t.TempDir(), "old-state.json.radius-correlation")
			if mode != "missing" {
				s.RADIUSCorrelationStateFile = pin
			}
			out, err := InitStateStore(path, keys, s)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			cfg := ManagerConfig{Enabled: true, StateFile: path, StateKeys: keys, LifecycleInterval: time.Hour}
			if mode == "conflict" {
				cfg.RADIUSCorrelationStateFile = path + ".radius-correlation"
			}
			m := NewManager(cfg, nil)
			t.Cleanup(m.Stop)
			if mode == "conflict" {
				require.ErrorContains(t, m.Start(), "conflicts")
				require.Zero(t, m.TaskCount())
				return
			}
			require.NoError(t, m.Start())
			got, err := m.RADIUSCorrelationStateFile()
			if mode == "missing" {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, pin, got)
			require.NotEqual(t, path+".radius-correlation", got)
			require.Equal(t, s.Incarnation, m.StateIncarnation())
		})
	}
	m := NewManager(ManagerConfig{RADIUSCorrelationStateFile: "explicit-legacy-sidecar"}, nil)
	defer m.Stop()
	pin, err := m.RADIUSCorrelationStateFile()
	require.NoError(t, err)
	require.Equal(t, "explicit-legacy-sidecar", pin)
}

func TestAdministrativeInvalidSnapshotHasNoRestoreEffects(t *testing.T) {
	store, path, keys := openInitializedState(t)
	s := stateFixture(t)
	plain, err := MarshalStateSnapshot(s)
	require.NoError(t, err)
	plain = bytes.Replace(plain, []byte(`"Status":4`), []byte(`"Status":99`), 1)
	sealed, err := store.writer.Seal(securestore.AdministrativeState, securestore.Binding{Store: [16]byte(s.Incarnation), Object: stateSnapshotObject}, plain)
	require.NoError(t, err)
	_, err = store.write(store.name, sealed)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	pusher := &mockFilterPusher{}
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path, StateKeys: keys, FilterPusher: pusher}, nil)
	t.Cleanup(m.Stop)
	require.Error(t, m.Start())
	require.Zero(t, m.TaskCount())
	require.Empty(t, m.ListDestinations())
	require.Empty(t, pusher.deletes)
	require.Empty(t, pusher.updates)
	_, err = OpenStateStore(path, keys)
	require.ErrorIs(t, err, ErrStateSnapshot)
	require.NotErrorIs(t, err, securestore.ErrLocked)
}

func TestAdministrativeConfiguredStateNeverInitializesAtRuntime(t *testing.T) {
	path, keys, _ := stateStoreFixture(t)
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path, StateKeys: keys}, nil)
	t.Cleanup(m.Stop)
	require.Error(t, m.Start())
	_, err := os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Zero(t, m.TaskCount())
	admission, ok := m.AcquireTaskAdmission(uuid.New(), 1)
	require.Nil(t, admission)
	require.False(t, ok)
}

func TestAdministrativeUncertainCheckpointClosesAllAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.enc")
	m, _, dids := newIdempotencyManager(t, path)
	task := idempotencyTask(uuid.New(), dids, time.Time{})
	require.NoError(t, m.ActivateTask(task))
	active, err := m.GetTaskDetails(task.XID)
	require.NoError(t, err)
	store := m.stateStore.(*EncryptedStateStore)
	replace := store.write
	store.write = func(name string, data []byte) (securestore.Outcome, error) {
		out, err := replace(name, data)
		require.NoError(t, err)
		require.Equal(t, securestore.Committed, out)
		return securestore.Uncertain, errors.New("injected sync uncertainty")
	}
	require.Error(t, m.persistState())
	_, ok := m.AcquireTaskAdmission(task.XID, active.ActivationGeneration)
	require.False(t, ok)
	require.Empty(t, m.GetActiveTasks())
	require.False(t, m.ReplayTaskAuthorized(task.XID, active.ActivationGeneration))
	require.ErrorIs(t, m.ActivateTask(task), ErrAdministrativeFault)
	require.ErrorIs(t, m.ModifyDestination(dids[0], &Destination{DID: dids[0], Address: "replacement", Port: 443}), ErrAdministrativeFault)
}

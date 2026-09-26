//go:build li

package li

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestAdministrativeKeyringRetainsAuthenticatedOwner(t *testing.T) {
	path, keys, material := stateStoreFixture(t)
	_, err := InitStateStore(path, keys, stateFixture(t))
	require.NoError(t, err)
	m := NewManager(ManagerConfig{Enabled: true, StateFile: path, StateKeys: keys}, nil)
	t.Cleanup(m.Stop)
	ring, err := m.AdministrativeKeyring()
	require.Error(t, err)
	require.Nil(t, ring)
	require.NoError(t, m.PrepareAdministrativeStorage())
	ring, err = m.AdministrativeKeyring()
	require.NoError(t, err)
	require.NotNil(t, ring)
	require.False(t, m.stateReady.Load(), "keys become available before reconciliation effects")
	require.NoError(t, os.WriteFile(keys.Active.File, bytes.Repeat([]byte{0x76}, securestore.KeyBytes), 0600))
	replaced, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	require.NoError(t, securestore.CheckIndependent(ring, replaced))
	retained, err := m.AdministrativeKeyring()
	require.NoError(t, err)
	require.Same(t, ring, retained)
	require.NoError(t, os.WriteFile(keys.Active.File, material, 0600))
	original, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	require.Error(t, securestore.CheckIndependent(ring, original))
	m.Stop()
	ring, err = m.AdministrativeKeyring()
	require.ErrorIs(t, err, os.ErrClosed)
	require.Nil(t, ring)
}

func TestAdministrativeKeyringDisabledAndFaulted(t *testing.T) {
	for _, cfg := range []ManagerConfig{{}, {Enabled: true}, {StateFile: "/unreadable/state", StateKeys: securestore.KeyConfig{}}} {
		m := NewManager(cfg, nil)
		ring, err := m.AdministrativeKeyring()
		require.NoError(t, err)
		require.Nil(t, ring)
		m.Stop()
	}
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	m.faultAdministrative(errors.New("storage failure"))
	ring, err := m.AdministrativeKeyring()
	require.ErrorIs(t, err, ErrAdministrativeFault)
	require.Nil(t, ring)
}

func TestAdministrativePreparedReleaseHasNoNotificationEffects(t *testing.T) {
	for _, mutate := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "pre-start-mutation"}[mutate], func(t *testing.T) {
			path, keys, _ := stateStoreFixture(t)
			_, err := InitializeEncryptedStateStore(path, keys, StateOfflineOptions{})
			require.NoError(t, err)
			var notifications atomic.Int64
			admf := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { notifications.Add(1) }))
			t.Cleanup(admf.Close)
			m := NewManager(ManagerConfig{Enabled: true, StateFile: path, StateKeys: keys, ADMFEndpoint: admf.URL}, nil)
			require.NoError(t, m.PrepareAdministrativeStorage())
			if mutate {
				require.NoError(t, m.CreateDestination(&Destination{DID: uuid.New(), Address: "mdf.example", Port: 443, X2Enabled: true}))
				require.True(t, m.stateReady.Load())
			}
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			require.NoError(t, m.ReleasePreparedAdministrativeStorage())
			require.NoError(t, m.ReleasePreparedAdministrativeStorage())
			require.Zero(t, notifications.Load())
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, before, after)
			store, err := OpenStateStore(path, keys)
			require.NoError(t, err)
			require.NoError(t, store.Close())
		})
	}
}

func TestAdministrativePreparedReleaseRejectsStartedLifecycle(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	t.Cleanup(m.Stop)
	require.NoError(t, m.Start())
	require.ErrorContains(t, m.ReleasePreparedAdministrativeStorage(), "already entered startup")
}

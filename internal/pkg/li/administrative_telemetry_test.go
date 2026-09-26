//go:build li

package li

import (
	"errors"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestAdministrativeStorageTelemetryDoesNotWaitForCommit(t *testing.T) {
	m, _, _, _ := administrativeTransactionManager(t)
	snapshot := readManagerStateTest(t, m)
	store := m.stateStore.(*EncryptedStateStore)
	write := store.write
	entered, release := make(chan struct{}), make(chan struct{})
	store.write = func(name string, data []byte) (securestore.Outcome, error) {
		close(entered)
		<-release
		out, err := write(name, data)
		if err != nil {
			return out, err
		}
		return securestore.Committed, errors.New("chosen-private-cleanup-path")
	}
	before := m.AdministrativeStorageStatus()
	done := make(chan error, 1)
	go func() { _, err := store.Save(snapshot); done <- err }()
	<-entered
	read := make(chan securestore.StorageStatus, 1)
	go func() { read <- m.AdministrativeStorageStatus() }()
	select {
	case s := <-read:
		require.Equal(t, before.Commits, s.Commits)
		require.Equal(t, "encrypted", s.Mode)
	case <-time.After(time.Second):
		close(release)
		t.Fatal("administrative telemetry waited for fsync")
	}
	close(release)
	require.Error(t, <-done)
	s := m.AdministrativeStorageStatus()
	require.Equal(t, before.Commits+1, s.Commits)
	require.Equal(t, uint64(1), s.CleanupWarnings)
	require.False(t, s.AdmissionBlocked)
	m.faultAdministrative(errors.New("private-task"))
	s = m.AdministrativeStorageStatus()
	require.True(t, s.AdmissionBlocked)
	require.Equal(t, "ready", s.State, "policy fault is separate from snapshot health")
	require.Equal(t, "reconciliation_required", s.PolicyFaultCode)
	m.Stop()
	require.Equal(t, "closed", m.AdministrativeStorageStatus().State)
	_, err := store.Load()
	require.Error(t, err)
	_, err = store.Save(snapshot)
	require.Error(t, err)
	require.Equal(t, "closed", m.AdministrativeStorageStatus().State)
	require.Equal(t, "not_committed", m.AdministrativeStorageStatus().LastOutcome)
}

func TestAdministrativeStorageTelemetryDisabled(t *testing.T) {
	m := NewManager(ManagerConfig{Enabled: true}, nil)
	defer m.Stop()
	s := m.AdministrativeStorageStatus()
	require.Equal(t, "disabled", s.Mode)
	require.Nil(t, s.Usage)
	require.Empty(t, s.ActiveKeyID)
	require.False(t, s.AdmissionBlocked)
}

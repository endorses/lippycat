package filtering

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestStorageStatusSnapshotOutcomesAndNonblockingCollection(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain, securestore.Committed} {
			t.Run(string(rune('a'+outcome))+map[bool]string{false: "/yaml", true: "/encrypted"}[encrypted], func(t *testing.T) {
				path := filepath.Join(privateStoreTestDir(t), "filters")
				var owner interface {
					Load(string) (map[string]*management.Filter, error)
					Save(string, map[string]*management.Filter) error
					StorageStatus() securestore.StorageStatus
					Close() error
				}
				var file *snapshotFile
				if encrypted {
					keys := storeTestKey(t, 93)
					_, err := InitializeEncryptedFilterStore(path, keys, OfflineOptions{})
					require.NoError(t, err)
					p, err := NewEncryptedPersistence(keys)
					require.NoError(t, err)
					owner, file = p, &p.file
				} else {
					p := NewYAMLPersistence()
					owner, file = p, &p.file
				}
				t.Cleanup(func() { require.NoError(t, owner.Close()) })
				_, err := owner.Load(path)
				require.NoError(t, err)
				before := owner.StorageStatus()
				require.Equal(t, map[bool]string{false: "yaml", true: "encrypted"}[encrypted], before.Mode)
				require.Equal(t, encrypted, before.Usage != nil)
				write := file.write
				entered, release := make(chan struct{}), make(chan struct{})
				file.write = func(name string, data []byte) (securestore.Outcome, error) {
					close(entered)
					<-release
					if outcome == securestore.Committed {
						_, err := write(name, data)
						if err != nil {
							return securestore.OutcomeOf(err), err
						}
					}
					return outcome, &securestore.CommitError{Outcome: outcome, Err: errors.New("chosen-private-path/selector")}
				}
				done := make(chan error, 1)
				go func() { done <- owner.Save(path, storeTestFilters("chosen-private-selector")) }()
				<-entered
				read := make(chan securestore.StorageStatus, 1)
				go func() { read <- owner.StorageStatus() }()
				select {
				case s := <-read:
					require.Empty(t, s.LastOutcome)
				case <-time.After(time.Second):
					close(release)
					t.Fatal("status waited for snapshot fsync")
				}
				close(release)
				require.Error(t, <-done)
				s := owner.StorageStatus()
				require.Equal(t, securestore.OutcomeName(outcome), s.LastOutcome)
				if outcome == securestore.Committed {
					require.Equal(t, uint64(1), s.Commits)
					require.Equal(t, uint64(1), s.CleanupWarnings)
					require.Equal(t, "ready", s.State)
				} else if outcome == securestore.Uncertain {
					require.Equal(t, uint64(1), s.Uncertain)
					require.Equal(t, "faulted", s.State)
				} else {
					require.Equal(t, uint64(1), s.DefiniteFailures)
				}
				encoded, err := json.Marshal(s)
				require.NoError(t, err)
				require.NotContains(t, string(encoded), "chosen-private")
				require.NotContains(t, string(encoded), path)
				require.NoError(t, owner.Close())
				require.Equal(t, "closed", owner.StorageStatus().State)
				_, err = owner.Load(path)
				require.Error(t, err)
				require.Error(t, owner.Save(path, storeTestFilters("after-close")))
				require.Equal(t, "closed", owner.StorageStatus().State)
				require.Equal(t, "not_committed", owner.StorageStatus().LastOutcome)
			})
		}
	}
}

func TestStorageStatusDisabledAndManagerPolicyFault(t *testing.T) {
	m := NewManager("", nil, nil, nil, nil)
	require.NoError(t, m.Initialize())
	s := m.StorageStatus()
	require.Equal(t, "disabled", s.Mode)
	require.False(t, s.AdmissionBlocked)
	m.mu.Lock()
	m.fault = errors.New("chosen-private-selector")
	m.mu.Unlock()
	s = m.StorageStatus()
	require.True(t, s.AdmissionBlocked)
	require.Equal(t, "reconciliation_required", s.PolicyFaultCode)
	require.Empty(t, s.LastOutcome)
	require.NoError(t, m.Close())
}

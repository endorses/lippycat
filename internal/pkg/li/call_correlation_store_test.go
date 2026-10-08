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

func correlationStoreRecord() StoredCallCorrelation {
	return StoredCallCorrelation{CallID: "secret-call@example.test", GroupID: 42, LastActivity: time.Unix(100, 0).UTC(), TerminalUntil: time.Unix(200, 0).UTC(), CommonTasks: []CallCorrelationTask{{XID: uuid.MustParse("11111111-1111-1111-1111-111111111111"), Generation: 1}}}
}
func openTestCorrelationStore(t *testing.T) (*CallCorrelationStore, string, securestore.KeyConfig) {
	t.Helper()
	path, keys, _ := stateStoreFixture(t)
	out, err := InitializeCallCorrelationStore(path, keys, 10)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	store, err := OpenCallCorrelationStore(path, keys, 10)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store, path, keys
}
func TestCallCorrelationStoreExplicitInitialization(t *testing.T) {
	path, keys, _ := stateStoreFixture(t)
	_, err := OpenCallCorrelationStore(path, keys, 10)
	require.ErrorIs(t, err, os.ErrNotExist)
	out, err := InitializeCallCorrelationStore(path, keys, 10)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	out, err = InitializeCallCorrelationStore(path, keys, 10)
	require.ErrorIs(t, err, os.ErrExist)
	require.Equal(t, securestore.NotCommitted, out)
	store, err := OpenCallCorrelationStore(path, keys, 10)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	_, err = OpenCallCorrelationStore(path, keys, 10)
	require.Error(t, err)
	other := filepath.Join(filepath.Dir(path), "other.enc")
	out, err = InitializeCallCorrelationStore(other, keys, 10)
	require.Error(t, err)
	require.Equal(t, securestore.NotCommitted, out, "same key cannot initialize independent store")
}
func TestCallCorrelationStoreRoundTripAndBounds(t *testing.T) {
	store, path, keys := openTestCorrelationStore(t)
	record := correlationStoreRecord()
	out, err := store.Save([]StoredCallCorrelation{record})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(raw), record.CallID)
	records, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, []StoredCallCorrelation{record}, records)
	records[0].CommonTasks[0].Generation = 7
	records, err = store.Load()
	require.NoError(t, err)
	require.Equal(t, uint64(1), records[0].CommonTasks[0].Generation)
	require.NoError(t, store.Close())
	restored, err := OpenCallCorrelationStore(path, keys, 10)
	require.NoError(t, err)
	defer func() { require.NoError(t, restored.Close()) }()
	records, err = restored.Load()
	require.NoError(t, err)
	require.Equal(t, []StoredCallCorrelation{record}, records)
	out, err = restored.Save([]StoredCallCorrelation{record, record})
	require.Error(t, err)
	require.Equal(t, securestore.NotCommitted, out)
	bad := record
	bad.CommonTasks = []CallCorrelationTask{{XID: uuid.Nil, Generation: 1}}
	_, err = restored.Save([]StoredCallCorrelation{bad})
	require.Error(t, err)
	require.Greater(t, restored.StorageStatus().Usage.Invocations, uint64(0))
}
func TestCallCorrelationStoreCommitOutcomes(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain} {
		t.Run(securestore.OutcomeName(outcome), func(t *testing.T) {
			store, path, keys := openTestCorrelationStore(t)
			record := correlationStoreRecord()
			replace := store.write
			failure := errors.New("injected persistence failure")
			store.write = func(name string, raw []byte) (securestore.Outcome, error) {
				if outcome == securestore.Uncertain {
					_, err := replace(name, raw)
					require.NoError(t, err)
				}
				return outcome, failure
			}
			out, err := store.Save([]StoredCallCorrelation{record})
			require.ErrorIs(t, err, failure)
			require.Equal(t, outcome, out)
			require.Equal(t, outcome, securestore.OutcomeOf(err))
			if outcome == securestore.Uncertain {
				require.Error(t, store.Fault())
				_, err = store.Load()
				require.ErrorIs(t, err, ErrStateStoreFault)
			} else {
				require.NoError(t, store.Fault())
				records, err := store.Load()
				require.NoError(t, err)
				require.Empty(t, records)
			}
			require.NoError(t, store.Close())
			reopened, err := OpenCallCorrelationStore(path, keys, 10)
			require.NoError(t, err)
			defer func() { require.NoError(t, reopened.Close()) }()
			records, err := reopened.Load()
			require.NoError(t, err)
			if outcome == securestore.Uncertain {
				require.Equal(t, []StoredCallCorrelation{record}, records)
			} else {
				require.Empty(t, records)
			}
		})
	}
}
func TestCallCorrelationStoreCorruptionAndBinding(t *testing.T) {
	store, path, keys := openTestCorrelationStore(t)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	raw[len(raw)-1] ^= 1
	require.NoError(t, os.WriteFile(path, raw, 0600))
	_, err = OpenCallCorrelationStore(path, keys, 10)
	require.ErrorIs(t, err, securestore.ErrAuthentication)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, raw, after)
	id := uuid.New()
	plain, err := marshalCorrelationSnapshot(id, []StoredCallCorrelation{correlationStoreRecord()}, 10)
	require.NoError(t, err)
	_, err = decodeCorrelationSnapshot(plain, uuid.New(), 10, 256<<20)
	require.ErrorIs(t, err, securestore.ErrBinding)
	_, err = decodeCorrelationSnapshot(plain, id, 10, 1)
	require.Error(t, err)
	_, err = decodeCorrelationSnapshot(append(plain, plain[bytes.IndexByte(plain, '\n')+1:]...), id, 1, 256<<20)
	require.Error(t, err)
}
func TestCallCorrelationStoreOfflineRotation(t *testing.T) {
	store, path, keys := openTestCorrelationStore(t)
	record := correlationStoreRecord()
	_, err := store.Save([]StoredCallCorrelation{record})
	require.NoError(t, err)
	id := store.StoreID()
	require.NoError(t, store.Close())
	keyPath := filepath.Join(filepath.Dir(path), "correlation-new.key")
	require.NoError(t, os.WriteFile(keyPath, bytes.Repeat([]byte{0x91}, securestore.KeyBytes), 0600))
	fresh := securestore.KeyConfig{Active: securestore.KeyRef{ID: "correlation-v2", File: keyPath}}
	destination := filepath.Join(filepath.Dir(path), "correlation-rotated.enc")
	result, err := RotateCallCorrelationStore(path, destination, keys, fresh, 10, StateRotationOptions{MaxWorkingBytes: 16 << 20})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, result.Outcome)
	require.True(t, result.Complete)
	restored, err := OpenCallCorrelationStore(destination, fresh, 10)
	require.NoError(t, err)
	defer func() { require.NoError(t, restored.Close()) }()
	require.Equal(t, id, restored.StoreID())
	records, err := restored.Load()
	require.NoError(t, err)
	require.Equal(t, []StoredCallCorrelation{record}, records)
}

func TestCallCorrelationStoreUncertainReconciliation(t *testing.T) {
	for _, didWrite := range []bool{false, true} {
		t.Run(map[bool]string{false: "predecessor", true: "successor"}[didWrite], func(t *testing.T) {
			store, _, _ := openTestCorrelationStore(t)
			record := correlationStoreRecord()
			replace := store.write
			store.write = func(name string, raw []byte) (securestore.Outcome, error) {
				if didWrite {
					_, err := replace(name, raw)
					require.NoError(t, err)
				}
				return securestore.Uncertain, errors.New("injected uncertain state")
			}
			out, err := store.Save([]StoredCallCorrelation{record})
			require.Error(t, err)
			require.Equal(t, securestore.Uncertain, out)
			require.NoError(t, store.Reconcile())
			require.NoError(t, store.Fault())
			out, err = store.Save([]StoredCallCorrelation{record})
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			records, err := store.Load()
			require.NoError(t, err)
			require.Equal(t, []StoredCallCorrelation{record}, records)
		})
	}
}

func TestCallCorrelationStoreReconciliationRejectsCorruption(t *testing.T) {
	store, path, _ := openTestCorrelationStore(t)
	store.write = func(string, []byte) (securestore.Outcome, error) {
		return securestore.Uncertain, errors.New("injected uncertain state")
	}
	_, err := store.Save([]StoredCallCorrelation{correlationStoreRecord()})
	require.Error(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	raw[len(raw)-1] ^= 1
	require.NoError(t, os.WriteFile(path, raw, 0600))
	require.ErrorIs(t, store.Reconcile(), securestore.ErrAuthentication)
	_, err = store.Save([]StoredCallCorrelation{correlationStoreRecord()})
	require.ErrorIs(t, err, ErrStateStoreFault)
}

func TestCallCorrelationStoreEmptyCommonContextIsRetained(t *testing.T) {
	store, _, _ := openTestCorrelationStore(t)
	record := correlationStoreRecord()
	record.CommonTasks = nil
	out, err := store.Save([]StoredCallCorrelation{record})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	records, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, []StoredCallCorrelation{record}, records, "empty context pins the ID while granting no new group membership")
}

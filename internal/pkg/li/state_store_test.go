//go:build li

package li

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func stateStoreFixture(t testing.TB) (string, securestore.KeyConfig, []byte) {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "private")
	require.NoError(t, os.Mkdir(dir, 0700))
	key := bytes.Repeat([]byte{0x43}, securestore.KeyBytes)
	keyPath := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyPath, key, 0600))
	return filepath.Join(dir, "state.enc"), securestore.KeyConfig{Active: securestore.KeyRef{ID: "state-v1", File: keyPath}}, key
}

func openInitializedState(t testing.TB) (*EncryptedStateStore, string, securestore.KeyConfig) {
	t.Helper()
	path, keys, _ := stateStoreFixture(t)
	out, err := InitStateStore(path, keys, stateFixture(t))
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	store, err := OpenStateStore(path, keys)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store, path, keys
}

func TestStateStoreRequiresExplicitInitialization(t *testing.T) {
	path, keys, _ := stateStoreFixture(t)
	_, err := OpenStateStore(path, keys)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	initial := stateFixture(t)
	out, err := InitStateStore(path, keys, initial)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	out, err = InitStateStore(path, keys, initial)
	require.Error(t, err)
	require.Equal(t, securestore.NotCommitted, out)
	require.Equal(t, out, securestore.OutcomeOf(err))
	store, err := OpenStateStore(path, keys)
	require.NoError(t, err)
	require.Equal(t, initial.Incarnation, store.StoreID())
	_, err = OpenStateStore(path, keys)
	require.Error(t, err, "snapshot and usage are lifetime-owned")
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	_, err = store.Load()
	require.ErrorIs(t, err, os.ErrClosed)
	store, err = OpenStateStore(path, keys)
	require.NoError(t, err)
	require.NoError(t, store.Close())
}

func TestStateStoreRoundTripAndNoCleartext(t *testing.T) {
	store, path, keys := openInitializedState(t)
	loaded, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, stateFixture(t), loaded)
	loaded.Tasks[0].Targets[0].Value = "sip:independent-secret@example.invalid"
	before, err := store.Load()
	require.NoError(t, err)
	require.NotEqual(t, loaded.Tasks[0].Targets, before.Tasks[0].Targets)
	out, err := store.Save(loaded)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	loaded.Tasks[0].Targets[0].Value = "caller changed after commit"
	after, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, "sip:independent-secret@example.invalid", after.Tasks[0].Targets[0].Value)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
		require.NoError(t, err)
		for _, secret := range []string{"independent-secret", "fixture-operator", "fixture-edge-a", "mdf.example.invalid", "synthetic destination removed", "li-11111111"} {
			require.NotContains(t, string(data), secret)
		}
	}
	require.NoError(t, store.Close())
	store, err = OpenStateStore(path, keys)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	recovered, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, after, recovered)
}

func TestStateStoreFailedOpenReleasesOwnership(t *testing.T) {
	store, path, keys := openInitializedState(t)
	valid, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	for _, bad := range [][]byte{[]byte(`{"version":2}`), append(append([]byte(nil), valid...), 0), bytes.Repeat([]byte{0}, len(valid))} {
		require.NoError(t, os.WriteFile(path, bad, 0600))
		_, err := OpenStateStore(path, keys)
		require.Error(t, err)
		require.NoError(t, os.WriteFile(path, valid, 0600))
		reopened, err := OpenStateStore(path, keys)
		require.NoError(t, err)
		require.NoError(t, reopened.Close())
	}
}

func TestStateStoreMissingLedgerAndWrongKeyFailClosed(t *testing.T) {
	store, path, keys := openInitializedState(t)
	ring, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	ledgerPath := filepath.Join(filepath.Dir(path), ring.UsageFileName())
	ledger, err := os.ReadFile(ledgerPath)
	require.NoError(t, err)
	require.NoError(t, os.Remove(ledgerPath))
	_, err = OpenStateStore(path, keys)
	require.Error(t, err)
	_, err = os.Stat(ledgerPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NoError(t, os.WriteFile(ledgerPath, ledger, 0600))
	require.NoError(t, os.WriteFile(keys.Active.File, bytes.Repeat([]byte{0x99}, securestore.KeyBytes), 0600))
	_, err = OpenStateStore(path, keys)
	require.Error(t, err)
}

func TestStateStoreDoesNotResetExistingLedger(t *testing.T) {
	store, path, keys := openInitializedState(t)
	require.NoError(t, store.Close())
	ring, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	ledgerPath := filepath.Join(filepath.Dir(path), ring.UsageFileName())
	before, err := os.ReadFile(ledgerPath)
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	out, err := InitStateStore(path, keys, stateFixture(t))
	require.Error(t, err)
	require.Equal(t, securestore.NotCommitted, out)
	require.Equal(t, out, securestore.OutcomeOf(err))
	after, err := os.ReadFile(ledgerPath)
	require.NoError(t, err)
	require.Equal(t, before, after)
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestStateStoreInitializationPartialOutcomes(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain, securestore.Committed} {
		t.Run(fmtStateOutcome(outcome), func(t *testing.T) {
			path, keys, _ := stateStoreFixture(t)
			failure := errors.New("injected initial snapshot failure")
			out, err := initStateStore(path, keys, stateFixture(t), func(dir *securestore.Dir, name string, data []byte) (securestore.Outcome, error) {
				if outcome != securestore.NotCommitted {
					actual, err := dir.Create(name, data)
					require.NoError(t, err)
					require.Equal(t, securestore.Committed, actual)
				}
				return outcome, failure
			})
			require.ErrorIs(t, err, failure)
			if outcome == securestore.Committed {
				require.Equal(t, securestore.Committed, out)
			} else {
				require.Equal(t, securestore.Uncertain, out)
			}
			require.Equal(t, out, securestore.OutcomeOf(err), "outer initialization includes committed ledger, even when snapshot was not committed")
			ring, err := securestore.LoadKeyring(keys)
			require.NoError(t, err)
			_, err = os.Stat(filepath.Join(filepath.Dir(path), ring.UsageFileName()))
			require.NoError(t, err, "partial initialization must not erase nonce accounting")
			_, err = InitStateStore(path, keys, stateFixture(t))
			require.Error(t, err, "provisioning never claims resumability or resets an existing ledger")
			if outcome != securestore.NotCommitted {
				store, err := OpenStateStore(path, keys)
				require.NoError(t, err)
				require.NoError(t, store.Close())
			}
		})
	}
}

func TestStateStoreAuthenticatedSchemaAndBindingRequired(t *testing.T) {
	for _, test := range []string{"purpose", "object", "inner incarnation", "schema"} {
		t.Run(test, func(t *testing.T) {
			store, path, keys := openInitializedState(t)
			s := stateFixture(t)
			purpose := securestore.AdministrativeState
			binding := securestore.Binding{Store: [16]byte(s.Incarnation), Object: stateSnapshotObject}
			if test == "purpose" {
				purpose = securestore.FilterSnapshot
			}
			if test == "object" {
				binding.Object = strings.Repeat("x", len(stateSnapshotObject))
			}
			if test == "inner incarnation" {
				s.Incarnation = uuid.New()
			}
			plain, err := MarshalStateSnapshot(s)
			require.NoError(t, err)
			if test == "schema" {
				plain = []byte(`{"version":2}`)
			}
			sealed, err := store.writer.Seal(purpose, binding, plain)
			require.NoError(t, err)
			out, err := store.write(store.name, sealed)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			require.NoError(t, store.Close())
			_, err = OpenStateStore(path, keys)
			require.Error(t, err)
		})
	}
}

func TestStateStoreUsageFailureDoesNotClaimSnapshotCommit(t *testing.T) {
	store, path, _ := openInitializedState(t)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, store.usage.Close())
	out, err := store.Save(stateFixture(t))
	require.ErrorIs(t, err, securestore.ErrUsageFault)
	require.Equal(t, securestore.NotCommitted, out)
	require.Equal(t, out, securestore.OutcomeOf(err))
	require.Error(t, store.Fault())
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestStateStoreBindingAndInvalidSaveDoNotMutate(t *testing.T) {
	store, path, _ := openInitializedState(t)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, modify := range []func(*StateSnapshot){func(s *StateSnapshot) { s.Incarnation = uuid.New() }, func(s *StateSnapshot) { s.Tasks[0].Targets[0].Value = "" }} {
		s := stateFixture(t)
		modify(s)
		out, err := store.Save(s)
		require.Error(t, err)
		require.Equal(t, securestore.NotCommitted, out)
		require.Equal(t, out, securestore.OutcomeOf(err))
		require.NoError(t, store.Fault())
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, before, after)
	}
}

func TestStateStoreCommitOutcomes(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain, securestore.Committed} {
		t.Run(fmtStateOutcome(outcome), func(t *testing.T) {
			store, _, _ := openInitializedState(t)
			failure := errors.New("injected storage fault")
			replace := store.write
			store.write = func(name string, data []byte) (securestore.Outcome, error) {
				if outcome != securestore.NotCommitted {
					committed, err := replace(name, data)
					require.NoError(t, err)
					require.Equal(t, securestore.Committed, committed)
				}
				return outcome, &securestore.CommitError{Outcome: outcome, Op: "injected", Err: failure}
			}
			s := stateFixture(t)
			s.Tasks[0].LastError = "saved candidate"
			out, err := store.Save(s)
			require.ErrorIs(t, err, failure)
			require.Equal(t, outcome, out)
			require.Equal(t, outcome, securestore.OutcomeOf(err))
			store.write = replace
			if outcome == securestore.Uncertain {
				require.Error(t, store.Fault())
				out, err = store.Save(s)
				require.ErrorIs(t, err, ErrStateStoreFault)
				require.Equal(t, securestore.NotCommitted, out)
				_, err = store.Load()
				require.ErrorIs(t, err, ErrStateStoreFault)
				return
			}
			require.NoError(t, store.Fault())
			loaded, err := store.Load()
			require.NoError(t, err)
			if outcome == securestore.Committed {
				require.Equal(t, s, loaded)
			} else {
				require.Equal(t, stateFixture(t), loaded)
			}
			out, err = store.Save(s)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
		})
	}
}

func fmtStateOutcome(outcome securestore.Outcome) string {
	switch outcome {
	case securestore.NotCommitted:
		return "not-committed"
	case securestore.Uncertain:
		return "uncertain"
	default:
		return "committed"
	}
}

func TestStateStoreRuntimeReadFailureLatches(t *testing.T) {
	store, path, _ := openInitializedState(t)
	valid, err := os.ReadFile(path)
	require.NoError(t, err)
	bad := append([]byte(nil), valid...)
	bad[len(bad)-1] ^= 1
	require.NoError(t, os.WriteFile(path, bad, 0600))
	_, err = store.Load()
	require.ErrorIs(t, err, securestore.ErrAuthentication)
	require.NoError(t, os.WriteFile(path, valid, 0600))
	out, err := store.Save(stateFixture(t))
	require.ErrorIs(t, err, ErrStateStoreFault)
	require.Equal(t, securestore.NotCommitted, out)
}

func TestStateStoreControlCapacityExplicit(t *testing.T) {
	path, keys, key := stateStoreFixture(t)
	out, err := InitStateStore(path, keys, stateFixture(t))
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	ring, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	ledgerPath := filepath.Join(filepath.Dir(path), ring.UsageFileName())
	ledger, err := os.ReadFile(ledgerPath)
	require.NoError(t, err)
	binary.BigEndian.PutUint64(ledger[24:32], securestore.MaxKeyInvocations*9/10)
	mac := hmac.New(sha256.New, key)
	_, err = mac.Write([]byte("lippycat/securestore/usage/v1\x00"))
	require.NoError(t, err)
	_, err = mac.Write(ledger[:40])
	require.NoError(t, err)
	copy(ledger[40:], mac.Sum(nil))
	require.NoError(t, os.WriteFile(ledgerPath, ledger, 0600))
	store, err := OpenStateStore(path, keys)
	require.NoError(t, err)
	defer func() { require.NoError(t, store.Close()) }()
	out, err = store.Save(stateFixture(t))
	require.ErrorIs(t, err, securestore.ErrKeyExhausted)
	require.Equal(t, securestore.NotCommitted, out)
	require.NoError(t, store.Fault())
	out, err = store.SaveControl(stateFixture(t))
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
}

func TestStateStoreRejectsKeyAndUnsafePathAliases(t *testing.T) {
	path, keys, _ := stateStoreFixture(t)
	before, err := os.ReadFile(keys.Active.File)
	require.NoError(t, err)
	_, err = OpenStateStore(keys.Active.File, keys)
	require.Error(t, err)
	out, err := InitStateStore(keys.Active.File, keys, stateFixture(t))
	require.Error(t, err)
	require.Equal(t, securestore.NotCommitted, out)
	after, err := os.ReadFile(keys.Active.File)
	require.NoError(t, err)
	require.Equal(t, before, after)
	for _, bad := range []string{"", path + "/", filepath.Dir(path) + "/../private/state.enc", filepath.Dir(path) + "/."} {
		_, err := OpenStateStore(bad, keys)
		require.Error(t, err)
	}
	link := filepath.Join(filepath.Dir(path), "alias")
	require.NoError(t, os.Symlink(keys.Active.File, link))
	_, err = OpenStateStore(link, keys)
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), string(before)))
}

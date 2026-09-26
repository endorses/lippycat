package filtering

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

	"github.com/endorses/lippycat/api/gen/management"
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func storeTestKey(t *testing.T, fill byte) securestore.KeyConfig {
	t.Helper()
	file := filepath.Join(privateStoreTestDir(t), "key")
	require.NoError(t, os.WriteFile(file, bytes.Repeat([]byte{fill}, 32), 0600))
	return securestore.KeyConfig{Active: securestore.KeyRef{ID: "active", File: file}}
}

func privateStoreTestDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	require.NoError(t, os.Chmod(path, 0700))
	return path
}

func storeTestFilters(marker string) map[string]*management.Filter {
	return map[string]*management.Filter{"target": {Id: "target", Type: management.FilterType_FILTER_SIP_USER, Pattern: marker, Enabled: true, Revision: 9, TargetHunters: []string{"hunter"}, Description: "synthetic private target"}}
}

func TestYAMLStrictStartupPreservesInvalidExistingBytes(t *testing.T) {
	for _, input := range []string{
		"filters:\n  - id: bad\n    type: unknown\n    pattern: chosen-sensitive-marker\n",
		"filters: []\nunexpected: chosen-sensitive-marker\n",
		"LCS1chosen-sensitive-marker",
		"filters: []\n---\nfilters: []\n",
	} {
		path := filepath.Join(privateStoreTestDir(t), "snapshot")
		require.NoError(t, os.WriteFile(path, []byte(input), 0600))
		p := NewYAMLPersistence()
		_, err := p.Load(path)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "chosen-sensitive-marker")
		require.Error(t, p.Save(path, storeTestFilters("must-not-commit")))
		require.NoError(t, p.Close())
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, input, string(data))
		// A failed startup must have released ownership.
		again := NewYAMLPersistence()
		_, err = again.Load(path)
		require.Error(t, err)
		require.NotErrorIs(t, err, securestore.ErrLocked)
		require.NoError(t, again.Close())
	}
}

func TestYAMLFirstRunEditingAndExclusiveOwnership(t *testing.T) {
	path := filepath.Join(privateStoreTestDir(t), "new", "nested", "filters.yaml")
	p := NewYAMLPersistence()
	filters, err := p.Load(path)
	require.NoError(t, err)
	require.Empty(t, filters)
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist, "loading an absent YAML snapshot must not persist an empty document")
	other := NewYAMLPersistence()
	_, err = other.Load(path)
	require.ErrorIs(t, err, securestore.ErrLocked)
	require.NoError(t, other.Close())
	require.NoError(t, p.Save(path, storeTestFilters("old")))
	require.NoError(t, p.Close())
	updated, err := filtercodec.MarshalManagedYAML(storeTestFilters("edited-while-stopped"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, updated, 0600))
	restarted := NewYAMLPersistence()
	defer func() { require.NoError(t, restarted.Close()) }()
	filters, err = restarted.Load(path)
	require.NoError(t, err)
	require.Equal(t, "edited-while-stopped", filters["target"].Pattern)
	require.Error(t, restarted.Save(filepath.Join(filepath.Dir(path), "different.yaml"), filters))
}

func TestEncryptedInitializationRoundTripAndNoPlaintext(t *testing.T) {
	path := filepath.Join(privateStoreTestDir(t), "filters.enc")
	keys := storeTestKey(t, 71)
	p, err := NewEncryptedPersistence(keys)
	require.NoError(t, err)
	_, err = p.Load(path)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Error(t, p.Save(path, storeTestFilters("must-not-initialize")))
	require.NoError(t, p.Close())
	out, err := InitializeEncryptedFilterStore(path, keys, OfflineOptions{})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	p, err = NewEncryptedPersistence(keys)
	require.NoError(t, err)
	filters, err := p.Load(path)
	require.NoError(t, err)
	require.Empty(t, filters)
	identity := p.StoreID()
	require.NotZero(t, identity)
	want := storeTestFilters("chosen-private-selector")
	require.NoError(t, p.Save(path, want))
	other, err := NewEncryptedPersistence(keys)
	require.NoError(t, err)
	_, err = other.Load(path)
	require.ErrorIs(t, err, securestore.ErrLocked)
	require.NoError(t, other.Close())
	require.NoError(t, p.Close())
	restarted, err := NewEncryptedPersistence(keys)
	require.NoError(t, err)
	defer func() { require.NoError(t, restarted.Close()) }()
	got, err := restarted.Load(path)
	require.NoError(t, err)
	require.Equal(t, identity, restarted.StoreID())
	require.True(t, proto.Equal(want["target"], got["target"]))
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(path), entry.Name()))
		require.NoError(t, err)
		require.NotContains(t, string(data), "chosen-private-selector")
		require.NotContains(t, string(data), "synthetic private target")
	}
}

func TestSnapshotUncertaintyLatchesButDefiniteFailureAllowsRetry(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain, securestore.Committed} {
			t.Run(strings.Join([]string{map[bool]string{false: "yaml", true: "encrypted"}[encrypted], string(rune('0' + outcome))}, "/"), func(t *testing.T) {
				path := filepath.Join(privateStoreTestDir(t), "snapshot")
				var p PersistenceHandler
				var state *snapshotFile
				var closeStore func() error
				if encrypted {
					keys := storeTestKey(t, 72)
					_, err := InitializeEncryptedFilterStore(path, keys, OfflineOptions{})
					require.NoError(t, err)
					e, err := NewEncryptedPersistence(keys)
					require.NoError(t, err)
					p, state, closeStore = e, &e.file, e.Close
				} else {
					y := NewYAMLPersistence()
					p, state, closeStore = y, &y.file, y.Close
				}
				defer func() { require.NoError(t, closeStore()) }()
				require.NoError(t, p.Save(path, storeTestFilters("old")))
				original := state.write
				calls := 0
				injected := errors.New("injected publication fault")
				state.write = func(name string, data []byte) (securestore.Outcome, error) {
					calls++
					if outcome != securestore.NotCommitted {
						_, err := original(name, data)
						require.NoError(t, err)
					}
					return outcome, &securestore.CommitError{Outcome: outcome, Op: "fault injection", Err: injected}
				}
				err := p.Save(path, storeTestFilters("candidate"))
				require.ErrorIs(t, err, injected)
				require.Equal(t, outcome, securestore.OutcomeOf(err))
				state.write = original
				err = p.Save(path, storeTestFilters("retry"))
				if outcome == securestore.Uncertain {
					require.ErrorIs(t, err, ErrStoreFault)
					require.NotNil(t, state.fault)
				} else {
					require.NoError(t, err)
					require.Nil(t, state.fault)
				}
				require.Equal(t, 1, calls)
			})
		}
	}
}

func TestEncryptedWrongFormatKeyAndIdentityFailClosed(t *testing.T) {
	keys := storeTestKey(t, 73)
	a := filepath.Join(privateStoreTestDir(t), "a.enc")
	b := filepath.Join(privateStoreTestDir(t), "b.enc")
	_, err := InitializeEncryptedFilterStore(a, keys, OfflineOptions{})
	require.NoError(t, err)
	_, err = InitializeEncryptedFilterStore(b, keys, OfflineOptions{})
	require.NoError(t, err)
	data, err := os.ReadFile(a)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(b, data, 0600))
	p, err := NewEncryptedPersistence(keys)
	require.NoError(t, err)
	_, err = p.Load(b)
	require.ErrorIs(t, err, securestore.ErrBinding)
	require.NoError(t, p.Close())
	wrong, err := NewEncryptedPersistence(storeTestKey(t, 74))
	require.NoError(t, err)
	_, err = wrong.Load(a)
	require.Error(t, err)
	require.NoError(t, wrong.Close())
	yaml := NewYAMLPersistence()
	require.Error(t, yaml.Save(a, storeTestFilters("must-not-overwrite")))
	require.NoError(t, yaml.Close())
	after, err := os.ReadFile(a)
	require.NoError(t, err)
	require.Equal(t, data, after)
}

func TestEncryptedFilterReductionsUseReservedKeyAllowance(t *testing.T) {
	path := filepath.Join(privateStoreTestDir(t), "filters.enc")
	keys := storeTestKey(t, 91)
	_, err := InitializeEncryptedFilterStore(path, keys, OfflineOptions{})
	require.NoError(t, err)
	p, err := NewEncryptedPersistence(keys)
	require.NoError(t, err)
	original := storeTestFilters("original")
	original["radius"] = &management.Filter{Id: "radius", Revision: 1, Enabled: true, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Radius: &management.RadiusFilterCriteria{Scope: &management.RadiusScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}}
	require.NoError(t, p.Save(path, original))
	require.NoError(t, p.Close())
	// Construct an authenticated on-disk high-watermark at the ordinary ceiling.
	setUsage := func(invocations uint64) {
		entries, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".usage-*"))
		require.NoError(t, err)
		require.Len(t, entries, 1)
		data, err := os.ReadFile(entries[0])
		require.NoError(t, err)
		require.Len(t, data, 72)
		binary.BigEndian.PutUint64(data[24:32], invocations)
		mac := hmac.New(sha256.New, bytes.Repeat([]byte{91}, 32))
		_, err = mac.Write(append([]byte("lippycat/securestore/usage/v1\x00"), data[:40]...))
		require.NoError(t, err)
		copy(data[40:], mac.Sum(nil))
		require.NoError(t, os.WriteFile(entries[0], data, 0600))
	}
	setUsage(securestore.MaxKeyInvocations * 9 / 10)
	p, err = NewEncryptedPersistence(keys)
	require.NoError(t, err)
	loaded, err := p.Load(path)
	require.NoError(t, err)
	loaded["target"].Pattern = "caller mutation must not change committed classification"
	require.ErrorIs(t, p.Save(path, storeTestFilters("changed")), securestore.ErrKeyExhausted)
	combined := storeTestFilters("changed")
	combined["target"].Enabled = false
	require.ErrorIs(t, p.Save(path, combined), securestore.ErrKeyExhausted)
	disabled := cloneFilterMap(original)
	disabled["target"].Enabled = false
	disabled["radius"].Enabled = false
	disabled["radius"].Revision = 2
	require.NoError(t, p.Save(path, disabled))
	disabledLoaded, err := p.Load(path)
	require.NoError(t, err)
	require.False(t, disabledLoaded["radius"].Enabled)
	require.Equal(t, uint64(2), disabledLoaded["radius"].Revision)
	disabledSnapshot, err := os.ReadFile(path)
	require.NoError(t, err)
	disabled["target"].Pattern = "caller mutation after commit"
	require.ErrorIs(t, p.Save(path, original), securestore.ErrKeyExhausted, "re-enabling cannot use control allowance")
	require.NoError(t, p.Save(path, map[string]*management.Filter{}))
	require.NoError(t, p.Close())
	// A new reduction at the absolute ceiling remains forbidden.
	setUsage(securestore.MaxKeyInvocations)
	require.NoError(t, os.WriteFile(path, disabledSnapshot, 0600))
	p, err = NewEncryptedPersistence(keys)
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Close()) }()
	_, err = p.Load(path)
	require.NoError(t, err)
	require.ErrorIs(t, p.Save(path, map[string]*management.Filter{}), securestore.ErrKeyExhausted)
}

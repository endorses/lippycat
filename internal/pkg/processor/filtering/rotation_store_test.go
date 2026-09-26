//go:build linux

package filtering

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func writeFilterRotationSource(t *testing.T, path string, keys securestore.KeyConfig, payload []byte) [16]byte {
	t.Helper()
	ring, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	dir, err := securestore.OpenDir(filepath.Dir(path))
	require.NoError(t, err)
	store := [16]byte(uuid.New())
	_, err = securestore.InitializeUsage(dir, ring, store)
	require.NoError(t, err)
	usage, err := securestore.OpenUsage(dir, ring, store)
	require.NoError(t, err)
	writer, err := securestore.NewWriter(usage)
	require.NoError(t, err)
	sealed, err := writer.Seal(securestore.FilterSnapshot, securestore.Binding{Store: store, Object: "filters"}, payload)
	require.NoError(t, err)
	_, err = dir.Create(filepath.Base(path), sealed)
	require.NoError(t, err)
	require.NoError(t, usage.Close())
	require.NoError(t, dir.Close())
	return store
}

func richFilterRotationPayload(t *testing.T) []byte {
	t.Helper()
	legacy, err := os.ReadFile("testdata/legacy_filters.yaml")
	require.NoError(t, err)
	filters, err := filtercodec.UnmarshalManagedYAML(legacy)
	require.NoError(t, err)
	payload, err := filtercodec.MarshalEncryptedFilters(filters)
	require.NoError(t, err)
	var spaced bytes.Buffer
	require.NoError(t, json.Indent(&spaced, payload, "", "  "))
	return append(spaced.Bytes(), '\n')
}

func TestFilterRotationPreservesExactRichPayload(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed basename", true: "in place"}[inPlace], func(t *testing.T) {
			dir := privateStoreTestDir(t)
			source, target := filepath.Join(dir, "old.enc"), filepath.Join(dir, "new.enc")
			if inPlace {
				target = source
			}
			old, next := storeTestKey(t, 31), storeTestKey(t, 32)
			next.Active.ID = "next"
			payload := richFilterRotationPayload(t)
			store := writeFilterRotationSource(t, source, old, payload)
			original, err := os.ReadFile(source)
			require.NoError(t, err)
			options := RotationOptions{InPlace: inPlace, MaxWorkingBytes: 128 << 20}
			result, err := RotateEncryptedFilterStore(source, target, old, next, options)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, result.Outcome)
			require.True(t, result.Complete)
			require.False(t, result.ResumeRequired)
			ring, err := securestore.LoadKeyring(next)
			require.NoError(t, err)
			sealed, err := os.ReadFile(target)
			require.NoError(t, err)
			got, err := ring.Open(securestore.FilterSnapshot, securestore.Binding{Store: store, Object: "filters"}, sealed, filtercodec.MaxManagedSnapshotBytes)
			require.NoError(t, err)
			require.Equal(t, payload, got, "including whitespace, every filter type and all RADIUS fields")
			if !inPlace {
				after, err := os.ReadFile(source)
				require.NoError(t, err)
				require.Equal(t, original, after)
			}
			options.Resume = true
			result, err = RotateEncryptedFilterStore(source, target, old, next, options)
			require.NoError(t, err)
			require.True(t, result.Complete)
		})
	}
}

func TestFilterRotationRejectsWholeMalformedPayload(t *testing.T) {
	dir := privateStoreTestDir(t)
	source, target := filepath.Join(dir, "old.enc"), filepath.Join(dir, "new.enc")
	old, next := storeTestKey(t, 33), storeTestKey(t, 34)
	next.Active.ID = "next"
	writeFilterRotationSource(t, source, old, []byte(`{"version":1,"filters":[{"id":"ok","type":"sip_user","pattern":"ok"},{"id":"bad","type":"SECRET"}]}`))
	original, err := os.ReadFile(source)
	require.NoError(t, err)
	result, err := RotateEncryptedFilterStore(source, target, old, next, RotationOptions{MaxWorkingBytes: 128 << 20})
	require.ErrorIs(t, err, filtercodec.ErrManagedSnapshot)
	require.NotContains(t, err.Error(), "SECRET")
	require.Equal(t, securestore.NotCommitted, result.Outcome)
	require.Equal(t, result.Outcome, securestore.OutcomeOf(err))
	_, err = os.Stat(target)
	require.ErrorIs(t, err, os.ErrNotExist)
	after, err := os.ReadFile(source)
	require.NoError(t, err)
	require.Equal(t, original, after)
}

func TestFilterRotationOwnerBudgetAndImmutableLoadedKeys(t *testing.T) {
	dir := privateStoreTestDir(t)
	source, target := filepath.Join(dir, "old.enc"), filepath.Join(dir, "new.enc")
	old, next := storeTestKey(t, 35), storeTestKey(t, 36)
	next.Active.ID = "next"
	payload := richFilterRotationPayload(t)
	store := writeFilterRotationSource(t, source, old, payload)
	oldRing, err := securestore.LoadKeyring(old)
	require.NoError(t, err)
	newRing, err := securestore.LoadKeyring(next)
	require.NoError(t, err)
	owner := filterRotationOwner()
	_, err = owner.Validate(payload, store, 64<<10)
	require.ErrorContains(t, err, "decode memory")
	validate := owner.Validate
	owner.Validate = func(data []byte, id [16]byte, remaining int64) (securestore.SnapshotValidation, error) {
		require.Less(t, remaining, int64(256<<20))
		// Change paths after key loading. The real coordinator must only use
		// the immutable rings supplied by the wrapper boundary.
		require.NoError(t, os.WriteFile(old.Active.File, bytes.Repeat([]byte{37}, 32), 0600))
		require.NoError(t, os.WriteFile(next.Active.File, bytes.Repeat([]byte{38}, 32), 0600))
		return validate(data, id, remaining)
	}
	result, err := securestore.RotateSnapshot(securestore.SnapshotRotationOptions{Source: source, Destination: target,
		SourceKeys: oldRing, NewKeys: newRing, MaxWorkingBytes: 128 << 20}, owner)
	require.NoError(t, err)
	require.True(t, result.Complete)
	sealed, err := os.ReadFile(target)
	require.NoError(t, err)
	got, err := newRing.Open(securestore.FilterSnapshot, securestore.Binding{Store: store, Object: "filters"}, sealed, filtercodec.MaxManagedSnapshotBytes)
	require.NoError(t, err)
	require.Equal(t, payload, got)
}

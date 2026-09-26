//go:build li

package li

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func stateMigrationSource(t testing.TB, directory string) (string, []byte) {
	t.Helper()
	data, err := os.ReadFile("testdata/legacy_state_v1.json")
	require.NoError(t, err)
	path := filepath.Join(directory, "legacy.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path, data
}

func loadMigratedState(t testing.TB, path string, keys securestore.KeyConfig) *StateSnapshot {
	t.Helper()
	store, err := OpenStateStore(path, keys)
	require.NoError(t, err)
	snapshot, err := store.Load()
	require.NoError(t, err)
	require.NoError(t, store.Close())
	return snapshot
}

func TestStateMigrationPreservesLegacyAndPinsAllocator(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprint(custom), func(t *testing.T) {
			destination, keys, _ := stateStoreFixture(t)
			source, raw := stateMigrationSource(t, filepath.Dir(destination))
			pin := source + ".radius-correlation"
			options := StateOfflineOptions{}
			if custom {
				pin = filepath.Join(filepath.Dir(destination), "custom.radius")
				options.RADIUSStateFile = pin
			}
			allocator := []byte(`{"reserved_through":987654321,"opaque":"allocator-marker"}`)
			require.NoError(t, os.WriteFile(pin, allocator, 0600))
			before, err := os.Stat(pin)
			require.NoError(t, err)
			out, err := MigrateJSONStateStore(source, destination, keys, options)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			got := loadMigratedState(t, destination, keys)
			expected, err := DecodeLegacyStateSnapshot(raw, got.Incarnation)
			require.NoError(t, err)
			expected.RADIUSCorrelationStateFile = pin
			require.Equal(t, expected, got)
			require.NotEqual(t, uuid.Nil, got.Incarnation)
			remaining, err := os.ReadFile(source)
			require.NoError(t, err)
			require.Equal(t, raw, remaining)
			after, err := os.Stat(pin)
			require.NoError(t, err)
			require.True(t, os.SameFile(before, after), "migration must not replace the allocator inode")
			remaining, err = os.ReadFile(pin)
			require.NoError(t, err)
			require.Equal(t, allocator, remaining)
			entries, err := os.ReadDir(filepath.Dir(destination))
			require.NoError(t, err)
			for _, entry := range entries {
				path := filepath.Join(filepath.Dir(destination), entry.Name())
				if path == source || path == pin || path == keys.Active.File {
					continue
				}
				data, err := os.ReadFile(path)
				require.NoError(t, err)
				require.NotContains(t, string(data), got.Tasks[0].Targets[0].Value)
				require.NotContains(t, string(data), pin)
			}
			options.Resume = true
			out, err = MigrateJSONStateStore(source, destination, keys, options)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			require.Equal(t, expected, loadMigratedState(t, destination, keys))
		})
	}
}

func TestStateMigrationEmptyInitializationAndExplicitReplacement(t *testing.T) {
	path, keys, _ := stateStoreFixture(t)
	out, err := InitializeEncryptedStateStore(path, keys, StateOfflineOptions{})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	snapshot := loadMigratedState(t, path, keys)
	require.Empty(t, snapshot.Tasks)
	require.Empty(t, snapshot.Destinations)
	require.Equal(t, time.Unix(0, 0).UTC(), snapshot.WrittenAt)
	require.Equal(t, path+".radius-correlation", snapshot.RADIUSCorrelationStateFile)
	before, err := os.ReadFile(path)
	require.NoError(t, err)
	out, err = InitializeEncryptedStateStore(path, keys, StateOfflineOptions{})
	require.ErrorIs(t, err, os.ErrExist)
	require.Equal(t, securestore.NotCommitted, out)
	out, err = InitializeEncryptedStateStore(path, keys, StateOfflineOptions{Resume: true})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	_, err = InitializeEncryptedStateStore(path, keys, StateOfflineOptions{InPlace: true})
	require.Error(t, err)

	otherPath, otherKeys, _ := stateStoreFixture(t)
	source, raw := stateMigrationSource(t, filepath.Dir(otherPath))
	_, err = MigrateJSONStateStore(source, source, otherKeys, StateOfflineOptions{})
	require.ErrorContains(t, err, "explicit in-place")
	_, err = MigrateJSONStateStore(source, otherPath, otherKeys, StateOfflineOptions{InPlace: true})
	require.Error(t, err)
	out, err = MigrateJSONStateStore(source, source, otherKeys, StateOfflineOptions{InPlace: true})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	snapshot = loadMigratedState(t, source, otherKeys)
	expected, err := DecodeLegacyStateSnapshot(raw, snapshot.Incarnation)
	require.NoError(t, err)
	expected.RADIUSCorrelationStateFile = source + ".radius-correlation"
	require.Equal(t, expected, snapshot)
	out, err = MigrateJSONStateStore(source, source, otherKeys, StateOfflineOptions{InPlace: true, Resume: true})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	require.Equal(t, snapshot, loadMigratedState(t, source, otherKeys))
}

func TestStateMigrationRejectsWholeInvalidLegacyBeforeWriting(t *testing.T) {
	for _, malformed := range []string{
		`{"version":1,"written_at":"2026-01-02T03:04:05Z","tasks":[],"destinations":[],"secret":"sensitive-marker"}`,
		`{"version":1,"version":1,"written_at":"2026-01-02T03:04:05Z","tasks":[],"destinations":[]}`,
		`{"version":1,"written_at":"2026-01-02T03:04:05Z","tasks":[],"destinations":[]} {}`,
		`{"version":1,"written_at":"2026-01-02T03:04:05Z","tasks":[{"xid":"sensitive-marker"}],"destinations":[]}`,
	} {
		path, keys, _ := stateStoreFixture(t)
		source := filepath.Join(filepath.Dir(path), "source.json")
		require.NoError(t, os.WriteFile(source, []byte(malformed), 0600))
		out, err := MigrateJSONStateStore(source, path, keys, StateOfflineOptions{})
		require.ErrorIs(t, err, ErrStateSnapshot)
		require.NotContains(t, err.Error(), "sensitive-marker")
		require.Equal(t, securestore.NotCommitted, out)
		require.Equal(t, out, securestore.OutcomeOf(err))
		entries, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".state-*"))
		require.NoError(t, err)
		require.Empty(t, entries, "whole legacy validation must precede initialization artifacts")
		entries, err = filepath.Glob(filepath.Join(filepath.Dir(path), ".usage-*"))
		require.NoError(t, err)
		require.Empty(t, entries)
		_, err = os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)
	}
}

// Stage a crash immediately after each durable boundary. Every call uses the
// same synced primitives as production; no reset/recovery bypass is introduced.
func stateMigrationBoundary(t testing.TB, source, target string, keys securestore.KeyConfig, pin string, stage int) [16]byte {
	t.Helper()
	dir, err := securestore.OpenDir(filepath.Dir(target))
	require.NoError(t, err)
	defer func() { require.NoError(t, dir.Close()) }()
	lock, err := dir.Lock(filepath.Base(target))
	require.NoError(t, err)
	defer func() { require.NoError(t, lock.Close()) }()
	ring, err := securestore.LoadKeyring(keys)
	require.NoError(t, err)
	var raw []byte
	sourceIdentity := ""
	if source != "" {
		var identity securestore.FileIdentity
		raw, identity, err = securestore.ReadFileWithIdentity(source, MaxStateSnapshotBytes)
		require.NoError(t, err)
		sourceIdentity = stateMigrationDigest([]byte(fmt.Sprintf("%d:%d", identity.Device, identity.Inode)))
	}
	if pin == "" {
		pin = target + ".radius-correlation"
		if source != "" {
			pin = source + ".radius-correlation"
		}
	}
	name := filepath.Base(target)
	bootstrapName := ".state-bootstrap-" + stateMigrationDigest([]byte(name))
	bootstrap, err := prepareStateBootstrap(dir, bootstrapName, false)
	require.NoError(t, err)
	plain, err := stateMigrationPayload(raw, source != "", bootstrap.store, pin)
	require.NoError(t, err)
	order, err := dir.LockOrderKey(name)
	require.NoError(t, err)
	operation := "initialize"
	if source != "" {
		operation = "json-migration"
	}
	intent := stateMigrationIntent{Version: 1, Operation: operation, SourcePath: stateMigrationDigest([]byte(source)), TargetPath: stateMigrationDigest([]byte(target)), SourceContent: stateMigrationDigest(raw), Payload: stateMigrationDigest(plain), KeyID: ring.ActiveID(), RadiusPath: stateMigrationDigest([]byte(pin)), SourceIdentity: sourceIdentity, TargetIdentity: stateMigrationDigest([]byte(order))}
	require.NoError(t, bootstrap.create(dir, bootstrapName, ring, intent))
	if stage == 0 {
		return bootstrap.store
	}
	usage, err := openStateMigrationUsage(dir, ring, bootstrap)
	require.NoError(t, err)
	defer func() { require.NoError(t, usage.Close()) }()
	if stage == 1 {
		return bootstrap.store
	}
	require.NoError(t, bootstrap.requireLedger(dir, bootstrapName, ring, intent))
	if stage == 2 {
		return bootstrap.store
	}
	writer, err := securestore.NewWriter(usage)
	require.NoError(t, err)
	intentData, err := json.Marshal(intent)
	require.NoError(t, err)
	binding := securestore.Binding{Store: bootstrap.store, Object: "administrative-state/offline-intent/" + stateMigrationDigest([]byte(name))}
	encoded, err := writer.Seal(securestore.AdministrativeState, binding, intentData)
	require.NoError(t, err)
	if stage == 3 {
		return bootstrap.store
	}
	_, err = dir.Create(".state-intent-"+stateMigrationDigest([]byte(name)), encoded)
	require.NoError(t, err)
	if stage == 4 {
		return bootstrap.store
	}
	encoded, err = writer.Seal(securestore.AdministrativeState, securestore.Binding{Store: bootstrap.store, Object: stateSnapshotObject}, plain)
	require.NoError(t, err)
	if stage == 5 {
		return bootstrap.store
	}
	if source == target {
		_, err = dir.Replace(name, encoded)
	} else {
		_, err = dir.Create(name, encoded)
	}
	require.NoError(t, err)
	return bootstrap.store
}

func TestStateMigrationResumeEveryDurableBoundary(t *testing.T) {
	for _, mode := range []string{"init", "migration", "in-place"} {
		for stage, boundary := range []string{"bootstrap", "zero-usage", "required-usage", "sealed-intent", "published-intent", "sealed-snapshot", "published-snapshot"} {
			t.Run(mode+"/"+boundary, func(t *testing.T) {
				path, keys, _ := stateStoreFixture(t)
				source := ""
				if mode != "init" {
					source, _ = stateMigrationSource(t, filepath.Dir(path))
				}
				if mode == "in-place" {
					path = source
				}
				identity := stateMigrationBoundary(t, source, path, keys, "", stage)
				options := StateOfflineOptions{Resume: true, InPlace: mode == "in-place"}
				var out securestore.Outcome
				var err error
				if mode == "init" {
					out, err = InitializeEncryptedStateStore(path, keys, options)
				} else {
					out, err = MigrateJSONStateStore(source, path, keys, options)
				}
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, out)
				store, err := OpenStateStore(path, keys)
				require.NoError(t, err)
				require.Equal(t, uuid.UUID(identity), store.StoreID())
				if stage >= 3 && stage < 6 {
					require.GreaterOrEqual(t, store.usage.Stats().Invocations, uint64(8192), "lost reservations cannot be reset")
				}
				require.NoError(t, store.Close())
			})
		}
	}
}

func TestStateMigrationResumeCannotResetUsageOrChangeIntent(t *testing.T) {
	for _, stage := range []int{2, 3, 4, 5, 6} {
		path, keys, _ := stateStoreFixture(t)
		stateMigrationBoundary(t, "", path, keys, "", stage)
		ring, err := securestore.LoadKeyring(keys)
		require.NoError(t, err)
		ledger := filepath.Join(filepath.Dir(path), ring.UsageFileName())
		require.NoError(t, os.Remove(ledger))
		out, err := InitializeEncryptedStateStore(path, keys, StateOfflineOptions{Resume: true})
		require.ErrorContains(t, err, "must never be recreated")
		require.Equal(t, securestore.NotCommitted, out)
		_, err = os.Stat(ledger)
		require.ErrorIs(t, err, os.ErrNotExist)
	}
	for _, change := range []string{"content", "source-inode", "key", "pin", "stage"} {
		t.Run(change, func(t *testing.T) {
			path, keys, _ := stateStoreFixture(t)
			source, raw := stateMigrationSource(t, filepath.Dir(path))
			stateMigrationBoundary(t, source, path, keys, "", 2)
			options := StateOfflineOptions{Resume: true}
			switch change {
			case "content":
				require.NoError(t, os.WriteFile(source, append(raw, ' '), 0600))
			case "source-inode":
				replacement := source + ".replacement"
				require.NoError(t, os.WriteFile(replacement, raw, 0600))
				require.NoError(t, os.Rename(replacement, source))
			case "key":
				require.NoError(t, os.WriteFile(keys.Active.File, bytes.Repeat([]byte{9}, securestore.KeyBytes), 0600))
			case "pin":
				options.RADIUSStateFile = filepath.Join(filepath.Dir(path), "other-radius")
			case "stage":
				bootstrap := filepath.Join(filepath.Dir(path), ".state-bootstrap-"+stateMigrationDigest([]byte(filepath.Base(path))))
				data, err := os.ReadFile(bootstrap)
				require.NoError(t, err)
				data[5] = stateBootstrapUninitialized
				require.NoError(t, os.WriteFile(bootstrap, data, 0600))
			}
			_, err := MigrateJSONStateStore(source, path, keys, options)
			require.ErrorContains(t, err, "authenticated commitment")
			_, err = os.Stat(path)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestStateMigrationAliasesAndOwners(t *testing.T) {
	for _, kind := range []string{"key-target", "key-source", "key-pin", "source-pin", "target-pin", "metadata-pin", "symlink-source", "symlink-dotdot", "hardlink-source", "owned-source", "owned-target"} {
		t.Run(kind, func(t *testing.T) {
			path, keys, rawKey := stateStoreFixture(t)
			source, raw := stateMigrationSource(t, filepath.Dir(path))
			options := StateOfflineOptions{}
			var owned *securestore.PrivateSource
			switch kind {
			case "key-target":
				path = keys.Active.File
			case "key-source":
				source = keys.Active.File
			case "key-pin":
				options.RADIUSStateFile = keys.Active.File
			case "source-pin":
				options.RADIUSStateFile = source
			case "target-pin":
				options.RADIUSStateFile = path
			case "metadata-pin":
				options.RADIUSStateFile = filepath.Join(filepath.Dir(path), ".state-intent-"+stateMigrationDigest([]byte(filepath.Base(path))))
			case "symlink-source":
				link := source + ".link"
				require.NoError(t, os.Symlink(source, link))
				source = link
			case "symlink-dotdot":
				dir := filepath.Join(filepath.Dir(path), "sub")
				require.NoError(t, os.Mkdir(dir, 0700))
				path = filepath.Join(dir, "legacy.json")
				require.NoError(t, os.WriteFile(path, raw, 0600))
				link := filepath.Join(dir, "link")
				require.NoError(t, os.Symlink(dir, link))
				source = link + "/../legacy.json"
				options.InPlace = true
				options.RADIUSStateFile = path + ".radius-correlation"
			case "hardlink-source":
				require.NoError(t, os.Link(source, source+".alias"))
			case "owned-source", "owned-target":
				target := source
				if kind == "owned-target" {
					target = path
					require.NoError(t, os.WriteFile(path, raw, 0600))
				}
				var err error
				owned, err = securestore.OpenPrivateSource(target)
				require.NoError(t, err)
				defer func() { require.NoError(t, owned.Close()) }()
			}
			_, err := MigrateJSONStateStore(source, path, keys, options)
			require.Error(t, err)
			if owned != nil {
				require.True(t, errors.Is(err, securestore.ErrLocked), err)
			}
			after, err := os.ReadFile(keys.Active.File)
			require.NoError(t, err)
			require.Equal(t, rawKey, after)
		})
	}
}

func TestStateMigrationTrustedLegacyDirectoryAndRelativePin(t *testing.T) {
	path, keys, _ := stateStoreFixture(t)
	legacyDirectory := filepath.Join(filepath.Dir(path), "legacy-config")
	require.NoError(t, os.Mkdir(legacyDirectory, 0755))
	source, raw := stateMigrationSource(t, legacyDirectory)
	pin := source + ".radius-correlation"
	require.NoError(t, os.WriteFile(pin, []byte("existing allocator"), 0600))
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)
	relativePin, err := filepath.Rel(workingDirectory, pin)
	require.NoError(t, err)
	out, err := MigrateJSONStateStore(source, path, keys, StateOfflineOptions{RADIUSStateFile: relativePin})
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	snapshot := loadMigratedState(t, path, keys)
	require.Equal(t, pin, snapshot.RADIUSCorrelationStateFile)
	retained, err := os.ReadFile(source)
	require.NoError(t, err)
	require.Equal(t, raw, retained)
	_, err = os.Stat(filepath.Join(legacyDirectory, ".securestore-lock-"+stateMigrationDigest([]byte(filepath.Base(pin)))))
	require.ErrorIs(t, err, os.ErrNotExist, "offline migration does not take the separately owned allocator lock")
}

func TestStateMigrationRejectsDescriptorKeyAliasesAfterDirectoryRename(t *testing.T) {
	for _, role := range []string{"source", "target", "radius", "metadata"} {
		t.Run(role, func(t *testing.T) {
			path, keys, _ := stateStoreFixture(t)
			ring, err := securestore.LoadKeyring(keys)
			require.NoError(t, err)
			previous := filepath.Dir(path)
			moved := previous + "-renamed"
			require.NoError(t, os.Rename(previous, moved))
			dir, err := securestore.OpenDir(moved)
			require.NoError(t, err)
			defer func() { require.NoError(t, dir.Close()) }()
			target := stateMigrationTarget{dir: dir, name: "state.enc"}
			var input *securestore.PrivateSource
			pin := filepath.Join(moved, "radius")
			switch role {
			case "source":
				input, err = securestore.PreparePrivateSource(filepath.Join(moved, "key"))
				require.NoError(t, err)
				defer func() { require.NoError(t, input.Close()) }()
			case "target":
				target.name = "key"
			case "radius":
				pin = filepath.Join(moved, "key")
			case "metadata":
				require.NoError(t, os.Rename(filepath.Join(moved, "key"), filepath.Join(moved, ".state-bootstrap-"+stateMigrationDigest([]byte(target.name)))))
			}
			radius, err := securestore.PreparePrivateSource(pin)
			require.NoError(t, err)
			defer func() { require.NoError(t, radius.Close()) }()
			require.Error(t, checkStateMigrationAliases(&target, input, radius, ring), "loaded key identity must survive pathname changes")
		})
	}
}

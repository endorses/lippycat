//go:build processor || tap || all

package processor

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func storageKeyRef(t *testing.T, id string, value byte) securestore.KeyRef {
	t.Helper()
	path := newTestFilterFile(t)
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{value}, securestore.KeyBytes), 0600))
	return securestore.KeyRef{ID: id, File: path}
}

func independentStorageConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		ListenAddr: "127.0.0.1:0", LIEnabled: true, FilterFile: newTestFilterFile(t), FilterStoreMode: filtering.StoreEncrypted,
		FilterStoreKeys:        securestore.KeyConfig{Active: storageKeyRef(t, "filter-active-marker", 1), Prior: []securestore.KeyRef{storageKeyRef(t, "filter-prior-marker", 2)}},
		LIStateFile:            newTestFilterFile(t),
		LIStateKeys:            securestore.KeyConfig{Active: storageKeyRef(t, "state-active-marker", 3), Prior: []securestore.KeyRef{storageKeyRef(t, "state-prior-marker", 4)}},
		LIDeliveryX2SpoolDir:   filepath.Join(t.TempDir(), "uncreated-x2"),
		LIDeliveryX2SpoolKeyID: "x2-active-marker", LIDeliveryX2SpoolKeyFile: storageKeyRef(t, "", 5).File,
		LIDeliveryX2SpoolReadKeys: []securestore.KeyRef{storageKeyRef(t, "x2-prior-marker", 6)},
	}
}

func filterStorageBackend(t *testing.T, config Config) *filtering.EncryptedPersistence {
	t.Helper()
	backend, err := filtering.NewEncryptedPersistence(config.FilterStoreKeys)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, backend.Close()) })
	return backend
}

func TestStorageKeysRejectCrossStoreActiveAndPriorReuse(t *testing.T) {
	for _, pair := range [][2]string{{"filter", "state"}, {"filter", "x2"}, {"state", "x2"}} {
		for _, leftPrior := range []bool{false, true} {
			for _, rightPrior := range []bool{false, true} {
				name := pair[0] + "/" + pair[1]
				if leftPrior {
					name += "/left-prior"
				} else {
					name += "/left-active"
				}
				if rightPrior {
					name += "/right-prior"
				} else {
					name += "/right-active"
				}
				t.Run(name, func(t *testing.T) {
					cfg := independentStorageConfig(t)
					refs := map[string][2]securestore.KeyRef{
						"filter": {cfg.FilterStoreKeys.Active, cfg.FilterStoreKeys.Prior[0]},
						"state":  {cfg.LIStateKeys.Active, cfg.LIStateKeys.Prior[0]},
						"x2":     {{ID: cfg.LIDeliveryX2SpoolKeyID, File: cfg.LIDeliveryX2SpoolKeyFile}, cfg.LIDeliveryX2SpoolReadKeys[0]},
					}
					li, ri := 0, 0
					if leftPrior {
						li = 1
					}
					if rightPrior {
						ri = 1
					}
					left, right := refs[pair[0]][li], refs[pair[1]][ri]
					material, err := os.ReadFile(left.File)
					require.NoError(t, err)
					require.NoError(t, os.WriteFile(right.File, material, 0600))
					p, err := New(cfg)
					require.ErrorContains(t, err, "independently provisioned")
					require.Nil(t, p)
					require.NotContains(t, err.Error(), "marker")
					require.NotContains(t, err.Error(), left.File)
					require.NotContains(t, err.Error(), right.File)
					entries, err := os.ReadDir(filepath.Dir(cfg.FilterFile))
					require.NoError(t, err)
					require.Empty(t, entries, "key rejection must precede even filter ownership sidecars")
					_, err = os.Stat(cfg.LIStateFile)
					require.ErrorIs(t, err, os.ErrNotExist)
					_, err = os.Stat(cfg.LIDeliveryX2SpoolDir)
					require.ErrorIs(t, err, os.ErrNotExist)
				})
			}
		}
	}
}

func TestStorageKeysAcceptIndependentEnabledStores(t *testing.T) {
	cfg := independentStorageConfig(t)
	backend := filterStorageBackend(t, cfg)
	require.NoError(t, validateIndependentStorageKeys(cfg, backend))
	// Key-file-only X2 retains its original implicit active and legacy selection.
	cfg.LIDeliveryX2SpoolKeyID = ""
	require.NoError(t, validateIndependentStorageKeys(cfg, backend))
	// Unconfigured owners do not require or inspect otherwise stale key references.
	cfg.LIStateFile, cfg.LIDeliveryX2SpoolDir = "", ""
	cfg.LIStateKeys = securestore.KeyConfig{Active: securestore.KeyRef{ID: "invalid id", File: "/absent/state-key"}}
	cfg.LIDeliveryX2SpoolKeyFile = "/absent/x2-key"
	require.NoError(t, validateIndependentStorageKeys(cfg, backend))
}

func TestStorageKeysUseActualLoadedFilterKeyring(t *testing.T) {
	cfg := independentStorageConfig(t)
	backend := filterStorageBackend(t, cfg)
	oldMaterial, err := os.ReadFile(cfg.FilterStoreKeys.Active.File)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfg.FilterStoreKeys.Active.File, bytes.Repeat([]byte{20}, securestore.KeyBytes), 0600))
	require.NoError(t, os.WriteFile(cfg.LIStateKeys.Active.File, oldMaterial, 0600))
	require.ErrorContains(t, validateIndependentStorageKeys(cfg, backend), "independently provisioned", "rereading the filter key path would miss reuse of the loaded key")
	require.NoError(t, os.WriteFile(cfg.LIStateKeys.Active.File, bytes.Repeat([]byte{20}, securestore.KeyBytes), 0600))
	require.NoError(t, validateIndependentStorageKeys(cfg, backend), "the filter backend still owns the original immutable key")
}

func TestStorageKeysRejectMissingAndMalformedEnabledReferences(t *testing.T) {
	for _, name := range []string{"state-missing", "state-duplicate-id", "state-duplicate-material", "state-too-many", "x2-missing", "x2-implicit-duplicate", "x2-legacy-missing"} {
		t.Run(name, func(t *testing.T) {
			cfg := independentStorageConfig(t)
			switch name {
			case "state-missing":
				cfg.LIStateKeys = securestore.KeyConfig{}
			case "state-duplicate-id":
				cfg.LIStateKeys.Prior[0].ID = cfg.LIStateKeys.Active.ID
			case "state-duplicate-material":
				cfg.LIStateKeys.Prior[0].File = cfg.LIStateKeys.Active.File
			case "state-too-many":
				cfg.LIStateKeys.Prior = make([]securestore.KeyRef, securestore.MaxPriorKeys+1)
			case "x2-missing":
				cfg.LIDeliveryX2SpoolKeyFile = ""
			case "x2-implicit-duplicate":
				cfg.LIDeliveryX2SpoolKeyID = ""
				cfg.LIDeliveryX2SpoolReadKeys[0].ID = "default"
			case "x2-legacy-missing":
				cfg.LIDeliveryX2SpoolLegacyKeyID = "unconfigured-marker"
			}
			p, err := New(cfg)
			require.Error(t, err)
			require.Nil(t, p)
			require.NotContains(t, err.Error(), "marker")
			_, err = os.Stat(cfg.LIStateFile)
			require.ErrorIs(t, err, os.ErrNotExist, "preflight must not initialize administrative state")
			_, err = os.Stat(cfg.LIDeliveryX2SpoolDir)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestStorageKeysDisabledLIDoesNotReadLIReferences(t *testing.T) {
	cfg := Config{ListenAddr: "127.0.0.1:0", FilterFile: newTestFilterFile(t), LIStateFile: "/unavailable/state.enc",
		LIStateKeys:          securestore.KeyConfig{Active: securestore.KeyRef{ID: "invalid id", File: "/unavailable/state-key"}},
		LIDeliveryX2SpoolDir: "/unavailable/x2", LIDeliveryX2SpoolKeyFile: "/unavailable/x2-key", LIDeliveryX2SpoolReadKeys: []securestore.KeyRef{{ID: "bad key id"}},
	}
	p, err := New(cfg)
	require.NoError(t, err)
	require.Equal(t, filtering.StoreYAML, p.config.FilterStoreMode)
	require.NoError(t, p.Shutdown())
}

func TestStorageKeysX2LegacyMappingMatchesJournal(t *testing.T) {
	for _, tc := range []struct{ name, id, legacy, wantID, wantLegacy string }{
		{"raw-key-only", "", "", "default", "default"},
		{"implicit-active-explicit-legacy", "", "old", "default", "old"},
		{"explicit-active-no-legacy", "new", "", "new", ""},
		{"explicit-both", "new", "old", "new", "old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := []securestore.KeyRef{{ID: "old", File: "/keys/old"}}
			cfg := Config{LIDeliveryX2SpoolKeyID: tc.id, LIDeliveryX2SpoolLegacyKeyID: tc.legacy, LIDeliveryX2SpoolKeyFile: "/keys/active", LIDeliveryX2SpoolReadKeys: prior}
			got := x2StorageKeyConfig(cfg)
			require.Equal(t, securestore.KeyRef{ID: tc.wantID, File: "/keys/active"}, got.Active)
			require.Equal(t, tc.wantLegacy, got.LegacyID)
			require.Equal(t, prior, got.Prior)
		})
	}
}

package filtering

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestStoreModeRuntimeMatrix(t *testing.T) {
	home := t.TempDir()
	homeDirectory := func() (string, error) { return home, nil }
	key := securestore.KeyConfig{Active: securestore.KeyRef{ID: "active", File: "explicit-key"}}
	for _, test := range []struct {
		name string
		li   bool
		mode StoreMode
		keys securestore.KeyConfig
		want StoreMode
		err  bool
	}{
		{"ordinary default", false, "", securestore.KeyConfig{}, StoreYAML, false},
		{"LI-capable runtime disabled", false, StoreAuto, securestore.KeyConfig{}, StoreYAML, false},
		{"LI automatic encryption", true, StoreAuto, key, StoreEncrypted, false},
		{"LI plaintext forbidden", true, StoreYAML, securestore.KeyConfig{}, "", true},
		{"optional encryption", false, StoreEncrypted, key, StoreEncrypted, false},
		{"LI encryption", true, StoreEncrypted, key, StoreEncrypted, false},
		{"encryption requires keys", false, StoreEncrypted, securestore.KeyConfig{}, "", true},
		{"auto YAML rejects keys", false, StoreAuto, key, "", true},
		{"YAML rejects keys", false, StoreYAML, key, "", true},
		{"unknown mode", false, "guess", key, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := resolveStoreConfig(StoreConfig{Mode: test.mode, Keys: test.keys}, test.li, homeDirectory)
			if test.err {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, cfg.Mode)
			name := "filters.yaml"
			if cfg.Mode == StoreEncrypted {
				name = "filters.enc"
			}
			require.Equal(t, filepath.Join(home, ".config", "lippycat", name), cfg.File)
		})
	}
}

func TestDefaultStoreConflictsAndExplicitPathAuthority(t *testing.T) {
	for _, existing := range []string{"yaml", "encrypted", "both"} {
		t.Run(existing, func(t *testing.T) {
			home := t.TempDir()
			homeDirectory := func() (string, error) { return home, nil }
			dir := filepath.Join(home, ".config", "lippycat")
			require.NoError(t, os.MkdirAll(dir, 0700))
			if existing == "yaml" || existing == "both" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "filters.yaml"), nil, 0600))
			}
			if existing == "encrypted" || existing == "both" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "filters.enc"), nil, 0600))
			}
			key := securestore.KeyConfig{Active: securestore.KeyRef{ID: "active", File: "key"}}
			for _, mode := range []StoreMode{StoreYAML, StoreEncrypted} {
				cfg := StoreConfig{Mode: mode}
				if mode == StoreEncrypted {
					cfg.Keys = key
				}
				_, err := resolveStoreConfig(cfg, false, homeDirectory)
				if existing == "both" || existing == "yaml" && mode == StoreEncrypted || existing == "encrypted" && mode == StoreYAML {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
				}
				cfg.File = "custom.authoritative-extension"
				resolved, err := resolveStoreConfig(cfg, false, homeDirectory)
				require.NoError(t, err)
				require.Equal(t, cfg.File, resolved.File)
			}
		})
	}
}

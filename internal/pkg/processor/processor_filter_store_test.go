//go:build processor || tap || all

package processor

import (
	"os"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestManagedStoreRuntimeModes(t *testing.T) {
	for _, test := range []struct {
		name      string
		li        bool
		mode      filtering.StoreMode
		encrypted bool
	}{
		{"ordinary_default", false, "", false},
		{"runtime_disabled_auto", false, filtering.StoreAuto, false},
		{"explicit_yaml", false, filtering.StoreYAML, false},
		{"optional_encryption", false, filtering.StoreEncrypted, true},
		{"LI_auto", true, filtering.StoreAuto, true},
		{"LI_encrypted", true, filtering.StoreEncrypted, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := Config{ListenAddr: "127.0.0.1:0", ProcessorID: "store-modes", FilterFile: newTestFilterFile(t), LIEnabled: test.li, FilterStoreMode: test.mode}
			if test.encrypted {
				cfg.FilterStoreKeys = newTestFilterKeys(t)
				_, err := filtering.InitializeEncryptedFilterStore(cfg.FilterFile, cfg.FilterStoreKeys, filtering.OfflineOptions{})
				require.NoError(t, err)
			}
			p, err := New(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
			if test.encrypted {
				require.Equal(t, filtering.StoreEncrypted, p.config.FilterStoreMode)
			} else {
				require.Equal(t, filtering.StoreYAML, p.config.FilterStoreMode)
				_, err = os.Stat(cfg.FilterFile)
				require.ErrorIs(t, err, os.ErrNotExist, "YAML first run must not require an initialized snapshot")
			}
			accepted, _, err := p.filterManager.UpdateCommitted(&management.Filter{Id: "ordinary", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Description: "distinctive-policy-marker", Enabled: true})
			require.NoError(t, err)
			require.NoError(t, p.Shutdown())
			data, err := os.ReadFile(cfg.FilterFile)
			require.NoError(t, err)
			if test.encrypted {
				require.Equal(t, "LCS1", string(data[:4]))
				require.NotContains(t, string(data), accepted.Description)
			} else {
				require.Contains(t, string(data), accepted.Description)
				// Stopped-node editing remains supported; next construction loads it.
				accepted.Description = "edited while stopped"
				data, err = filtercodec.MarshalManagedYAML(map[string]*management.Filter{accepted.Id: accepted})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(cfg.FilterFile, data, 0o600))
			}
			restarted, err := New(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, restarted.Shutdown()) })
			require.Len(t, restarted.filterManager.GetAll(), 1)
			require.Equal(t, accepted.Description, restarted.filterManager.GetAll()[0].Description)
		})
	}
}

func TestManagedStoreRejectsUnsafeStartup(t *testing.T) {
	for _, name := range []string{"LI_yaml", "LI_missing_keys", "yaml_keys", "encrypted_missing", "encrypted_plaintext", "yaml_ciphertext", "wrong_key", "corrupted", "unknown_mode"} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{ListenAddr: "127.0.0.1:0", FilterFile: newTestFilterFile(t), FilterStoreMode: filtering.StoreEncrypted, FilterStoreKeys: newTestFilterKeys(t)}
			switch name {
			case "LI_yaml":
				cfg.LIEnabled, cfg.FilterStoreMode, cfg.FilterStoreKeys = true, filtering.StoreYAML, securestore.KeyConfig{}
			case "LI_missing_keys":
				cfg.LIEnabled, cfg.FilterStoreMode, cfg.FilterStoreKeys = true, filtering.StoreAuto, securestore.KeyConfig{}
			case "yaml_keys":
				cfg.FilterStoreMode = filtering.StoreYAML
			case "encrypted_plaintext":
				require.NoError(t, os.WriteFile(cfg.FilterFile, []byte("filters: []\n"), 0o600))
			case "yaml_ciphertext", "wrong_key", "corrupted":
				_, err := filtering.InitializeEncryptedFilterStore(cfg.FilterFile, cfg.FilterStoreKeys, filtering.OfflineOptions{})
				require.NoError(t, err)
				switch name {
				case "yaml_ciphertext":
					cfg.FilterStoreMode, cfg.FilterStoreKeys = filtering.StoreYAML, securestore.KeyConfig{}
				case "wrong_key":
					cfg.FilterStoreKeys = newTestFilterKeys(t)
				case "corrupted":
					data, err := os.ReadFile(cfg.FilterFile)
					require.NoError(t, err)
					data[len(data)-1] ^= 1
					require.NoError(t, os.WriteFile(cfg.FilterFile, data, 0o600))
				}
			case "unknown_mode":
				cfg.FilterStoreMode = "guess"
			}
			before, beforeErr := os.ReadFile(cfg.FilterFile)
			p, err := New(cfg)
			require.Error(t, err)
			require.Nil(t, p, "reject before LI runtime, outputs, listeners or capture exist")
			after, afterErr := os.ReadFile(cfg.FilterFile)
			if beforeErr != nil {
				require.ErrorIs(t, beforeErr, os.ErrNotExist)
				require.ErrorIs(t, afterErr, os.ErrNotExist)
			} else {
				require.NoError(t, afterErr)
				require.Equal(t, before, after, "failed startup cannot replace a snapshot")
			}
		})
	}
}

func TestManagedStoreConstructorOwnership(t *testing.T) {
	cfg := Config{ListenAddr: "127.0.0.1:0", FilterFile: newTestFilterFile(t)}
	p, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, p.Shutdown()) })
	other, err := New(cfg)
	require.Error(t, err)
	require.Nil(t, other)
	require.NoError(t, p.Shutdown())
	// A later constructor failure must also release the filter ownership lock.
	cfg.EventIngressProfile = "invalid-profile"
	other, err = New(cfg)
	require.Error(t, err)
	require.Nil(t, other)
	cfg.EventIngressProfile = ""
	other, err = New(cfg)
	require.NoError(t, err)
	require.NoError(t, other.Shutdown())
}

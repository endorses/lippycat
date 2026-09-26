//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func storageKeyStartupConfig(t *testing.T) Config {
	t.Helper()
	cfg := independentStorageConfig(t)
	certDir := filepath.Join("..", "..", "..", "test", "testcerts", "li")
	cfg.LIDeliveryTLSCertFile = filepath.Join(certDir, "delivery-client-cert.pem")
	cfg.LIDeliveryTLSKeyFile = filepath.Join(certDir, "delivery-client-key.pem")
	cfg.LIDeliveryTLSCAFile = filepath.Join(certDir, "ca-cert.pem")
	cfg.LIDeliveryX2SpoolMaxBytes = 1 << 20
	_, err := filtering.InitializeEncryptedFilterStore(cfg.FilterFile, cfg.FilterStoreKeys, filtering.OfflineOptions{})
	require.NoError(t, err)
	_, err = li.InitializeEncryptedStateStore(cfg.LIStateFile, cfg.LIStateKeys, li.StateOfflineOptions{})
	require.NoError(t, err)
	return cfg
}

func replaceStorageKey(t *testing.T, source, target string) {
	t.Helper()
	material, err := os.ReadFile(source)
	require.NoError(t, err)
	temporary := target + ".replacement"
	require.NoError(t, os.WriteFile(temporary, material, 0600))
	require.NoError(t, os.Rename(temporary, target))
}

func TestStorageKeysStartupRetainsOwnersAcrossKeyReplacement(t *testing.T) {
	for _, pair := range [][2]string{{"filter", "state"}, {"filter", "x2"}, {"state", "x2"}} {
		for sourceRole := range 2 {
			for targetRole := range 2 {
				name := pair[0] + "/" + pair[1] + "/" + []string{"active", "prior"}[sourceRole] + "/" + []string{"active", "prior"}[targetRole]
				t.Run(name, func(t *testing.T) {
					cfg := storageKeyStartupConfig(t)
					p, err := newTestProcessor(t, cfg)
					require.NoError(t, err)
					refs := map[string][2]string{
						"filter": {cfg.FilterStoreKeys.Active.File, cfg.FilterStoreKeys.Prior[0].File},
						"state":  {cfg.LIStateKeys.Active.File, cfg.LIStateKeys.Prior[0].File},
						"x2":     {cfg.LIDeliveryX2SpoolKeyFile, cfg.LIDeliveryX2SpoolReadKeys[0].File},
					}
					client := p.liStorage.client
					ring, err := p.liManager.AdministrativeKeyring()
					require.NoError(t, err)
					replaceStorageKey(t, refs[pair[0]][sourceRole], refs[pair[1]][targetRole])
					require.NoError(t, p.prepareLIStorage(), "existing owners never reload replaced key files")
					require.Same(t, client, p.liStorage.client)
					retained, err := p.liManager.AdministrativeKeyring()
					require.NoError(t, err)
					require.Same(t, ring, retained)
					// A later owner must reject the newly deployed reused material,
					// without disturbing the already authenticated live owner.
					other, err := New(cfg)
					require.ErrorContains(t, err, "independently provisioned")
					require.NotContains(t, err.Error(), "marker")
					require.Nil(t, other)
					require.Same(t, client, liDeliveryClient)
					p.ctx, p.cancel = context.WithCancel(context.Background())
					require.NoError(t, p.startLIManager())
					require.NoError(t, p.Shutdown())
				})
			}
		}
	}
}

func TestStorageKeysStartupAcceptsSeparateOwnedRings(t *testing.T) {
	cfg := storageKeyStartupConfig(t)
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	// Independently replaced key references are likewise not reloaded by an
	// owner whose authenticated ring and usage ledger are already retained.
	original, err := os.ReadFile(cfg.LIStateKeys.Active.File)
	require.NoError(t, err)
	replacement := storageKeyRef(t, "replacement", 24)
	replaceStorageKey(t, replacement.File, cfg.LIStateKeys.Active.File)
	require.NoError(t, p.prepareLIStorage())
	p.ctx, p.cancel = context.WithCancel(context.Background())
	require.NoError(t, p.startLIManager())
	require.NoError(t, p.Shutdown())
	_, err = li.OpenStateStore(cfg.LIStateFile, cfg.LIStateKeys)
	require.Error(t, err, "replacement material did not silently become the owner key")
	require.NoError(t, os.WriteFile(cfg.LIStateKeys.Active.File, original, 0600))
	state, err := li.OpenStateStore(cfg.LIStateFile, cfg.LIStateKeys)
	require.NoError(t, err)
	require.NoError(t, state.Close())
}

func TestStorageKeysValidatorRequiresConfiguredOwner(t *testing.T) {
	cfg := independentStorageConfig(t)
	backend := filterStorageBackend(t, cfg)
	p := &Processor{config: cfg, filterManager: filtering.NewManager(cfg.FilterFile, backend, nil, nil, nil)}
	_, err := p.storageKeyValidator(nil)
	require.ErrorContains(t, err, "ownership is incomplete")
	state, err := securestore.LoadKeyring(cfg.LIStateKeys)
	require.NoError(t, err)
	validate, err := p.storageKeyValidator(state)
	require.NoError(t, err)
	require.Error(t, validate(nil))
	p.config.LIStateFile = ""
	_, err = p.storageKeyValidator(state)
	require.Error(t, err)
	p.config.LIEnabled = false
	validate, err = p.storageKeyValidator(nil)
	require.NoError(t, err)
	require.Nil(t, validate)
}

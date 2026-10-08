//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func correlationStorageConfig(t *testing.T) li.CallCorrelationConfig {
	t.Helper()
	cfg := li.DefaultCallCorrelationConfig()
	cfg.SessionHeaders = []string{"X-Session"}
	cfg.StoreFile = newTestFilterFile(t)
	cfg.StoreKeys = securestore.KeyConfig{Active: storageKeyRef(t, "correlation-active", 51), Prior: []securestore.KeyRef{storageKeyRef(t, "correlation-prior", 52)}}
	out, err := li.InitializeCallCorrelationStore(cfg.StoreFile, cfg.StoreKeys, cfg.MaxRecords)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	return cfg
}
func TestProcessorCorrelationStorageDisabledAndMemoryOnly(t *testing.T) {
	disabled := li.DefaultCallCorrelationConfig()
	disabled.StoreFile = filepath.Join(t.TempDir(), "missing.enc")
	disabled.StoreKeys = securestore.KeyConfig{Active: securestore.KeyRef{ID: "missing", File: "missing.key"}}
	p := &Processor{config: Config{LICallCorrelation: disabled}, liStorage: &liStoragePreparation{}}
	require.NoError(t, p.prepareLICorrelation())
	require.Nil(t, p.liStorage.correlation)
	require.Nil(t, p.liCorrelationKeyring())
	_, err := os.Stat(disabled.StoreFile)
	require.ErrorIs(t, err, os.ErrNotExist)
	memory := li.DefaultCallCorrelationConfig()
	memory.AddressChaining = true
	p.config.LICallCorrelation = memory
	require.NoError(t, p.prepareLICorrelation())
	require.NotNil(t, p.liStorage.correlation)
	require.Nil(t, p.liStorage.correlationStore)
	require.False(t, p.liStorage.correlation.Stats().Persistence)
	require.NoError(t, p.stopLIManager())
}
func TestProcessorCorrelationStorageRequiresAuthentication(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "corrupt"}[corrupt], func(t *testing.T) {
			cfg := correlationStorageConfig(t)
			if corrupt {
				raw, err := os.ReadFile(cfg.StoreFile)
				require.NoError(t, err)
				raw[len(raw)-1] ^= 1
				require.NoError(t, os.WriteFile(cfg.StoreFile, raw, 0600))
			} else {
				require.NoError(t, os.Remove(cfg.StoreFile))
			}
			p := &Processor{config: Config{LICallCorrelation: cfg}, liStorage: &liStoragePreparation{}}
			require.Error(t, p.prepareLICorrelation())
			require.Nil(t, p.liStorage.correlation)
			require.Nil(t, p.liStorage.correlationStore)
		})
	}
}
func TestProcessorCorrelationStorageRejectsPathCollisions(t *testing.T) {
	for _, which := range []string{"filter", "administrative", "radius"} {
		t.Run(which, func(t *testing.T) {
			cfg := correlationStorageConfig(t)
			p := &Processor{config: Config{LICallCorrelation: cfg}, liStorage: &liStoragePreparation{}}
			switch which {
			case "filter":
				p.config.FilterFile = cfg.StoreFile
			case "administrative":
				p.config.LIStateFile = cfg.StoreFile
			case "radius":
				p.config.LIRADIUSCorrelationStateFile = cfg.StoreFile
			}
			require.ErrorContains(t, p.prepareLICorrelation(), "separate from other stores")
			reopened, err := li.OpenCallCorrelationStore(cfg.StoreFile, cfg.StoreKeys, cfg.MaxRecords)
			require.NoError(t, err)
			require.NoError(t, reopened.Close(), "failed preparation cannot retain storage locks")
		})
	}
}
func TestProcessorCorrelationStorageRejectsCrossStoreKeyReuse(t *testing.T) {
	for _, role := range []string{"filter", "state", "x2"} {
		for _, prior := range []bool{false, true} {
			t.Run(role+map[bool]string{false: "-active", true: "-prior"}[prior], func(t *testing.T) {
				cfg := independentStorageConfig(t)
				cfg.LICallCorrelation = li.DefaultCallCorrelationConfig()
				cfg.LICallCorrelation.SessionHeaders = []string{"X-Session"}
				cfg.LICallCorrelation.StoreFile = "unused-correlation.enc"
				refs := map[string][]securestore.KeyRef{"filter": {cfg.FilterStoreKeys.Active, cfg.FilterStoreKeys.Prior[0]}, "state": {cfg.LIStateKeys.Active, cfg.LIStateKeys.Prior[0]}, "x2": {{ID: cfg.LIDeliveryX2SpoolKeyID, File: cfg.LIDeliveryX2SpoolKeyFile}, cfg.LIDeliveryX2SpoolReadKeys[0]}}
				ref := refs[role][0]
				if prior {
					ref = refs[role][1]
				}
				cfg.LICallCorrelation.StoreKeys = securestore.KeyConfig{Active: ref}
				backend := filterStorageBackend(t, cfg)
				require.ErrorContains(t, validateIndependentStorageKeys(cfg, backend), "independently provisioned")
			})
		}
	}
}
func TestProcessorCorrelationStorageRetainsOwnedRingAndStopsMaintenance(t *testing.T) {
	cfg := correlationStorageConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &Processor{config: Config{LICallCorrelation: cfg}, liStorage: &liStoragePreparation{}, ctx: ctx}
	require.NoError(t, p.prepareLICorrelation())
	ring := p.liCorrelationKeyring()
	require.NotNil(t, ring)
	replaceStorageKey(t, storageKeyRef(t, "replacement", 60).File, cfg.StoreKeys.Active.File)
	require.Same(t, ring, p.liCorrelationKeyring(), "runtime independence checks use actual immutable owned keys")
	p.startLICorrelationMaintenance()
	require.NoError(t, p.stopLIManager())
	require.NoError(t, p.stopLIManager())
	require.Equal(t, "closed", p.liStorage.correlationStore.StorageStatus().State)
	// Close has released locks even though new key material no longer authenticates.
	_, err := li.OpenCallCorrelationStore(cfg.StoreFile, cfg.StoreKeys, cfg.MaxRecords)
	require.Error(t, err)
	require.NotErrorIs(t, err, securestore.ErrLocked)
}
func TestProcessorCorrelationStorageConstructorFailureReleasesOwner(t *testing.T) {
	cfg := storageKeyStartupConfig(t)
	cfg.LICallCorrelation = correlationStorageConfig(t)
	cfg.LIDeliveryX2SpoolReplayManifest = "missing-manifest.json"
	p, err := New(cfg)
	require.Error(t, err)
	require.Nil(t, p)
	reopened, err := li.OpenCallCorrelationStore(cfg.LICallCorrelation.StoreFile, cfg.LICallCorrelation.StoreKeys, cfg.LICallCorrelation.MaxRecords)
	require.NoError(t, err)
	require.NoError(t, reopened.Close())
}

func TestProcessorCorrelationTaskContextPersistentAndStateless(t *testing.T) {
	cfg := li.DefaultCallCorrelationConfig()
	cfg.AddressChaining = true
	first := &Processor{config: Config{LICallCorrelation: cfg}, liStorage: &liStoragePreparation{}}
	second := &Processor{config: Config{LICallCorrelation: cfg}, liStorage: &liStoragePreparation{}}
	require.NoError(t, first.prepareLICorrelation())
	require.NoError(t, second.prepareLICorrelation())
	require.NotEqual(t, first.liStorage.correlationContext, second.liStorage.correlationContext)
	require.NoError(t, first.stopLIManager())
	require.NoError(t, second.stopLIManager())
	config := storageKeyStartupConfig(t)
	config.LICallCorrelation = cfg
	original, err := newTestProcessor(t, config)
	require.NoError(t, err)
	context := original.liStorage.correlationContext
	require.Equal(t, original.liManager.StateIncarnation(), context)
	require.NoError(t, original.Shutdown())
	restarted, err := newTestProcessor(t, config)
	require.NoError(t, err)
	require.Equal(t, context, restarted.liStorage.correlationContext, "authenticated administrative incarnation survives restart")
}

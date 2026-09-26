//go:build (processor || tap || all) && li

package processor

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestLIConstructorAuthenticatesBeforeOutputEffects(t *testing.T) {
	for _, failure := range []string{"missing-state", "corrupt-state", "corrupt-journal", "invalid-x1"} {
		t.Run(failure, func(t *testing.T) {
			cfg := storageKeyStartupConfig(t)
			var notifications atomic.Int64
			admf := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { notifications.Add(1) }))
			t.Cleanup(admf.Close)
			cfg.LIADMFEndpoint = admf.URL
			base := t.TempDir()
			cfg.PcapWriterConfig = DefaultPcapWriterConfig()
			cfg.PcapWriterConfig.Enabled, cfg.PcapWriterConfig.OutputDir = true, filepath.Join(base, "per-call")
			cfg.AutoRotateConfig = DefaultAutoRotateConfig()
			cfg.AutoRotateConfig.Enabled, cfg.AutoRotateConfig.OutputDir = true, filepath.Join(base, "auto-rotate")
			cfg.TLSKeylogConfig = DefaultTLSKeylogWriterConfig()
			cfg.TLSKeylogConfig.OutputDir = filepath.Join(base, "keylog")
			cfg.WriteFile = filepath.Join(base, "unified.pcap")
			switch failure {
			case "missing-state":
				require.NoError(t, os.Remove(cfg.LIStateFile))
			case "corrupt-state":
				require.NoError(t, os.WriteFile(cfg.LIStateFile, []byte("invalid state"), 0600))
			case "corrupt-journal":
				require.NoError(t, os.Mkdir(cfg.LIDeliveryX2SpoolDir, 0700))
				require.NoError(t, os.WriteFile(filepath.Join(cfg.LIDeliveryX2SpoolDir, ".state"), []byte("invalid journal"), 0600))
			case "invalid-x1":
				cfg.LIX1ListenAddr = "127.0.0.1:0"
			}
			p, err := New(cfg)
			require.Error(t, err)
			require.Nil(t, p, "authentication failure must never expose a processor for target application or Start")
			entries, err := os.ReadDir(base)
			require.NoError(t, err)
			require.Empty(t, entries, "output constructors and unified PCAP must follow authentication")
			require.Zero(t, notifications.Load(), "failed preparation must not send ADMF startup or shutdown")
			if failure != "corrupt-journal" {
				_, err := os.Stat(cfg.LIDeliveryX2SpoolDir)
				require.ErrorIs(t, err, os.ErrNotExist, "invalid state/configuration precedes journal construction")
			}
		})
	}
}

func TestLIConstructorLateFailureReleasesAllPreparedOwners(t *testing.T) {
	cfg := storageKeyStartupConfig(t)
	cfg.EventIngressProfile = "invalid-profile"
	var notifications atomic.Int64
	admf := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { notifications.Add(1) }))
	t.Cleanup(admf.Close)
	cfg.LIADMFEndpoint = admf.URL
	p, err := New(cfg)
	require.ErrorContains(t, err, "event subscription")
	require.Nil(t, p)
	require.Zero(t, notifications.Load())
	state, err := li.OpenStateStore(cfg.LIStateFile, cfg.LIStateKeys)
	require.NoError(t, err)
	require.NoError(t, state.Close())
	filter := filterStorageBackend(t, cfg)
	_, err = filter.Load(cfg.FilterFile)
	require.NoError(t, err)
	require.NoError(t, filter.Close())
	journal, err := delivery.OpenJournal(delivery.JournalConfig{
		Dir: cfg.LIDeliveryX2SpoolDir, KeyFile: cfg.LIDeliveryX2SpoolKeyFile, KeyID: cfg.LIDeliveryX2SpoolKeyID,
		ReadKeys: cfg.LIDeliveryX2SpoolReadKeys, MaxBytes: cfg.LIDeliveryX2SpoolMaxBytes, MaxPending: 8, MaxRecords: 32,
	})
	require.NoError(t, err)
	require.NoError(t, journal.Close())
}

func TestLICompetingPreparationDoesNotReplaceRuntimeOwner(t *testing.T) {
	cfg := storageKeyStartupConfig(t)
	p, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	client, manager, sequencer, direction := liDeliveryClient, liDeliveryMgr, liSequencer, liMediaDirection
	otherCfg := storageKeyStartupConfig(t)
	otherCfg.LIStateFile, otherCfg.LIStateKeys = cfg.LIStateFile, cfg.LIStateKeys
	other, err := New(otherCfg)
	require.Error(t, err)
	require.Nil(t, other)
	require.Same(t, client, liDeliveryClient)
	require.Same(t, manager, liDeliveryMgr)
	require.Same(t, sequencer, liSequencer)
	require.Same(t, direction, liMediaDirection)
	require.NoError(t, p.prepareLIStorage())
	require.NoError(t, p.prepareLIStorage())
	_, err = p.liManager.AdministrativeKeyring()
	require.NoError(t, err)
}

func TestLIConstructorPreservesCallLifecycleSubscription(t *testing.T) {
	p, err := newTestProcessor(t, Config{ListenAddr: "127.0.0.1:0", LIEnabled: true})
	require.NoError(t, err)
	xid, callID := uuid.New(), "retained-call"
	calls := &sync.Map{}
	calls.Store(callID, struct{}{})
	liPinnedCalls.Store(xid, calls)
	t.Cleanup(func() { liPinnedCalls.Delete(xid) })
	require.True(t, p.callLifecycle.Finalize(callID, CallFinalizationManual).Finalized)
	_, retained := calls.Load(callID)
	require.False(t, retained, "late runtime wiring must subscribe to the constructed call lifecycle")
}

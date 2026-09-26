//go:build li

package delivery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestJournalKeyValidationPrecedesFilesystemEffects(t *testing.T) {
	cfg := journalTestConfig(t)
	cfg.Dir = filepath.Join(cfg.Dir, "uncreated", "journal")
	rejected := errors.New("keys rejected")
	calls := 0
	cfg.ValidateKeys = func(ring *securestore.Keyring) error {
		calls++
		require.NotNil(t, ring)
		return rejected
	}
	j, err := OpenJournal(cfg)
	require.ErrorIs(t, err, rejected)
	require.Nil(t, j)
	require.Equal(t, 1, calls)
	_, err = os.Stat(filepath.Dir(cfg.Dir))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestJournalKeyValidationRetainsExactLoadedRing(t *testing.T) {
	cfg := journalTestConfig(t)
	original, err := os.ReadFile(cfg.KeyFile)
	require.NoError(t, err)
	var checked *securestore.Keyring
	calls := 0
	cfg.ValidateKeys = func(ring *securestore.Keyring) error {
		calls++
		checked = ring
		return os.WriteFile(cfg.KeyFile, bytes.Repeat([]byte{0x71}, securestore.KeyBytes), 0600)
	}
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Same(t, checked, j.keys)
	require.NoError(t, j.Close())
	// Reopening with the validated key proves initialization did not reload the
	// replaced file after the callback accepted the original material.
	require.NoError(t, os.WriteFile(cfg.KeyFile, original, 0600))
	cfg.ValidateKeys = nil
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.NoError(t, j.Close())
}

func TestClientKeyValidationPrecedesRecoveryAndPurge(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	journalAdmit(t, j, JournalRecord{Data: []byte("retained product")})
	require.NoError(t, j.Close())
	temporary := filepath.Join(cfg.Dir, "00000000000000000002.x2.tmp")
	require.NoError(t, os.WriteFile(temporary, []byte("incomplete product"), 0600))
	entries, err := os.ReadDir(cfg.Dir)
	require.NoError(t, err)
	before := make(map[string][]byte)
	for _, entry := range entries {
		before[entry.Name()], err = os.ReadFile(filepath.Join(cfg.Dir, entry.Name()))
		require.NoError(t, err)
	}
	rejected := errors.New("keys rejected")
	clientCfg := DefaultClientConfig()
	clientCfg.X2SpoolDir, clientCfg.X2SpoolKeyFile = cfg.Dir, cfg.KeyFile
	clientCfg.X2SpoolMaxBytes, clientCfg.X2SpoolReplayPolicy = cfg.MaxBytes, "purge"
	clientCfg.X2SpoolValidateKeys = func(*securestore.Keyring) error { return rejected }
	c := NewClient(nil, clientCfg)
	require.ErrorIs(t, c.Err(), rejected)
	c.Stop()
	entries, err = os.ReadDir(cfg.Dir)
	require.NoError(t, err)
	require.Len(t, entries, len(before))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(cfg.Dir, entry.Name()))
		require.NoError(t, err)
		require.Equal(t, before[entry.Name()], data, "rejection must precede recovery and purge")
	}
}

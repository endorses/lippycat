//go:build all || cli || processor || tap

package migrate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	store "github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0700))
	return dir
}

func commandKey(t *testing.T) string {
	t.Helper()
	path := filepath.Join(privateDir(t), "key")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{11}, 32), 0600))
	return path
}

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs(append([]string{"filter-store"}, args...))
	err := cmd.Execute()
	return output.String(), err
}

func TestFilterStoreInitializeAndResume(t *testing.T) {
	key := commandKey(t)
	destination := filepath.Join(privateDir(t), "custom.snapshot")
	args := []string{"--init", "--destination", destination, "--key-file", key, "--key-id", "active"}
	output, err := execute(t, args...)
	require.NoError(t, err)
	require.Equal(t, "Encrypted filter store committed.\n", output)
	_, err = execute(t, args...)
	require.ErrorIs(t, err, os.ErrExist)
	require.Equal(t, securestore.NotCommitted, securestore.OutcomeOf(err))
	_, err = execute(t, append(args, "--resume")...)
	require.NoError(t, err)
	p, err := store.NewEncryptedPersistence(securestore.KeyConfig{Active: securestore.KeyRef{ID: "active", File: key}})
	require.NoError(t, err)
	defer func() { require.NoError(t, p.Close()) }()
	filters, err := p.Load(destination)
	require.NoError(t, err)
	require.Empty(t, filters)
}

func TestFilterStoreMigrationRequiresExplicitSourceFormat(t *testing.T) {
	key := commandKey(t)
	dir := privateDir(t)
	source := filepath.Join(dir, "source.unrelated-extension")
	destination := filepath.Join(dir, "destination.yaml")
	yaml := []byte("filters:\n  - id: target\n    type: sip_user\n    pattern: synthetic-sensitive-selector\n    enabled: true\n")
	require.NoError(t, os.WriteFile(source, yaml, 0600))
	base := []string{"--source", source, "--destination", destination, "--key-file", key, "--key-id", "active"}
	_, err := execute(t, base...)
	require.ErrorContains(t, err, "source-format")
	_, err = execute(t, append(base, "--source-format", "encrypted")...)
	require.Error(t, err)
	_, err = os.Stat(destination)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = execute(t, append(base, "--source-format", "yaml")...)
	require.NoError(t, err)
	data, err := os.ReadFile(destination)
	require.NoError(t, err)
	require.Equal(t, "LCS1", string(data[:4]), "mode must not be inferred from the destination extension")
	require.NotContains(t, string(data), "synthetic-sensitive-selector")
	original, err := os.ReadFile(source)
	require.NoError(t, err)
	require.Equal(t, yaml, original)
}

func TestFilterStoreInPlaceMigration(t *testing.T) {
	key := commandKey(t)
	path := filepath.Join(privateDir(t), "filters.yaml")
	require.NoError(t, os.WriteFile(path, []byte("filters: []\n"), 0600))
	args := []string{"--source", path, "--destination", path, "--source-format", "yaml", "--key-file", key, "--key-id", "active"}
	_, err := execute(t, args...)
	require.ErrorContains(t, err, "in-place")
	_, err = execute(t, append(args, "--in-place")...)
	require.NoError(t, err)
	_, err = execute(t, append(args, "--in-place", "--resume")...)
	require.NoError(t, err)
}

func TestFilterStoreRejectsInvalidOptionsAndPrivateSourceWithoutLeakage(t *testing.T) {
	key := commandKey(t)
	for _, args := range [][]string{
		{},
		{"--init", "--destination", "unused"},
		{"--init", "--destination", "unused", "--key-file", key, "--key-id", "active", "--source", "unused"},
		{"--init", "--destination", "unused", "--key-file", key, "--key-id", "active", "--source-format", "yaml"},
		{"--init", "--destination", "unused", "--key-file", key, "--key-id", "active", "--in-place"},
		{"--init", "--destination", "unused", "--key-file", key, "--key-id", "active", "--read-key", "invalid"},
	} {
		_, err := execute(t, args...)
		require.Error(t, err)
		require.Equal(t, securestore.NotCommitted, securestore.OutcomeOf(err))
	}
	dir := privateDir(t)
	source, destination := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
	require.NoError(t, os.WriteFile(source, []byte("filters:\n  - id: sensitive-marker\n    type: unknown\n    pattern: private-secret\n"), 0600))
	output, err := execute(t, "--source", source, "--source-format", "yaml", "--destination", destination, "--key-file", key, "--key-id", "active")
	require.Error(t, err)
	require.NotContains(t, err.Error()+output, "sensitive-marker")
	require.NotContains(t, err.Error()+output, "private-secret")
	_, err = os.Stat(destination)
	require.ErrorIs(t, err, os.ErrNotExist)
}

type failedOutput struct{ err error }

func (w failedOutput) Write([]byte) (int, error) { return 0, w.err }

func TestFilterStoreReportsCommittedOutputFailure(t *testing.T) {
	key := commandKey(t)
	destination := filepath.Join(privateDir(t), "filters.enc")
	cmd := NewCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	failed := errors.New("output unavailable")
	cmd.SetOut(failedOutput{err: failed})
	cmd.SetArgs([]string{"filter-store", "--init", "--destination", destination, "--key-file", key, "--key-id", "active"})
	err := cmd.Execute()
	require.ErrorIs(t, err, failed)
	require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
	_, err = os.Stat(destination)
	require.NoError(t, err)
	uncertain := filterStoreError(securestore.Uncertain, failed)
	require.Equal(t, securestore.Uncertain, securestore.OutcomeOf(uncertain))
	require.ErrorContains(t, uncertain, "keep the node stopped")
}

//go:build (all || cli || processor || tap) && li

package migrate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func executeState(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs(append([]string{"li-state"}, args...))
	err := cmd.Execute()
	return output.String(), err
}

func TestLIStateCommandInitializeAndResume(t *testing.T) {
	key := commandKey(t)
	destination := filepath.Join(privateDir(t), "state.enc")
	pin := filepath.Join(filepath.Dir(destination), "existing-radius")
	raw := []byte("allocator bytes must be retained")
	require.NoError(t, os.WriteFile(pin, raw, 0600))
	args := []string{"--init", "--destination", destination, "--key-file", key, "--key-id", "state-active", "--radius-state-file", pin}
	output, err := executeState(t, args...)
	require.NoError(t, err)
	require.Equal(t, "Encrypted LI state store committed.\n", output)
	_, err = executeState(t, args...)
	require.ErrorIs(t, err, os.ErrExist)
	require.Equal(t, securestore.NotCommitted, securestore.OutcomeOf(err))
	_, err = executeState(t, append(args, "--resume")...)
	require.NoError(t, err)
	store, err := li.OpenStateStore(destination, securestore.KeyConfig{Active: securestore.KeyRef{ID: "state-active", File: key}})
	require.NoError(t, err)
	snapshot, err := store.Load()
	require.NoError(t, err)
	require.NoError(t, store.Close())
	require.Empty(t, snapshot.Tasks)
	require.Equal(t, pin, snapshot.RADIUSCorrelationStateFile)
	after, err := os.ReadFile(pin)
	require.NoError(t, err)
	require.Equal(t, raw, after)
}

func TestLIStateCommandExplicitJSONMigrationAndInPlace(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-path", true: "in-place"}[inPlace], func(t *testing.T) {
			key := commandKey(t)
			dir := privateDir(t)
			source, destination := filepath.Join(dir, "source.unknown"), filepath.Join(dir, "destination.json")
			raw := []byte(`{"version":1,"written_at":"2026-01-02T03:04:05Z","tasks":[],"destinations":[]}`)
			require.NoError(t, os.WriteFile(source, raw, 0600))
			if inPlace {
				destination = source
			}
			args := []string{"--source", source, "--destination", destination, "--key-file", key, "--key-id", "state-active"}
			_, err := executeState(t, args...)
			require.ErrorContains(t, err, "source-format=json")
			args = append(args, "--source-format=json")
			if inPlace {
				args = append(args, "--in-place")
			}
			_, err = executeState(t, args...)
			require.NoError(t, err)
			_, err = executeState(t, append(args, "--resume")...)
			require.NoError(t, err)
			store, err := li.OpenStateStore(destination, securestore.KeyConfig{Active: securestore.KeyRef{ID: "state-active", File: key}})
			require.NoError(t, err)
			snapshot, err := store.Load()
			require.NoError(t, err)
			require.NoError(t, store.Close())
			require.Equal(t, source+".radius-correlation", snapshot.RADIUSCorrelationStateFile)
			if !inPlace {
				retained, err := os.ReadFile(source)
				require.NoError(t, err)
				require.Equal(t, raw, retained)
			}
		})
	}
}

func TestLIStateCommandRejectsAmbiguousOptions(t *testing.T) {
	for _, extra := range [][]string{
		{}, {"--source-format=json"}, {"--source=source.json"}, {"--source=source.json", "--source-format=yaml"},
		{"--init", "--source=source.json"}, {"--init", "--source-format=json"}, {"--init", "--in-place"}, {"--init", "--read-key=sensitive-marker"},
	} {
		_, err := executeState(t, append([]string{"--destination=/unused/state.enc", "--key-file=/unused/key", "--key-id=state"}, extra...)...)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "sensitive-marker")
	}
}

func TestLIStateCommandIsRegistered(t *testing.T) {
	root := NewCommand()
	cmd, _, err := root.Find([]string{"li-state"})
	require.NoError(t, err)
	require.Equal(t, "li-state", cmd.Name())
	for _, name := range []string{"source", "source-format", "destination", "init", "in-place", "resume", "key-file", "key-id", "read-key", "radius-state-file"} {
		require.NotNil(t, cmd.Flags().Lookup(name), name)
	}
}

func TestLIStateCommandReportsCommittedOutputFailure(t *testing.T) {
	key := commandKey(t)
	destination := filepath.Join(privateDir(t), "state.enc")
	cmd := NewCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	failure := errors.New("output unavailable")
	cmd.SetOut(failedOutput{err: failure})
	cmd.SetArgs([]string{"li-state", "--init", "--destination", destination, "--key-file", key, "--key-id", "active"})
	err := cmd.Execute()
	require.ErrorIs(t, err, failure)
	require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
	_, err = os.Stat(destination)
	require.NoError(t, err)
	uncertain := liStateStoreError(securestore.Uncertain, failure)
	require.Equal(t, securestore.Uncertain, securestore.OutcomeOf(uncertain))
	require.ErrorContains(t, uncertain, "keep the node stopped")
}

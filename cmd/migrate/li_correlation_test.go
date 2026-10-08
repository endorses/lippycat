//go:build (all || cli || processor || tap) && li

package migrate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func executeCorrelation(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs(append([]string{"li-correlation"}, args...))
	err := cmd.Execute()
	return output.String(), err
}

func TestLICorrelationCommandInitializeAndRejectOverwrite(t *testing.T) {
	key := commandKey(t)
	path := filepath.Join(privateDir(t), "correlation.enc")
	args := []string{"--output", path, "--key-file", key, "--key-id", "correlation-1", "--max-records", "10"}
	output, err := executeCorrelation(t, args...)
	require.NoError(t, err)
	require.Equal(t, "Encrypted LI call correlation store committed.\n", output)
	store, err := li.OpenCallCorrelationStore(path, securestore.KeyConfig{Active: securestore.KeyRef{ID: "correlation-1", File: key}}, 10)
	require.NoError(t, err)
	records, err := store.Load()
	require.NoError(t, err)
	require.Empty(t, records)
	require.NoError(t, store.Close())
	original, err := os.ReadFile(path)
	require.NoError(t, err)
	_, err = executeCorrelation(t, args...)
	require.ErrorIs(t, err, os.ErrExist)
	require.Equal(t, securestore.NotCommitted, securestore.OutcomeOf(err))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, after)
}

func TestLICorrelationCommandRotationPreservesDecisionsAndResume(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-path", true: "in-place"}[inPlace], func(t *testing.T) {
			oldKey, newKey := rotationCommandKey(t, 91), rotationCommandKey(t, 92)
			dir := privateDir(t)
			source, destination := filepath.Join(dir, "original.enc"), filepath.Join(dir, "rotated.enc")
			_, err := executeCorrelation(t, "--output", source, "--key-file", oldKey, "--key-id", "old", "--max-records", "10")
			require.NoError(t, err)
			store, err := li.OpenCallCorrelationStore(source, securestore.KeyConfig{Active: securestore.KeyRef{ID: "old", File: oldKey}}, 10)
			require.NoError(t, err)
			retained := []li.StoredCallCorrelation{{CallID: "invented-call", GroupID: 123, LastActivity: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), CommonTasks: []li.CallCorrelationTask{{XID: uuid.New(), Generation: 1}}}}
			outcome, err := store.Save(retained)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, outcome)
			require.NoError(t, store.Close())
			original, err := os.ReadFile(source)
			require.NoError(t, err)
			if inPlace {
				destination = source
			}
			args := []string{"rotate", "--source", source, "--destination", destination, "--source-key-id", "old", "--source-key-file", oldKey, "--key-id", "new", "--key-file", newKey, "--max-records", "10"}
			if inPlace {
				args = append(args, "--in-place")
			}
			output, err := executeCorrelation(t, args...)
			require.NoError(t, err)
			require.Contains(t, output, "Encrypted LI call correlation store rotation committed.")
			require.Contains(t, output, "Complete: true; resume required: false.")
			_, err = executeCorrelation(t, append(args, "--resume")...)
			require.NoError(t, err)
			store, err = li.OpenCallCorrelationStore(destination, securestore.KeyConfig{Active: securestore.KeyRef{ID: "new", File: newKey}}, 10)
			require.NoError(t, err)
			records, err := store.Load()
			require.NoError(t, err)
			require.Equal(t, retained, records)
			require.NoError(t, store.Close())
			if !inPlace {
				after, err := os.ReadFile(source)
				require.NoError(t, err)
				require.Equal(t, original, after)
			}
		})
	}
}

func TestLICorrelationCommandRejectsInvalidOptionsBeforeEffects(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--output=unused"}, {"--output=unused", "--key-file=absent"},
		{"--output=unused", "--key-file=absent", "--key-id=key", "--max-records=0"},
		{"--output=unused", "--key-file=absent", "--key-id=key", "--max-records=1000001"},
		{"rotate"}, {"rotate", "--source=absent", "--destination=unused", "--key-file=absent", "--key-id=new"},
		{"rotate", "--source=absent", "--destination=unused", "--source-key-id=old", "--source-key-file=absent", "--key-file=absent", "--key-id=new", "--max-working-bytes=0"},
		{"rotate", "--source=absent", "--destination=unused", "--source-key-id=old", "--source-key-file=absent", "--key-file=absent", "--key-id=new", "--read-key=sensitive-invalid-reference"},
	} {
		_, err := executeCorrelation(t, args...)
		require.Error(t, err)
		require.NotContains(t, err.Error(), "sensitive-invalid-reference")
	}
}

func TestLICorrelationCommandReportsCommittedOutputFailure(t *testing.T) {
	key := commandKey(t)
	path := filepath.Join(privateDir(t), "correlation.enc")
	cmd := NewCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	failure := errors.New("output unavailable")
	cmd.SetOut(failedOutput{err: failure})
	cmd.SetArgs([]string{"li-correlation", "--output", path, "--key-file", key, "--key-id", "active"})
	err := cmd.Execute()
	require.ErrorIs(t, err, failure)
	require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
	_, err = os.Stat(path)
	require.NoError(t, err)
	for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain, securestore.Committed} {
		err := liCorrelationStoreError(outcome, failure)
		require.Equal(t, outcome, securestore.OutcomeOf(err))
		require.ErrorIs(t, err, failure)
		if outcome == securestore.Uncertain {
			require.ErrorContains(t, err, "keep the node stopped")
		}
	}
}

func TestLICorrelationCommandRegistered(t *testing.T) {
	root := NewCommand()
	cmd, _, err := root.Find([]string{"li-correlation"})
	require.NoError(t, err)
	require.Equal(t, "li-correlation", cmd.Name())
	for _, name := range []string{"output", "key-file", "key-id", "max-records"} {
		require.NotNil(t, cmd.Flags().Lookup(name), name)
	}
	cmd, _, err = root.Find([]string{"li-correlation", "rotate"})
	require.NoError(t, err)
	require.Equal(t, "rotate", cmd.Name())
	for _, name := range []string{"source", "destination", "source-key-id", "source-key-file", "key-file", "key-id", "read-key", "max-records", "in-place", "resume", "max-working-bytes"} {
		require.NotNil(t, cmd.Flags().Lookup(name), name)
	}
}

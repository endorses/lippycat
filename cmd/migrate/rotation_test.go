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

func rotationCommandKey(t *testing.T, fill byte) string {
	t.Helper()
	path := filepath.Join(privateDir(t), "key")
	require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{fill}, securestore.KeyBytes), 0600))
	return path
}

func TestFilterStoreCommandEncryptedRotationAndResume(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-basename", true: "in-place"}[inPlace], func(t *testing.T) {
			oldKey, newKey := rotationCommandKey(t, 51), rotationCommandKey(t, 52)
			dir := privateDir(t)
			source, destination := filepath.Join(dir, "filters.enc"), filepath.Join(dir, "rotated.enc")
			_, err := execute(t, "--init", "--destination", source, "--key-id", "old", "--key-file", oldKey)
			require.NoError(t, err)
			original, err := os.ReadFile(source)
			require.NoError(t, err)
			if inPlace {
				destination = source
			}
			args := []string{"--source-format=encrypted", "--source", source, "--destination", destination,
				"--source-key-id=old", "--source-key-file", oldKey, "--key-id=new", "--key-file", newKey}
			if inPlace {
				args = append(args, "--in-place")
			}
			output, err := execute(t, args...)
			require.NoError(t, err)
			require.Contains(t, output, "Encrypted filter store rotation committed.")
			require.Contains(t, output, "Complete: true; resume required: false.")
			require.Contains(t, output, "Source active key: old; output active key: new.")
			require.Contains(t, output, "External backups are outside this inventory.")
			_, err = execute(t, append(args, "--resume")...)
			require.NoError(t, err)
			p, err := store.NewEncryptedPersistence(securestore.KeyConfig{Active: securestore.KeyRef{ID: "new", File: newKey}})
			require.NoError(t, err)
			filters, err := p.Load(destination)
			require.NoError(t, err)
			require.Empty(t, filters)
			require.NoError(t, p.Close())
			if !inPlace {
				retained, err := os.ReadFile(source)
				require.NoError(t, err)
				require.Equal(t, original, retained)
			}
		})
	}
}

func TestRotationFlagsRequireExplicitEncryptedModeBeforeEffects(t *testing.T) {
	for _, extra := range [][]string{
		{"--source-key-id=old"}, {"--source-key-file="}, {"--max-working-bytes=1"},
	} {
		for _, mode := range [][]string{{"--init"}, {"--source=absent", "--source-format=yaml"}} {
			args := append([]string{"--destination=unused", "--key-id=new", "--key-file=absent"}, mode...)
			_, err := execute(t, append(args, extra...)...)
			require.ErrorContains(t, err, "require --source-format=encrypted")
		}
	}
	base := []string{"--source-format=encrypted", "--source=absent", "--destination=unused", "--key-id=new", "--key-file=absent"}
	for _, extra := range [][]string{nil, {"--source-key-id=old"}, {"--source-key-file=absent"}} {
		_, err := execute(t, append(append([]string{}, base...), extra...)...)
		require.ErrorContains(t, err, "requires --source-key-id and --source-key-file")
	}
	for _, value := range []string{"0", "-1"} {
		args := append(append([]string{}, base...), "--source-key-id=old", "--source-key-file=absent", "--max-working-bytes="+value)
		_, err := execute(t, args...)
		require.ErrorContains(t, err, "positive --max-working-bytes")
	}
}

func TestRotationReportPreservesSnapshotAndAuxiliaryOutcomes(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain, securestore.Committed} {
		cmd := NewCommand()
		var output bytes.Buffer
		cmd.SetOut(&output)
		aux := &securestore.UsageError{ReservationOutcome: securestore.Uncertain, Err: errors.New("injected usage fault")}
		result := securestore.SnapshotRotationResult{Outcome: outcome, ResumeRequired: true}
		err := finishSnapshotRotation(cmd, "filter store", result, aux)
		require.Equal(t, outcome, securestore.OutcomeOf(err))
		require.ErrorContains(t, err, "keep the node stopped and resume")
		var usage *securestore.UsageError
		require.ErrorAs(t, err, &usage)
		require.Equal(t, securestore.Uncertain, usage.ReservationOutcome)
		if outcome != securestore.NotCommitted {
			require.Contains(t, output.String(), "resume required: true")
		}
		if outcome == securestore.Committed {
			require.Contains(t, err.Error(), "committed")
		}
	}
	cmd := NewCommand()
	failed := errors.New("output unavailable")
	cmd.SetOut(failedOutput{err: failed})
	err := finishSnapshotRotation(cmd, "filter store", securestore.SnapshotRotationResult{Outcome: securestore.Committed, Complete: true}, nil)
	require.ErrorIs(t, err, failed)
	require.Equal(t, securestore.Committed, securestore.OutcomeOf(err))
}

func TestRotationReadKeysBelongToSourceAndCannotReuseNewMaterial(t *testing.T) {
	oldKey, newKey := rotationCommandKey(t, 61), rotationCommandKey(t, 62)
	dir := privateDir(t)
	source, destination := filepath.Join(dir, "source.enc"), filepath.Join(dir, "dest.enc")
	_, err := execute(t, "--init", "--destination", source, "--key-id=old", "--key-file", oldKey)
	require.NoError(t, err)
	_, err = execute(t, "--source-format=encrypted", "--source", source, "--destination", destination,
		"--source-key-id=old", "--source-key-file", oldKey, "--key-id=new", "--key-file", newKey, "--read-key=prior="+newKey)
	require.Error(t, err)
	require.Equal(t, securestore.NotCommitted, securestore.OutcomeOf(err))
	_, err = os.Stat(destination)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRotationCommandReadsSourceWithPriorKey(t *testing.T) {
	readKey, activeKey, newKey := rotationCommandKey(t, 81), rotationCommandKey(t, 82), rotationCommandKey(t, 83)
	dir := privateDir(t)
	source, destination := filepath.Join(dir, "source.enc"), filepath.Join(dir, "dest.enc")
	_, err := execute(t, "--init", "--destination", source, "--key-id=read-old", "--key-file", readKey)
	require.NoError(t, err)
	// Model a valid source ring whose snapshot still selects its prior read key;
	// the active ledger independently authenticates the same store incarnation.
	d, err := securestore.OpenDir(dir)
	require.NoError(t, err)
	readRing, err := securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: "read-old", File: readKey}})
	require.NoError(t, err)
	u, err := securestore.OpenUsage(d, readRing, [16]byte{})
	require.NoError(t, err)
	storeID := u.StoreID()
	require.NoError(t, u.Close())
	activeRing, err := securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: "source-active", File: activeKey}})
	require.NoError(t, err)
	outcome, err := securestore.InitializeUsage(d, activeRing, storeID)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, outcome)
	require.NoError(t, d.Close())
	output, err := execute(t, "--source-format=encrypted", "--source", source, "--destination", destination,
		"--source-key-id=source-active", "--source-key-file", activeKey, "--read-key=read-old="+readKey, "--key-id=new", "--key-file", newKey)
	require.NoError(t, err)
	require.Contains(t, output, "rotation committed")
}

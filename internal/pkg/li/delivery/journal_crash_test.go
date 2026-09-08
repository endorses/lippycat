//go:build li

package delivery

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestJournalENOSPCPreservesExistingAndUncertainReservation(t *testing.T) {
	cfg := journalTestConfig(t)
	cfg.PreserveSequences = true
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	xid := uuid.New()
	journalAdmit(t, j, JournalRecord{XID: xid, Data: journalSequencePDU(t, xid, 1)})
	before := j.Stats().Bytes
	write := j.writeFile
	j.writeFile = func(path string, data []byte) error {
		if strings.HasSuffix(path, ".seq") {
			return syscall.ENOSPC
		}
		return write(path, data)
	}
	done := make(chan error, 1)
	_, err = j.Admit(JournalRecord{XID: xid, Data: journalSequencePDU(t, xid, 2)}, func(_ uint64, err error) { done <- err })
	require.NoError(t, err)
	require.ErrorIs(t, <-done, syscall.ENOSPC)
	require.Greater(t, j.Stats().Bytes, before)
	require.Equal(t, 1, j.Stats().Persisted)
	require.Contains(t, j.Stats().LastError, "no space left")
	_, err = j.Admit(JournalRecord{}, nil)
	require.ErrorIs(t, err, ErrJournalClosed)
	require.Error(t, j.Close())
	// The uncertain new product may be present; neither it nor the old durable
	// record was deleted when updating its sequence checkpoint failed.
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, 2, j.Stats().Held)
	require.NoError(t, j.Close())
}

func TestJournalProcessCrashBeforeAndAfterSync(t *testing.T) {
	for _, phase := range []string{"before_sync", "after_product_sync", "after_commit"} {
		t.Run(phase, func(t *testing.T) {
			cfg := journalTestConfig(t)
			cfg.PreserveSequences = true
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			journalAdmit(t, j, JournalRecord{Data: journalSequencePDU(t, uuid.New(), 1)})
			require.NoError(t, j.Close())
			cmd := exec.Command(os.Args[0], "-test.run=^TestJournalCrashHelper$")
			cmd.Env = append(os.Environ(), "GORACE=atexit_sleep_ms=0", "LC_JOURNAL_CRASH_PHASE="+phase, "LC_JOURNAL_CRASH_DIR="+cfg.Dir, "LC_JOURNAL_CRASH_KEY="+cfg.KeyFile)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, string(output))
			j, err = OpenJournal(cfg)
			require.NoError(t, err)
			want := 2
			if phase == "before_sync" {
				want = 1
			}
			require.Equal(t, want, j.Stats().Held)
			require.NoError(t, j.Close())
		})
	}
}
func TestJournalCrashHelper(t *testing.T) {
	phase := os.Getenv("LC_JOURNAL_CRASH_PHASE")
	if phase == "" {
		t.Skip("subprocess helper")
	}
	cfg := JournalConfig{Dir: os.Getenv("LC_JOURNAL_CRASH_DIR"), KeyFile: os.Getenv("LC_JOURNAL_CRASH_KEY"), MaxBytes: 1 << 20, MaxPending: 8, MaxRecords: 32, PreserveSequences: true}
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	write := j.writeFile
	j.writeFile = func(path string, data []byte) error {
		if strings.HasSuffix(path, ".x2") && phase == "before_sync" {
			if err := os.WriteFile(path+".tmp", data[:5], 0600); err != nil {
				return err
			}
			os.Exit(0)
		}
		err := write(path, data)
		if err == nil && strings.HasSuffix(path, ".x2") && phase == "after_product_sync" {
			os.Exit(0)
		}
		return err
	}
	journalAdmit(t, j, JournalRecord{Data: journalSequencePDU(t, uuid.New(), 2)})
	if phase == "after_commit" {
		os.Exit(0)
	}
	t.Fatal(errors.New("crash hook not reached: " + filepath.Base(cfg.Dir)))
}

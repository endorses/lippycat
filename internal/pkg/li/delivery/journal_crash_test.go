//go:build li

package delivery

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestJournalRecoveryRepairsCheckpointsBeforePurge(t *testing.T) {
	for _, preserve := range []bool{false, true} {
		t.Run(fmt.Sprint(preserve), func(t *testing.T) {
			cfg := journalTestConfig(t)
			cfg.PreserveSequences = preserve
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			xid := uuid.New()
			// Leave a real durable product, then fail the first checkpoint write.
			// This is the same storage state as a crash after product sync.
			write := j.writeFile
			j.writeFile = func(path string, data []byte) error {
				if !strings.HasSuffix(path, ".x2") {
					return syscall.ENOSPC
				}
				return write(path, data)
			}
			done := make(chan error, 1)
			id, err := j.Admit(JournalRecord{XID: xid, Data: journalSequencePDU(t, xid, 9)}, func(_ uint64, err error) { done <- err })
			require.NoError(t, err)
			require.ErrorIs(t, <-done, ErrPersistenceUncertain)
			require.Error(t, j.Close())
			if preserve {
				// The surviving product fits, but repairing its missing sequence
				// checkpoint must not consume the fault/scratch reservation.
				tight := cfg
				tight.MaxBytes = j.faultReserve + j.diskSize(1)
				_, err = OpenJournal(tight)
				require.ErrorIs(t, err, ErrJournalFull)
				_, err = os.Stat(j.path(id))
				require.NoError(t, err, "failed recovery must preserve product")
			}

			// Successful reopen also verifies failed repair releases the lock.
			j, err = OpenJournal(cfg)
			require.NoError(t, err)
			require.NoError(t, j.Purge(id))
			require.NoError(t, j.Close())
			j, err = OpenJournal(cfg)
			require.NoError(t, err)
			defer func() { require.NoError(t, j.Close()) }()
			if preserve {
				s := x2x3.NewSequencer(10)
				require.NoError(t, j.VisitSequences(s.RestoreCheckpoint))
				next, err := s.Next(x2x3.SequenceContext{PDUType: x2x3.PDUTypeX2, XID: xid, CorrelationID: 42})
				require.NoError(t, err)
				require.Equal(t, uint32(10), next)
			}
			nextID := journalAdmit(t, j, JournalRecord{XID: xid, Data: journalSequencePDU(t, xid, 10)})
			require.Greater(t, nextID, id)
		})
	}
}

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

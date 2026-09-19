package eventspool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type faultFile struct {
	spoolFile
	write func([]byte) (int, error)
	sync  func() error
}

func TestRetiredRecordsRetryCleanupAfterJournalCleanupFailure(t *testing.T) {
	for _, operation := range []string{"ack", "enqueue", "flush"} {
		t.Run(operation, func(t *testing.T) {
			now := time.Unix(100, 0)
			s, err := Open(Config{Directory: t.TempDir(), CheckpointEvery: 1, MaxAge: time.Second, Clock: func() time.Time { return now }})
			require.NoError(t, err)
			defer s.Close()
			_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
			require.NoError(t, err)
			victim := s.records[0].path
			if operation == "flush" {
				_, err = s.RetainLosses(ownRangeLoss(batch("node", "session", 2, 2, 2)))
				require.NoError(t, err)
			}
			oldJournal := journalPath(s.config.Directory, s.generation)
			fs := defaultFS()
			fs.remove = func(path string) error {
				if path == oldJournal || path == victim {
					return errors.New("injected cleanup failure")
				}
				return os.Remove(path)
			}
			s.fs = fs
			now = now.Add(2 * time.Second)
			switch operation {
			case "ack":
				err = s.Ack("node", "session", 1)
			case "enqueue":
				var result EnqueueResult
				result, err = s.Enqueue(batch("node", "session", 2, 2, 2))
				require.True(t, result.Stored)
			case "flush":
				var result EnqueueResult
				result, err = s.FlushPendingLosses("node", "session", 2, 1)
				require.True(t, result.Stored)
			}
			var cleanupErr *CleanupError
			require.ErrorAs(t, err, &cleanupErr)
			require.False(t, s.Contains("node", "session", 1))
			require.FileExists(t, victim)
			s.fs = defaultFS()
			require.NoError(t, s.Ack("node", "session", 1))
			require.NoFileExists(t, victim, "retired records must be registered for retry even when journal cleanup fails first")
			require.NoFileExists(t, oldJournal)
			require.Equal(t, s.Bytes(), s.PhysicalBytes())
			require.Empty(t, s.Status().CleanupError)
		})
	}
}

func TestRecoverySyncsVisibleJournalBeforeRetiringRecords(t *testing.T) {
	for _, boundary := range []string{"journal", "directory"} {
		t.Run(boundary, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(Config{Directory: dir})
			require.NoError(t, err)
			defer s.Close()
			_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
			require.NoError(t, err)
			victim := s.records[0].path
			journal := journalPath(dir, s.generation)
			beforeACK, err := os.ReadFile(journal)
			require.NoError(t, err)
			fs := defaultFS()
			open := fs.openFile
			fs.openFile = func(path string, flags int, mode os.FileMode) (spoolFile, error) {
				f, err := open(path, flags, mode)
				if err != nil {
					return nil, err
				}
				return &faultFile{spoolFile: f, sync: func() error { return errors.New("injected journal sync failure") }}, nil
			}
			s.fs = fs
			require.ErrorIs(t, s.Ack("node", "session", 1), ErrDurabilityUncertain)
			require.FileExists(t, victim)
			if boundary == "directory" {
				fs = defaultFS()
				fs.syncDir = func(string) error { return errors.New("injected recovery directory sync failure") }
				s.fs = fs
			}
			require.ErrorIs(t, s.Recover(), ErrDurabilityUncertain)
			require.True(t, s.Status().DurabilityUncertain)
			require.FileExists(t, victim, "failed recovery must preserve records required by the old durable journal")
			if boundary == "journal" {
				// A second crash can lose the still-unsynced ACK transaction.
				require.NoError(t, os.WriteFile(journal, beforeACK, 0o600))
			}
			fs = defaultFS()
			open = fs.openFile
			journalSynced, directorySynced := false, false
			fs.openFile = func(path string, flags int, mode os.FileMode) (spoolFile, error) {
				f, err := open(path, flags, mode)
				if err != nil {
					return nil, err
				}
				return &faultFile{spoolFile: f, sync: func() error {
					err := f.Sync()
					journalSynced = err == nil
					return err
				}}, nil
			}
			fs.syncDir = func(path string) error {
				require.True(t, journalSynced, "recovery must sync journal contents before the directory")
				err := syncDirectory(path)
				directorySynced = err == nil
				return err
			}
			fs.remove = func(path string) error {
				require.True(t, journalSynced && directorySynced, "cleanup must follow both recovery durability barriers")
				return os.Remove(path)
			}
			s.fs = fs
			require.NoError(t, s.Recover())
			if boundary == "journal" {
				require.True(t, s.Contains("node", "session", 1))
			} else {
				require.False(t, s.HasPending())
				require.NoFileExists(t, victim)
			}
		})
	}
}

func TestRecoverySyncsVisibleCheckpointBeforeRetiringJournal(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	defer s.Close()
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	oldJournal := journalPath(dir, s.generation)
	oldManifest, err := os.ReadFile(filepath.Join(dir, manifestFileName))
	require.NoError(t, err)
	fs := defaultFS()
	rename := fs.rename
	manifestRenamed := false
	fs.rename = func(from, to string) error {
		err := rename(from, to)
		if err == nil && filepath.Base(to) == manifestFileName {
			manifestRenamed = true
		}
		return err
	}
	fs.syncDir = func(path string) error {
		if manifestRenamed {
			return errors.New("injected directory sync failure")
		}
		return syncDirectory(path)
	}
	s.fs = fs
	require.ErrorIs(t, s.rotateCheckpoint(), ErrDurabilityUncertain)
	require.ErrorIs(t, s.Recover(), ErrDurabilityUncertain)
	require.FileExists(t, oldJournal, "the visible replacement checkpoint is not yet durable")
	// Model losing the unsynced checkpoint rename at a second crash.
	require.NoError(t, os.WriteFile(filepath.Join(dir, manifestFileName), oldManifest, 0o600))
	s.fs = defaultFS()
	require.NoError(t, s.Recover())
	require.True(t, s.Contains("node", "session", 1))
}

func (f *faultFile) Write(p []byte) (int, error) {
	if f.write != nil {
		return f.write(p)
	}
	return f.spoolFile.Write(p)
}
func (f *faultFile) Sync() error {
	if f.sync != nil {
		return f.sync()
	}
	return f.spoolFile.Sync()
}

func TestDrainedReopenPreservesIdentityAndHighWater(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("node", "session", 7, 40, 44))
	require.NoError(t, err)
	require.NoError(t, s.Ack("node", "session", 7))
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	source, session, event, batchSequence, err := reopened.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, "node", source)
	require.Equal(t, "session", session)
	require.Equal(t, uint64(44), event)
	require.Equal(t, uint64(7), batchSequence)
	require.NoError(t, reopened.Close())
}

func TestRetainLossesIsImmediatelyDurable(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	loss := &eventsv1.EventLoss{Kind: eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT, Count: 2, SourceNodeId: "node", ProducerSessionId: "session", EventSequenceRanges: []*eventsv1.SequenceRange{{First: 8, Last: 9}}}
	result, err := s.RetainLosses([]*eventsv1.EventLoss{loss})
	require.NoError(t, err)
	require.True(t, result.Committed)
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.True(t, reopened.HasPendingLosses())
	_, _, event, _, err := reopened.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, uint64(9), event)
	require.NoError(t, reopened.Close())
}

func TestManifestCheckpointFailureMatrixAfterCommittedTransaction(t *testing.T) {
	for _, kind := range []string{"create", "write", "fsync", "rename", "dirsync"} {
		t.Run(kind, func(t *testing.T) {
			s, err := Open(Config{Directory: t.TempDir(), CheckpointEvery: 1})
			require.NoError(t, err)
			fs := defaultFS()
			originalCreate := fs.createTemp
			fs.createTemp = func(dir, pattern string) (spoolFile, error) {
				if strings.HasPrefix(pattern, ".manifest-") {
					if kind == "create" {
						return nil, errors.New("injected manifest create")
					}
					f, e := originalCreate(dir, pattern)
					if e != nil {
						return nil, e
					}
					if kind == "write" {
						return &faultFile{spoolFile: f, write: func([]byte) (int, error) { return 0, errors.New("injected manifest write") }}, nil
					}
					if kind == "fsync" {
						return &faultFile{spoolFile: f, sync: func() error { return errors.New("injected manifest fsync") }}, nil
					}
					return f, nil
				}
				return originalCreate(dir, pattern)
			}
			originalRename := fs.rename
			fs.rename = func(from, to string) error {
				if kind == "rename" && filepath.Base(to) == manifestFileName {
					return errors.New("injected manifest rename")
				}
				return originalRename(from, to)
			}
			syncs := 0
			fs.syncDir = func(path string) error {
				syncs++
				if kind == "dirsync" && syncs == 3 {
					return errors.New("injected manifest dirsync")
				}
				return syncDirectory(path)
			}
			s.fs = fs
			result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
			require.Error(t, err)
			require.True(t, result.Stored)
			status := s.Status()
			if kind == "dirsync" {
				require.True(t, status.DurabilityUncertain)
				require.False(t, status.CheckpointRequired)
				require.ErrorIs(t, err, ErrDurabilityUncertain)
			} else {
				require.False(t, status.DurabilityUncertain)
				require.True(t, status.CheckpointRequired)
				require.ErrorIs(t, err, ErrCheckpointRequired)
			}
			require.False(t, s.Contains("node", "session", 1), "barrier must suspend sends")
			_, _, _, _, stateErr := s.RecoveryState()
			require.Error(t, stateErr)
			s.fs = defaultFS()
			require.NoError(t, s.Recover())
			require.Len(t, s.Batches(), 1)
			require.True(t, s.Contains("node", "session", 1))
			require.NoError(t, s.Close())
		})
	}
}

func TestCheckpointFailureBlocksFurtherWorkUntilRecovery(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir, CheckpointEvery: 1})
	require.NoError(t, err)

	fs := defaultFS()
	originalCreate := fs.createTemp
	fs.createTemp = func(directory, pattern string) (spoolFile, error) {
		if strings.HasPrefix(pattern, ".manifest-") {
			return nil, errors.New("injected persistent checkpoint failure")
		}
		return originalCreate(directory, pattern)
	}
	s.fs = fs
	result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
	require.ErrorIs(t, err, ErrCheckpointRequired)
	require.True(t, result.Stored)
	require.True(t, s.Status().CheckpointRequired)
	require.True(t, s.HasPending())
	_, err = s.BatchesAfter("node", "session", 0, 1)
	require.ErrorIs(t, err, ErrCheckpointRequired)

	journalInfo, err := os.Stat(filepath.Join(dir, journalFileName))
	require.NoError(t, err)
	result, err = s.Enqueue(batch("node", "session", 2, 2, 2))
	require.ErrorIs(t, err, ErrCheckpointRequired)
	require.False(t, result.Stored)
	afterInfo, err := os.Stat(filepath.Join(dir, journalFileName))
	require.NoError(t, err)
	require.Equal(t, journalInfo.Size(), afterInfo.Size(), "blocked mutations must not grow replay work")

	s.fs = defaultFS()
	require.NoError(t, s.Recover())
	require.False(t, s.Status().CheckpointRequired)
	result, err = s.Enqueue(batch("node", "session", 2, 2, 2))
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.NoError(t, s.Close())
}

func TestCleanupENOENTReconcilesPhysicalBytes(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)

	fs := defaultFS()
	fs.remove = func(path string) error {
		if filepath.Ext(path) == recordExtension {
			if err := os.Remove(path); err != nil {
				return err
			}
			return errors.New("injected ambiguous unlink result")
		}
		return os.Remove(path)
	}
	s.fs = fs
	err = s.Ack("node", "session", 1)
	require.Error(t, err)
	require.Positive(t, s.PhysicalBytes(), "ambiguous cleanup remains accounted until reconciliation")

	s.fs = defaultFS()
	// The next safe mutation point retries cleanup. ENOENT must reconcile the
	// physical counter instead of merely forgetting the failed orphan.
	require.NoError(t, s.Ack("node", "session", 1))
	require.Zero(t, s.PhysicalBytes())
	require.Empty(t, s.orphanFailures)
	require.NoError(t, s.Close())
}

func TestJournalWriteAndSyncFailureRecoveryOutcomes(t *testing.T) {
	for _, kind := range []string{"partial_write", "sync"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(Config{Directory: dir})
			require.NoError(t, err)
			fs := defaultFS()
			originalOpen := fs.openFile
			fs.openFile = func(path string, flags int, mode os.FileMode) (spoolFile, error) {
				f, e := originalOpen(path, flags, mode)
				if e != nil {
					return nil, e
				}
				if filepath.Base(path) != journalFileName {
					return f, nil
				}
				if kind == "partial_write" {
					return &faultFile{spoolFile: f, write: func(p []byte) (int, error) { n, _ := f.Write(p[:len(p)/2]); return n, io.ErrShortWrite }}, nil
				}
				return &faultFile{spoolFile: f, sync: func() error { return errors.New("injected journal sync") }}, nil
			}
			s.fs = fs
			result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
			require.ErrorIs(t, err, ErrDurabilityUncertain)
			require.False(t, result.Stored)
			require.True(t, s.HasPending())
			s.fs = defaultFS()
			require.NoError(t, s.Recover())
			if kind == "partial_write" {
				require.Empty(t, s.Batches())
			} else {
				require.Len(t, s.Batches(), 1)
			}
			require.NoError(t, s.Close())
		})
	}
}

func TestDefiniteJournalFailureCleansPublishedRecordImmediately(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	fs := defaultFS()
	open := fs.openFile
	fs.openFile = func(path string, flags int, mode os.FileMode) (spoolFile, error) {
		if filepath.Base(path) == journalFileName {
			return nil, errors.New("injected journal open failure")
		}
		return open(path, flags, mode)
	}
	s.fs = fs
	result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
	require.ErrorContains(t, err, "journal open failure")
	require.False(t, result.Stored)
	require.False(t, s.Status().DurabilityUncertain)
	require.Zero(t, s.PhysicalBytes())
	records, globErr := filepath.Glob(filepath.Join(dir, "*"+recordExtension))
	require.NoError(t, globErr)
	require.Empty(t, records)
	s.fs = defaultFS()
	require.NoError(t, s.Close())
}

func TestModeledPowerLossAtUnsyncedJournalBoundaryAllowsOnlyCompleteStates(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	oldState := snapshotSpoolFiles(t, dir)

	fs := defaultFS()
	originalOpen := fs.openFile
	fs.openFile = func(path string, flags int, mode os.FileMode) (spoolFile, error) {
		f, openErr := originalOpen(path, flags, mode)
		base := filepath.Base(path)
		if openErr != nil || (base != journalFileName && !strings.HasPrefix(base, "journal-")) {
			return f, openErr
		}
		return &faultFile{spoolFile: f, sync: func() error { return errors.New("modeled unsynced journal") }}, nil
	}
	s.fs = fs
	result, err := s.Enqueue(batch("node", "session", 2, 2, 2))
	require.ErrorIs(t, err, ErrDurabilityUncertain)
	require.False(t, result.Stored)
	newState := snapshotSpoolFiles(t, dir)
	s.fs = defaultFS()
	require.NoError(t, s.Close())

	for name, model := range map[string]struct {
		files     map[string][]byte
		sequences []uint64
	}{
		"old durable directory entry": {files: oldState, sequences: []uint64{1}},
		"new durable directory entry": {files: newState, sequences: []uint64{1, 2}},
	} {
		t.Run(name, func(t *testing.T) {
			modelDir := t.TempDir()
			materializeSpoolFiles(t, modelDir, model.files)
			reopened, openErr := Open(Config{Directory: modelDir})
			require.NoError(t, openErr)
			batches := reopened.Batches()
			sequences := make([]uint64, 0, len(batches))
			for _, got := range batches {
				sequences = append(sequences, got.GetBatchSequence())
			}
			require.Equal(t, model.sequences, sequences)
			require.NoError(t, reopened.Close())
		})
	}
}

func snapshotSpoolFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	files := make(map[string][]byte)
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == lockFileName {
			continue
		}
		payload, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, readErr)
		files[entry.Name()] = payload
	}
	return files
}

func materializeSpoolFiles(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for name, payload := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), payload, 0o600))
	}
}

func TestRecordPublicationFailureMatrix(t *testing.T) {
	for _, kind := range []string{"create", "write", "fsync", "rename", "dirsync"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(Config{Directory: dir})
			require.NoError(t, err)
			fs := defaultFS()
			originalCreate := fs.createTemp
			fs.createTemp = func(dir, pattern string) (spoolFile, error) {
				if strings.HasPrefix(pattern, ".eventbatch-") {
					if kind == "create" {
						return nil, errors.New("injected record create")
					}
					f, e := originalCreate(dir, pattern)
					if e != nil {
						return nil, e
					}
					if kind == "write" {
						return &faultFile{spoolFile: f, write: func([]byte) (int, error) { return 0, errors.New("injected record write") }}, nil
					}
					if kind == "fsync" {
						return &faultFile{spoolFile: f, sync: func() error { return errors.New("injected record fsync") }}, nil
					}
					return f, nil
				}
				return originalCreate(dir, pattern)
			}
			originalRename := fs.rename
			fs.rename = func(from, to string) error {
				if kind == "rename" && strings.HasSuffix(to, recordExtension) {
					return errors.New("injected record rename")
				}
				return originalRename(from, to)
			}
			fs.syncDir = func(path string) error {
				if kind == "dirsync" {
					return errors.New("injected record dirsync")
				}
				return syncDirectory(path)
			}
			s.fs = fs
			result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
			require.Error(t, err)
			require.False(t, result.Stored)
			if kind == "dirsync" {
				require.ErrorIs(t, err, ErrDurabilityUncertain)
				s.fs = defaultFS()
				require.NoError(t, s.Recover())
			}
			require.Empty(t, s.Batches())
			s.fs = defaultFS()
			require.NoError(t, s.Close())
		})
	}
}

func TestPublicationHandlesShortWritesWithoutError(t *testing.T) {
	shorten := func(file spoolFile) spoolFile {
		return &faultFile{spoolFile: file, write: func(payload []byte) (int, error) {
			if len(payload) == 0 {
				return 0, nil
			}
			limit := max(1, len(payload)/2)
			return file.Write(payload[:limit])
		}}
	}

	t.Run("initial journal", func(t *testing.T) {
		fs := defaultFS()
		create := fs.createTemp
		fs.createTemp = func(directory, pattern string) (spoolFile, error) {
			file, err := create(directory, pattern)
			if err == nil && strings.HasPrefix(pattern, ".journal-") {
				file = shorten(file)
			}
			return file, err
		}
		s, err := Open(Config{Directory: t.TempDir(), fs: fs})
		require.NoError(t, err)
		require.NoError(t, s.Close())
	})

	t.Run("record", func(t *testing.T) {
		s, err := Open(Config{Directory: t.TempDir()})
		require.NoError(t, err)
		fs := defaultFS()
		create := fs.createTemp
		fs.createTemp = func(directory, pattern string) (spoolFile, error) {
			file, createErr := create(directory, pattern)
			if createErr == nil && strings.HasPrefix(pattern, ".eventbatch-") {
				file = shorten(file)
			}
			return file, createErr
		}
		s.fs = fs
		_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
		require.NoError(t, err)
		require.Len(t, s.Batches(), 1)
		s.fs = defaultFS()
		require.NoError(t, s.Close())
	})

	t.Run("checkpoint", func(t *testing.T) {
		s, err := Open(Config{Directory: t.TempDir(), CheckpointEvery: 1})
		require.NoError(t, err)
		fs := defaultFS()
		create := fs.createTemp
		fs.createTemp = func(directory, pattern string) (spoolFile, error) {
			file, createErr := create(directory, pattern)
			if createErr == nil && strings.HasPrefix(pattern, ".manifest-") {
				file = shorten(file)
			}
			return file, createErr
		}
		s.fs = fs
		result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
		require.True(t, result.Stored)
		require.NoError(t, err)
		s.fs = defaultFS()
		require.NoError(t, s.Close())
	})
}

func TestDropOldestCleanupFailureAtEachVictim(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("victim_%d", failAt), func(t *testing.T) {
			dir := t.TempDir()
			now := time.Unix(1, 0)
			s, err := Open(Config{Directory: dir, MaxAge: time.Second, Clock: func() time.Time { return now }})
			require.NoError(t, err)
			for i := uint64(1); i <= 3; i++ {
				_, err = s.Enqueue(batch("node", "session", i, i, i))
				require.NoError(t, err)
			}
			now = now.Add(2 * time.Second)
			calls := 0
			fs := defaultFS()
			fs.remove = func(path string) error {
				if strings.HasSuffix(path, recordExtension) {
					calls++
					if calls == failAt {
						return errors.New("injected victim cleanup")
					}
				}
				return os.Remove(path)
			}
			s.fs = fs
			result, err := s.Enqueue(batch("node", "session", 4, 4, 4))
			require.True(t, result.Stored)
			var cleanupErr *CleanupError
			require.ErrorAs(t, err, &cleanupErr)
			require.Len(t, s.Batches(), 1)
			require.Equal(t, uint64(4), s.Batches()[0].GetBatchSequence())
			s.fs = defaultFS()
			require.NoError(t, s.Close())
			reopened, err := Open(Config{Directory: dir})
			require.NoError(t, err)
			require.Len(t, reopened.Batches(), 1)
			require.NoError(t, reopened.Close())
		})
	}
}

func TestGenerationHandoffRetiresOldJournalAfterDurableCheckpoint(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir, CheckpointEvery: 1})
	require.NoError(t, err)
	result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	require.True(t, result.Stored)
	require.Equal(t, uint64(2), s.generation)
	_, err = os.Stat(journalPath(dir, 1))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(journalPath(dir, 2))
	require.NoError(t, err)
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Len(t, reopened.Batches(), 1)
	require.Equal(t, uint64(2), reopened.generation)
	require.NoError(t, reopened.Close())
}

func TestOpenRetriesObsoleteJournalCleanup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir, CheckpointEvery: 1})
	require.NoError(t, err)
	fs := defaultFS()
	old := journalPath(dir, 1)
	fs.remove = func(path string) error {
		if path == old {
			return errors.New("injected old journal cleanup")
		}
		return os.Remove(path)
	}
	s.fs = fs
	result, err := s.Enqueue(batch("node", "session", 1, 1, 1))
	require.True(t, result.Stored)
	var cleanupErr *CleanupError
	require.ErrorAs(t, err, &cleanupErr)
	_, statErr := os.Stat(old)
	require.NoError(t, statErr)
	s.fs = defaultFS()
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	_, statErr = os.Stat(old)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	require.Len(t, reopened.Batches(), 1)
	require.NoError(t, reopened.Close())
}

func TestLegacyMigrationFailureIsRetryableAndIdempotent(t *testing.T) {
	dir := t.TempDir()
	payload, err := proto.Marshal(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	writeRawRecord(t, filepath.Join(dir, "legacy"+recordExtension), uint64(len(payload)), payload)
	fs := defaultFS()
	fs.rename = func(from, to string) error {
		if filepath.Base(to) == manifestFileName {
			return errors.New("injected migration rename")
		}
		return os.Rename(from, to)
	}
	_, err = Open(Config{Directory: dir, fs: fs})
	require.ErrorContains(t, err, "injected migration rename")
	_, err = os.Stat(journalPath(dir, 1))
	require.NoError(t, err, "generation journal must be durable before manifest publication")
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Len(t, s.Batches(), 1)
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.Len(t, reopened.Batches(), 1)
	require.NoError(t, reopened.Close())
}

func TestEmptyStartupJournalFailurePublishesNoManifest(t *testing.T) {
	dir := t.TempDir()
	fs := defaultFS()
	original := fs.createTemp
	fs.createTemp = func(directory, pattern string) (spoolFile, error) {
		if strings.HasPrefix(pattern, ".journal-") {
			return nil, errors.New("injected initial journal failure")
		}
		return original(directory, pattern)
	}
	_, err := Open(Config{Directory: dir, fs: fs})
	require.ErrorContains(t, err, "initial journal failure")
	_, statErr := os.Stat(filepath.Join(dir, manifestFileName))
	require.ErrorIs(t, statErr, os.ErrNotExist)
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.NoError(t, s.Close())
}

func TestResetSessionIsDurableAndAtomicWhenDrained(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	old := sessionPolicy("old", "reliable", false)
	require.NoError(t, s.BindSessionPolicy(old))
	_, err = s.Enqueue(batch("hunter", "old", 1, 1, 3))
	require.NoError(t, err)
	require.NoError(t, s.Ack("hunter", "old", 1))
	next := sessionPolicy("new", "memory_only", true)
	require.NoError(t, s.ResetSession(next))
	source, session, event, batchSequence, err := s.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, "hunter", source)
	require.Equal(t, "new", session)
	require.Zero(t, event)
	require.Zero(t, batchSequence)
	require.NoError(t, s.Close())
	reopened, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.NoError(t, reopened.BindSessionPolicy(next))
	source, session, event, batchSequence, err = reopened.RecoveryState()
	require.NoError(t, err)
	require.Equal(t, "hunter", source)
	require.Equal(t, "new", session)
	require.Zero(t, event)
	require.Zero(t, batchSequence)
	_, err = reopened.Enqueue(batch("hunter", "old", 2, 4, 4))
	require.ErrorContains(t, err, "fixed spool session")
	require.NoError(t, reopened.Close())
}

func TestManifestRejectsIdentityAndHighWaterContradictions(t *testing.T) {
	for _, kind := range []string{"identity", "event_high_water", "batch_high_water", "policy_identity"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(Config{Directory: dir, CheckpointEvery: 1})
			require.NoError(t, err)
			policy := sessionPolicy("session", "reliable", false)
			require.NoError(t, s.BindSessionPolicy(policy))
			_, err = s.Enqueue(batch("hunter", "session", 3, 10, 12))
			require.NoError(t, err)
			require.NoError(t, s.Close())
			path := filepath.Join(dir, manifestFileName)
			m, err := readManifest(path)
			require.NoError(t, err)
			switch kind {
			case "identity":
				m.SourceNodeID = "other"
			case "event_high_water":
				m.LastEventSequence = 1
			case "batch_high_water":
				m.LastBatchSequence = 1
			case "policy_identity":
				m.SessionPolicy.SourceNodeID = "other"
			}
			payload, err := json.Marshal(m)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path, payload, 0o600))
			_, err = Open(Config{Directory: dir})
			require.Error(t, err)
		})
	}
}

func TestCleanupStatusPersistsUntilEveryOrphanSucceeds(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	for i := uint64(1); i <= 2; i++ {
		_, err = s.Enqueue(batch("node", "session", i, i, i))
		require.NoError(t, err)
	}
	failedName := s.records[0].name
	fs := defaultFS()
	fs.remove = func(path string) error {
		if filepath.Base(path) == failedName {
			return errors.New("persistent orphan failure")
		}
		return os.Remove(path)
	}
	s.fs = fs
	err = s.Ack("node", "session", 2)
	require.Error(t, err)
	require.NotEmpty(t, s.Status().CleanupError)
	result, err := s.Enqueue(batch("node", "session", 3, 3, 3))
	require.True(t, result.Stored)
	var cleanupErr *CleanupError
	require.ErrorAs(t, err, &cleanupErr)
	require.NotEmpty(t, s.Status().CleanupError, "successfully cleaning other files must not clear the unresolved orphan")
	s.fs = defaultFS()
	_, err = s.Enqueue(batch("node", "session", 4, 4, 4))
	require.NoError(t, err)
	require.Empty(t, s.Status().CleanupError)
	require.NoError(t, s.Close())
}

func TestCleanupTracksEveryFailedRemoval(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	for i := uint64(1); i <= 3; i++ {
		_, err = s.Enqueue(batch("node", "session", i, i, i))
		require.NoError(t, err)
	}

	failed := map[string]bool{
		s.records[0].name: true,
		s.records[1].name: true,
	}
	fs := defaultFS()
	fs.remove = func(path string) error {
		if failed[filepath.Base(path)] {
			return errors.New("persistent orphan failure")
		}
		return os.Remove(path)
	}
	s.fs = fs

	err = s.Ack("node", "session", 3)
	require.Error(t, err)
	require.Len(t, s.orphanFailures, 2)
	for name := range failed {
		require.Error(t, s.orphanFailures[name])
	}

	s.fs = defaultFS()
	_, err = s.Enqueue(batch("node", "session", 4, 4, 4))
	require.NoError(t, err)
	require.Empty(t, s.orphanFailures)
	require.Empty(t, s.Status().CleanupError)
	require.NoError(t, s.Close())
}

func TestOrphanSymlinkCleanupRetryReconcilesPhysicalBytes(t *testing.T) {
	dir := t.TempDir()
	initial, err := Open(Config{Directory: dir})
	require.NoError(t, err)
	require.NoError(t, initial.Close())

	target := filepath.Join(t.TempDir(), "external-target")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0o600))
	orphan := filepath.Join(dir, "orphan"+recordExtension)
	require.NoError(t, os.Symlink(target, orphan))
	linkInfo, err := os.Lstat(orphan)
	require.NoError(t, err)

	fs := defaultFS()
	remove := fs.remove
	failed := false
	fs.remove = func(path string) error {
		if path == orphan && !failed {
			failed = true
			return errors.New("injected orphan cleanup failure")
		}
		return remove(path)
	}

	s, err := Open(Config{Directory: dir, fs: fs})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	require.Equal(t, uint64(linkInfo.Size()), s.PhysicalBytes())
	require.FileExists(t, target)

	_, err = s.Enqueue(batch("node", "session", 1, 1, 1))
	require.NoError(t, err)
	require.NoFileExists(t, orphan)
	require.FileExists(t, target)
	require.Equal(t, s.Bytes(), s.PhysicalBytes(), "cleanup retry must remove exactly the symlink entry's accounted bytes")
}

package securestore

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func groupedTestStore(t *testing.T) (string, *Dir, *Lock) {
	t.Helper()
	path, dir := privateTestDir(t)
	lock, err := dir.Lock("head")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lock.Close()) })
	_, err = dir.Create("head", []byte("old-head"))
	require.NoError(t, err)
	return path, dir, lock
}

func TestGroupedPublicationWaitsForBothFilesAndParent(t *testing.T) {
	path, dir, _ := groupedTestStore(t)
	entered, synced := make(chan struct{}, 2), make(chan struct{}, 2)
	releaseFiles, atParent, releaseParent := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		for _, release := range []chan struct{}{releaseFiles, releaseParent} {
			select {
			case <-release:
			default:
				close(release)
			}
		}
	}()
	var completed, parentSyncs atomic.Int32
	dir.ops.sync = func(f *os.File) error {
		if f == dir.file {
			parentSyncs.Add(1)
			close(atParent)
			<-releaseParent
			return f.Sync()
		}
		entered <- struct{}{}
		<-releaseFiles
		err := f.Sync()
		completed.Add(1)
		synced <- struct{}{}
		return err
	}
	dir.ops.noReplace = func(a int, from string, b int, to string) (bool, bool, error) {
		if completed.Load() != 2 {
			return false, true, errors.New("published before both file syncs")
		}
		return publishNoReplace(a, from, b, to)
	}
	result := make(chan error, 1)
	go func() {
		out, err := dir.CreateAndReplace("batch", []byte("encrypted-batch-marker"), "head", []byte("new-head"))
		if out != Committed && err == nil {
			err = errors.New("wrong grouped outcome")
		}
		result <- err
	}()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("two file syncs did not run concurrently")
		}
	}
	_, err := os.Stat(filepath.Join(path, "batch"))
	require.ErrorIs(t, err, os.ErrNotExist)
	close(releaseFiles)
	for range 2 {
		<-synced
	}
	select {
	case <-atParent:
	case <-time.After(time.Second):
		t.Fatal("grouped publication did not reach parent sync")
	}
	data, err := os.ReadFile(filepath.Join(path, "head"))
	require.NoError(t, err)
	require.Equal(t, "new-head", string(data))
	select {
	case <-result:
		t.Fatal("returned before final directory sync")
	default:
	}
	close(releaseParent)
	require.NoError(t, <-result)
	require.EqualValues(t, 1, parentSyncs.Load())
}

func TestGroupedPublicationFailureOutcomes(t *testing.T) {
	for _, stage := range []string{"write-first", "write-second", "sync-first", "sync-second", "close-first", "close-second",
		"batch-publish", "batch-after-publish", "head-rename", "parent-sync", "retired-head-close", "temporary-cleanup"} {
		t.Run(stage, func(t *testing.T) {
			path, dir, _ := groupedTestStore(t)
			injected := errors.New("synthetic grouped fault")
			var written [2]*os.File
			writeCount := 0
			dir.ops.write = func(f *os.File, data []byte) (int, error) {
				written[writeCount] = f
				writeCount++
				if (stage == "write-first" && writeCount == 1) || (stage == "write-second" && writeCount == 2) || stage == "temporary-cleanup" {
					return 0, injected
				}
				return f.Write(data)
			}
			dir.ops.sync = func(f *os.File) error {
				if (stage == "sync-first" && f == written[0]) || (stage == "sync-second" && f == written[1]) || (stage == "parent-sync" && f == dir.file) {
					return injected
				}
				return f.Sync()
			}
			var closeCount atomic.Int32
			dir.ops.close = func(f *os.File) error {
				count := closeCount.Add(1)
				err := f.Close()
				if (stage == "close-first" && count == 1) || (stage == "close-second" && count == 2) || (stage == "retired-head-close" && count == 3) {
					return errors.Join(err, injected)
				}
				return err
			}
			dir.ops.noReplace = func(a int, from string, b int, to string) (bool, bool, error) {
				if stage == "batch-publish" {
					return false, true, injected
				}
				published, remaining, err := publishNoReplace(a, from, b, to)
				if stage == "batch-after-publish" {
					err = errors.Join(err, injected)
				}
				return published, remaining, err
			}
			dir.ops.rename = func(a int, from string, b int, to string) error {
				if stage == "head-rename" {
					return injected
				}
				return unix.Renameat(a, from, b, to)
			}
			cleanupErr := errors.New("synthetic cleanup fault")
			if stage == "temporary-cleanup" {
				dir.ops.unlink = func(int, string, int) error { return cleanupErr }
			}
			out, err := dir.CreateAndReplace("batch", []byte("synthetic ciphertext"), "head", []byte("new-head"))
			want := NotCommitted
			if stage == "parent-sync" {
				want = Uncertain
			}
			if stage == "retired-head-close" {
				want = Committed
			}
			require.Equal(t, want, out)
			require.Equal(t, want, OutcomeOf(err))
			require.ErrorIs(t, err, injected)
			if stage == "temporary-cleanup" {
				require.ErrorIs(t, err, cleanupErr)
			}
			head, readErr := os.ReadFile(filepath.Join(path, "head"))
			require.NoError(t, readErr)
			wantHead := "old-head"
			if want != NotCommitted {
				wantHead = "new-head"
			}
			require.Equal(t, wantHead, string(head))
			_, statErr := os.Stat(filepath.Join(path, "batch"))
			if stage == "batch-after-publish" || stage == "head-rename" || want != NotCommitted {
				require.NoError(t, statErr)
			} else {
				require.ErrorIs(t, statErr, os.ErrNotExist)
			}
			if stage != "temporary-cleanup" {
				matches, err := filepath.Glob(filepath.Join(path, ".securestore-tmp-*"))
				require.NoError(t, err)
				require.Empty(t, matches)
			}
			require.NotContains(t, err.Error(), "synthetic ciphertext")
		})
	}
}

func TestGroupedPublicationJoinsFailedSyncPeer(t *testing.T) {
	path, dir, _ := groupedTestStore(t)
	injected := errors.New("synthetic sync failure")
	firstFailed, peerStarted, releasePeer := make(chan struct{}), make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-releasePeer:
		default:
			close(releasePeer)
		}
	}()
	var syncs atomic.Int32
	dir.ops.sync = func(f *os.File) error {
		if syncs.Add(1) == 1 {
			close(firstFailed)
			return injected
		}
		close(peerStarted)
		<-releasePeer
		return f.Sync()
	}
	result := make(chan error, 1)
	go func() {
		_, err := dir.CreateAndReplace("batch", []byte("batch"), "head", []byte("head"))
		result <- err
	}()
	for _, reached := range []chan struct{}{firstFailed, peerStarted} {
		select {
		case <-reached:
		case <-time.After(time.Second):
			t.Fatal("both sync peers must run")
		}
	}
	select {
	case <-result:
		t.Fatal("failed sync abandoned the other active descriptor")
	default:
	}
	_, err := os.Stat(filepath.Join(path, "batch"))
	require.ErrorIs(t, err, os.ErrNotExist)
	close(releasePeer)
	err = <-result
	require.ErrorIs(t, err, injected)
	require.Equal(t, NotCommitted, OutcomeOf(err))
}

func TestGroupedPublicationRejectsExistingHeadSize(t *testing.T) {
	for _, size := range []int64{0, MaxGroupedHeadBytes + 1} {
		path, dir, _ := groupedTestStore(t)
		require.NoError(t, os.Truncate(filepath.Join(path, "head"), size))
		out, err := dir.CreateAndReplace("batch", []byte("batch"), "head", []byte("new"))
		require.Equal(t, NotCommitted, out)
		require.ErrorContains(t, err, "head size")
	}
}

func TestGroupedPublicationRejectsAliasesBoundsAndLostOwnership(t *testing.T) {
	path, dir, lock := groupedTestStore(t)
	for _, names := range [][2]string{{"head", "head"}, {"../batch", "head"}, {"batch", "a/head"}, {".securestore-tmp-reserved", "head"}, {"batch", "unowned"}} {
		out, err := dir.CreateAndReplace(names[0], []byte("batch"), names[1], []byte("new"))
		require.Equal(t, NotCommitted, out)
		require.Error(t, err)
	}
	for _, data := range [][2][]byte{{nil, []byte("new")}, {[]byte("batch"), nil}, {make([]byte, MaxGroupedNewBytes+1), []byte("new")}, {[]byte("batch"), make([]byte, MaxGroupedHeadBytes+1)}} {
		out, err := dir.CreateAndReplace("batch", data[0], "head", data[1])
		require.Equal(t, NotCommitted, out)
		require.Error(t, err)
	}
	require.NoError(t, os.Link(filepath.Join(path, "head"), filepath.Join(path, "alias")))
	_, err := dir.CreateAndReplace("alias", []byte("batch"), "head", []byte("new"))
	require.Error(t, err)
	require.NoError(t, os.Remove(filepath.Join(path, "alias")))
	require.NoError(t, os.Rename(filepath.Join(path, "head"), filepath.Join(path, "old")))
	require.NoError(t, os.WriteFile(filepath.Join(path, "head"), []byte("substituted"), 0600))
	_, err = dir.CreateAndReplace("batch", []byte("batch"), "head", []byte("new"))
	require.ErrorContains(t, err, "owned inode")
	require.NoError(t, lock.Close())
	_, err = dir.CreateAndReplace("batch", []byte("batch"), "head", []byte("new"))
	require.ErrorContains(t, err, "ownership")
}

func TestGroupedPublicationRetainsLocksAndDescriptorDirectory(t *testing.T) {
	path, dir, _ := groupedTestStore(t)
	batchLock, err := dir.Lock("batch")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, batchLock.Close()) })
	moved := path + "-moved"
	require.NoError(t, os.Rename(path, moved))
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(moved)) })
	require.NoError(t, os.Mkdir(path, 0700))
	out, err := dir.CreateAndReplace("batch", []byte("batch"), "head", []byte("new"))
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	_, err = os.Stat(filepath.Join(path, "head"))
	require.ErrorIs(t, err, os.ErrNotExist)
	other, err := OpenDir(moved)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, other.Close()) })
	_, err = other.Lock("head")
	require.ErrorIs(t, err, ErrLocked)
	for _, name := range []string{"head", "batch"} {
		require.NoError(t, os.Rename(filepath.Join(moved, name), filepath.Join(moved, name+"-alias")))
		_, err := other.Lock(name + "-alias")
		require.ErrorIs(t, err, ErrLocked, "replacement inode lock must follow moved %s", name)
	}
}

func TestGroupedPublicationProcessDeath(t *testing.T) {
	if stage := os.Getenv("SECURESTORE_GROUP_CRASH_STAGE"); stage != "" {
		dir, err := OpenDir(os.Getenv("SECURESTORE_GROUP_CRASH_DIR"))
		require.NoError(t, err)
		_, err = dir.Lock("head")
		require.NoError(t, err)
		if stage == "before-batch" {
			dir.ops.noReplace = func(int, string, int, string) (bool, bool, error) { os.Exit(78); return false, true, nil }
		}
		if stage == "before-head" {
			dir.ops.rename = func(int, string, int, string) error { os.Exit(78); return nil }
		}
		dir.ops.sync = func(f *os.File) error {
			if f == dir.file && stage == "before-parent-sync" {
				os.Exit(78)
			}
			err := f.Sync()
			if f == dir.file && stage == "after-parent-sync" {
				os.Exit(78)
			}
			return err
		}
		_, err = dir.CreateAndReplace("batch", []byte("batch"), "head", []byte("new-head"))
		t.Fatalf("child did not exit: %v", err)
	}
	for _, stage := range []string{"before-batch", "before-head", "before-parent-sync", "after-parent-sync"} {
		t.Run(stage, func(t *testing.T) {
			path, dir, lock := groupedTestStore(t)
			require.NoError(t, lock.Close())
			child := exec.Command(os.Args[0], "-test.run=^TestGroupedPublicationProcessDeath$")
			child.Env = append(os.Environ(), "SECURESTORE_GROUP_CRASH_STAGE="+stage, "SECURESTORE_GROUP_CRASH_DIR="+path)
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, string(output))
			require.Equal(t, 78, exit.ExitCode(), string(output))
			owned, err := dir.Lock("head")
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, owned.Close()) })
			data, err := dir.Read("head", 100)
			require.NoError(t, err)
			want := "old-head"
			if strings.Contains(stage, "parent-sync") {
				want = "new-head"
			}
			require.Equal(t, want, string(data))
			_, err = dir.Read("batch", 100)
			if stage == "before-batch" {
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

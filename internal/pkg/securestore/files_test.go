package securestore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func privateTestDir(t *testing.T) (string, *Dir) {
	t.Helper()
	path := t.TempDir()
	require.NoError(t, os.Chmod(path, 0700))
	dir, err := OpenDir(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dir.Close()) })
	return path, dir
}

func TestPrivateFileRoundTripAndNoClobber(t *testing.T) {
	path, dir := privateTestDir(t)
	lock, err := dir.Lock("snapshot")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lock.Close()) })
	out, err := dir.Create("snapshot", []byte("first"))
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	out, err = dir.Create("snapshot", []byte("must not replace"))
	require.ErrorIs(t, err, os.ErrExist)
	require.Equal(t, NotCommitted, out)
	require.Equal(t, out, OutcomeOf(err))
	data, err := dir.Read("snapshot", 5)
	require.NoError(t, err)
	require.Equal(t, "first", string(data))
	out, err = dir.Replace("snapshot", []byte("replacement"))
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	st, err := os.Stat(filepath.Join(path, "snapshot"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), st.Mode().Perm())
	data, err = ReadFile(filepath.Join(path, "snapshot"), 100)
	require.NoError(t, err)
	require.Equal(t, "replacement", string(data))
	require.NoError(t, os.Chmod(filepath.Join(path, "snapshot"), 0400))
	_, err = dir.Read("snapshot", 100)
	require.NoError(t, err)
	require.NoError(t, dir.Close())
	_, err = dir.Read("snapshot", 100)
	require.ErrorIs(t, err, os.ErrClosed)
	_, err = dir.Replace("snapshot", nil)
	require.ErrorIs(t, err, os.ErrClosed)
	require.NoError(t, lock.Close())
	require.NoError(t, lock.Close())
}

func TestPrivateReadsRejectUntrustedObjects(t *testing.T) {
	path, dir := privateTestDir(t)
	require.NoError(t, os.WriteFile(filepath.Join(path, "source"), []byte("secret"), 0600))
	require.NoError(t, os.Symlink("source", filepath.Join(path, "symlink")))
	require.NoError(t, os.Link(filepath.Join(path, "source"), filepath.Join(path, "hardlink")))
	require.NoError(t, os.WriteFile(filepath.Join(path, "public"), []byte("secret"), 0644))
	require.NoError(t, os.Mkdir(filepath.Join(path, "directory"), 0700))
	require.NoError(t, unix.Mkfifo(filepath.Join(path, "fifo"), 0600))
	for _, name := range []string{"symlink", "hardlink", "source", "public", "directory", "fifo", "../source", ".", "", "a/b", "a\x00b", strings.Repeat("x", 256)} {
		t.Run(name, func(t *testing.T) {
			_, err := dir.Read(name, 100)
			require.Error(t, err)
			_, err = dir.Replace(name, []byte("new"))
			require.Error(t, err)
			_, err = dir.Lock(name)
			require.Error(t, err)
		})
	}
}

func TestPrivateReadBoundBeforeAllocation(t *testing.T) {
	path, dir := privateTestDir(t)
	file, err := os.OpenFile(filepath.Join(path, "huge"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	require.NoError(t, err)
	require.NoError(t, file.Truncate(1<<40))
	require.NoError(t, file.Close())
	_, err = dir.Read("huge", 100)
	require.ErrorContains(t, err, "read limit")
	_, err = dir.Read("huge", -1)
	require.ErrorContains(t, err, "negative")
	_, err = dir.Read("missing", 100)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = dir.Create("empty", nil)
	require.NoError(t, err)
	data, err := dir.Read("empty", 0)
	require.NoError(t, err)
	require.Empty(t, data)
}

func TestPrivateDirectoryPolicy(t *testing.T) {
	path, dir := privateTestDir(t)
	require.NoError(t, dir.Close())
	for _, mode := range []os.FileMode{0700, 0750} {
		require.NoError(t, os.Chmod(path, mode))
		opened, err := OpenDir(path)
		require.NoError(t, err)
		require.NoError(t, opened.Close())
	}
	for _, mode := range []os.FileMode{0755, 0770, 0777, 0500} {
		require.NoError(t, os.Chmod(path, mode))
		_, err := OpenDir(path)
		require.Error(t, err)
	}
	require.NoError(t, os.Chmod(path, 0700))
	require.NoError(t, os.Mkdir(filepath.Join(path, "child"), 0700))
	require.NoError(t, os.Symlink(filepath.Join(path, "child"), filepath.Join(path, "alias")))
	_, err := OpenDir(filepath.Join(path, "alias"))
	require.Error(t, err)
	_, err = OpenDir(path + "/alias/../child")
	require.Error(t, err, "lexical cleaning must not hide a symlink before '..'")
	require.NoError(t, os.WriteFile(filepath.Join(path, "key"), nil, 0600))
	_, err = ReadFile(path+"/alias/../key", 0)
	require.Error(t, err)
	viaParent, err := OpenDir(path + "/child/../child")
	require.NoError(t, err)
	require.NoError(t, viaParent.Close())
	require.NoError(t, os.Mkdir(filepath.Join(path, "child", "nested"), 0700))
	_, err = OpenDir(filepath.Join(path, "alias", "nested"))
	require.Error(t, err)
	require.NoError(t, os.Chmod(filepath.Join(path, "child"), 0770))
	_, err = OpenDir(filepath.Join(path, "child", "nested"))
	require.ErrorContains(t, err, "ancestor")
	_, err = OpenDir(filepath.Join(path, "absent"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadFileAllowsTrustedNonprivateParent(t *testing.T) {
	path, dir := privateTestDir(t)
	require.NoError(t, dir.Close())
	require.NoError(t, os.WriteFile(filepath.Join(path, "key"), bytes.Repeat([]byte{1}, 32), 0400))
	require.NoError(t, os.Chmod(path, 0755))
	data, err := ReadFile(filepath.Join(path, "key"), 32)
	require.NoError(t, err)
	require.Len(t, data, 32)
	_, err = OpenDir(path)
	require.Error(t, err)
}

func TestStableOwnershipAcrossReplacementAndAliases(t *testing.T) {
	path, dir := privateTestDir(t)
	_, err := dir.Create("snapshot", []byte("old"))
	require.NoError(t, err)
	lock, err := dir.Lock("snapshot")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lock.Close()) })
	other, err := OpenDir(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, other.Close()) })
	_, err = other.Lock("snapshot")
	require.ErrorIs(t, err, ErrLocked)
	// The original inode must be locked before the first replacement too.
	require.NoError(t, os.Rename(filepath.Join(path, "snapshot"), filepath.Join(path, "initial-alias")))
	_, err = other.Lock("initial-alias")
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, os.Rename(filepath.Join(path, "initial-alias"), filepath.Join(path, "snapshot")))
	_, err = dir.Replace("snapshot", []byte("new"))
	require.NoError(t, err)
	_, err = other.Lock("snapshot")
	require.ErrorIs(t, err, ErrLocked)
	// Renaming a locked inode to a different basename cannot bypass ownership.
	require.NoError(t, os.Rename(filepath.Join(path, "snapshot"), filepath.Join(path, "renamed")))
	_, err = other.Lock("renamed")
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, os.Rename(filepath.Join(path, "renamed"), filepath.Join(path, "snapshot")))
	require.NoError(t, lock.Close())
	newLock, err := other.Lock("snapshot")
	require.NoError(t, err)
	require.NoError(t, newLock.Close())
	_, err = os.Stat(filepath.Join(path, ownershipLockName("snapshot")))
	require.NoError(t, err, "the stable lock file must be retained")
}

func ownershipLockName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return ".securestore-lock-" + hex.EncodeToString(sum[:])
}

func TestOwnershipRejectsLockSymlinkAndHardlink(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path, dir := privateTestDir(t)
			source := filepath.Join(path, "private")
			require.NoError(t, os.WriteFile(source, nil, 0600))
			target := filepath.Join(path, ownershipLockName("snapshot"))
			if kind == "symlink" {
				require.NoError(t, os.Symlink(source, target))
			} else {
				require.NoError(t, os.Link(source, target))
			}
			_, err := dir.Lock("snapshot")
			require.Error(t, err)
		})
	}
}

func TestOwnershipRejectsChangedFileOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	path, dir := privateTestDir(t)
	target := filepath.Join(path, "foreign")
	require.NoError(t, os.WriteFile(target, nil, 0600))
	require.NoError(t, os.Chown(target, 1, -1))
	_, err := dir.Read("foreign", 0)
	require.ErrorContains(t, err, "user-owned")
	_, err = dir.Lock("foreign")
	require.Error(t, err)
}

func TestDurableReplacementFaultOutcomes(t *testing.T) {
	injected := errors.New("injected I/O fault")
	tests := []struct {
		name    string
		install func(*Dir)
		outcome Outcome
		want    string
	}{
		{"short writes", func(d *Dir) { d.ops.write = func(f *os.File, p []byte) (int, error) { return f.Write(p[:1]) } }, Committed, "new"},
		{"zero write", func(d *Dir) { d.ops.write = func(*os.File, []byte) (int, error) { return 0, nil } }, NotCommitted, "old"},
		{"full disk", func(d *Dir) { d.ops.write = func(*os.File, []byte) (int, error) { return 0, unix.ENOSPC } }, NotCommitted, "old"},
		{"sync data", func(d *Dir) { d.ops.sync = func(*os.File) error { return injected } }, NotCommitted, "old"},
		{"close data", func(d *Dir) { d.ops.close = func(f *os.File) error { return errors.Join(f.Close(), injected) } }, NotCommitted, "old"},
		{"rename", func(d *Dir) { d.ops.rename = func(int, string, int, string) error { return injected } }, NotCommitted, "old"},
		{"sync directory", func(d *Dir) {
			d.ops.sync = func(f *os.File) error {
				if f == d.file {
					return injected
				}
				return f.Sync()
			}
		}, Uncertain, "new"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, dir := privateTestDir(t)
			_, err := dir.Create("snapshot", []byte("old"))
			require.NoError(t, err)
			tc.install(dir)
			out, err := dir.Replace("snapshot", []byte("new"))
			require.Equal(t, tc.outcome, out)
			require.Equal(t, tc.outcome, OutcomeOf(err))
			if out == Committed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				var commit *CommitError
				require.ErrorAs(t, err, &commit)
			}
			data, err := os.ReadFile(filepath.Join(path, "snapshot"))
			require.NoError(t, err)
			require.Equal(t, tc.want, string(data))
			matches, err := filepath.Glob(filepath.Join(path, ".securestore-tmp-*"))
			require.NoError(t, err)
			require.Empty(t, matches)
		})
	}
}

func TestReplacementCleanupPreservesPrimaryError(t *testing.T) {
	_, dir := privateTestDir(t)
	cleanupErr := errors.New("cleanup failed")
	dir.ops.write = func(*os.File, []byte) (int, error) { return 0, unix.ENOSPC }
	dir.ops.unlink = func(int, string, int) error { return cleanupErr }
	out, err := dir.Replace("snapshot", []byte("chosen-marker"))
	require.Equal(t, NotCommitted, out)
	require.ErrorIs(t, err, unix.ENOSPC)
	require.ErrorIs(t, err, cleanupErr)
	require.NotContains(t, err.Error(), "chosen-marker")
}

func TestCreatePublicationAndCleanupUncertainty(t *testing.T) {
	path, dir := privateTestDir(t)
	dir.ops.unlink = func(int, string, int) error { return unix.EIO }
	out, err := dir.Create("snapshot", []byte("new"))
	require.Equal(t, Uncertain, out)
	require.Equal(t, Uncertain, OutcomeOf(err))
	require.ErrorIs(t, err, unix.EIO)
	data, err := os.ReadFile(filepath.Join(path, "snapshot"))
	require.NoError(t, err)
	require.Equal(t, "new", string(data))
	// The interrupted hardlink publication is rejected until reconciled.
	_, err = dir.Read("snapshot", 100)
	require.ErrorContains(t, err, "hardlinked")
}

func TestDescriptorRemainsBoundToOpenedDirectory(t *testing.T) {
	parent := t.TempDir()
	old := filepath.Join(parent, "original")
	moved := filepath.Join(parent, "moved")
	require.NoError(t, os.Mkdir(old, 0700))
	dir, err := OpenDir(old)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dir.Close()) })
	require.NoError(t, os.Rename(old, moved))
	require.NoError(t, os.Mkdir(old, 0700))
	_, err = dir.Create("snapshot", []byte("bound"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(old, "snapshot"))
	require.ErrorIs(t, err, os.ErrNotExist)
	data, err := os.ReadFile(filepath.Join(moved, "snapshot"))
	require.NoError(t, err)
	require.Equal(t, "bound", string(data))
}

func TestStorageCrashBoundary(t *testing.T) {
	if stage := os.Getenv("SECURESTORE_TEST_CRASH_STAGE"); stage != "" {
		dir, err := OpenDir(os.Getenv("SECURESTORE_TEST_CRASH_DIR"))
		if err != nil {
			t.Fatal(err)
		}
		if stage == "before-rename" {
			dir.ops.rename = func(int, string, int, string) error { os.Exit(78); return nil }
		} else {
			dir.ops.sync = func(f *os.File) error {
				if f == dir.file {
					os.Exit(78)
				}
				return f.Sync()
			}
		}
		_, err = dir.Replace("snapshot", []byte("new"))
		t.Fatalf("child did not crash: %v", err)
	}
	for _, stage := range []string{"before-rename", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			path, dir := privateTestDir(t)
			_, err := dir.Create("snapshot", []byte("old"))
			require.NoError(t, err)
			child := exec.Command(os.Args[0], "-test.run=^TestStorageCrashBoundary$")
			child.Env = append(os.Environ(), "SECURESTORE_TEST_CRASH_STAGE="+stage, "SECURESTORE_TEST_CRASH_DIR="+path)
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, string(output))
			require.Equal(t, 78, exit.ExitCode(), string(output))
			data, err := dir.Read("snapshot", 100)
			require.NoError(t, err)
			want := "old"
			if stage == "after-rename" {
				want = "new"
			}
			require.Equal(t, want, string(data))
		})
	}
}

func TestOutcomeOfWrappedErrors(t *testing.T) {
	require.Equal(t, Committed, OutcomeOf(nil))
	require.Equal(t, NotCommitted, OutcomeOf(io.ErrShortWrite))
	require.Equal(t, Uncertain, OutcomeOf(errors.Join(&CommitError{Outcome: Uncertain, Op: "replace", Err: unix.EIO}, io.ErrShortWrite)))
}

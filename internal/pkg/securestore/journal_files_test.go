package securestore

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJournalDescriptorWalkAndAllocation(t *testing.T) {
	path, dir := privateTestDir(t)
	_, err := dir.Create("object", []byte("encrypted bytes"))
	require.NoError(t, err)
	// Keep reading the descriptor-pinned original after a directory rename.
	require.NoError(t, os.Rename(path, path+"-renamed"))
	t.Cleanup(func() { require.NoError(t, os.Rename(path+"-renamed", path)) })
	count := 0
	require.NoError(t, dir.WalkEntries(func(name string) error {
		count++
		data, err := dir.Read(name, 64)
		require.Equal(t, []byte("encrypted bytes"), data)
		return err
	}))
	require.Equal(t, 1, count)
	allocated, err := dir.AllocatedSize("object")
	require.NoError(t, err)
	require.GreaterOrEqual(t, allocated, int64(512))
	unit, err := dir.AllocationUnit()
	require.NoError(t, err)
	require.GreaterOrEqual(t, unit, int64(4096))
	sentinel := errors.New("stop bounded recovery")
	require.ErrorIs(t, dir.WalkEntries(func(string) error { return sentinel }), sentinel)
}

func TestJournalDurableRemoveOutcomes(t *testing.T) {
	for _, fault := range []string{"unlink", "sync", "none"} {
		t.Run(fault, func(t *testing.T) {
			_, dir := privateTestDir(t)
			_, err := dir.Create("object", []byte("encrypted"))
			require.NoError(t, err)
			if fault == "unlink" {
				dir.ops.unlink = func(int, string, int) error { return syscall.EIO }
			}
			if fault == "sync" {
				dir.ops.sync = func(*os.File) error { return syscall.EIO }
			}
			out, err := dir.Remove("object")
			switch fault {
			case "unlink":
				require.Equal(t, NotCommitted, out)
				require.ErrorIs(t, err, syscall.EIO)
			case "sync":
				require.Equal(t, Uncertain, out)
				require.ErrorIs(t, err, syscall.EIO)
			default:
				require.Equal(t, Committed, out)
				require.NoError(t, err)
			}
			require.Equal(t, out, OutcomeOf(err))
			_, readErr := dir.Read("object", 64)
			if fault == "unlink" {
				require.NoError(t, readErr)
			} else {
				require.ErrorIs(t, readErr, os.ErrNotExist)
			}
		})
	}
}

func TestJournalTemporaryRecovery(t *testing.T) {
	for _, kind := range []string{"unpublished", "published", "external_link", "symlink", "wrong_mode"} {
		t.Run(kind, func(t *testing.T) {
			path, dir := privateTestDir(t)
			name := ".securestore-tmp-" + strings.Repeat("a", 32)
			file := filepath.Join(path, name)
			require.NoError(t, os.WriteFile(file, []byte("encrypted payload"), 0600))
			switch kind {
			case "published":
				require.NoError(t, os.Link(file, filepath.Join(path, "product")))
			case "external_link":
				require.NoError(t, os.Link(file, filepath.Join(t.TempDir(), "external")))
			case "symlink":
				require.NoError(t, os.Remove(file))
				require.NoError(t, os.Symlink("product", file))
			case "wrong_mode":
				require.NoError(t, os.Chmod(file, 0644))
			}
			out, err := dir.RecoverTemporaries()
			if kind == "unpublished" || kind == "published" {
				require.Equal(t, Committed, out)
				require.NoError(t, err)
				_, err = os.Lstat(file)
				require.ErrorIs(t, err, os.ErrNotExist)
				if kind == "published" {
					data, err := dir.Read("product", 64)
					require.NoError(t, err)
					require.Equal(t, []byte("encrypted payload"), data)
				}
			} else {
				require.Error(t, err)
				require.Equal(t, NotCommitted, out)
			}
		})
	}
}

func TestJournalMetadataAllocationRejectsHiddenUnboundedFiles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		size  int
		valid bool
	}{
		{".securestore-lock-" + strings.Repeat("a", 64), 0, true},
		{".securestore-lock-" + strings.Repeat("a", 64), 4096, false},
		{".usage-" + strings.Repeat("b", 64), usageBytes, true},
		{".usage-" + strings.Repeat("b", 64), usageBytes + 1, false},
		{".usage-invalid", usageBytes, false},
	} {
		t.Run(tc.name+strconv.Itoa(tc.size), func(t *testing.T) {
			path, dir := privateTestDir(t)
			require.NoError(t, os.WriteFile(filepath.Join(path, tc.name), make([]byte, tc.size), 0600))
			allocated, err := dir.MetadataAllocatedSize(tc.name)
			if tc.valid {
				require.NoError(t, err)
				require.GreaterOrEqual(t, allocated, int64(tc.size))
			} else {
				require.Error(t, err)
			}
		})
	}
}

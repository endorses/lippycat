//go:build linux

package securestore

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const fixedTestName = "segment.lsg"
const fixedTestStage = ".lsg-init-00112233445566778899aabbccddeeff.tmp"

func fixedTestSegment(t *testing.T) (string, *Dir, *FixedSegment) {
	t.Helper()
	path, d := privateTestDir(t)
	lock, err := d.Lock(fixedTestName)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lock.Close()) })
	out, err := d.InitializeFixedSegment(fixedTestStage, fixedTestName, bytes.Repeat([]byte{0x53}, FixedSegmentDataStart))
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	s, err := d.OpenFixedSegment(fixedTestName)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	require.NoError(t, s.Activate(FixedSegmentDataStart, 1))
	return path, d, s
}
func TestFixedSegmentSingleMutableHandle(t *testing.T) {
	_, d, s := fixedTestSegment(t)
	second, err := d.OpenFixedSegment(fixedTestName)
	require.Error(t, err)
	require.Nil(t, second)
	require.Error(t, s.owner.Close(), "ownership cannot end while a mutable descriptor survives")
	out, err := s.Commit(make([]byte, FixedSegmentBlock), make([]byte, FixedSegmentBlock))
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	require.NoError(t, s.Close())
	second, err = d.OpenFixedSegment(fixedTestName)
	require.NoError(t, err)
	require.NoError(t, second.Activate(FixedSegmentDataStart+FixedSegmentBlock, 0))
	require.NoError(t, second.Close())
}

func TestFixedSegmentPreservesEarlierCommittedBytes(t *testing.T) {
	for _, afterHead := range []bool{false, true} {
		_, _, s := fixedTestSegment(t)
		first := bytes.Repeat([]byte{0x33}, FixedSegmentBlock)
		out, err := s.Commit(first, bytes.Repeat([]byte{0x61}, FixedSegmentBlock))
		require.NoError(t, err)
		require.Equal(t, Committed, out)
		s.ops.writeAt = func(f *os.File, b []byte, off int64) (int, error) {
			if (off < FixedSegmentDataStart) == afterHead {
				n, e := f.WriteAt(b[:17], off)
				return n, errors.Join(e, unix.ENOSPC)
			}
			return f.WriteAt(b, off)
		}
		out, err = s.Commit(bytes.Repeat([]byte{0x44}, FixedSegmentBlock), bytes.Repeat([]byte{0x62}, FixedSegmentBlock))
		require.ErrorIs(t, err, unix.ENOSPC)
		if afterHead {
			require.Equal(t, Uncertain, out)
		} else {
			require.Equal(t, NotCommitted, out)
		}
		got := make([]byte, FixedSegmentBlock)
		require.NoError(t, s.ReadAt(got, FixedSegmentDataStart))
		require.Equal(t, first, got)
	}
}

func TestFixedSegmentStreamsBootstrapAndReportsCloseError(t *testing.T) {
	_, d := privateTestDir(t)
	owner, err := d.Lock(fixedTestName)
	require.NoError(t, err)
	defer func() { require.NoError(t, owner.Close()) }()
	ops := defaultFixedSegmentOps()
	zeroWrites := 0
	ops.writeAt = func(f *os.File, b []byte, off int64) (int, error) {
		require.LessOrEqual(t, len(b), 64<<10)
		if len(b) == 64<<10 {
			zeroWrites++
			require.Equal(t, make([]byte, len(b)), b)
		}
		return f.WriteAt(b, off)
	}
	out, err := d.initializeFixedSegment(fixedTestStage, fixedTestName, make([]byte, FixedSegmentDataStart), ops)
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	require.Equal(t, FixedSegmentBytes/(64<<10), zeroWrites)
	s, err := d.OpenFixedSegment(fixedTestName)
	require.NoError(t, err)
	require.NoError(t, s.Activate(FixedSegmentDataStart, 1))
	out, err = s.Commit(make([]byte, FixedSegmentBlock), make([]byte, FixedSegmentBlock))
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	d.ops.close = func(f *os.File) error { return errors.Join(f.Close(), unix.EIO) }
	require.ErrorIs(t, s.Close(), unix.EIO)
	require.Equal(t, Committed, out, "close failure cannot revise the prior durable outcome")
	out, err = s.Commit(make([]byte, FixedSegmentBlock), make([]byte, FixedSegmentBlock))
	require.Error(t, err)
	require.Equal(t, NotCommitted, out)
}

func TestFixedSegmentTransactionBounds(t *testing.T) {
	for _, tc := range []struct {
		name       string
		data, head int
		cursor     int64
		valid      bool
	}{
		{"empty", 0, FixedSegmentBlock, FixedSegmentDataStart, false},
		{"unaligned", FixedSegmentBlock - 1, FixedSegmentBlock, FixedSegmentDataStart, false},
		{"over-max", FixedSegmentMaxAppend + FixedSegmentBlock, FixedSegmentBlock, FixedSegmentDataStart, false},
		{"short-head", FixedSegmentBlock, FixedSegmentBlock - 1, FixedSegmentDataStart, false},
		{"long-head", FixedSegmentBlock, FixedSegmentBlock + 1, FixedSegmentDataStart, false},
		{"file-full", FixedSegmentBlock, FixedSegmentBlock, FixedSegmentBytes, false},
		{"max", FixedSegmentMaxAppend, FixedSegmentBlock, FixedSegmentDataStart, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, s := fixedTestSegment(t)
			s.cursor = tc.cursor
			writes := 0
			write := s.ops.writeAt
			s.ops.writeAt = func(f *os.File, data []byte, off int64) (int, error) {
				writes++
				return write(f, data, off)
			}
			out, err := s.Commit(make([]byte, tc.data), make([]byte, tc.head))
			if tc.valid {
				require.NoError(t, err)
				require.Equal(t, Committed, out)
				require.Equal(t, 2, writes)
			} else {
				require.Error(t, err)
				require.Equal(t, NotCommitted, out)
				require.Zero(t, writes)
			}
		})
	}
}
func TestFixedSegmentFaultOutcomesAndPoison(t *testing.T) {
	for _, stage := range []string{"success", "data-zero", "data-invalid", "data-partial", "head-zero", "head-partial", "sync", "post-sync-identity"} {
		t.Run(stage, func(t *testing.T) {
			path, _, s := fixedTestSegment(t)
			injected := errors.New("synthetic fixed failure")
			s.ops.writeAt = func(f *os.File, b []byte, offset int64) (int, error) {
				if offset >= FixedSegmentDataStart {
					switch stage {
					case "data-zero":
						return 0, injected
					case "data-invalid":
						return len(b) + 1, nil
					case "data-partial":
						n, err := f.WriteAt(b[:17], offset)
						return n, errors.Join(err, injected)
					}
				} else {
					switch stage {
					case "head-zero":
						return 0, injected
					case "head-partial":
						n, err := f.WriteAt(b[:128], offset)
						return n, errors.Join(err, injected)
					}
				}
				return f.WriteAt(b, offset)
			}
			s.ops.dataSync = func(f *os.File) error {
				if stage == "sync" {
					return injected
				}
				err := unix.Fdatasync(int(f.Fd()))
				if stage == "post-sync-identity" {
					require.NoError(t, os.Chmod(filepath.Join(path, fixedTestName), 0400))
				}
				return err
			}
			out, err := s.Commit(bytes.Repeat([]byte{0x44}, FixedSegmentBlock), bytes.Repeat([]byte{0x48}, FixedSegmentBlock))
			want := NotCommitted
			if stage == "success" || stage == "post-sync-identity" {
				want = Committed
			} else if stage == "head-zero" || stage == "head-partial" || stage == "sync" {
				want = Uncertain
			}
			require.Equal(t, want, out)
			if stage == "success" {
				require.NoError(t, err)
				require.EqualValues(t, FixedSegmentDataStart+FixedSegmentBlock, s.cursor)
			} else {
				require.Error(t, err)
				require.Equal(t, want, OutcomeOf(err))
				_, again := s.Commit(make([]byte, FixedSegmentBlock), make([]byte, FixedSegmentBlock))
				require.Error(t, again)
				require.Error(t, s.Activate(FixedSegmentDataStart, 1))
			}
			immutable := make([]byte, FixedSegmentBlock)
			f, err := os.Open(filepath.Join(path, fixedTestName))
			require.NoError(t, err)
			_, err = f.ReadAt(immutable, 0)
			require.NoError(t, err)
			require.NoError(t, f.Close())
			require.Equal(t, bytes.Repeat([]byte{0x53}, FixedSegmentBlock), immutable)
		})
	}
}
func TestFixedSegmentInitializationFaults(t *testing.T) {
	for _, stage := range []string{"allocate", "zero-write", "bootstrap-write", "file-sync", "close", "publish", "parent-sync"} {
		t.Run(stage, func(t *testing.T) {
			path, d := privateTestDir(t)
			lock, err := d.Lock(fixedTestName)
			require.NoError(t, err)
			defer func() { require.NoError(t, lock.Close()) }()
			ops := defaultFixedSegmentOps()
			injected := errors.New("synthetic bootstrap failure")
			ops.allocate = func(f *os.File, n int64) error {
				if stage == "allocate" {
					return injected
				}
				return unix.Fallocate(int(f.Fd()), 0, 0, n)
			}
			ops.writeAt = func(f *os.File, b []byte, off int64) (int, error) {
				if stage == "zero-write" || stage == "bootstrap-write" && len(b) == FixedSegmentDataStart {
					return 0, injected
				}
				return f.WriteAt(b, off)
			}
			d.ops.sync = func(f *os.File) error {
				if stage == "file-sync" && f != d.file || stage == "parent-sync" && f == d.file {
					return injected
				}
				return f.Sync()
			}
			d.ops.close = func(f *os.File) error {
				err := f.Close()
				if stage == "close" {
					return errors.Join(err, injected)
				}
				return err
			}
			d.ops.noReplace = func(a int, from string, b int, to string) (bool, bool, error) {
				if stage == "publish" {
					return false, true, injected
				}
				return publishNoReplace(a, from, b, to)
			}
			out, err := d.initializeFixedSegment(fixedTestStage, fixedTestName, make([]byte, FixedSegmentDataStart), ops)
			require.ErrorIs(t, err, injected)
			want := NotCommitted
			if stage == "parent-sync" {
				want = Uncertain
			}
			require.Equal(t, want, out)
			require.Equal(t, want, OutcomeOf(err))
			name := fixedTestStage
			if want == Uncertain {
				name = fixedTestName
			}
			_, err = os.Stat(filepath.Join(path, name))
			require.NoError(t, err)
		})
	}
}
func TestFixedSegmentWaitsForDataSyncAndKeepsOwnership(t *testing.T) {
	path, d, s := fixedTestSegment(t)
	moved := path + "-moved"
	require.NoError(t, os.Rename(path, moved))
	defer func() { require.NoError(t, os.RemoveAll(moved)) }()
	require.NoError(t, os.Mkdir(path, 0700))
	reached, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	s.ops.dataSync = func(f *os.File) error { close(reached); <-release; return unix.Fdatasync(int(f.Fd())) }
	result := make(chan error, 1)
	go func() {
		out, err := s.Commit(make([]byte, FixedSegmentBlock), make([]byte, FixedSegmentBlock))
		if out != Committed && err == nil {
			err = errors.New("unexpected outcome")
		}
		result <- err
	}()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("sync not reached")
	}
	select {
	case <-result:
		t.Fatal("completed before data sync")
	default:
	}
	other, err := OpenDir(moved)
	require.NoError(t, err)
	defer func() { require.NoError(t, other.Close()) }()
	_, err = other.Lock(fixedTestName)
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, os.Rename(filepath.Join(moved, fixedTestName), filepath.Join(moved, "alias")))
	_, err = other.Lock("alias")
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, os.Rename(filepath.Join(moved, "alias"), filepath.Join(moved, fixedTestName)))
	close(release)
	require.NoError(t, <-result)
	require.EqualValues(t, FixedSegmentBytes, s.AllocatedBytes())
	_, err = os.Stat(filepath.Join(path, fixedTestName))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.NotNil(t, d)
}
func TestFixedSegmentRejectsChangedIdentitySizeAndAllocation(t *testing.T) {
	for _, kind := range []string{"size", "hole", "inode", "hardlink", "mode", "parent-mode", "stable-inode", "io-descriptor", "parent-descriptor"} {
		t.Run(kind, func(t *testing.T) {
			path, d, s := fixedTestSegment(t)
			switch kind {
			case "size":
				require.NoError(t, os.Truncate(filepath.Join(path, fixedTestName), FixedSegmentBytes+1))
			case "hole":
				require.NoError(t, unix.Fallocate(int(s.file.Fd()), unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, FixedSegmentDataStart, FixedSegmentBlock))
			case "inode":
				require.NoError(t, os.Rename(filepath.Join(path, fixedTestName), filepath.Join(path, "old")))
				require.NoError(t, os.WriteFile(filepath.Join(path, fixedTestName), []byte("different"), 0600))
			case "hardlink":
				require.NoError(t, os.Link(filepath.Join(path, fixedTestName), filepath.Join(path, "alias")))
			case "mode":
				require.NoError(t, os.Chmod(filepath.Join(path, fixedTestName), 0400))
			case "parent-mode":
				require.NoError(t, os.Chmod(path, 0777))
				defer func() { require.NoError(t, os.Chmod(path, 0700)) }()
			case "stable-inode":
				name := s.owner.file.Name()
				require.NoError(t, os.Rename(filepath.Join(path, name), filepath.Join(path, "old-lock")))
				require.NoError(t, os.WriteFile(filepath.Join(path, name), nil, 0600))
			case "io-descriptor":
				replacement, err := os.CreateTemp(path, "io-substitute-")
				require.NoError(t, err)
				defer func() { require.NoError(t, replacement.Close()) }()
				old := s.file
				s.file = replacement
				defer func() { s.file = old }()
			case "parent-descriptor":
				otherPath := t.TempDir()
				other, err := os.Open(otherPath)
				require.NoError(t, err)
				defer func() { require.NoError(t, other.Close()) }()
				old := d.file
				d.file = other
				defer func() { d.file = old }()
			}
			out, err := s.Commit(make([]byte, FixedSegmentBlock), make([]byte, FixedSegmentBlock))
			require.Equal(t, NotCommitted, out)
			require.Error(t, err)
		})
	}
}
func TestFixedSegmentDirtyTailAndBounds(t *testing.T) {
	path, d, s := fixedTestSegment(t)
	require.NoError(t, s.Close())
	f, err := os.OpenFile(filepath.Join(path, fixedTestName), os.O_RDWR, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte{1}, FixedSegmentDataStart)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	reopened, err := d.OpenFixedSegment(fixedTestName)
	require.NoError(t, err)
	defer func() { require.NoError(t, reopened.Close()) }()
	require.ErrorIs(t, reopened.Activate(FixedSegmentDataStart, 1), ErrFixedDirtyTail)
	require.ErrorIs(t, reopened.Activate(FixedSegmentDataStart+FixedSegmentBlock, 1), ErrFixedDirtyTail)
	for _, offset := range []int64{-1, FixedSegmentBytes, 1 << 62} {
		require.Error(t, reopened.ReadAt(make([]byte, 1), offset))
	}
}
func TestFixedSegmentProcessDeath(t *testing.T) {
	if stage := os.Getenv("SECURESTORE_FIXED_CRASH"); stage != "" {
		d, err := OpenDir(os.Getenv("SECURESTORE_FIXED_DIR"))
		require.NoError(t, err)
		_, err = d.Lock(fixedTestName)
		require.NoError(t, err)
		s, err := d.OpenFixedSegment(fixedTestName)
		require.NoError(t, err)
		require.NoError(t, s.Activate(FixedSegmentDataStart, 1))
		s.ops.writeAt = func(f *os.File, b []byte, off int64) (int, error) {
			if off >= FixedSegmentDataStart && stage == "data-partial" {
				n, err := f.WriteAt(b[:17], off)
				require.NoError(t, err)
				require.Equal(t, 17, n)
				os.Exit(80)
			}
			if off < FixedSegmentDataStart && stage == "before-head" {
				os.Exit(80)
			}
			if off < FixedSegmentDataStart && stage == "head-partial" {
				n, err := f.WriteAt(b[:128], off)
				require.NoError(t, err)
				require.Equal(t, 128, n)
				os.Exit(80)
			}
			n, err := f.WriteAt(b, off)
			if off < FixedSegmentDataStart && stage == "after-head" {
				os.Exit(80)
			}
			return n, err
		}
		s.ops.dataSync = func(f *os.File) error {
			if stage == "before-sync" {
				os.Exit(80)
			}
			err := unix.Fdatasync(int(f.Fd()))
			if err == nil && stage == "after-sync" {
				os.Exit(80)
			}
			return err
		}
		_, err = s.Commit(bytes.Repeat([]byte{0x44}, FixedSegmentBlock), bytes.Repeat([]byte{0x48}, FixedSegmentBlock))
		t.Fatalf("crash boundary not reached: %v", err)
	}
	for _, stage := range []string{"data-partial", "before-head", "head-partial", "after-head", "before-sync", "after-sync"} {
		t.Run(stage, func(t *testing.T) {
			path, d, s := fixedTestSegment(t)
			require.NoError(t, s.Close())
			require.NoError(t, s.owner.Close())
			require.NoError(t, d.Close())
			child := exec.Command(os.Args[0], "-test.run=^TestFixedSegmentProcessDeath$")
			child.Env = append(os.Environ(), "SECURESTORE_FIXED_CRASH="+stage, "SECURESTORE_FIXED_DIR="+path)
			err := child.Run()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			require.Equal(t, 80, exit.ExitCode())
			f, err := os.Open(filepath.Join(path, fixedTestName))
			require.NoError(t, err)
			st, err := f.Stat()
			require.NoError(t, err)
			require.EqualValues(t, FixedSegmentBytes, st.Size())
			data := make([]byte, FixedSegmentDataStart+1)
			_, err = f.ReadAt(data, 0)
			require.NoError(t, err)
			require.NoError(t, f.Close())
			require.Equal(t, bytes.Repeat([]byte{0x53}, FixedSegmentBlock), data[:FixedSegmentBlock])
			require.Equal(t, byte(0x44), data[FixedSegmentDataStart])
			if stage == "data-partial" || stage == "before-head" {
				require.Equal(t, byte(0x53), data[FixedSegmentBlock])
			} else {
				require.Equal(t, byte(0x48), data[FixedSegmentBlock])
			}
		})
	}
}

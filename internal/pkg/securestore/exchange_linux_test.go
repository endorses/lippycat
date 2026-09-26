//go:build linux

package securestore

import (
	"errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const exchangeStage = ".lch-stage-00112233445566778899aabbccddeeff.tmp"
const exchangeArchive = "head-112233445566778899aabbccddeeff00.lhc"

func TestExchangePublicationFaults(t *testing.T) {
	for _, stage := range []string{"success", "write", "zero-write", "invalid-write", "file-sync", "writer-close", "unsupported-exchange", "archive", "archive-after", "parent-sync", "retired-close"} {
		t.Run(stage, func(t *testing.T) {
			path, d, _ := groupedTestStore(t)
			injected := errors.New("synthetic exchange failure")
			d.ops.write = func(f *os.File, b []byte) (int, error) {
				switch stage {
				case "write":
					return 0, injected
				case "zero-write":
					return 0, nil
				case "invalid-write":
					return len(b) + 1, nil
				}
				return f.Write(b)
			}
			d.ops.sync = func(f *os.File) error {
				if stage == "file-sync" && f != d.file || stage == "parent-sync" && f == d.file {
					return injected
				}
				return f.Sync()
			}
			closes := 0
			d.ops.close = func(f *os.File) error {
				closes++
				err := f.Close()
				if stage == "writer-close" && closes == 1 || stage == "retired-close" && closes == 2 {
					return errors.Join(err, injected)
				}
				return err
			}
			d.ops.exchange = func(a int, from string, b int, to string) error {
				if stage == "unsupported-exchange" {
					return unix.EOPNOTSUPP
				}
				return exchangeNames(a, from, b, to)
			}
			d.ops.noReplace = func(a int, from string, b int, to string) (bool, bool, error) {
				if stage == "archive" {
					return false, true, injected
				}
				published, remaining, err := publishNoReplace(a, from, b, to)
				if stage == "archive-after" {
					err = errors.Join(err, injected)
				}
				return published, remaining, err
			}
			out, err := d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new-head"))
			expected := NotCommitted
			if stage == "success" || stage == "retired-close" {
				expected = Committed
			} else if stage == "archive" || stage == "archive-after" || stage == "parent-sync" {
				expected = Uncertain
			}
			require.Equal(t, expected, out)
			if stage == "success" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Equal(t, expected, OutcomeOf(err))
				require.NotContains(t, err.Error(), "new-head")
			}
			head, err := os.ReadFile(filepath.Join(path, "head"))
			require.NoError(t, err)
			if expected == NotCommitted {
				require.Equal(t, "old-head", string(head))
			} else {
				require.Equal(t, "new-head", string(head))
			}
			if stage == "archive" {
				old, err := os.ReadFile(filepath.Join(path, exchangeStage))
				require.NoError(t, err)
				require.Equal(t, "old-head", string(old))
			}
			if stage == "success" || stage == "archive-after" || stage == "parent-sync" || stage == "retired-close" {
				old, err := os.ReadFile(filepath.Join(path, exchangeArchive))
				require.NoError(t, err)
				require.Equal(t, "old-head", string(old))
			}
			// Recovery of generic private-writer temporaries must never delete stages.
			if expected == NotCommitted || stage == "archive" {
				_, err = d.RecoverTemporaries()
				require.NoError(t, err)
				_, err = os.Stat(filepath.Join(path, exchangeStage))
				require.NoError(t, err)
			}
		})
	}
}

func TestExchangeInitialBoundsAndOwnership(t *testing.T) {
	path, d := privateTestDir(t)
	lock, err := d.Lock("head")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lock.Close()) })
	_, err = d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new"))
	require.Error(t, err)
	out, err := d.ExchangeAndArchive(exchangeStage, "head", "", []byte("root"))
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	_, err = d.ExchangeAndArchive(exchangeStage, "head", "", []byte("root"))
	require.Error(t, err)
	for _, names := range [][3]string{{"head", "head", exchangeArchive}, {exchangeStage, "head", "head"}, {"../stage", "head", exchangeArchive}, {".securestore-tmp-0011", "head", exchangeArchive}, {exchangeStage, "unowned", exchangeArchive}} {
		out, err := d.ExchangeAndArchive(names[0], names[1], names[2], []byte("new"))
		require.Equal(t, NotCommitted, out)
		require.Error(t, err)
	}
	for _, data := range [][]byte{nil, make([]byte, MaxExchangeBytes+1)} {
		_, err = d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, data)
		require.Error(t, err)
	}
	require.NoError(t, os.Link(filepath.Join(path, "head"), filepath.Join(path, "alias")))
	_, err = d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new"))
	require.Error(t, err)
	require.NoError(t, os.Remove(filepath.Join(path, "alias")))
	require.NoError(t, os.WriteFile(filepath.Join(path, exchangeArchive), []byte("collision"), 0600))
	_, err = d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new"))
	require.ErrorIs(t, err, os.ErrExist)
	require.NoError(t, os.Remove(filepath.Join(path, exchangeArchive)))
	require.NoError(t, os.Rename(filepath.Join(path, "head"), filepath.Join(path, "old")))
	require.NoError(t, os.WriteFile(filepath.Join(path, "head"), []byte("substituted"), 0600))
	_, err = d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new"))
	require.ErrorContains(t, err, "identity")
}

func TestExchangeWaitsForParentAndRetainsLocks(t *testing.T) {
	path, d, _ := groupedTestStore(t)
	moved := path + "-moved"
	require.NoError(t, os.Rename(path, moved))
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(moved)) })
	require.NoError(t, os.Mkdir(path, 0700))
	reached, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	d.ops.sync = func(f *os.File) error {
		if f == d.file {
			close(reached)
			<-release
		}
		return f.Sync()
	}
	result := make(chan error, 1)
	go func() {
		_, err := d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new-head"))
		result <- err
	}()
	select {
	case <-reached:
	case <-time.After(time.Second):
		t.Fatal("missing parent sync")
	}
	select {
	case <-result:
		t.Fatal("returned before directory sync")
	default:
	}
	other, err := OpenDir(moved)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, other.Close()) })
	_, err = other.Lock("head")
	require.ErrorIs(t, err, ErrLocked)
	// Both data inodes remain locked through the commit boundary, including archive.
	_, err = other.Lock(exchangeArchive)
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, os.Rename(filepath.Join(moved, "head"), filepath.Join(moved, "head-alias")))
	_, err = other.Lock("head-alias")
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, os.Rename(filepath.Join(moved, "head-alias"), filepath.Join(moved, "head")))
	close(release)
	require.NoError(t, <-result)
	_, err = os.Stat(filepath.Join(path, "head"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestExchangeProcessDeath(t *testing.T) {
	if stage := os.Getenv("SECURESTORE_EXCHANGE_CRASH"); stage != "" {
		d, err := OpenDir(os.Getenv("SECURESTORE_EXCHANGE_DIR"))
		require.NoError(t, err)
		_, err = d.Lock("head")
		require.NoError(t, err)
		d.ops.exchange = func(a int, from string, b int, to string) error {
			if stage == "before-exchange" {
				os.Exit(79)
			}
			err := exchangeNames(a, from, b, to)
			if err == nil && stage == "after-exchange" {
				os.Exit(79)
			}
			return err
		}
		d.ops.noReplace = func(a int, from string, b int, to string) (bool, bool, error) {
			if stage == "before-archive" {
				os.Exit(79)
			}
			p, r, err := publishNoReplace(a, from, b, to)
			if err == nil && stage == "after-archive" {
				os.Exit(79)
			}
			return p, r, err
		}
		d.ops.sync = func(f *os.File) error {
			if f == d.file && stage == "before-parent" {
				os.Exit(79)
			}
			err := f.Sync()
			if err == nil && f == d.file && stage == "after-parent" {
				os.Exit(79)
			}
			return err
		}
		_, err = d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new-head"))
		t.Fatalf("crash not reached: %v", err)
	}
	for _, stage := range []string{"before-exchange", "after-exchange", "before-archive", "after-archive", "before-parent", "after-parent"} {
		t.Run(stage, func(t *testing.T) {
			path, d, lock := groupedTestStore(t)
			require.NoError(t, lock.Close())
			require.NoError(t, d.Close())
			child := exec.Command(os.Args[0], "-test.run=^TestExchangeProcessDeath$")
			child.Env = append(os.Environ(), "SECURESTORE_EXCHANGE_CRASH="+stage, "SECURESTORE_EXCHANGE_DIR="+path)
			err := child.Run()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit)
			require.Equal(t, 79, exit.ExitCode())
			d, err = OpenDir(path)
			require.NoError(t, err)
			defer func() { require.NoError(t, d.Close()) }()
			lock, err = d.Lock("head")
			require.NoError(t, err)
			defer func() { require.NoError(t, lock.Close()) }()
			head, err := d.Read("head", 64)
			require.NoError(t, err)
			expected := "new-head"
			if stage == "before-exchange" {
				expected = "old-head"
			}
			require.Equal(t, expected, string(head))
			oldName := exchangeArchive
			if stage == "before-exchange" || stage == "after-exchange" || stage == "before-archive" {
				oldName = exchangeStage
			}
			old, err := d.Read(oldName, 64)
			require.NoError(t, err)
			if stage == "before-exchange" {
				require.Equal(t, "new-head", string(old))
			} else {
				require.Equal(t, "old-head", string(old))
			}
		})
	}
}

func TestExchangeFullBoundPartialWritesAndStageSubstitution(t *testing.T) {
	t.Run("full-bound-short-writes", func(t *testing.T) {
		_, d, _ := groupedTestStore(t)
		d.ops.write = func(f *os.File, data []byte) (int, error) { return f.Write(data[:min(len(data), 32768)]) }
		out, err := d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, make([]byte, MaxExchangeBytes))
		require.NoError(t, err)
		require.Equal(t, Committed, out)
		data, err := d.Read("head", MaxExchangeBytes)
		require.NoError(t, err)
		require.Len(t, data, MaxExchangeBytes)
	})
	t.Run("substituted-stage", func(t *testing.T) {
		path, d, _ := groupedTestStore(t)
		d.ops.close = func(f *os.File) error {
			err := f.Close()
			require.NoError(t, os.Rename(filepath.Join(path, exchangeStage), filepath.Join(path, "displaced-candidate")))
			require.NoError(t, os.WriteFile(filepath.Join(path, exchangeStage), []byte("other"), 0600))
			return err
		}
		out, err := d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new-head"))
		require.Equal(t, NotCommitted, out)
		require.ErrorContains(t, err, "identity")
		old, err := d.Read("head", 64)
		require.NoError(t, err)
		require.Equal(t, "old-head", string(old))
	})
	t.Run("archive-collision-after-exchange", func(t *testing.T) {
		path, d, _ := groupedTestStore(t)
		d.ops.exchange = func(a int, from string, b int, to string) error {
			err := exchangeNames(a, from, b, to)
			require.NoError(t, os.WriteFile(filepath.Join(path, exchangeArchive), []byte("collision"), 0600))
			return err
		}
		out, err := d.ExchangeAndArchive(exchangeStage, "head", exchangeArchive, []byte("new-head"))
		require.Equal(t, Uncertain, out)
		require.ErrorIs(t, err, os.ErrExist)
		old, err := d.Read(exchangeStage, 64)
		require.NoError(t, err)
		require.Equal(t, "old-head", string(old))
	})
}

//go:build linux

package securestore

import (
	"bytes"
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

func rotationConfig() RotationIOConfig {
	return RotationIOConfig{Token: strings.Repeat("a", 64), Purpose: FilterSnapshot, Destination: "snapshot", UsageName: ".usage-" + strings.Repeat("b", 64), EnvelopeBytes: 32 << 10, MaxWorkingBytes: 1 << 20}
}

func rotationTestIO(t *testing.T) (string, *Dir, *RotationIO) {
	t.Helper()
	path, dir := privateTestDir(t)
	lock, err := dir.Lock("snapshot")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, lock.Close()) })
	r, err := OpenRotationIO(dir, rotationConfig())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, r.Close()) })
	return path, dir, r
}

func TestRotationIOPreallocatesExactBoundedRoles(t *testing.T) {
	path, dir, r := rotationTestIO(t)
	require.NoError(t, r.PrepareAll())
	n, err := r.AllocatedBytes()
	require.NoError(t, err)
	require.Equal(t, 2*r.rounded(RotationCandidate)+5*r.rounded(RotationBootstrap), n)
	require.Equal(t, 2*r.rounded(RotationCandidate)+12*r.rounded(RotationBootstrap), r.RequiredBytes())
	for role := RotationRole(0); role < rotationRoleCount; role++ {
		st, err := r.ops.stat(int(r.slots[role].file.Fd()))
		require.NoError(t, err)
		require.Zero(t, st.Size, "preallocation must not add logical padding")
		require.Equal(t, r.rounded(role), st.Blocks*512)
		require.Equal(t, uint32(0600), st.Mode&07777)
	}
	for role := RotationRole(0); role < rotationRoleCount; role++ {
		out, err := r.Create(role, []byte("encoded"))
		require.NoError(t, err)
		require.Equal(t, Committed, out)
		data, err := dir.Read(r.names[role], r.limit(role))
		require.NoError(t, err)
		require.Equal(t, "encoded", string(data))
		allocated, err := dir.AllocatedSize(r.names[role])
		require.NoError(t, err)
		require.Equal(t, r.rounded(role), allocated, "rename preserves physical reservation")
	}
	// Metadata rewrites charge current plus pending, never accumulate a third slot.
	for i := 0; i < 3; i++ {
		require.NoError(t, r.Prepare(RotationProgress))
		out, err := r.Replace(RotationProgress, bytes.Repeat([]byte{'x'}, i+1))
		require.NoError(t, err)
		require.Equal(t, Committed, out)
	}
	n, err = r.AllocatedBytes()
	require.NoError(t, err)
	require.LessOrEqual(t, n, r.RequiredBytes())
	require.NoError(t, r.Close())
	entries, err := os.ReadDir(path)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasPrefix(entry.Name(), rotationTempPrefix))
	}
}

func TestRotationIORejectsInvalidConfigurationBeforeArtifacts(t *testing.T) {
	_, dir, r := rotationTestIO(t)
	for _, alter := range []func(*RotationIOConfig){
		func(c *RotationIOConfig) { c.Token = "../escape" },
		func(c *RotationIOConfig) { c.Token = strings.Repeat("A", 64) },
		func(c *RotationIOConfig) { c.Token = strings.Repeat("0", 64) },
		func(c *RotationIOConfig) { c.Purpose = X2Product },
		func(c *RotationIOConfig) { c.Destination = "../snapshot" },
		func(c *RotationIOConfig) { c.Destination = ".rotation-reserved" },
		func(c *RotationIOConfig) { c.UsageName = "ledger" },
		func(c *RotationIOConfig) { c.EnvelopeBytes = MaxEnvelopeBytes + 1 },
		func(c *RotationIOConfig) { c.MaxWorkingBytes = r.RequiredBytes() - 1 },
	} {
		cfg := rotationConfig()
		alter(&cfg)
		_, err := OpenRotationIO(dir, cfg)
		require.Error(t, err)
	}
	_, err := r.Name(rotationRoleCount)
	require.Error(t, err)
	temps, n, err := r.inventory()
	require.NoError(t, err)
	require.Empty(t, temps)
	require.Zero(t, n)
	require.Error(t, r.owner.Close(), "active mutable handle retains ownership")
	require.NoError(t, r.Close())
	require.NoError(t, r.owner.Close())
	_, err = OpenRotationIO(dir, rotationConfig())
	require.ErrorContains(t, err, "ownership")
}

func TestRotationIORejectsUnsupportedOrFalseAllocation(t *testing.T) {
	for _, kind := range []string{"unsupported", "full", "sparse", "overallocated", "grew-length"} {
		t.Run(kind, func(t *testing.T) {
			_, _, r := rotationTestIO(t)
			allocate := r.ops.allocate
			r.ops.allocate = func(f *os.File, n int64) error {
				switch kind {
				case "unsupported":
					return unix.EOPNOTSUPP
				case "full":
					return unix.ENOSPC
				case "sparse":
					return nil
				case "overallocated":
					return allocate(f, n+r.unit)
				default:
					return unix.Fallocate(int(f.Fd()), 0, 0, n)
				}
			}
			require.Error(t, r.Prepare(RotationProgress))
			require.ErrorIs(t, r.Prepare(RotationProgress), ErrRotationIOFault)
			temps, _, err := r.inventory()
			require.NoError(t, err)
			require.Empty(t, temps)
		})
	}
}

func TestRotationIOFaultOutcomesAndRetainedLocks(t *testing.T) {
	for _, stage := range []string{"partial", "zero", "full", "file-sync", "close", "rename", "dir-sync", "short-success"} {
		t.Run(stage, func(t *testing.T) {
			path, dir, r := rotationTestIO(t)
			_, err := dir.Create("snapshot", []byte("original"))
			require.NoError(t, err)
			require.NoError(t, r.Prepare(RotationDestination))
			fault := errors.New("injected rotation fault")
			switch stage {
			case "partial":
				dir.ops.write = func(f *os.File, b []byte) (int, error) { n, _ := f.Write(b[:1]); return n, fault }
			case "zero":
				dir.ops.write = func(*os.File, []byte) (int, error) { return 0, nil }
			case "full":
				dir.ops.write = func(*os.File, []byte) (int, error) { return 0, unix.ENOSPC }
			case "file-sync":
				dir.ops.sync = func(f *os.File) error {
					if f != dir.file {
						return fault
					}
					return f.Sync()
				}
			case "close":
				dir.ops.close = func(f *os.File) error { return errors.Join(f.Close(), fault) }
			case "rename":
				dir.ops.rename = func(int, string, int, string) error { return fault }
			case "dir-sync":
				dir.ops.sync = func(f *os.File) error {
					if f == dir.file {
						return fault
					}
					return f.Sync()
				}
			case "short-success":
				dir.ops.write = func(f *os.File, b []byte) (int, error) { return f.Write(b[:1]) }
			}
			out, err := r.Replace(RotationDestination, []byte("replacement"))
			want, expected := "original", NotCommitted
			if stage == "dir-sync" {
				want, expected = "replacement", Uncertain
			} else if stage == "short-success" {
				want, expected = "replacement", Committed
			}
			require.Equal(t, expected, out)
			if expected != Committed {
				require.Error(t, err)
				require.Equal(t, out, OutcomeOf(err))
				require.ErrorIs(t, r.Prepare(RotationProgress), ErrRotationIOFault)
			} else {
				require.NoError(t, err)
			}
			data, err := os.ReadFile(filepath.Join(path, "snapshot"))
			require.NoError(t, err)
			require.Equal(t, want, string(data))
			dir.ops = defaultFileOps()
			other, err := OpenDir(path)
			require.NoError(t, err)
			defer func() { require.NoError(t, other.Close()) }()
			_, err = other.Lock("snapshot")
			require.ErrorIs(t, err, ErrLocked)
			require.NoError(t, os.Rename(filepath.Join(path, "snapshot"), filepath.Join(path, "alias")))
			_, err = other.Lock("alias")
			require.ErrorIs(t, err, ErrLocked, "data inode lock survives success and uncertainty")
			require.NoError(t, os.Rename(filepath.Join(path, "alias"), filepath.Join(path, "snapshot")))
		})
	}
}

func TestRotationIONoClobberAndPublishedError(t *testing.T) {
	for _, kind := range []string{"exists", "unsupported", "after-publication"} {
		t.Run(kind, func(t *testing.T) {
			path, dir, r := rotationTestIO(t)
			if kind == "exists" {
				_, err := dir.Create("snapshot", []byte("original"))
				require.NoError(t, err)
			}
			require.NoError(t, r.Prepare(RotationDestination))
			if kind == "unsupported" {
				dir.ops.noReplace = func(int, string, int, string) (bool, bool, error) { return false, true, unix.EOPNOTSUPP }
			} else if kind == "after-publication" {
				dir.ops.noReplace = func(a int, b string, c int, d string) (bool, bool, error) {
					published, remaining, err := publishNoReplace(a, b, c, d)
					return published, remaining, errors.Join(err, unix.EIO)
				}
			}
			out, err := r.Create(RotationDestination, []byte("new"))
			require.Error(t, err)
			if kind == "after-publication" {
				require.Equal(t, Uncertain, out)
				require.NoError(t, os.Rename(filepath.Join(path, "snapshot"), filepath.Join(path, "alias")))
				other, err := OpenDir(path)
				require.NoError(t, err)
				_, err = other.Lock("alias")
				require.ErrorIs(t, err, ErrLocked)
				require.NoError(t, other.Close())
			} else {
				require.Equal(t, NotCommitted, out)
				if kind == "exists" {
					data, err := dir.Read("snapshot", 100)
					require.NoError(t, err)
					require.Equal(t, "original", string(data))
				} else {
					_, err := dir.Read("snapshot", 100)
					require.ErrorIs(t, err, os.ErrNotExist)
				}
			}
			dir.ops = defaultFileOps()
		})
	}
}

func TestRotationIORecoveryPreservesOtherOwnersAndRejectsAliases(t *testing.T) {
	for _, kind := range []string{"clean", "symlink", "hardlink", "key-alias", "bad-role", "bad-mode", "oversized", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			path, dir, r := rotationTestIO(t)
			require.NoError(t, r.Prepare(RotationProgress))
			owned := r.slots[RotationProgress].name
			require.NoError(t, r.Close())
			generic := ".securestore-tmp-" + strings.Repeat("c", 32)
			foreign := rotationTempPrefix + strings.Repeat("d", 64) + "-progress-" + strings.Repeat("e", 32)
			for _, name := range []string{generic, foreign, "unrelated"} {
				require.NoError(t, os.WriteFile(filepath.Join(path, name), []byte("retain"), 0600))
			}
			cfg := rotationConfig()
			switch kind {
			case "symlink":
				require.NoError(t, os.Remove(filepath.Join(path, owned)))
				require.NoError(t, os.Symlink("unrelated", filepath.Join(path, owned)))
			case "hardlink":
				require.NoError(t, os.Link(filepath.Join(path, owned), filepath.Join(path, "alias")))
			case "key-alias":
				require.NoError(t, os.WriteFile(filepath.Join(path, owned), bytes.Repeat([]byte{91}, 32), 0600))
				require.NoError(t, os.Rename(filepath.Join(path, owned), filepath.Join(path, "key")))
				cfg.Keyrings = []*Keyring{cryptoRing(t, KeyConfig{Active: KeyRef{ID: "key", File: filepath.Join(path, "key")}})}
				require.NoError(t, os.Rename(filepath.Join(path, "key"), filepath.Join(path, owned)))
			case "bad-role":
				require.NoError(t, os.Rename(filepath.Join(path, owned), filepath.Join(path, strings.Replace(owned, "-progress-", "-arbitrary-", 1))))
			case "bad-mode":
				require.NoError(t, os.Chmod(filepath.Join(path, owned), 0400))
			case "oversized":
				require.NoError(t, os.Truncate(filepath.Join(path, owned), rotationMetadataBytes+1))
			case "duplicate":
				require.NoError(t, os.WriteFile(filepath.Join(path, rotationTempPrefix+cfg.Token+"-progress-"+strings.Repeat("f", 32)), nil, 0600))
			}
			again, err := OpenRotationIO(dir, cfg)
			if kind != "clean" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				out, err := again.Recover()
				require.NoError(t, err)
				require.Equal(t, Committed, out)
				_, err = os.Stat(filepath.Join(path, owned))
				require.ErrorIs(t, err, os.ErrNotExist)
				require.NoError(t, again.Close())
			}
			for _, name := range []string{generic, foreign, "unrelated"} {
				data, err := os.ReadFile(filepath.Join(path, name))
				require.NoError(t, err)
				require.Equal(t, "retain", string(data))
			}
		})
	}
}

func TestRotationIOUsageAlwaysUsesAttributedReservations(t *testing.T) {
	path, dir, initial := rotationTestIO(t)
	require.NoError(t, initial.Close())
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "fresh", 77)})
	cfg := rotationConfig()
	cfg.UsageName, cfg.Keyrings = ring.UsageFileName(), []*Keyring{ring}
	r, err := OpenRotationIO(dir, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()
	id := [16]byte{1, 2, 3}
	out, err := r.InitializeUsage(ring, id)
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	usage, err := r.OpenUsage(ring, id)
	require.NoError(t, err)
	writer, err := NewWriter(usage)
	require.NoError(t, err)
	writes := 0
	dir.ops.rename = func(a int, from string, b int, to string) error {
		require.True(t, strings.HasPrefix(from, rotationTempPrefix+cfg.Token+"-usage-"))
		require.Equal(t, ring.UsageFileName(), to)
		writes++
		return unix.Renameat(a, from, b, to)
	}
	for i := 0; i < 2; i++ {
		_, err = writer.Seal(FilterSnapshot, Binding{Store: id, Object: "filters"}, []byte("data"))
		require.NoError(t, err)
		require.NoError(t, usage.Close())
		if i == 0 {
			usage, err = r.OpenUsage(ring, id)
			require.NoError(t, err)
			writer, err = NewWriter(usage)
			require.NoError(t, err)
		}
	}
	require.Equal(t, 2, writes)
	before, err := dir.Read(ring.UsageFileName(), usageBytes)
	require.NoError(t, err)
	out, err = r.InitializeUsage(ring, id)
	require.ErrorIs(t, err, os.ErrExist)
	require.Equal(t, NotCommitted, out)
	after, err := dir.Read(ring.UsageFileName(), usageBytes)
	require.NoError(t, err)
	require.Equal(t, before, after, "existing used allowance cannot be reset")
	_, seals, _, err := decodeUsage(ring.active, after)
	require.NoError(t, err)
	require.Equal(t, 2*invocationReservation, seals)
	entries, err := os.ReadDir(path)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, temporaryName(entry.Name()), "usage must never use generic temporaries")
	}
}

func TestRotationIOUsageUncertaintyPreventsSeal(t *testing.T) {
	_, dir, initial := rotationTestIO(t)
	require.NoError(t, initial.Close())
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "fresh", 78)})
	cfg := rotationConfig()
	cfg.UsageName = ring.UsageFileName()
	r, err := OpenRotationIO(dir, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()
	id := [16]byte{1}
	_, err = r.InitializeUsage(ring, id)
	require.NoError(t, err)
	u, err := r.OpenUsage(ring, id)
	require.NoError(t, err)
	defer func() { require.NoError(t, u.Close()) }()
	w, err := NewWriter(u)
	require.NoError(t, err)
	require.NoError(t, r.Prepare(RotationUsage))
	dir.ops.sync = func(f *os.File) error {
		if f == dir.file {
			return unix.EIO
		}
		return f.Sync()
	}
	data, err := w.Seal(FilterSnapshot, Binding{Store: id, Object: "filters"}, []byte("never emitted"))
	require.Nil(t, data)
	require.ErrorIs(t, err, ErrUsageFault)
	var usageErr *UsageError
	require.ErrorAs(t, err, &usageErr)
	require.Equal(t, Uncertain, usageErr.ReservationOutcome)
	require.Equal(t, NotCommitted, OutcomeOf(err))
	dir.ops = defaultFileOps()
	_, err = w.Seal(FilterSnapshot, Binding{Store: id, Object: "filters"}, nil)
	require.ErrorIs(t, err, ErrUsageFault)
}

func TestRotationIORejectsAllocationDriftAndIdentitySwap(t *testing.T) {
	for _, kind := range []string{"allocation", "identity", "oversize", "unprepared"} {
		t.Run(kind, func(t *testing.T) {
			path, dir, r := rotationTestIO(t)
			if kind != "unprepared" {
				require.NoError(t, r.Prepare(RotationProgress))
			}
			data := []byte("encoded")
			switch kind {
			case "allocation":
				dir.ops.write = func(f *os.File, b []byte) (int, error) {
					n, err := f.Write(b)
					return n, errors.Join(err, unix.Fallocate(int(f.Fd()), unix.FALLOC_FL_KEEP_SIZE, 0, r.rounded(RotationProgress)+r.unit))
				}
			case "identity":
				name := r.slots[RotationProgress].name
				require.NoError(t, os.Rename(filepath.Join(path, name), filepath.Join(path, "moved")))
				require.NoError(t, os.WriteFile(filepath.Join(path, name), nil, 0600))
			case "oversize":
				data = make([]byte, rotationMetadataBytes+1)
			}
			out, err := r.Create(RotationProgress, data)
			require.Error(t, err)
			require.Equal(t, NotCommitted, out)
			_, err = dir.Read(r.names[RotationProgress], rotationMetadataBytes)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestRotationIOReservationCleanupJoinsErrors(t *testing.T) {
	_, dir, r := rotationTestIO(t)
	allocationErr, closeErr, unlinkErr, syncErr := errors.New("allocation"), errors.New("close"), errors.New("unlink"), errors.New("sync")
	r.ops.allocate = func(*os.File, int64) error { return allocationErr }
	dir.ops.close = func(f *os.File) error { return errors.Join(f.Close(), closeErr) }
	dir.ops.unlink = func(int, string, int) error { return unlinkErr }
	dir.ops.sync = func(*os.File) error { return syncErr }
	err := r.Prepare(RotationProgress)
	for _, expected := range []error{allocationErr, closeErr, unlinkErr, syncErr} {
		require.ErrorIs(t, err, expected)
	}
	dir.ops = defaultFileOps()
	require.NoError(t, r.Close())
	again, err := OpenRotationIO(dir, rotationConfig())
	require.NoError(t, err)
	_, err = again.Recover()
	require.NoError(t, err)
	require.NoError(t, again.Close())
}

func TestRotationIORecoveryFaultOutcomes(t *testing.T) {
	for _, stage := range []string{"close", "unlink", "sync"} {
		t.Run(stage, func(t *testing.T) {
			_, dir, r := rotationTestIO(t)
			require.NoError(t, r.Prepare(RotationProgress))
			switch stage {
			case "close":
				dir.ops.close = func(f *os.File) error { return errors.Join(f.Close(), unix.EIO) }
			case "unlink":
				dir.ops.unlink = func(int, string, int) error { return unix.EIO }
			case "sync":
				dir.ops.sync = func(*os.File) error { return unix.EIO }
			}
			out, err := r.Recover()
			require.ErrorIs(t, err, unix.EIO)
			want := NotCommitted
			if stage == "sync" {
				want = Uncertain
			}
			require.Equal(t, want, out)
			require.Equal(t, want, OutcomeOf(err))
			dir.ops = defaultFileOps()
		})
	}
}

func TestRotationIOBoundedInventoryAndProtectedInput(t *testing.T) {
	path, dir, r := rotationTestIO(t)
	require.NoError(t, os.WriteFile(filepath.Join(path, "snapshot"), []byte("protected"), 0600))
	id, err := dir.FileIdentity("snapshot")
	require.NoError(t, err)
	cfg := rotationConfig()
	cfg.Protected = []FileIdentity{id}
	r.config.Protected = cfg.Protected
	_, _, err = r.inventory()
	require.ErrorContains(t, err, "protected")
	r.config.Protected = nil
	for i := 0; i < rotationInventoryMax; i++ {
		f, err := os.CreateTemp(path, "unrelated-")
		require.NoError(t, err)
		require.NoError(t, f.Close())
	}
	_, err = r.AllocatedBytes()
	require.ErrorContains(t, err, "inventory limit")
}

func TestRotationIOUsageMissingAndMismatchedKeysFailClosed(t *testing.T) {
	_, dir, initial := rotationTestIO(t)
	require.NoError(t, initial.Close())
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "active", 82)})
	cfg := rotationConfig()
	cfg.UsageName = ring.UsageFileName()
	r, err := OpenRotationIO(dir, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, r.Close()) }()
	_, err = r.OpenUsage(ring, [16]byte{1})
	require.ErrorIs(t, err, os.ErrNotExist)
	other := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "other", 83)})
	_, err = r.OpenUsage(other, [16]byte{1})
	require.ErrorContains(t, err, "does not match")
	out, err := r.InitializeUsage(other, [16]byte{1})
	require.Error(t, err)
	require.Equal(t, NotCommitted, out)
	_, err = dir.Read(ring.UsageFileName(), usageBytes)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRotationIORejectsDuplicateAndCrossHelperOwnership(t *testing.T) {
	_, dir, r := rotationTestIO(t)
	_, err := OpenRotationIO(dir, rotationConfig())
	require.ErrorIs(t, err, ErrLocked)
	_, err = dir.InitializeFixedSegment("fixed-stage", "snapshot", make([]byte, FixedSegmentDataStart))
	require.Error(t, err, "rotation ownership excludes a fixed initializer")
	require.NoError(t, r.Close())
	_, err = dir.InitializeFixedSegment("fixed-stage", "snapshot", make([]byte, FixedSegmentDataStart))
	require.NoError(t, err)
	fixed, err := dir.OpenFixedSegment("snapshot")
	require.NoError(t, err)
	_, err = OpenRotationIO(dir, rotationConfig())
	require.ErrorIs(t, err, ErrLocked, "fixed mutable handle excludes rotation")
	require.NoError(t, fixed.Close())
	again, err := OpenRotationIO(dir, rotationConfig())
	require.NoError(t, err)
	_, err = dir.OpenFixedSegment("snapshot")
	require.Error(t, err, "rotation excludes a fixed mutable handle")
	require.NoError(t, again.Close())
	fixed, err = dir.OpenFixedSegment("snapshot")
	require.NoError(t, err)
	require.NoError(t, fixed.Close())
}

func TestRotationIOChecksNamedStableAndDataOwnership(t *testing.T) {
	for _, role := range []string{"stable-lock", "data"} {
		t.Run(role, func(t *testing.T) {
			path, dir, r := rotationTestIO(t)
			_, err := dir.Create("snapshot", []byte("original"))
			require.NoError(t, err)
			require.NoError(t, r.Prepare(RotationDestination))
			name := "snapshot"
			if role == "stable-lock" {
				name = rotationLockName(name)
			}
			require.NoError(t, os.Rename(filepath.Join(path, name), filepath.Join(path, "moved")))
			require.NoError(t, os.WriteFile(filepath.Join(path, name), []byte("substitution"), 0600))
			out, err := r.Replace(RotationDestination, []byte("must not publish"))
			require.ErrorContains(t, err, "ownership inode changed")
			require.Equal(t, NotCommitted, out)
			data, err := dir.Read("snapshot", 100)
			require.NoError(t, err)
			want := "original"
			if role == "data" {
				want = "substitution"
			}
			require.Equal(t, want, string(data))
			require.NoError(t, r.Close())
			_, err = OpenRotationIO(dir, rotationConfig())
			require.Error(t, err)
			require.False(t, r.owner.rotationIOActive, "failed constructor releases its admission flag")
		})
	}
}

func TestRotationIOCommittedCleanupErrorKeepsNewInodeOwned(t *testing.T) {
	path, dir, r := rotationTestIO(t)
	_, err := dir.Create("snapshot", []byte("original"))
	require.NoError(t, err)
	require.NoError(t, r.Prepare(RotationDestination))
	dir.ops.rename = func(a int, b string, c int, d string) error {
		if err := unix.Renameat(a, b, c, d); err != nil {
			return err
		}
		return r.owner.data.Close() // subsequent handoff cleanup reports already closed
	}
	out, err := r.Replace(RotationDestination, []byte("committed"))
	require.Error(t, err)
	require.Equal(t, Committed, out)
	require.Equal(t, Committed, OutcomeOf(err))
	data, err := dir.Read("snapshot", 100)
	require.NoError(t, err)
	require.Equal(t, "committed", string(data))
	require.NoError(t, os.Rename(filepath.Join(path, "snapshot"), filepath.Join(path, "alias")))
	other, err := OpenDir(path)
	require.NoError(t, err)
	_, err = other.Lock("alias")
	require.ErrorIs(t, err, ErrLocked)
	require.NoError(t, other.Close())
}

func TestRotationIOUsageCrashBoundary(t *testing.T) {
	if stage := os.Getenv("SECURESTORE_ROTATION_USAGE_CRASH"); stage != "" {
		path := os.Getenv("SECURESTORE_ROTATION_CRASH_DIR")
		ring := cryptoRing(t, KeyConfig{Active: KeyRef{ID: "key", File: filepath.Join(path, "key")}})
		dir, err := OpenDir(path)
		require.NoError(t, err)
		_, err = dir.Lock("snapshot")
		require.NoError(t, err)
		cfg := rotationConfig()
		cfg.UsageName = ring.UsageFileName()
		r, err := OpenRotationIO(dir, cfg)
		require.NoError(t, err)
		u, err := r.OpenUsage(ring, [16]byte{1})
		require.NoError(t, err)
		w, err := NewWriter(u)
		require.NoError(t, err)
		dir.ops.rename = func(a int, b string, c int, d string) error {
			require.True(t, strings.HasPrefix(b, rotationTempPrefix+cfg.Token+"-usage-"))
			if stage == "after-rename" {
				require.NoError(t, unix.Renameat(a, b, c, d))
			}
			os.Exit(80)
			return nil
		}
		_, err = w.Seal(FilterSnapshot, Binding{Store: [16]byte{1}, Object: "filters"}, []byte("not returned"))
		t.Fatalf("child did not crash: %v", err)
	}
	for _, stage := range []string{"before-rename", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			path, dir, initial := rotationTestIO(t)
			require.NoError(t, initial.Close())
			require.NoError(t, os.WriteFile(filepath.Join(path, "key"), bytes.Repeat([]byte{93}, 32), 0600))
			ring := cryptoRing(t, KeyConfig{Active: KeyRef{ID: "key", File: filepath.Join(path, "key")}})
			cfg := rotationConfig()
			cfg.UsageName = ring.UsageFileName()
			r, err := OpenRotationIO(dir, cfg)
			require.NoError(t, err)
			_, err = r.InitializeUsage(ring, [16]byte{1})
			require.NoError(t, err)
			require.NoError(t, r.Close())
			require.NoError(t, initial.owner.Close())
			child := exec.Command(os.Args[0], "-test.run=^TestRotationIOUsageCrashBoundary$")
			child.Env = append(os.Environ(), "SECURESTORE_ROTATION_USAGE_CRASH="+stage, "SECURESTORE_ROTATION_CRASH_DIR="+path)
			output, err := child.CombinedOutput()
			var exited *exec.ExitError
			require.ErrorAs(t, err, &exited, string(output))
			require.Equal(t, 80, exited.ExitCode(), string(output))
			lock, err := dir.Lock("snapshot")
			require.NoError(t, err)
			again, err := OpenRotationIO(dir, cfg)
			require.NoError(t, err)
			_, err = again.Recover()
			require.NoError(t, err)
			u, err := again.OpenUsage(ring, [16]byte{1})
			require.NoError(t, err)
			want := uint64(0)
			if stage == "after-rename" {
				want = invocationReservation
			}
			require.Equal(t, want, u.Stats().Invocations)
			w, err := NewWriter(u)
			require.NoError(t, err)
			_, err = w.Seal(FilterSnapshot, Binding{Store: [16]byte{1}, Object: "filters"}, []byte("after restart"))
			require.NoError(t, err)
			require.Equal(t, want+invocationReservation, u.Stats().Invocations)
			require.NoError(t, u.Close())
			require.NoError(t, again.Close())
			require.NoError(t, lock.Close())
		})
	}
}

func TestRotationIOCrashBoundary(t *testing.T) {
	if stage := os.Getenv("SECURESTORE_ROTATION_CRASH_STAGE"); stage != "" {
		dir, err := OpenDir(os.Getenv("SECURESTORE_ROTATION_CRASH_DIR"))
		require.NoError(t, err)
		_, err = dir.Lock("snapshot")
		require.NoError(t, err)
		r, err := OpenRotationIO(dir, rotationConfig())
		require.NoError(t, err)
		if stage == "allocate" {
			allocate := r.ops.allocate
			r.ops.allocate = func(f *os.File, n int64) error {
				err := allocate(f, n)
				require.NoError(t, err)
				os.Exit(79)
				return nil
			}
		}
		require.NoError(t, r.Prepare(RotationDestination))
		switch stage {
		case "write":
			dir.ops.write = func(f *os.File, b []byte) (int, error) {
				_, err := f.Write(b[:1])
				require.NoError(t, err)
				os.Exit(79)
				return 0, io.EOF
			}
		case "before-rename":
			dir.ops.rename = func(int, string, int, string) error { os.Exit(79); return nil }
		case "after-rename":
			dir.ops.sync = func(f *os.File) error {
				if f == dir.file {
					os.Exit(79)
				}
				return f.Sync()
			}
		}
		_, err = r.Replace(RotationDestination, []byte("new ciphertext"))
		t.Fatalf("child did not crash: %v", err)
	}
	for _, stage := range []string{"allocate", "write", "before-rename", "after-rename"} {
		t.Run(stage, func(t *testing.T) {
			path, dir := privateTestDir(t)
			_, err := dir.Create("snapshot", []byte("old ciphertext"))
			require.NoError(t, err)
			generic := ".securestore-tmp-" + strings.Repeat("c", 32)
			require.NoError(t, os.WriteFile(filepath.Join(path, generic), []byte("unrelated"), 0600))
			child := exec.Command(os.Args[0], "-test.run=^TestRotationIOCrashBoundary$")
			child.Env = append(os.Environ(), "SECURESTORE_ROTATION_CRASH_STAGE="+stage, "SECURESTORE_ROTATION_CRASH_DIR="+path)
			output, err := child.CombinedOutput()
			var exited *exec.ExitError
			require.ErrorAs(t, err, &exited, string(output))
			require.Equal(t, 79, exited.ExitCode(), string(output))
			lock, err := dir.Lock("snapshot")
			require.NoError(t, err)
			defer func() { require.NoError(t, lock.Close()) }()
			cfg := rotationConfig()
			cfg.DestinationIsOutput = stage == "after-rename"
			r, err := OpenRotationIO(dir, cfg)
			require.NoError(t, err)
			out, err := r.Recover()
			require.NoError(t, err)
			require.Equal(t, Committed, out)
			data, err := dir.Read("snapshot", 100)
			require.NoError(t, err)
			want := "old ciphertext"
			if stage == "after-rename" {
				want = "new ciphertext"
			}
			require.Equal(t, want, string(data))
			data, err = os.ReadFile(filepath.Join(path, generic))
			require.NoError(t, err)
			require.Equal(t, "unrelated", string(data))
			require.NoError(t, r.Close())
		})
	}
}

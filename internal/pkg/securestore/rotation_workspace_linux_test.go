//go:build linux

package securestore

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func workspaceConfig() RotationWorkspaceConfig {
	cfg := RotationWorkspaceConfig{RotationIOConfig: rotationConfig()}
	for s := RotationStage(0); s < RotationSourceCatalogStage; s++ {
		cfg.Stages = append(cfg.Stages, s)
	}
	return cfg
}
func workspaceFixture(t *testing.T, cfg RotationWorkspaceConfig) (string, *Dir, *RotationWorkspace) {
	t.Helper()
	path, d := privateTestDir(t)
	for _, name := range []string{cfg.Destination, cfg.UsageName} {
		o, err := d.Lock(name)
		require.NoError(t, err)
		cfg.Owners = append(cfg.Owners, o)
		t.Cleanup(func() { require.NoError(t, o.Close()) })
	}
	w, err := OpenRotationWorkspace(d, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, w.Close()) })
	return path, d, w
}
func reopenWorkspace(t *testing.T, w *RotationWorkspace, cfg RotationWorkspaceConfig) *RotationWorkspace {
	t.Helper()
	require.NoError(t, w.Close())
	cfg.Owners = w.cfg.Owners
	fresh, err := OpenRotationWorkspace(w.dir, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, fresh.Close()) })
	return fresh
}

func TestRotationWorkspaceConsumesExactFiniteInodes(t *testing.T) {
	_, d, w := workspaceFixture(t, workspaceConfig())
	require.False(t, w.Ready())
	require.NoError(t, w.Reserve())
	require.True(t, w.Ready())
	require.Equal(t, 2*w.round(RotationPublication)+12*w.round(RotationPlanned), w.RequiredPoolBytes())
	n, err := w.AllocatedBytes()
	require.NoError(t, err)
	require.Equal(t, w.RequiredPoolBytes(), n)
	ids := map[RotationStage]FileIdentity{}
	for _, s := range w.cfg.Stages {
		st, err := validatePrivate(int(w.slots[s].file.Fd()))
		require.NoError(t, err)
		require.Zero(t, st.Size)
		ids[s] = FileIdentity{Device: uint64(st.Dev), Inode: uint64(st.Ino)}
	}
	// Reservation is irrevocably closed: no fallocate call is available to writes.
	w.ops.allocate = func(*os.File, int64) error { t.Fatal("allocation after readiness"); return nil }
	for _, s := range w.cfg.Stages {
		_, err := d.FileIdentity(w.names[s])
		create := errors.Is(err, os.ErrNotExist)
		var out Outcome
		if create {
			out, err = w.Create(s, []byte(rotationStageNames[s]))
		} else {
			out, err = w.Replace(s, []byte(rotationStageNames[s]))
		}
		require.NoError(t, err)
		require.Equal(t, Committed, out)
		id, err := d.FileIdentity(w.names[s])
		require.NoError(t, err)
		require.Equal(t, ids[s], id, "same preallocated inode must be published")
	}
	require.Equal(t, Committed, w.SnapshotOutcome())
	require.Error(t, w.Reserve(), "no refill")
	out, err := w.Replace(RotationComplete, []byte("again"))
	require.Error(t, err)
	require.Equal(t, NotCommitted, out)
}

func TestRotationWorkspaceRejectsBeforeReadinessAndInvalidSets(t *testing.T) {
	_, d, w := workspaceFixture(t, workspaceConfig())
	out, err := w.Create(RotationPlanned, []byte("unready"))
	require.Error(t, err)
	require.Equal(t, NotCommitted, out)
	entries, err := os.ReadDir(d.file.Name())
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, alter := range []func(*RotationWorkspaceConfig){
		func(c *RotationWorkspaceConfig) { c.Stages = append(c.Stages, RotationPlanned) }, func(c *RotationWorkspaceConfig) { c.Stages = []RotationStage{rotationStageCount} }, func(c *RotationWorkspaceConfig) { c.Token = "../escape" }, func(c *RotationWorkspaceConfig) { c.EnvelopeBytes = MaxEnvelopeBytes + 1 }, func(c *RotationWorkspaceConfig) { c.MaxWorkingBytes = 1 }, func(c *RotationWorkspaceConfig) { c.UsageName = "not-usage" }, func(c *RotationWorkspaceConfig) { c.Owners = c.Owners[:1] }, func(c *RotationWorkspaceConfig) { c.Owners[1] = c.Owners[0] }, func(c *RotationWorkspaceConfig) { c.DestinationIsOutput = true },
	} {
		require.NoError(t, w.Close())
		cfg := workspaceConfig()
		cfg.Owners = append([]*Lock(nil), w.cfg.Owners...)
		alter(&cfg)
		_, err := OpenRotationWorkspace(d, cfg)
		require.Error(t, err)
	}
}

func TestRotationWorkspaceEveryReservationCutRequiresWholeRebuild(t *testing.T) {
	for _, kind := range []string{"allocate", "file-sync"} {
		for failed := 0; failed < int(RotationSourceCatalogStage); failed++ {
			t.Run(fmt.Sprintf("%s-%d", kind, failed), func(t *testing.T) {
				path, d, w := workspaceFixture(t, workspaceConfig())
				calls := 0
				alloc := w.ops.allocate
				syncFile := d.ops.sync
				if kind == "allocate" {
					w.ops.allocate = func(f *os.File, n int64) error {
						calls++
						if calls == failed+1 {
							return unix.ENOSPC
						}
						return alloc(f, n)
					}
				} else {
					d.ops.sync = func(f *os.File) error {
						if f != d.file {
							calls++
							if calls == failed+1 {
								return unix.EIO
							}
						}
						return syncFile(f)
					}
				}
				require.Error(t, w.Reserve())
				require.False(t, w.Ready())
				require.Equal(t, NotCommitted, w.SnapshotOutcome())
				out, err := w.Create(RotationPlanned, []byte("no"))
				require.Error(t, err)
				require.Equal(t, NotCommitted, out)
				d.ops.sync = syncFile
				w = reopenWorkspace(t, w, workspaceConfig())
				out, err = w.RecoverUnselected()
				require.NoError(t, err)
				require.Equal(t, Committed, out)
				entries, err := os.ReadDir(path)
				require.NoError(t, err)
				require.Len(t, entries, 2)
				require.NoError(t, w.Reserve())
				require.True(t, w.Ready())
			})
		}
	}
}

func TestRotationWorkspaceUnsupportedAllocationAndGateSync(t *testing.T) {
	for _, kind := range []string{"unsupported", "sparse", "over", "gate-sync"} {
		t.Run(kind, func(t *testing.T) {
			_, d, w := workspaceFixture(t, workspaceConfig())
			allocate := w.ops.allocate
			syncFile := d.ops.sync
			switch kind {
			case "unsupported":
				w.ops.allocate = func(*os.File, int64) error { return unix.EOPNOTSUPP }
			case "sparse":
				w.ops.allocate = func(*os.File, int64) error { return nil }
			case "over":
				w.ops.allocate = func(f *os.File, n int64) error { return allocate(f, n+w.unit) }
			case "gate-sync":
				d.ops.sync = func(f *os.File) error {
					if f == d.file {
						return unix.EIO
					}
					return syncFile(f)
				}
			}
			require.Error(t, w.Reserve())
			require.False(t, w.Ready())
			d.ops.sync = syncFile
		})
	}
}

func TestRotationWorkspaceAllStagePublicationFaults(t *testing.T) {
	for s := RotationStage(0); s < RotationSourceCatalogStage; s++ {
		for _, kind := range []string{"short", "disk-full", "file-sync", "close", "rename", "directory-sync"} {
			t.Run(rotationStageNames[s]+"-"+kind, func(t *testing.T) {
				_, d, w := workspaceFixture(t, workspaceConfig())
				require.NoError(t, w.Reserve())
				base := d.ops
				defer func() { d.ops = base }()
				switch kind {
				case "short":
					d.ops.write = func(*os.File, []byte) (int, error) { return 0, nil }
				case "disk-full":
					d.ops.write = func(f *os.File, b []byte) (int, error) { n, e := f.Write(b[:1]); return n, errors.Join(e, unix.ENOSPC) }
				case "file-sync":
					d.ops.sync = func(f *os.File) error {
						if f != d.file {
							return unix.EIO
						}
						return base.sync(f)
					}
				case "close":
					d.ops.close = func(f *os.File) error { return errors.Join(base.close(f), unix.EIO) }
				case "rename":
					d.ops.noReplace = func(int, string, int, string) (bool, bool, error) { return false, false, unix.EIO }
				case "directory-sync":
					d.ops.sync = func(f *os.File) error {
						if f == d.file {
							return unix.EIO
						}
						return base.sync(f)
					}
				}
				out, err := w.Create(s, []byte("ciphertext"))
				require.Error(t, err)
				want := NotCommitted
				if kind == "directory-sync" {
					want = Uncertain
				}
				require.Equal(t, want, out)
				require.Equal(t, want, OutcomeOf(err))
				require.False(t, w.Ready())
				if s == RotationPublication {
					require.Equal(t, want, w.SnapshotOutcome())
				}
				if kind == "directory-sync" && (s == RotationPublication || s >= RotationUsageZero && s <= RotationUsageReservation3) {
					owner := d.locks[w.names[s]]
					require.NotNil(t, owner.data)
					require.NoError(t, rotationNamedIdentity(int(d.file.Fd()), w.names[s], owner.data))
				}
			})
		}
	}
}

func TestRotationWorkspacePartialWritesNoClobberAndReplaceFault(t *testing.T) {
	for _, kind := range []string{"partial-success", "existing", "unsupported-no-replace", "replace-failure", "published-error"} {
		t.Run(kind, func(t *testing.T) {
			_, d, w := workspaceFixture(t, workspaceConfig())
			require.NoError(t, w.Reserve())
			base := d.ops
			defer func() { d.ops = base }()
			if kind == "partial-success" {
				d.ops.write = func(f *os.File, b []byte) (int, error) { return base.write(f, b[:1]) }
				out, err := w.Create(RotationPublication, []byte("ciphertext"))
				require.NoError(t, err)
				require.Equal(t, Committed, out)
				return
			}
			if kind == "existing" || kind == "replace-failure" {
				out, err := w.Create(RotationBootstrapUninitialized, []byte("U"))
				require.NoError(t, err)
				require.Equal(t, Committed, out)
			}
			if kind == "unsupported-no-replace" {
				d.ops.noReplace = func(int, string, int, string) (bool, bool, error) { return false, false, unix.EOPNOTSUPP }
			}
			if kind == "replace-failure" {
				d.ops.rename = func(int, string, int, string) error { return unix.EIO }
				out, err := w.Replace(RotationBootstrapRequired, []byte("R"))
				require.Error(t, err)
				require.Equal(t, NotCommitted, out)
				return
			}
			if kind == "published-error" {
				d.ops.noReplace = func(a int, b string, c int, e string) (bool, bool, error) {
					p, r, err := base.noReplace(a, b, c, e)
					return p, r, errors.Join(err, unix.EIO)
				}
			}
			out, err := w.Create(RotationBootstrapRequired, []byte("R"))
			require.Error(t, err)
			want := NotCommitted
			if kind == "published-error" {
				want = Uncertain
			}
			require.Equal(t, want, out)
		})
	}
}

func TestRotationWorkspaceOwnersAndAliases(t *testing.T) {
	for _, kind := range []string{"duplicate", "stable-moved", "data-replaced", "pending-alias", "generic-untouched", "current-alias"} {
		t.Run(kind, func(t *testing.T) {
			path, d, w := workspaceFixture(t, workspaceConfig())
			switch kind {
			case "duplicate":
				_, err := OpenRotationWorkspace(d, w.cfg)
				require.ErrorIs(t, err, ErrLocked)
				_, err = OpenRotationIO(d, w.cfg.RotationIOConfig)
				require.ErrorIs(t, err, ErrLocked)
				for _, owner := range w.cfg.Owners {
					require.Error(t, owner.Close())
				}
			case "stable-moved":
				name := rotationLockName(w.cfg.UsageName)
				require.NoError(t, os.Rename(filepath.Join(path, name), filepath.Join(path, "moved")))
				require.NoError(t, os.WriteFile(filepath.Join(path, name), nil, 0600))
				require.Error(t, w.Reserve())
			case "data-replaced":
				require.NoError(t, w.Reserve())
				out, err := w.Create(RotationUsageZero, []byte("ledger"))
				require.NoError(t, err)
				require.Equal(t, Committed, out)
				require.NoError(t, os.Rename(filepath.Join(path, w.cfg.UsageName), filepath.Join(path, "moved")))
				require.NoError(t, os.WriteFile(filepath.Join(path, w.cfg.UsageName), []byte("other"), 0600))
				_, err = w.Replace(RotationUsageReservation0, []byte("updated"))
				require.Error(t, err)
			case "pending-alias":
				require.NoError(t, w.Reserve())
				require.NoError(t, os.Link(filepath.Join(path, w.slots[RotationPlanned].name), filepath.Join(path, "alias")))
				_, err := w.Create(RotationPlanned, []byte("ciphertext"))
				require.Error(t, err)
			case "current-alias":
				require.NoError(t, w.Reserve())
				out, err := w.Create(RotationPlanned, []byte("ciphertext"))
				require.NoError(t, err)
				require.Equal(t, Committed, out)
				require.NoError(t, os.Link(filepath.Join(path, w.names[RotationPlanned]), filepath.Join(path, w.names[RotationCandidateStage])))
				_, err = w.Replace(RotationPrepared, []byte("other"))
				require.Error(t, err)
			case "generic-untouched":
				require.NoError(t, w.Reserve())
				generic := ".securestore-tmp-unrelated"
				other := rotationWorkspacePrefix + strings.Repeat("c", 64) + "-planned-" + strings.Repeat("d", 32)
				require.NoError(t, os.WriteFile(filepath.Join(path, generic), []byte("keep"), 0600))
				require.NoError(t, os.WriteFile(filepath.Join(path, other), []byte("keep"), 0600))
				w = reopenWorkspace(t, w, workspaceConfig())
				_, err := w.RecoverUnselected()
				require.NoError(t, err)
				for _, name := range []string{generic, other} {
					b, err := os.ReadFile(filepath.Join(path, name))
					require.NoError(t, err)
					require.Equal(t, "keep", string(b))
				}
			}
		})
	}
}

func TestRotationWorkspaceRecoveryPartialAndCapacitySettlement(t *testing.T) {
	for _, kind := range []string{"unlink", "cleanup-sync", "settle-then-capacity", "changed-proof"} {
		t.Run(kind, func(t *testing.T) {
			path, d, w := workspaceFixture(t, workspaceConfig())
			require.NoError(t, w.Reserve())
			cipher := []byte("new snapshot")
			out, err := w.Create(RotationPublication, cipher)
			require.NoError(t, err)
			require.Equal(t, Committed, out)
			id, err := d.FileIdentity(w.cfg.Destination)
			require.NoError(t, err)
			cfg := workspaceConfig()
			cfg.Stages = []RotationStage{RotationUsageReservation3, RotationComplete}
			cfg.PriorOutput = &RotationOutputProof{Identity: id, Bytes: int64(len(cipher)), SHA256: sha256.Sum256(cipher)}
			w = reopenWorkspace(t, w, cfg)
			base := d.ops
			defer func() { d.ops = base }()
			switch kind {
			case "unlink":
				calls := 0
				d.ops.unlink = func(fd int, s string, flags int) error {
					calls++
					if calls == 2 {
						return unix.EIO
					}
					return base.unlink(fd, s, flags)
				}
			case "cleanup-sync":
				d.ops.sync = func(f *os.File) error {
					if f == d.file {
						return unix.EIO
					}
					return base.sync(f)
				}
			case "changed-proof":
				require.NoError(t, os.WriteFile(filepath.Join(path, cfg.Destination), []byte("changed bytes"), 0600))
			}
			out, err = w.RecoverUnselected()
			if kind == "settle-then-capacity" {
				require.NoError(t, err)
				require.Equal(t, Committed, out)
				require.Equal(t, Committed, w.SnapshotOutcome())
				w.ops.allocate = func(*os.File, int64) error { return unix.ENOSPC }
				require.Error(t, w.Reserve())
				require.Equal(t, Committed, w.SnapshotOutcome())
			} else {
				require.Error(t, err)
				require.Equal(t, Uncertain, w.SnapshotOutcome())
				require.Equal(t, Uncertain, out)
			}
		})
	}
}

func TestRotationWorkspaceUsageBorrowsLockAndNeverAllocates(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new", 80)})
	cfg := workspaceConfig()
	cfg.UsageName = ring.UsageFileName()
	cfg.Keyrings = []*Keyring{ring}
	_, d, w := workspaceFixture(t, cfg)
	id := [16]byte{1}
	_, err := w.OpenUsage(ring, id)
	require.Error(t, err)
	require.NoError(t, w.Reserve())
	w.ops.allocate = func(*os.File, int64) error { t.Fatal("usage allocated after readiness"); return nil }
	out, err := w.InitializeUsage(ring, id)
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	u, err := w.OpenUsage(ring, id)
	require.NoError(t, err)
	require.Error(t, w.Close())
	_, err = w.OpenUsage(ring, id)
	require.Error(t, err)
	writer, err := NewWriter(u)
	require.NoError(t, err)
	for i := 0; i < 4; i++ {
		// Force each seal to need a distinct durable reservation. These are four
		// finite planned object seals, not four refills of a mutable role.
		if i > 0 {
			u.mu.Lock()
			u.usedSeals = u.reservedSeals
			u.mu.Unlock()
		}
		b, err := writer.Seal(FilterSnapshot, Binding{Store: id, Object: "filters"}, []byte("payload"))
		require.NoError(t, err)
		require.NotEmpty(t, b)
		require.True(t, w.slots[RotationUsageReservation0+RotationStage(i)].consumed)
	}
	_, err = writer.Seal(FilterSnapshot, Binding{Store: id, Object: "filters"}, nil)
	require.Error(t, err)
	require.Equal(t, 4*invocationReservation, u.Stats().Invocations)
	require.NoError(t, u.Close())
	require.Error(t, u.lock.Close(), "workspace still owns ledger lock")
	require.NoError(t, w.Close())
	require.NoError(t, u.lock.Close())
	fresh, err := OpenUsage(d, ring, id)
	require.NoError(t, err)
	require.Equal(t, 4*invocationReservation, fresh.usedSeals)
	require.NoError(t, fresh.Close())
}

func TestRotationWorkspaceUsageFaultsAndControlBudget(t *testing.T) {
	for _, kind := range []string{"missing", "wrong-identity", "control", "uncertain", "fault-with-headroom", "zero-no-clobber"} {
		t.Run(kind, func(t *testing.T) {
			ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new", 81)})
			cfg := workspaceConfig()
			cfg.UsageName = ring.UsageFileName()
			_, d, w := workspaceFixture(t, cfg)
			id := [16]byte{2}
			require.NoError(t, w.Reserve())
			if kind == "missing" {
				_, err := w.OpenUsage(ring, id)
				require.ErrorIs(t, err, os.ErrNotExist)
				return
			}
			out, err := w.InitializeUsage(ring, id)
			require.NoError(t, err)
			require.Equal(t, Committed, out)
			if kind == "zero-no-clobber" {
				out, err = w.InitializeUsage(ring, id)
				require.Error(t, err)
				require.Equal(t, NotCommitted, out)
				return
			}
			if kind == "wrong-identity" {
				_, err := w.OpenUsage(ring, [16]byte{3})
				require.ErrorIs(t, err, ErrBinding)
				return
			}
			u, err := w.OpenUsage(ring, id)
			require.NoError(t, err)
			defer func() { require.NoError(t, u.Close()) }()
			writer, err := NewWriter(u)
			require.NoError(t, err)
			base := d.ops
			defer func() { d.ops = base }()
			if kind == "control" {
				_, err = writer.SealControl(FilterSnapshot, Binding{Store: id, Object: "filters"}, nil)
				require.Error(t, err)
				require.Zero(t, u.Stats().Invocations)
				return
			}
			if kind == "fault-with-headroom" {
				_, err = writer.Seal(FilterSnapshot, Binding{Store: id, Object: "filters"}, nil)
				require.NoError(t, err)
				w.mu.Lock()
				w.fault = unix.EIO
				w.mu.Unlock()
			} else {
				d.ops.sync = func(f *os.File) error {
					if f == d.file {
						return unix.EIO
					}
					return base.sync(f)
				}
			}
			b, err := writer.Seal(FilterSnapshot, Binding{Store: id, Object: "filters"}, nil)
			require.Error(t, err)
			require.Nil(t, b)
			require.Equal(t, NotCommitted, OutcomeOf(err))
			require.True(t, u.Stats().Faulted)
		})
	}
}

func TestRotationWorkspaceCrashRebuild(t *testing.T) {
	if path := os.Getenv("LIPPYCAT_WORKSPACE_CRASH_PATH"); path != "" {
		d, err := OpenDir(path)
		if err != nil {
			os.Exit(2)
		}
		cfg := workspaceConfig()
		for _, name := range []string{cfg.Destination, cfg.UsageName} {
			o, err := d.Lock(name)
			if err != nil {
				os.Exit(3)
			}
			cfg.Owners = append(cfg.Owners, o)
		}
		w, err := OpenRotationWorkspace(d, cfg)
		if err != nil {
			os.Exit(4)
		}
		if err = w.Reserve(); err != nil {
			os.Exit(5)
		}
		if os.Getenv("LIPPYCAT_WORKSPACE_CRASH_WRITE") == "yes" {
			out, err := w.Create(RotationPlanned, []byte("authenticated progress placeholder"))
			if err != nil || out != Committed {
				os.Exit(6)
			}
		}
		os.Exit(0)
	}
	for _, write := range []string{"no", "yes"} {
		t.Run(write, func(t *testing.T) {
			path, d := privateTestDir(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestRotationWorkspaceCrashRebuild$")
			cmd.Env = append(os.Environ(), "LIPPYCAT_WORKSPACE_CRASH_PATH="+path, "LIPPYCAT_WORKSPACE_CRASH_WRITE="+write)
			b, err := cmd.CombinedOutput()
			require.NoError(t, err, string(b))
			cfg := workspaceConfig()
			for _, name := range []string{cfg.Destination, cfg.UsageName} {
				o, err := d.Lock(name)
				require.NoError(t, err)
				cfg.Owners = append(cfg.Owners, o)
				defer func() { require.NoError(t, o.Close()) }()
			}
			w, err := OpenRotationWorkspace(d, cfg)
			require.NoError(t, err)
			defer func() { require.NoError(t, w.Close()) }()
			require.False(t, w.Ready())
			out, err := w.RecoverUnselected()
			require.NoError(t, err)
			require.Equal(t, Committed, out)
			if write == "yes" {
				b, err := d.Read(w.names[RotationPlanned], rotationMetadataBytes)
				require.NoError(t, err)
				require.True(t, bytes.Contains(b, []byte("progress")))
			}
			require.NoError(t, w.Reserve())
		})
	}
}

func TestRotationWorkspacePhysicalDriftRejectedBeforeWrite(t *testing.T) {
	for _, kind := range []string{"allocation", "length", "inode", "permissions"} {
		t.Run(kind, func(t *testing.T) {
			path, d, w := workspaceFixture(t, workspaceConfig())
			require.NoError(t, w.Reserve())
			slot := w.slots[RotationPlanned]
			switch kind {
			case "allocation":
				// Reservation keeps EOF at zero. Punching a hole beyond EOF can
				// succeed without releasing that preallocation on some filesystems.
				// Grow then shrink so the allocated range is actually truncated,
				// leaving only allocation changed (length is again zero).
				require.NoError(t, slot.file.Truncate(w.round(RotationPlanned)))
				require.NoError(t, slot.file.Truncate(0))
				require.NoError(t, slot.file.Sync())
				var st unix.Stat_t
				require.NoError(t, unix.Fstat(int(slot.file.Fd()), &st))
				require.Zero(t, st.Size)
				require.Less(t, st.Blocks*512, w.round(RotationPlanned), "fixture must remove reserved allocation")
			case "length":
				_, err := slot.file.WriteAt([]byte("unexpected"), 0)
				require.NoError(t, err)
			case "inode":
				require.NoError(t, os.Rename(filepath.Join(path, slot.name), filepath.Join(path, "moved-slot")))
				require.NoError(t, os.WriteFile(filepath.Join(path, slot.name), nil, 0600))
			case "permissions":
				require.NoError(t, slot.file.Chmod(0400))
			}
			d.ops.write = func(*os.File, []byte) (int, error) { t.Fatal("write began after reservation drift"); return 0, nil }
			out, err := w.Create(RotationPlanned, []byte("ciphertext"))
			require.Error(t, err)
			require.Equal(t, NotCommitted, out)
		})
	}
}

func TestRotationWorkspaceRetainedAccountingAndReadonlyOwners(t *testing.T) {
	path, d := privateTestDir(t)
	cfg := workspaceConfig()
	cfg.Stages = []RotationStage{RotationComplete}
	require.NoError(t, os.WriteFile(filepath.Join(path, "source"), bytes.Repeat([]byte{'s'}, 20000), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(path, "old-ledger"), []byte("history"), 0600))
	for _, name := range []string{cfg.Destination, cfg.UsageName, "source", "old-ledger"} {
		o, err := d.Lock(name)
		require.NoError(t, err)
		cfg.Owners = append(cfg.Owners, o)
		defer func() { require.NoError(t, o.Close()) }()
	}
	id, err := d.FileIdentity("source")
	require.NoError(t, err)
	cfg.Protected = []FileIdentity{id}
	w, err := OpenRotationWorkspace(d, cfg)
	require.NoError(t, err)
	name := w.names[RotationPlanned]
	require.NoError(t, w.Close())
	require.NoError(t, os.WriteFile(filepath.Join(path, name), []byte("retained progress"), 0600))
	retained, err := d.AllocatedSize(name)
	require.NoError(t, err)
	// All four locks are charged by actual blocks, including allocated lock data.
	require.NoError(t, os.WriteFile(filepath.Join(path, rotationLockName("source")), []byte("lock"), 0600))
	lockStat, err := validatePrivate(int(cfg.Owners[2].file.Fd()))
	require.NoError(t, err)
	lockBytes := lockStat.Blocks * 512
	cfg.MaxWorkingBytes = w.pool + retained + lockBytes - 1
	w, err = OpenRotationWorkspace(d, cfg)
	require.NoError(t, err)
	require.ErrorContains(t, w.Reserve(), "retained plus remaining")
	require.NoError(t, w.Close())
	cfg.MaxWorkingBytes++
	w, err = OpenRotationWorkspace(d, cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, w.Close()) }()
	require.NoError(t, w.Reserve())
	allocated, err := w.AllocatedBytes()
	require.NoError(t, err)
	require.Equal(t, cfg.MaxWorkingBytes, allocated)
}

func TestRotationWorkspaceInventoryAndProtectedInputs(t *testing.T) {
	for _, kind := range []string{"bound", "malformed", "duplicate", "key-alias", "protected-alias"} {
		t.Run(kind, func(t *testing.T) {
			path, d, w := workspaceFixture(t, workspaceConfig())
			cfg := w.cfg
			require.NoError(t, w.Close())
			switch kind {
			case "bound":
				for i := 0; i < rotationInventoryMax; i++ {
					require.NoError(t, os.WriteFile(filepath.Join(path, fmt.Sprintf("entry-%d", i)), nil, 0600))
				}
			case "malformed":
				require.NoError(t, os.WriteFile(filepath.Join(path, rotationWorkspacePrefix+cfg.Token+"-torn"), nil, 0600))
			case "duplicate":
				for _, c := range []string{"c", "d"} {
					name := rotationWorkspacePrefix + cfg.Token + "-planned-" + strings.Repeat(c, 32)
					require.NoError(t, os.WriteFile(filepath.Join(path, name), nil, 0600))
				}
			case "key-alias":
				require.NoError(t, os.WriteFile(filepath.Join(path, w.names[RotationPlanned]), bytes.Repeat([]byte{91}, 32), 0600))
				ring := cryptoRing(t, KeyConfig{Active: KeyRef{ID: "key", File: filepath.Join(path, w.names[RotationPlanned])}})
				cfg.Keyrings = []*Keyring{ring}
			case "protected-alias":
				require.NoError(t, os.WriteFile(filepath.Join(path, w.names[RotationPlanned]), []byte("protected"), 0600))
				id, err := d.FileIdentity(w.names[RotationPlanned])
				require.NoError(t, err)
				cfg.Protected = []FileIdentity{id}
			}
			_, err := OpenRotationWorkspace(d, cfg)
			require.Error(t, err)
		})
	}
}

func TestRotationWorkspaceConcurrentUsageCloseOwnership(t *testing.T) {
	ring := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new", 93)})
	cfg := workspaceConfig()
	cfg.UsageName = ring.UsageFileName()
	_, _, w := workspaceFixture(t, cfg)
	require.NoError(t, w.Reserve())
	id := [16]byte{9}
	_, err := w.InitializeUsage(ring, id)
	require.NoError(t, err)
	u, err := w.OpenUsage(ring, id)
	require.NoError(t, err)
	writer, err := NewWriter(u)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 4; i++ {
			_, _ = writer.Seal(FilterSnapshot, Binding{Store: id, Object: "filters"}, nil)
		}
	}()
	require.NoError(t, u.Close())
	<-done
	require.NoError(t, w.Close())
}

func TestRotationWorkspaceVerificationClosePreservesCommittedOutcome(t *testing.T) {
	for _, kind := range []string{"publication", "metadata", "recovery", "settle", "readiness"} {
		t.Run(kind, func(t *testing.T) {
			_, d, w := workspaceFixture(t, workspaceConfig())
			require.NoError(t, w.Reserve())
			cipher := []byte("authenticated output")
			if kind != "publication" {
				out, err := w.Create(RotationPublication, cipher)
				require.NoError(t, err)
				require.Equal(t, Committed, out)
			}
			if kind == "recovery" || kind == "settle" || kind == "readiness" {
				cfg := workspaceConfig()
				cfg.Stages = []RotationStage{RotationComplete}
				id, err := d.FileIdentity(cfg.Destination)
				require.NoError(t, err)
				cfg.PriorOutput = &RotationOutputProof{Identity: id, Bytes: int64(len(cipher)), SHA256: sha256.Sum256(cipher)}
				w = reopenWorkspace(t, w, cfg)
				if kind == "readiness" {
					_, err := w.RecoverUnselected()
					require.NoError(t, err)
				}
			}
			base := d.ops.close
			defer func() { d.ops.close = base }()
			d.ops.close = func(f *os.File) error {
				err := base(f)
				if f.Name() == w.cfg.Destination {
					return errors.Join(err, unix.EIO)
				}
				return err
			}
			var out Outcome
			var err error
			switch kind {
			case "publication":
				out, err = w.Create(RotationPublication, cipher)
			case "metadata":
				out, err = w.Create(RotationComplete, []byte("receipt"))
			case "recovery":
				out, err = w.RecoverUnselected()
			case "settle":
				err = w.SettleOutput()
				out = OutcomeOf(err)
			case "readiness":
				err = w.Reserve()
				out = w.SnapshotOutcome()
			}
			require.ErrorIs(t, err, unix.EIO)
			require.Equal(t, Committed, out)
			require.Equal(t, Committed, w.SnapshotOutcome())
			if kind != "readiness" {
				require.Equal(t, Committed, OutcomeOf(err))
			}
			require.False(t, w.Ready())
		})
	}
}

func TestRotationWorkspaceRejectsIndependentRoleOwner(t *testing.T) {
	_, d, w := workspaceFixture(t, workspaceConfig())
	require.NoError(t, w.Reserve())
	competing, err := d.Lock(w.names[RotationPlanned])
	require.NoError(t, err)
	defer func() { require.NoError(t, competing.Close()) }()
	out, err := w.Create(RotationPlanned, []byte("ciphertext"))
	require.ErrorIs(t, err, ErrLocked)
	require.Equal(t, NotCommitted, out)
}

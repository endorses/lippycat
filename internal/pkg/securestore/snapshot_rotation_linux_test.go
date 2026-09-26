//go:build linux

package securestore

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type rotationFixture struct {
	path     string
	dir      *Dir
	old, new *Keyring
	options  SnapshotRotationOptions
	owner    SnapshotRotationOwner
	store    [16]byte
	payload  []byte
}

func newRotationFixture(t *testing.T, inPlace bool) *rotationFixture {
	t.Helper()
	path, d := privateTestDir(t)
	old := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "old", 101)})
	newKey := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new", 102)})
	store := [16]byte{8, 7}
	plain := []byte("{  \"exact\": [1, 2, 3], \"revision\": 9 }\n")
	out, err := InitializeUsage(d, old, store)
	require.NoError(t, err)
	require.Equal(t, Committed, out)
	u, err := OpenUsage(d, old, store)
	require.NoError(t, err)
	writer, err := NewWriter(u)
	require.NoError(t, err)
	b, err := writer.Seal(FilterSnapshot, Binding{Store: store, Object: "filters"}, plain)
	require.NoError(t, err)
	_, err = d.Create("source", b)
	require.NoError(t, err)
	require.NoError(t, u.Close())
	dest := filepath.Join(path, "destination")
	if inPlace {
		dest = filepath.Join(path, "source")
	}
	return &rotationFixture{path: path, dir: d, old: old, new: newKey, store: store, payload: plain, options: SnapshotRotationOptions{Source: filepath.Join(path, "source"), Destination: dest, SourceKeys: old, NewKeys: newKey, InPlace: inPlace, MaxWorkingBytes: 4 << 20}, owner: SnapshotRotationOwner{Purpose: FilterSnapshot, Object: "filters", MaxPayloadBytes: 1 << 20, Validate: func(b []byte, s [16]byte, budget int64) (SnapshotValidation, error) {
		if !bytes.Equal(b, plain) || s != store || budget <= 0 {
			return SnapshotValidation{}, ErrBinding
		}
		return SnapshotValidation{}, nil
	}}}
}
func (f *rotationFixture) assertOutput(t *testing.T, ring *Keyring, payload []byte) {
	t.Helper()
	b, err := ReadFile(f.options.Destination, MaxEnvelopeBytes)
	require.NoError(t, err)
	plain, err := ring.Open(FilterSnapshot, Binding{Store: f.store, Object: "filters"}, b, 1<<20)
	require.NoError(t, err)
	require.Equal(t, payload, plain)
}
func TestRotateSnapshotExactRoundTripAndHistory(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		t.Run(fmt.Sprint(inPlace), func(t *testing.T) {
			f := newRotationFixture(t, inPlace)
			oldLedger, err := f.dir.Read(f.old.UsageFileName(), usageBytes)
			require.NoError(t, err)
			report, err := RotateSnapshot(f.options, f.owner)
			require.NoError(t, err)
			require.Equal(t, Committed, report.Outcome)
			require.True(t, report.Complete)
			require.False(t, report.ResumeRequired)
			require.True(t, report.ExternalBackupsExcluded)
			f.assertOutput(t, f.new, f.payload)
			current, err := f.dir.Read(f.old.UsageFileName(), usageBytes)
			require.NoError(t, err)
			require.Equal(t, oldLedger, current)
			if !inPlace {
				b, err := f.dir.Read("source", MaxEnvelopeBytes)
				require.NoError(t, err)
				_, err = f.old.Open(FilterSnapshot, Binding{Store: f.store, Object: "filters"}, b, 1<<20)
				require.NoError(t, err)
			}
			f.options.Resume = true
			again, err := RotateSnapshot(f.options, f.owner)
			require.NoError(t, err)
			require.True(t, again.Complete)
			require.Equal(t, Committed, again.Outcome)
		})
	}
}

func TestRotateSnapshotResumeEveryDurableCut(t *testing.T) {
	cuts := []string{"reserved", "bootstrap-u", "usage-zero", "bootstrap-r", "usage-reserved", "planned-sealed", "planned", "candidate-sealed", "candidate", "prepared-sealed", "prepared", "publication", "complete-sealed", "complete", "temporary-cleanup", "candidate-removed"}
	for _, inPlace := range []bool{false, true} {
		for _, cut := range cuts {
			t.Run(fmt.Sprintf("%v/%s", inPlace, cut), func(t *testing.T) {
				f := newRotationFixture(t, inPlace)
				hit := false
				report, err := rotateSnapshot(f.options, f.owner, &snapshotRotationHooks{step: func(at string) error {
					if at == cut {
						hit = true
						return unix.EIO
					}
					return nil
				}})
				require.True(t, hit)
				require.Error(t, err)
				want := NotCommitted
				if cut == "publication" || cut == "complete-sealed" || cut == "complete" || cut == "temporary-cleanup" || cut == "candidate-removed" {
					want = Committed
				}
				require.Equal(t, want, report.Outcome)
				require.Equal(t, want, OutcomeOf(err))
				f.options.Resume = true
				report, err = RotateSnapshot(f.options, f.owner)
				require.NoError(t, err)
				require.True(t, report.Complete)
				require.Equal(t, Committed, report.Outcome)
				f.assertOutput(t, f.new, f.payload)
			})
		}
	}
}

func TestRotateSnapshotMissingRequiredLedgerAndExactSource(t *testing.T) {
	for _, kind := range []string{"missing-ledger", "changed-source", "changed-key", "candidate-tampered", "prepared-missing-candidate"} {
		t.Run(kind, func(t *testing.T) {
			f := newRotationFixture(t, true)
			cut := "planned"
			if kind == "missing-ledger" {
				cut = "usage-reserved"
			}
			if kind == "candidate-tampered" {
				cut = "candidate"
			}
			if kind == "prepared-missing-candidate" {
				cut = "prepared"
			}
			_, err := rotateSnapshot(f.options, f.owner, &snapshotRotationHooks{step: func(at string) error {
				if at == cut {
					return unix.EIO
				}
				return nil
			}})
			require.Error(t, err)
			names := rotationNames(FilterSnapshot, "source", f.new.UsageFileName(), "")
			switch kind {
			case "missing-ledger":
				_, err = f.dir.Remove(f.new.UsageFileName())
				require.NoError(t, err)
			case "changed-source":
				b, err := f.dir.Read("source", MaxEnvelopeBytes)
				require.NoError(t, err)
				_, err = f.dir.Replace("source", b)
				require.NoError(t, err)
			case "changed-key":
				f.options.NewKeys = cryptoRing(t, KeyConfig{Active: cryptoKey(t, "new", 103)})
			case "candidate-tampered":
				b, err := f.dir.Read(names[RotationCandidateStage], MaxEnvelopeBytes)
				require.NoError(t, err)
				b[len(b)-1] ^= 1
				_, err = f.dir.Replace(names[RotationCandidateStage], b)
				require.NoError(t, err)
			case "prepared-missing-candidate":
				_, err = f.dir.Remove(names[RotationCandidateStage])
				require.NoError(t, err)
			}
			f.options.Resume = true
			report, err := RotateSnapshot(f.options, f.owner)
			require.Error(t, err)
			require.Equal(t, NotCommitted, report.Outcome)
			if kind == "missing-ledger" {
				_, err = f.dir.Read(f.new.UsageFileName(), usageBytes)
				require.ErrorIs(t, err, os.ErrNotExist)
			}
		})
	}
}

func TestRotateSnapshotFreshRejectsAliasesAndUsedKeys(t *testing.T) {
	for _, kind := range []string{"same-key", "used-ledger", "different-parent", "source-symlink", "hardlink", "validator-mutates", "protected-absent", "protected-source"} {
		t.Run(kind, func(t *testing.T) {
			f := newRotationFixture(t, false)
			switch kind {
			case "same-key":
				f.options.NewKeys = f.old
			case "used-ledger":
				_, err := InitializeUsage(f.dir, f.new, f.store)
				require.NoError(t, err)
			case "different-parent":
				other, _ := privateTestDir(t)
				f.options.Destination = filepath.Join(other, "output")
			case "source-symlink":
				require.NoError(t, os.Symlink(f.options.Source, filepath.Join(f.path, "alias")))
				f.options.Source = filepath.Join(f.path, "alias")
			case "hardlink":
				require.NoError(t, os.Link(f.options.Source, f.options.Destination))
			case "validator-mutates":
				f.owner.Validate = func(b []byte, _ [16]byte, _ int64) (SnapshotValidation, error) {
					b[0] ^= 1
					return SnapshotValidation{}, nil
				}
			case "protected-absent":
				f.owner.Validate = func([]byte, [16]byte, int64) (SnapshotValidation, error) {
					return SnapshotValidation{ProtectedPaths: []string{f.options.Destination}}, nil
				}
			case "protected-source":
				f.owner.Validate = func([]byte, [16]byte, int64) (SnapshotValidation, error) {
					return SnapshotValidation{ProtectedPaths: []string{f.options.Source}}, nil
				}
			}
			report, err := RotateSnapshot(f.options, f.owner)
			require.Error(t, err)
			require.Equal(t, NotCommitted, report.Outcome)
		})
	}
}

func TestRotateSnapshotOldExhaustionAndNewUsageBudget(t *testing.T) {
	f := newRotationFixture(t, true)
	_, err := f.dir.Replace(f.old.UsageFileName(), encodeUsage(f.old.active, f.store, MaxKeyInvocations, MaxKeyBlocks))
	require.NoError(t, err)
	report, err := RotateSnapshot(f.options, f.owner)
	require.NoError(t, err)
	require.True(t, report.Complete)
}

func TestRotateSnapshotRuntimeSaveThenNextRotation(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		t.Run(fmt.Sprint(inPlace), func(t *testing.T) {
			f := newRotationFixture(t, inPlace)
			_, err := RotateSnapshot(f.options, f.owner)
			require.NoError(t, err)
			u, err := OpenUsage(f.dir, f.new, f.store)
			require.NoError(t, err)
			writer, err := NewWriter(u)
			require.NoError(t, err)
			changed := []byte("changed runtime payload")
			b, err := writer.Seal(FilterSnapshot, Binding{Store: f.store, Object: "filters"}, changed)
			require.NoError(t, err)
			_, err = f.dir.Replace(filepath.Base(f.options.Destination), b)
			require.NoError(t, err)
			require.NoError(t, u.Close())
			third := cryptoRing(t, KeyConfig{Active: cryptoKey(t, "third", 104)})
			f.options.Source = f.options.Destination
			f.options.SourceKeys = f.new
			f.options.NewKeys = third
			f.options.InPlace = true
			f.owner.Validate = func(p []byte, s [16]byte, n int64) (SnapshotValidation, error) {
				require.Equal(t, changed, p)
				return SnapshotValidation{}, nil
			}
			report, err := RotateSnapshot(f.options, f.owner)
			require.NoError(t, err)
			require.True(t, report.Complete)
			f.assertOutput(t, third, changed)
		})
	}
}

func TestRotateSnapshotPredecessorHandoffCuts(t *testing.T) {
	for _, cut := range []string{"predecessor-bootstrap", "predecessor-progress", "bootstrap-u", "predecessor-progress-removed", "usage-zero", "bootstrap-r", "planned", "publication", "complete", "predecessor-bootstrap-removed"} {
		t.Run(cut, func(t *testing.T) {
			f := newRotationFixture(t, true)
			_, err := RotateSnapshot(f.options, f.owner)
			require.NoError(t, err)
			f.options.SourceKeys = f.new
			f.options.NewKeys = cryptoRing(t, KeyConfig{Active: cryptoKey(t, "third", 105)})
			hit := false
			_, err = rotateSnapshot(f.options, f.owner, &snapshotRotationHooks{step: func(at string) error {
				if at == cut {
					hit = true
					return unix.EIO
				}
				return nil
			}})
			require.Error(t, err)
			require.True(t, hit)
			f.options.Resume = true
			report, err := RotateSnapshot(f.options, f.owner)
			require.NoError(t, err)
			require.True(t, report.Complete)
			f.assertOutput(t, f.options.NewKeys, f.payload)
		})
	}
}

func TestRotateSnapshotPublicationUncertaintyAndCapacityAfterSettlement(t *testing.T) {
	f := newRotationFixture(t, true)
	published := false
	report, err := rotateSnapshot(f.options, f.owner, &snapshotRotationHooks{configure: func(d *Dir) {
		base := d.ops
		d.ops.rename = func(a int, b string, c int, name string) error {
			err := base.rename(a, b, c, name)
			if name == "source" && err == nil {
				published = true
			}
			return err
		}
		d.ops.sync = func(file *os.File) error {
			if file == d.file && published {
				return unix.EIO
			}
			return base.sync(file)
		}
	}})
	require.Error(t, err)
	require.Equal(t, Uncertain, report.Outcome)
	f.options.Resume = true
	report, err = rotateSnapshot(f.options, f.owner, &snapshotRotationHooks{workspace: func(w *RotationWorkspace) { w.ops.allocate = func(*os.File, int64) error { return unix.ENOSPC } }})
	require.Error(t, err)
	require.Equal(t, Committed, report.Outcome)
	require.True(t, report.ResumeRequired)
	report, err = RotateSnapshot(f.options, f.owner)
	require.NoError(t, err)
	require.True(t, report.Complete)
}

func TestRotateSnapshotSubprocessCrashCuts(t *testing.T) {
	if path := os.Getenv("LIPPYCAT_SNAPSHOT_ROTATION_CRASH"); path != "" {
		old, err := LoadKeyring(KeyConfig{Active: KeyRef{ID: "old", File: filepath.Join(path, "old.key")}})
		if err != nil {
			os.Exit(2)
		}
		fresh, err := LoadKeyring(KeyConfig{Active: KeyRef{ID: "new", File: filepath.Join(path, "new.key")}})
		if err != nil {
			os.Exit(3)
		}
		opts := SnapshotRotationOptions{Source: filepath.Join(path, "source"), Destination: filepath.Join(path, "source"), SourceKeys: old, NewKeys: fresh, InPlace: true, MaxWorkingBytes: 4 << 20}
		owner := SnapshotRotationOwner{Purpose: FilterSnapshot, Object: "filters", MaxPayloadBytes: 1 << 20, Validate: func([]byte, [16]byte, int64) (SnapshotValidation, error) { return SnapshotValidation{}, nil }}
		_, err = rotateSnapshot(opts, owner, &snapshotRotationHooks{step: func(at string) error {
			if at == os.Getenv("LIPPYCAT_SNAPSHOT_ROTATION_CUT") {
				os.Exit(0)
			}
			return nil
		}})
		if err != nil {
			os.Exit(4)
		}
		os.Exit(5)
	}
	for _, cut := range []string{"reserved", "bootstrap-u", "usage-zero", "bootstrap-r", "usage-reserved", "planned", "candidate", "prepared", "publication", "complete", "temporary-cleanup"} {
		t.Run(cut, func(t *testing.T) {
			f := newRotationFixture(t, true)
			require.NoError(t, os.WriteFile(filepath.Join(f.path, "old.key"), f.old.active.raw[:], 0600))
			require.NoError(t, os.WriteFile(filepath.Join(f.path, "new.key"), f.new.active.raw[:], 0600))
			cmd := exec.Command(os.Args[0], "-test.run=^TestRotateSnapshotSubprocessCrashCuts$")
			cmd.Env = append(os.Environ(), "LIPPYCAT_SNAPSHOT_ROTATION_CRASH="+f.path, "LIPPYCAT_SNAPSHOT_ROTATION_CUT="+cut)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, string(output))
			f.options.Resume = true
			report, err := RotateSnapshot(f.options, f.owner)
			require.NoError(t, err)
			require.True(t, report.Complete)
			f.assertOutput(t, f.new, f.payload)
		})
	}
}

func TestRotateSnapshotKnownOutcomeSurvivesAuxiliaryCandidateFailure(t *testing.T) {
	for _, complete := range []bool{false, true} {
		for _, kind := range []string{"corrupt", "unreadable"} {
			t.Run(fmt.Sprintf("%v-%s", complete, kind), func(t *testing.T) {
				f := newRotationFixture(t, true)
				cut := "publication"
				if complete {
					cut = "complete"
				}
				_, err := rotateSnapshot(f.options, f.owner, &snapshotRotationHooks{step: func(at string) error {
					if at == cut {
						return unix.EIO
					}
					return nil
				}})
				require.Error(t, err)
				names := rotationNames(FilterSnapshot, "source", f.new.UsageFileName(), "")
				path := filepath.Join(f.path, names[RotationCandidateStage])
				if kind == "corrupt" {
					b, err := os.ReadFile(path)
					require.NoError(t, err)
					b[len(b)-1] ^= 1
					require.NoError(t, os.WriteFile(path, b, 0600))
				} else {
					require.NoError(t, os.Chmod(path, 0000))
					defer func() { require.NoError(t, os.Chmod(path, 0600)) }()
				}
				f.options.Resume = true
				report, err := RotateSnapshot(f.options, f.owner)
				require.Error(t, err)
				want := Uncertain
				if complete {
					want = Committed
				}
				require.Equal(t, want, report.Outcome)
				require.Equal(t, want, OutcomeOf(err))
				require.True(t, report.ResumeRequired)
			})
		}
	}
}

func TestRotateSnapshotUnsupportedOwnerCeilingHasNoEffects(t *testing.T) {
	f := newRotationFixture(t, true)
	before, err := os.ReadDir(f.path)
	require.NoError(t, err)
	f.owner.MaxPayloadBytes = MaxPlaintextBytes - 1024
	called := false
	f.owner.Validate = func([]byte, [16]byte, int64) (SnapshotValidation, error) {
		called = true
		return SnapshotValidation{}, nil
	}
	report, err := RotateSnapshot(f.options, f.owner)
	require.Error(t, err)
	require.Equal(t, NotCommitted, report.Outcome)
	require.False(t, called)
	after, err := os.ReadDir(f.path)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestRotateSnapshotInjectedWritesAndCompetingOwner(t *testing.T) {
	for _, kind := range []string{"zero-write", "disk-full", "file-sync", "close", "no-replace", "competing-owner"} {
		t.Run(kind, func(t *testing.T) {
			f := newRotationFixture(t, true)
			before, err := f.dir.Read("source", MaxEnvelopeBytes)
			require.NoError(t, err)
			var held *Lock
			if kind == "competing-owner" {
				held, err = f.dir.Lock("source")
				require.NoError(t, err)
			}
			report, err := rotateSnapshot(f.options, f.owner, &snapshotRotationHooks{workspace: func(w *RotationWorkspace) {
				base := w.dir.ops
				switch kind {
				case "zero-write":
					w.dir.ops.write = func(*os.File, []byte) (int, error) { return 0, nil }
				case "disk-full":
					w.dir.ops.write = func(file *os.File, b []byte) (int, error) {
						n, err := file.Write(b[:1])
						if err != nil {
							return n, err
						}
						return n, unix.ENOSPC
					}
				case "file-sync":
					w.dir.ops.sync = func(file *os.File) error {
						if file != w.dir.file {
							return unix.EIO
						}
						return base.sync(file)
					}
				case "close":
					w.dir.ops.close = func(file *os.File) error { _ = base.close(file); return unix.EIO }
				case "no-replace":
					w.dir.ops.noReplace = func(int, string, int, string) (bool, bool, error) { return false, false, unix.EOPNOTSUPP }
				}
			}})
			require.Error(t, err)
			require.Equal(t, NotCommitted, report.Outcome)
			after, err := f.dir.Read("source", MaxEnvelopeBytes)
			require.NoError(t, err)
			require.Equal(t, before, after)
			if held != nil {
				require.NoError(t, held.Close())
			}
			f.options.Resume = true
			report, err = RotateSnapshot(f.options, f.owner)
			require.NoError(t, err)
			require.True(t, report.Complete)
		})
	}
}

func TestRotateSnapshotResumeNeverBorrowsControlReserve(t *testing.T) {
	f := newRotationFixture(t, true)
	_, err := rotateSnapshot(f.options, f.owner, &snapshotRotationHooks{step: func(at string) error {
		if at == "planned" {
			return unix.EIO
		}
		return nil
	}})
	require.Error(t, err)
	spent := encodeUsage(f.new.active, f.store, MaxKeyInvocations*9/10, blockReservation)
	_, err = f.dir.Replace(f.new.UsageFileName(), spent)
	require.NoError(t, err)
	before, err := os.ReadDir(f.path)
	require.NoError(t, err)
	f.options.Resume = true
	report, err := RotateSnapshot(f.options, f.owner)
	require.ErrorIs(t, err, ErrKeyExhausted)
	require.Equal(t, NotCommitted, report.Outcome)
	after, err := os.ReadDir(f.path)
	require.NoError(t, err)
	require.Equal(t, before, after)
	retained, err := f.dir.Read(f.new.UsageFileName(), usageBytes)
	require.NoError(t, err)
	require.Equal(t, spent, retained)
}

func TestRotateSnapshotRetainedOriginalStartsIndependentLineage(t *testing.T) {
	f := newRotationFixture(t, false)
	_, err := RotateSnapshot(f.options, f.owner)
	require.NoError(t, err)
	first, err := ReadFile(f.options.Destination, MaxEnvelopeBytes)
	require.NoError(t, err)
	f.options.Destination = filepath.Join(f.path, "another")
	f.options.NewKeys = cryptoRing(t, KeyConfig{Active: cryptoKey(t, "third", 106)})
	report, err := RotateSnapshot(f.options, f.owner)
	require.NoError(t, err)
	require.True(t, report.Complete)
	f.assertOutput(t, f.options.NewKeys, f.payload)
	unchanged, err := ReadFile(filepath.Join(f.path, "destination"), MaxEnvelopeBytes)
	require.NoError(t, err)
	require.Equal(t, first, unchanged)
}

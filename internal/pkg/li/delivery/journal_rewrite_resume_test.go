//go:build li && linux

package delivery

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func TestJournalRewriteInterruptionResumesExactOperation(t *testing.T) {
	for _, inPlace := range []bool{false, true} {
		for _, cut := range []string{"bootstrap", "allocated", "ledger-required", "usage-reserved", "planned", "prepared", "retired", "published", "complete"} {
			if inPlace && cut == "retired" {
				continue
			}
			name := "changed/" + cut
			if inPlace {
				name = "in-place/" + cut
			}
			t.Run(name, func(t *testing.T) {
				source, destination, original, metadata := journalRewriteFixture(t, PDUTypeX3, inPlace)
				o := JournalRewriteOptions{SourceFormat: "segments", InPlace: inPlace, MaxWorkingBytes: 1 << 30}
				injected := errors.New("test interruption")
				report, err := rewriteJournalWithHooks(source, destination, o, &journalRewriteHooks{step: func(step string) error {
					if step == cut {
						return injected
					}
					return nil
				}})
				require.ErrorIs(t, err, injected)
				require.False(t, report.Complete)
				require.True(t, report.ResumeRequired)
				if cut == "published" || cut == "complete" {
					require.Equal(t, securestore.Committed, report.Outcome)
				} else {
					require.Equal(t, securestore.NotCommitted, report.Outcome)
				}
				o.Resume = true
				report, err = RewriteJournal(source, destination, o)
				require.NoError(t, err)
				require.True(t, report.Complete)
				require.Equal(t, securestore.Committed, report.Outcome)
				reader, err := OpenJournalRewriteSource(destination, "segments")
				require.NoError(t, err)
				require.Equal(t, metadata.RecordHighwater, reader.Metadata().RecordHighwater)
				require.Equal(t, metadata.AdmissionHighwater, reader.Metadata().AdmissionHighwater)
				require.NoError(t, reader.VisitRecords(func(record JournalRecord, _ uint64) error { require.Equal(t, original, record); return nil }))
				require.NoError(t, reader.Close())
			})
		}
	}
}

func TestJournalRewriteRepeatsInPlaceAfterRuntimeAdvancement(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "resume-new-bootstrap"}[interrupt], func(t *testing.T) {
			source, second, original, _ := journalRewriteFixture(t, PDUTypeX3, true)
			options := JournalRewriteOptions{SourceFormat: "segments", InPlace: true, MaxWorkingBytes: 1 << 30}
			_, err := RewriteJournal(source, second, options)
			require.NoError(t, err)
			j, err := OpenJournal(second)
			require.NoError(t, err)
			secondID := journalAdmit(t, j, productionRecord(t, second, 2048))
			require.NoError(t, j.Close())
			advanced, err := os.ReadFile(filepath.Join(second.Dir, ".segments"))
			require.NoError(t, err)
			resume := options
			resume.Resume = true
			_, err = RewriteJournal(source, second, resume)
			require.Error(t, err, "old completion cannot replace a later runtime catalog")
			current, err := os.ReadFile(filepath.Join(second.Dir, ".segments"))
			require.NoError(t, err)
			require.Equal(t, advanced, current)
			reader, err := OpenJournalRewriteSource(second, "segments")
			require.NoError(t, err)
			metadata := reader.Metadata()
			expected := map[uint64]JournalRecord{}
			require.NoError(t, reader.VisitRecords(func(r JournalRecord, _ uint64) error { r.Data = bytes.Clone(r.Data); expected[r.ID] = r; return nil }))
			require.NoError(t, reader.Close())
			require.Contains(t, expected, original.ID)
			require.Contains(t, expected, secondID)
			third := second
			third.KeyID = "third"
			third.KeyFile = filepath.Join(t.TempDir(), "third-key")
			require.NoError(t, os.WriteFile(third.KeyFile, bytes.Repeat([]byte{0x7b}, 32), 0600))
			if interrupt {
				_, err := rewriteJournalWithHooks(second, third, options, &journalRewriteHooks{step: func(step string) error {
					if step == "bootstrap" {
						return errors.New("interrupted third key")
					}
					return nil
				}})
				require.Error(t, err)
				options.Resume = true
			}
			report, err := RewriteJournal(second, third, options)
			require.NoError(t, err)
			require.True(t, report.Complete)
			foundOld := false
			for _, artifact := range report.Artifacts {
				if artifact.KeyID == source.KeyID {
					foundOld = true
					require.False(t, artifact.DependencyKnown)
				}
			}
			require.True(t, foundOld, "prior receipt reports the retained first-key dependency")
			reader, err = OpenJournalRewriteSource(third, "segments")
			require.NoError(t, err)
			require.Equal(t, metadata.RecordHighwater, reader.Metadata().RecordHighwater)
			require.Equal(t, metadata.AdmissionHighwater, reader.Metadata().AdmissionHighwater)
			require.NoError(t, reader.VisitRecords(func(r JournalRecord, _ uint64) error {
				require.Equal(t, expected[r.ID], r)
				delete(expected, r.ID)
				return nil
			}))
			require.Empty(t, expected)
			require.NoError(t, reader.Close())
			for _, cfg := range []JournalConfig{source, second, third} {
				ring, err := rewriteLoadKeys(cfg)
				require.NoError(t, err)
				_, err = os.Stat(filepath.Join(third.Dir, ring.UsageFileName()))
				require.NoError(t, err, "all historical usage ledgers survive")
			}
		})
	}
}

func TestJournalRewriteResumeRejectsChangedRequestAndMissingRequiredLedger(t *testing.T) {
	for _, mutation := range []string{"budget", "key", "ledger", "candidate"} {
		t.Run(mutation, func(t *testing.T) {
			source, destination, _, _ := journalRewriteFixture(t, PDUTypeX3, true)
			o := JournalRewriteOptions{SourceFormat: "segments", InPlace: true, MaxWorkingBytes: 1 << 30}
			cut := "usage-reserved"
			if mutation == "candidate" {
				cut = "prepared"
			}
			_, err := rewriteJournalWithHooks(source, destination, o, &journalRewriteHooks{step: func(step string) error {
				if step == cut {
					return errors.New("interrupted")
				}
				return nil
			}})
			require.Error(t, err)
			sourceCatalog, err := os.ReadFile(filepath.Join(source.Dir, ".segments"))
			require.NoError(t, err)
			switch mutation {
			case "budget":
				o.MaxWorkingBytes++
			case "key":
				require.NoError(t, os.WriteFile(destination.KeyFile, make([]byte, 32), 0600))
			case "ledger":
				ring, err := rewriteLoadKeys(destination)
				require.NoError(t, err)
				require.NoError(t, os.Remove(filepath.Join(destination.Dir, ring.UsageFileName())))
			case "candidate":
				_, _, name := rewriteNames()
				raw, err := os.ReadFile(filepath.Join(destination.Dir, name))
				require.NoError(t, err)
				raw[len(raw)-1] ^= 1
				require.NoError(t, os.WriteFile(filepath.Join(destination.Dir, name), raw, 0600))
			}
			o.Resume = true
			report, err := RewriteJournal(source, destination, o)
			require.Error(t, err)
			require.False(t, report.Complete)
			current, err := os.ReadFile(filepath.Join(source.Dir, ".segments"))
			require.NoError(t, err)
			require.Equal(t, sourceCatalog, current)
		})
	}
}

func TestJournalRewriteMigratesBothPriorX2Formats(t *testing.T) {
	for _, format := range []string{"lcx2", "per-record"} {
		for _, inPlace := range []bool{false, true} {
			name := format + "/changed"
			if inPlace {
				name = format + "/in-place"
			}
			t.Run(name, func(t *testing.T) {
				var source JournalConfig
				if format == "lcx2" {
					source = legacyJournalFixture(t)
					source.KeyID = "legacy"
					source.LegacyKeyID = "legacy"
				} else {
					source = journalTestConfig(t)
					source.KeyID = "source"
					source.Interface = PDUTypeX2
					source.PreserveSequences = true
					j, err := openLegacyJournal(source, false)
					require.NoError(t, err)
					journalAdmit(t, j, productionRecord(t, source, 1024))
					require.NoError(t, j.Close())
				}
				source.Interface = PDUTypeX2
				source.MaxBytes = 512 << 20
				reader, err := OpenJournalRewriteSource(source, format)
				require.NoError(t, err)
				metadata := reader.Metadata()
				var expected JournalRecord
				require.NoError(t, reader.VisitRecords(func(r JournalRecord, _ uint64) error { r.Data = bytes.Clone(r.Data); expected = r; return nil }))
				require.NoError(t, reader.Close())
				destination := source
				destination.KeyID = "replacement"
				destination.LegacyKeyID = ""
				destination.KeyFile = filepath.Join(t.TempDir(), "replacement-key")
				require.NoError(t, os.WriteFile(destination.KeyFile, bytes.Repeat([]byte{0x6c}, 32), 0600))
				if !inPlace {
					destination.Dir = t.TempDir()
					require.NoError(t, os.Chmod(destination.Dir, 0700))
				}
				options := JournalRewriteOptions{SourceFormat: format, InPlace: inPlace, MaxWorkingBytes: 1 << 30}
				_, err = RewriteJournal(source, destination, options)
				require.NoError(t, err)
				reader, err = OpenJournalRewriteSource(destination, "segments")
				require.NoError(t, err)
				expected.JournalUUID = reader.Metadata().JournalUUID
				if expected.ContentSHA256 == [32]byte{} {
					prefix, err := recordPrefix(expected, uint64(len(expected.Data)))
					require.NoError(t, err)
					expected.ContentSHA256 = recordContentHash(prefix, expected.Data)
				}
				require.Equal(t, metadata.RecordHighwater, reader.Metadata().RecordHighwater)
				require.NoError(t, reader.VisitRecords(func(r JournalRecord, _ uint64) error { require.Equal(t, expected, r); return nil }))
				require.NoError(t, reader.Close())
			})
		}
	}
}

//go:build li && linux

package delivery

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
)

func journalRewriteFixture(t *testing.T, iface PDUType, inPlace bool) (JournalConfig, JournalConfig, JournalRecord, JournalRewriteMetadata) {
	t.Helper()
	source := productionJournalConfig(t, iface)
	source.KeyID = "source"
	j, err := OpenJournal(source)
	require.NoError(t, err)
	id := journalAdmit(t, j, productionRecord(t, source, 1024))
	if iface == PDUTypeX3 {
		r, err := j.readRecord(id)
		require.NoError(t, err)
		out, err := j.CloseCall(callForRecord(r).identity())
		require.NoError(t, err)
		require.Equal(t, securestore.Committed, out)
	}
	require.NoError(t, j.Close())
	reader, err := OpenJournalRewriteSource(source, "segments")
	require.NoError(t, err)
	var record JournalRecord
	require.NoError(t, reader.VisitRecords(func(r JournalRecord, _ uint64) error { record = r; record.Data = bytes.Clone(r.Data); return nil }))
	metadata := reader.Metadata()
	require.NoError(t, reader.Close())
	destination := source
	if !inPlace {
		destination.Dir = t.TempDir()
		require.NoError(t, os.Chmod(destination.Dir, 0700))
	}
	destination.KeyID = "fresh"
	destination.KeyFile = filepath.Join(t.TempDir(), "fresh-key")
	require.NoError(t, os.WriteFile(destination.KeyFile, bytes.Repeat([]byte{0x5a}, 32), 0600))
	return source, destination, record, metadata
}

func TestJournalRewritePreservesExactProductsAndContinuity(t *testing.T) {
	for _, iface := range []PDUType{PDUTypeX2, PDUTypeX3} {
		for _, inPlace := range []bool{false, true} {
			name := "changed-path"
			if inPlace {
				name = "in-place"
			}
			if iface == PDUTypeX2 {
				name = "x2/" + name
			} else {
				name = "x3/" + name
			}
			t.Run(name, func(t *testing.T) {
				source, destination, original, metadata := journalRewriteFixture(t, iface, inPlace)
				report, err := RewriteJournal(source, destination, JournalRewriteOptions{SourceFormat: "segments", InPlace: inPlace, MaxWorkingBytes: 1 << 30})
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, report.Outcome)
				require.True(t, report.Complete)
				require.False(t, report.ResumeRequired)
				require.True(t, report.ExternalBackupsExcluded)
				if !inPlace {
					old, err := OpenJournal(source)
					require.Error(t, err, "changed-path source cannot remain writable")
					require.Nil(t, old)
				}
				// The original key-file-only X2 configuration also recognizes an
				// explicitly migrated segment catalog; it cannot regress to .state.
				if iface == PDUTypeX2 {
					destination.Interface = 0
				}
				j, err := OpenJournal(destination)
				require.NoError(t, err)
				defer func() { require.NoError(t, j.Close()) }()
				require.Equal(t, metadata.JournalUUID, j.UUID())
				got, err := j.readRecord(original.ID)
				require.NoError(t, err)
				require.Equal(t, original, got, "IDs, bytes, provenance, capture/admission times and deadlines are immutable")
				high, admission := j.Highwaters()
				require.GreaterOrEqual(t, high, metadata.RecordHighwater)
				require.GreaterOrEqual(t, admission, metadata.AdmissionHighwater)
				sequences := 0
				require.NoError(t, j.VisitSequences(func(cp x2x3.SequenceCheckpoint) error {
					sequences++
					require.Equal(t, x2x3.PDUType(iface), cp.Context.PDUType)
					require.Equal(t, uint32(8), cp.Next)
					return nil
				}))
				require.Equal(t, 1, sequences)
				if iface == PDUTypeX3 {
					backend := j.segments.(*journalSegments)
					c := backend.controls[journalCallKey(callForRecord(got))]
					require.Equal(t, "call_close", c.Kind)
					require.Equal(t, "capture_closed", c.Call.State)
					require.NotNil(t, c.Call.ClosedAt)
				}
			})
		}
	}
}

func TestJournalRewriteRejectsOccupiedDestinationAndInsufficientSpace(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		t.Run(map[bool]string{false: "workspace", true: "occupied"}[occupied], func(t *testing.T) {
			source, destination, original, _ := journalRewriteFixture(t, PDUTypeX3, false)
			options := JournalRewriteOptions{SourceFormat: "segments", MaxWorkingBytes: 1}
			marker := []byte("unrelated destination must survive")
			if occupied {
				options.MaxWorkingBytes = 1 << 30
				require.NoError(t, os.WriteFile(filepath.Join(destination.Dir, ".segments"), marker, 0600))
			}
			report, err := RewriteJournal(source, destination, options)
			require.Error(t, err)
			require.Equal(t, securestore.NotCommitted, report.Outcome)
			reader, err := OpenJournalRewriteSource(source, "segments")
			require.NoError(t, err)
			require.NoError(t, reader.VisitRecords(func(r JournalRecord, _ uint64) error { require.Equal(t, original, r); return nil }))
			require.NoError(t, reader.Close())
			if occupied {
				got, err := os.ReadFile(filepath.Join(destination.Dir, ".segments"))
				require.NoError(t, err)
				require.Equal(t, marker, got)
			}
		})
	}
}

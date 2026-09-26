//go:build li

package delivery

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// These files are frozen LCX2 v1 bytes, not output from the current writer.
func TestJournalLegacyLCX2FixtureRecovery(t *testing.T) {
	root := filepath.Join("testdata", "legacy_lcx2_v1")
	cfg := journalTestConfig(t)
	cfg.PreserveSequences = true
	key, err := os.ReadFile(filepath.Join(root, "fixture.key"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfg.KeyFile, key, 0600))
	files, err := os.ReadDir(filepath.Join(root, "objects"))
	require.NoError(t, err)
	require.Len(t, files, 3)
	for _, file := range files {
		b, err := os.ReadFile(filepath.Join(root, "objects", file.Name()))
		require.NoError(t, err)
		require.Equal(t, "LCX2\x01", string(b[:5]))
		require.NoError(t, os.WriteFile(filepath.Join(cfg.Dir, file.Name()), b, 0600))
	}
	productHex, err := os.ReadFile(filepath.Join(root, "product.hex"))
	require.NoError(t, err)
	product, err := hex.DecodeString(strings.TrimSpace(string(productHex)))
	require.NoError(t, err)

	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, j.Close()) }()
	require.Equal(t, 1, j.Stats().Held)
	require.Equal(t, 1, j.Stats().Persisted)
	var records []JournalRecord
	require.NoError(t, j.VisitHeld(func(r JournalRecord) error {
		records = append(records, r)
		return nil
	}))
	require.Len(t, records, 1)
	require.Equal(t, JournalRecord{
		ID: 7, DID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		XID:            uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		TaskGeneration: 3, DestinationGeneration: 5, CallGeneration: 9,
		CallID: "synthetic-call@example.invalid", Data: product,
		AdmittedAt: time.Date(2026, 1, 2, 3, 4, 5, 6_000_000, time.UTC),
		CapturedAt: time.Date(2026, 1, 2, 3, 4, 4, 5_000_000, time.UTC),
	}, records[0])

	var checkpoints []x2x3.SequenceCheckpoint
	require.NoError(t, j.VisitSequences(func(cp x2x3.SequenceCheckpoint) error {
		checkpoints = append(checkpoints, cp)
		return nil
	}))
	require.Equal(t, []x2x3.SequenceCheckpoint{{Context: x2x3.SequenceContext{
		PDUType: x2x3.PDUTypeX2, XID: records[0].XID, DomainID: "fixture-domain",
		NFID: "fixture-nf", IPID: "fixture-ip", CorrelationID: 23,
	}, Next: 42}}, checkpoints)
	cp, err := x2x3.X2SequenceCheckpoint(product)
	require.NoError(t, err)
	require.Equal(t, checkpoints[0], cp)
	sequencer := x2x3.NewSequencer(2)
	require.NoError(t, sequencer.RestoreCheckpoint(cp))
	next, err := sequencer.Next(cp.Context)
	require.NoError(t, err)
	require.Equal(t, uint32(42), next)

	// Historical raw-key use is unknown, so this owner is explicitly read-only.
	// The offline upgrade suite checks continuity after a fresh-key bootstrap.
	require.True(t, j.ReadOnly())
	require.ErrorIs(t, j.Purge(7), ErrJournalMigrationRequired)
	_, err = j.Admit(records[0], nil)
	require.ErrorIs(t, err, ErrJournalMigrationRequired)
}

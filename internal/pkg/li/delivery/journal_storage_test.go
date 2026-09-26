//go:build li

package delivery

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func legacyJournalFixture(t *testing.T) JournalConfig {
	t.Helper()
	cfg := journalTestConfig(t)
	cfg.PreserveSequences = true
	root := filepath.Join("testdata", "legacy_lcx2_v1")
	key, err := os.ReadFile(filepath.Join(root, "fixture.key"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(cfg.KeyFile, key, 0600))
	entries, err := os.ReadDir(filepath.Join(root, "objects"))
	require.NoError(t, err)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(root, "objects", entry.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(cfg.Dir, entry.Name()), data, 0600))
	}
	return cfg
}

func journalUpgradeConfig(t *testing.T, old JournalConfig) JournalConfig {
	t.Helper()
	cfg := old
	cfg.KeyID, cfg.LegacyKeyID = "fresh", "legacy"
	cfg.ReadKeys = []securestore.KeyRef{{ID: "legacy", File: old.KeyFile}}
	cfg.KeyFile = filepath.Join(t.TempDir(), "fresh.key")
	require.NoError(t, os.WriteFile(cfg.KeyFile, bytes.Repeat([]byte{91}, 32), 0600))
	return cfg
}

func TestJournalUpgradePreservesMixedRecordsSequencesAndWatermark(t *testing.T) {
	legacy := legacyJournalFixture(t)
	cfg := journalUpgradeConfig(t, legacy)
	oldProduct, err := os.ReadFile(filepath.Join(cfg.Dir, journalRecordName(7)))
	require.NoError(t, err)
	out, err := UpgradeLegacyJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	require.False(t, j.ReadOnly())
	storeID := j.storeID
	records, err := journalRecords(j)
	require.NoError(t, err)
	require.Len(t, records, 1)
	original := records[0]
	var pdu x2x3.PDU
	require.NoError(t, pdu.UnmarshalBinary(original.Data))
	for _, attr := range pdu.Attributes {
		if attr.Type == x2x3.AttrSequenceNumber {
			binary.BigEndian.PutUint32(attr.Value, 42)
		}
	}
	updated, err := pdu.MarshalBinary()
	require.NoError(t, err)
	newRecord := original
	newRecord.Data = updated
	id := journalAdmit(t, j, newRecord)
	require.Equal(t, uint64(12), id, "legacy .state highwater must survive upgrade")
	require.NoError(t, j.Close())
	unchanged, err := os.ReadFile(filepath.Join(cfg.Dir, journalRecordName(7)))
	require.NoError(t, err)
	require.Equal(t, oldProduct, unchanged, "upgrade must not re-encode surviving legacy products")
	newProduct, err := os.ReadFile(filepath.Join(cfg.Dir, journalRecordName(id)))
	require.NoError(t, err)
	require.Equal(t, "LCS1", string(newProduct[:4]))
	require.NotContains(t, string(newProduct), original.CallID)
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, storeID, j.storeID)
	records, err = journalRecords(j)
	require.NoError(t, err)
	require.Len(t, records, 2)
	require.Equal(t, original, records[0])
	require.Equal(t, updated, records[1].Data)
	var checkpoints []x2x3.SequenceCheckpoint
	require.NoError(t, j.VisitSequences(func(cp x2x3.SequenceCheckpoint) error {
		checkpoints = append(checkpoints, cp)
		return nil
	}))
	require.Len(t, checkpoints, 1)
	require.Equal(t, uint32(43), checkpoints[0].Next)
	require.NoError(t, j.Purge(7))
	require.NoError(t, j.Purge(id))
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, uint64(13), journalAdmit(t, j, newRecord))
	require.NoError(t, j.Close())
}

func TestJournalUpgradeRequiresFreshMappedKeyAndValidEntireSource(t *testing.T) {
	legacy := legacyJournalFixture(t)
	out, err := UpgradeLegacyJournal(legacy)
	require.Error(t, err)
	require.Equal(t, securestore.NotCommitted, out)
	cfg := journalUpgradeConfig(t, legacy)
	cfg.KeyFile = legacy.KeyFile
	_, err = UpgradeLegacyJournal(cfg)
	require.ErrorContains(t, err, "duplicated")
	cfg = journalUpgradeConfig(t, legacy)
	statePath := filepath.Join(cfg.Dir, ".state")
	before, err := os.ReadFile(statePath)
	require.NoError(t, err)
	productPath := filepath.Join(cfg.Dir, journalRecordName(7))
	data, err := os.ReadFile(productPath)
	require.NoError(t, err)
	data[4] = 99
	require.NoError(t, os.WriteFile(productPath, data, 0600))
	out, err = UpgradeLegacyJournal(cfg)
	require.ErrorContains(t, err, "version")
	require.Equal(t, securestore.NotCommitted, out)
	ledgers, err := filepath.Glob(filepath.Join(cfg.Dir, ".usage-*"))
	require.NoError(t, err)
	require.Empty(t, ledgers, "invalid source must not bootstrap a write key")
	after, err := os.ReadFile(statePath)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestJournalUpgradeResumesAfterDurableLedgerBeforeStateRewrite(t *testing.T) {
	for _, statePresent := range []bool{true, false} {
		t.Run(map[bool]string{true: "state-present", false: "state-absent"}[statePresent], func(t *testing.T) {
			legacy := legacyJournalFixture(t)
			if !statePresent {
				require.NoError(t, os.Remove(filepath.Join(legacy.Dir, ".state")))
			}
			cfg := journalUpgradeConfig(t, legacy)
			checked, err := OpenJournal(legacy)
			require.NoError(t, err)
			require.True(t, checked.ReadOnly())
			require.NoError(t, checked.Close())
			// Model process loss after an explicitly requested upgrade authenticated all
			// input and durably initialized the fresh key, before rewriting any object.
			dir, err := securestore.OpenDir(cfg.Dir)
			require.NoError(t, err)
			lock, err := dir.Lock(".lock")
			require.NoError(t, err)
			ring, err := securestore.LoadKeyring(securestore.KeyConfig{Active: securestore.KeyRef{ID: cfg.KeyID, File: cfg.KeyFile}, Prior: cfg.ReadKeys, LegacyID: cfg.LegacyKeyID})
			require.NoError(t, err)
			storeID := [16]byte(uuid.New())
			out, err := securestore.InitializeUsage(dir, ring, storeID)
			require.NoError(t, err)
			require.Equal(t, securestore.Committed, out)
			require.NoError(t, lock.Close())
			require.NoError(t, dir.Close())
			if !statePresent {
				_, err := OpenJournal(cfg)
				require.ErrorContains(t, err, "required journal state is missing")
			}
			for range 2 {
				out, err = UpgradeLegacyJournal(cfg)
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, out)
				j, err := OpenJournal(cfg)
				require.NoError(t, err)
				require.Equal(t, storeID, j.storeID, "resume must never initialize another incarnation")
				require.Equal(t, 1, j.Stats().Held)
				require.NoError(t, j.Close())
			}
		})
	}
}

func TestJournalRejectsMissingLedgerAndCrossStoreOrPurposeSubstitution(t *testing.T) {
	for _, attack := range []string{"missing-ledger", "missing-ledger-all-objects", "wrong-store", "wrong-purpose", "unknown-version"} {
		t.Run(attack, func(t *testing.T) {
			cfg := journalTestConfig(t)
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			id := journalAdmit(t, j, JournalRecord{Data: []byte("synthetic original")})
			require.NoError(t, j.Close())
			product := filepath.Join(cfg.Dir, journalRecordName(id))
			switch attack {
			case "missing-ledger", "missing-ledger-all-objects":
				paths, err := filepath.Glob(filepath.Join(cfg.Dir, ".usage-*"))
				require.NoError(t, err)
				require.Len(t, paths, 1)
				require.NoError(t, os.Remove(paths[0]))
				if attack == "missing-ledger-all-objects" {
					require.NoError(t, os.Remove(product))
					require.NoError(t, os.Remove(filepath.Join(cfg.Dir, ".state")))
				}
			case "wrong-store":
				other := journalTestConfig(t) // Same synthetic key material; different UUID.
				owner, err := OpenJournal(other)
				require.NoError(t, err)
				journalAdmit(t, owner, JournalRecord{Data: []byte("another store")})
				require.NoError(t, owner.Close())
				data, err := os.ReadFile(filepath.Join(other.Dir, journalRecordName(id)))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(product, data, 0600))
			case "wrong-purpose":
				data, err := os.ReadFile(filepath.Join(cfg.Dir, ".state"))
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(product, data, 0600))
			case "unknown-version":
				data, err := os.ReadFile(product)
				require.NoError(t, err)
				data[4] = 255
				require.NoError(t, os.WriteFile(product, data, 0600))
			}
			_, err = OpenJournal(cfg)
			require.Error(t, err)
			if attack == "wrong-store" {
				require.ErrorIs(t, err, securestore.ErrBinding)
			}
			if strings.HasPrefix(attack, "missing-ledger") {
				paths, err := filepath.Glob(filepath.Join(cfg.Dir, ".usage-*"))
				require.NoError(t, err)
				require.Empty(t, paths, "runtime must not reset lost usage accounting")
			}
		})
	}
}

func TestJournalUpgradeCannotRecreateLostUsedState(t *testing.T) {
	cfg := journalUpgradeConfig(t, legacyJournalFixture(t))
	_, err := UpgradeLegacyJournal(cfg)
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(cfg.Dir, ".state")))
	out, err := UpgradeLegacyJournal(cfg)
	require.ErrorContains(t, err, "after encryption usage was reserved")
	require.Equal(t, securestore.NotCommitted, out)
	_, err = os.Stat(filepath.Join(cfg.Dir, ".state"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestJournalRejectsMalformedMetadataBeforeRecovery(t *testing.T) {
	for _, prefix := range []string{".securestore-lock-", ".usage-"} {
		t.Run(prefix, func(t *testing.T) {
			cfg := journalTestConfig(t)
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			require.NoError(t, j.Close())
			name := prefix + strings.Repeat("a", 64)
			require.NoError(t, os.WriteFile(filepath.Join(cfg.Dir, name), []byte("unexpected metadata content"), 0600))
			_, err = OpenJournal(cfg)
			require.ErrorContains(t, err, "unexpected metadata size")
		})
	}
}

func TestJournalOwnershipAlsoBlocksLegacyLockProtocol(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	f, err := os.OpenFile(filepath.Join(cfg.Dir, ".lock"), os.O_RDWR, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	require.Error(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
	require.NoError(t, j.Close())
	require.NoError(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
}

func TestJournalManifestExportRejectsRenamedStoreAndPriorKey(t *testing.T) {
	cfg := journalUpgradeConfig(t, legacyJournalFixture(t))
	_, err := UpgradeLegacyJournal(cfg)
	require.NoError(t, err)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, j.Close()) })
	c := &Client{journal: j}
	moved := cfg.Dir + "-moved"
	require.NoError(t, os.Rename(cfg.Dir, moved))
	t.Cleanup(func() { require.NoError(t, os.Rename(moved, cfg.Dir)) })
	state, err := os.ReadFile(filepath.Join(moved, ".state"))
	require.NoError(t, err)
	require.ErrorContains(t, c.ExportHeldJournalManifest(filepath.Join(moved, ".state")), "outside the spool")
	after, err := os.ReadFile(filepath.Join(moved, ".state"))
	require.NoError(t, err)
	require.Equal(t, state, after)
	for _, path := range []string{cfg.KeyFile, cfg.ReadKeys[0].File} {
		require.NoError(t, os.Chmod(filepath.Dir(path), 0700))
		before, err := os.ReadFile(path)
		require.NoError(t, err)
		require.ErrorContains(t, c.ExportHeldJournalManifest(path), "must not replace the journal key")
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, before, after)
	}
}

func TestJournalClientRejectsLegacyLiveOutputUntilExplicitUpgrade(t *testing.T) {
	legacy := legacyJournalFixture(t)
	cfg := DefaultClientConfig()
	cfg.X2SpoolDir, cfg.X2SpoolKeyFile, cfg.X2SpoolMaxBytes = legacy.Dir, legacy.KeyFile, legacy.MaxBytes
	c := NewClient(&Manager{}, cfg)
	require.ErrorIs(t, c.Err(), ErrJournalMigrationRequired)
	c.Stop()
	// A failed live initialization releases ownership for an offline reader.
	j, err := OpenJournal(legacy)
	require.NoError(t, err)
	require.True(t, j.ReadOnly())
	require.NoError(t, j.Close())
}

func TestJournalCheckpointFaultStopsRemainingMutations(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	first := journalAdmit(t, j, JournalRecord{Data: []byte("first")})
	second := journalAdmit(t, j, JournalRecord{Data: []byte("second")})
	require.NoError(t, os.Chmod(j.path(first), 0644))
	j.mu.Lock()
	j.entries[first].completing = true
	j.entries[second].completing = true
	j.checkpoints = []uint64{first, second}
	j.mu.Unlock()
	j.checkpoint()
	require.NotEmpty(t, j.Stats().LastError)
	_, err = os.Stat(j.path(second))
	require.NoError(t, err, "later checkpoint cannot mutate a faulted store")
	require.Error(t, j.Close())
	require.NoError(t, os.Chmod(j.path(first), 0600))
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Equal(t, 2, j.Stats().Held)
	require.NoError(t, j.Close())
}

func TestJournalSchemaRejectsDuplicatesNullAndUnknownFields(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, j.Close()) }()
	plain := `{"version":1,"record":{"ID":1,"DID":"00000000-0000-0000-0000-000000000000","XID":"00000000-0000-0000-0000-000000000000","TaskGeneration":0,"DestinationGeneration":0,"CallGeneration":0,"CallID":"","AdmittedAt":"0001-01-01T00:00:00Z","CapturedAt":"0001-01-01T00:00:00Z","Data":null}}`
	for _, bad := range []string{
		strings.Replace(plain, `"ID":1`, `"ID":1,"ID":2`, 1),
		strings.Replace(plain, `"version":1`, `"version":2`, 1),
		strings.Replace(plain, `"version":1`, `"version":null`, 1),
		strings.Replace(plain, `"ID":1`, `"unexpected":1,"ID":1`, 1),
		strings.Replace(plain, `"ID":1`, `"ID":18446744073709551616`, 1),
		strings.Replace(plain, `"CallID":""`, `"CallID":"\ud800"`, 1),
		strings.Replace(plain, `"CallID":""`, `"CallID":"\udc00"`, 1),
		plain + " {}",
	} {
		encoded, err := j.writer.Seal(securestore.X2Product, securestore.Binding{Store: j.storeID, Object: "1"}, []byte(bad))
		require.NoError(t, err)
		_, err = j.decodeObject(securestore.X2Product, "1", encoded, 4096)
		require.Error(t, err)
	}
	valid := strings.Replace(plain, `"CallID":""`, `"CallID":"\ud83d\ude00"`, 1)
	var decoded journalEnvelopeRecord
	require.NoError(t, decodeJournalJSON([]byte(valid), journalWrapperFields, &decoded))
	require.Equal(t, "😀", decoded.Record.CallID)
}

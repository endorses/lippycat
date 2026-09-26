//go:build li && linux

package delivery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Excluding ownership sidecars makes the assertion about store content rather
// than legitimate acquisition of process ownership. Hash segment files without
// retaining their allocated zero padding in test memory.
func preflightFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	names, err := os.ReadDir(dir)
	require.NoError(t, err)
	out := map[string]string{}
	for _, e := range names {
		if strings.HasPrefix(e.Name(), ".securestore-lock-") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		require.NoError(t, err)
		h := sha256.New()
		_, err = io.Copy(h, f)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		out[e.Name()] = hex.EncodeToString(h.Sum(nil))
	}
	return out
}
func preflightCorruptCatalog(t *testing.T, cfg JournalConfig) {
	t.Helper()
	path := filepath.Join(cfg.Dir, ".segments")
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	b[len(b)-1] ^= 1
	require.NoError(t, os.WriteFile(path, b, 0600))
}
func TestJournalPreflightOtherStoreFailureHasNoWritableEffects(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-x2", true: "existing-x2"}[existing], func(t *testing.T) {
			x2 := productionJournalConfig(t, PDUTypeX2)
			x3 := productionJournalConfig(t, PDUTypeX3)
			require.NoError(t, os.WriteFile(x3.KeyFile, bytes.Repeat([]byte{43}, 32), 0600))
			if existing {
				j, err := OpenJournal(x2)
				require.NoError(t, err)
				journalAdmit(t, j, productionRecord(t, x2, 100))
				require.NoError(t, j.Close())
			}
			j, err := OpenJournal(x3)
			require.NoError(t, err)
			journalAdmit(t, j, productionRecord(t, x3, 100))
			require.NoError(t, j.Close())
			before := preflightFiles(t, x2.Dir)
			preflightCorruptCatalog(t, x3)
			owners, err := PrepareJournals([]JournalConfig{x2, x3})
			require.Error(t, err)
			require.Nil(t, owners)
			require.Equal(t, before, preflightFiles(t, x2.Dir))
			// A failed group releases all ownership, including the first store.
			j, err = OpenJournal(x2)
			require.NoError(t, err)
			require.NoError(t, j.Close())
		})
	}
}
func TestJournalPreflightMissingDirectoryIsNotProvisionedOnAuthFailure(t *testing.T) {
	x2 := productionJournalConfig(t, PDUTypeX2)
	require.NoError(t, os.Remove(x2.Dir))
	x3 := productionJournalConfig(t, PDUTypeX3)
	require.NoError(t, os.WriteFile(x3.KeyFile, bytes.Repeat([]byte{43}, 32), 0600))
	j, err := OpenJournal(x3)
	require.NoError(t, err)
	require.NoError(t, j.Close())
	preflightCorruptCatalog(t, x3)
	_, err = PrepareJournals([]JournalConfig{x2, x3})
	require.Error(t, err)
	_, err = os.Stat(x2.Dir)
	require.True(t, os.IsNotExist(err))
}
func TestJournalPreflightPromotesSameRetainedOwners(t *testing.T) {
	for _, iface := range []PDUType{0, PDUTypeX2, PDUTypeX3} {
		t.Run(string(rune('0'+iface)), func(t *testing.T) {
			cfg := productionJournalConfig(t, iface)
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			if iface != 0 {
				journalAdmit(t, j, productionRecord(t, cfg, 100))
			} else {
				legacyPDUConfig := cfg
				legacyPDUConfig.Interface = PDUTypeX2
				journalAdmit(t, j, productionRecord(t, legacyPDUConfig, 100))
			}
			require.NoError(t, j.Close())
			before := preflightFiles(t, cfg.Dir)
			prepared, err := PrepareJournals([]JournalConfig{cfg})
			require.NoError(t, err)
			p := prepared[0]
			retained := p.journal
			ring, usage, owner := retained.keys, retained.usage, p.lock
			require.Equal(t, before, preflightFiles(t, cfg.Dir))
			_, err = OpenJournal(cfg)
			require.ErrorIs(t, err, securestore.ErrLocked)
			// Mutable key paths cannot alter the authenticated keyring on promotion.
			require.NoError(t, os.WriteFile(cfg.KeyFile, bytes.Repeat([]byte{0x97}, 32), 0600))
			j, err = p.Activate()
			require.NoError(t, err)
			require.Same(t, retained, j)
			require.Same(t, ring, j.keys)
			require.Same(t, usage, j.usage)
			require.Same(t, owner, j.lock)
			require.NoError(t, p.Close())
			require.NoError(t, j.Close())
		})
	}
}
func TestJournalPreflightValidatesRuntimeIncarnationAndMissingLedger(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	require.NoError(t, j.Close())
	before := preflightFiles(t, cfg.Dir)
	wrong := cfg
	wrong.StateIncarnation = uuid.New()
	_, err = PrepareJournals([]JournalConfig{wrong})
	require.Error(t, err)
	require.Equal(t, before, preflightFiles(t, cfg.Dir))
	names, err := os.ReadDir(cfg.Dir)
	require.NoError(t, err)
	for _, name := range names {
		if strings.HasPrefix(name.Name(), ".usage-") {
			require.NoError(t, os.Remove(filepath.Join(cfg.Dir, name.Name())))
		}
	}
	before = preflightFiles(t, cfg.Dir)
	_, err = PrepareJournals([]JournalConfig{cfg})
	require.Error(t, err)
	require.Equal(t, before, preflightFiles(t, cfg.Dir))
}
func TestJournalPreflightFreshOwnersDoNotInitializeBeforePromotion(t *testing.T) {
	a, b := productionJournalConfig(t, PDUTypeX2), productionJournalConfig(t, PDUTypeX3)
	require.NoError(t, os.WriteFile(b.KeyFile, bytes.Repeat([]byte{43}, 32), 0600))
	owners, err := PrepareJournals([]JournalConfig{a, b})
	require.NoError(t, err)
	require.Empty(t, preflightFiles(t, a.Dir))
	require.Empty(t, preflightFiles(t, b.Dir))
	for _, p := range owners {
		j, err := p.Activate()
		require.NoError(t, err)
		require.NoError(t, p.Close())
		require.NoError(t, j.Close())
	}
	require.Contains(t, preflightFiles(t, a.Dir), ".segments")
	require.Contains(t, preflightFiles(t, b.Dir), ".segments")
}

func TestJournalPreflightAuthenticatesSelectedProductPlaintext(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX2)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	s := j.segments.(*journalSegments)
	r := productionRecord(t, cfg, 100)
	r.ID = 1
	r.JournalUUID = j.UUID()
	r.Interface = PDUTypeX2
	r.AdmittedAt = time.Now().UTC()
	r.Provenance = li.DeliveryProvenance{Kind: "legacy_x2"}
	meta, err := encodeRecordMetadata(r)
	require.NoError(t, err)
	// Keep all frame, envelope, index and head authentication valid, but make
	// decrypted product bytes disagree with the exact logical content digest.
	altered := append([]byte(nil), r.Data...)
	altered[len(altered)-1] ^= 1
	s.ioMu.Lock()
	cipher, err := j.writer.Seal(securestore.X2Product, s.productBinding(1, 0), altered)
	require.NoError(t, err)
	f := segmentFragment{ID: 1, Admission: 1, Parts: 1, Total: uint32(len(r.Data)), Offset: segmentFrameHeader, Length: uint32(len(cipher)), Hash: sha256.Sum256(cipher), Metadata: meta}
	out, err := s.appendFrame(s.activeData, cipher, []segmentFragment{f}, nil)
	require.NoError(t, err)
	require.Equal(t, securestore.Committed, out)
	s.activeData.live = 1
	s.ioMu.Unlock()
	require.NoError(t, j.Close())
	before := preflightFiles(t, cfg.Dir)
	// Metadata-only offline opening succeeds, showing that body validation is a
	// separate required gate performed by the startup preparation owner.
	readCfg := cfg
	readCfg.offline = true
	readCfg.preflight = true
	indexed, err := openSegmentJournal(readCfg, false)
	require.NoError(t, err)
	require.NoError(t, indexed.Close())
	_, err = PrepareJournals([]JournalConfig{cfg})
	require.Error(t, err)
	require.Equal(t, before, preflightFiles(t, cfg.Dir))
}

func TestJournalPreflightLegacyRepairFailurePreservesOutcomeAndReleasesOwners(t *testing.T) {
	for _, outcome := range []securestore.Outcome{securestore.NotCommitted, securestore.Uncertain, securestore.Committed} {
		t.Run(string(rune('0'+outcome)), func(t *testing.T) {
			cfg := journalTestConfig(t)
			original, err := OpenJournal(cfg)
			require.NoError(t, err)
			journalAdmit(t, original, JournalRecord{Data: []byte("original retained product")})
			require.NoError(t, original.Close())
			prepared, err := PrepareJournals([]JournalConfig{cfg})
			require.NoError(t, err)
			p := prepared[0]
			retained := p.journal
			injected := errors.New("injected prepared repair failure")
			writableDuringRepair := false
			retained.writeFile = func(string, []byte) error {
				writableDuringRepair = !retained.readOnly && retained.cfg.offline
				return &securestore.CommitError{Outcome: outcome, Op: "prepared repair", Err: injected}
			}
			result := make(chan error, 1)
			go func() { _, err := p.Activate(); result <- err }()
			select {
			case err = <-result:
			case <-time.After(5 * time.Second):
				t.Fatal("failed promotion waited for an unstarted worker")
			}
			require.ErrorIs(t, err, injected)
			require.Equal(t, outcome, securestore.OutcomeOf(err))
			require.True(t, writableDuringRepair)
			require.True(t, retained.readOnly)
			require.True(t, retained.cfg.offline)
			select {
			case <-retained.done:
				t.Fatal("failed promotion launched a runtime worker")
			default:
			}
			require.NoError(t, p.Close())
			// Pure cleanup released the directory, primary inode and usage owners.
			reopened, err := OpenJournal(cfg)
			require.NoError(t, err)
			require.Equal(t, 1, reopened.Stats().Held)
			require.NoError(t, reopened.Close())
		})
	}
}
func TestJournalPreflightLegacyMissingOwnerRequiresMigration(t *testing.T) {
	cfg := legacyJournalFixture(t)
	before := preflightFiles(t, cfg.Dir)
	_, err := PrepareJournals([]JournalConfig{cfg})
	require.ErrorIs(t, err, ErrJournalMigrationRequired)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Equal(t, before, preflightFiles(t, cfg.Dir))
	// Rejection preserves the historical offline reader and releases ownership.
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	require.True(t, j.ReadOnly())
	require.NoError(t, j.Close())
}

//go:build li

package delivery

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func legacyTaskControl(j *Journal, xid uuid.UUID, generation uint64) *li.StateRevocation {
	high, admission := j.Highwaters()
	return &li.StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: j.UUID(), StateIncarnation: j.cfg.StateIncarnation, Scope: li.StateRevokeTask, XID: &xid, TaskGeneration: &generation, CoveredRecordHighwater: high, CoveredAdmissionHighwater: admission, RevokedAt: li.NewStateTimestamp(time.Now())}
}

func TestLegacyJournalConflictRevocationRestartAndPartialFailure(t *testing.T) {
	for _, stateful := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			name := "stateless"
			if stateful {
				name = "stateful"
			}
			if fail {
				name += "-partial"
			}
			t.Run(name, func(t *testing.T) {
				cfg := journalTestConfig(t)
				cfg.PreserveSequences = true
				if stateful {
					cfg.StateIncarnation = uuid.New()
				}
				j, err := OpenJournal(cfg)
				require.NoError(t, err)
				require.Nil(t, j.segments, "existing small per-record spools must not migrate")
				xid, other, did := uuid.New(), uuid.New(), uuid.New()
				record := func(id uuid.UUID, seq uint32) JournalRecord {
					return JournalRecord{XID: id, DID: did, TaskGeneration: 7, DestinationGeneration: 3, Data: journalSequencePDU(t, id, seq), AdmittedAt: time.Now()}
				}
				journalAdmit(t, j, record(xid, 0))
				journalAdmit(t, j, record(xid, 1))
				journalAdmit(t, j, record(other, 0))
				require.NoError(t, j.Close())
				j, err = OpenJournal(cfg)
				require.NoError(t, err)
				require.Equal(t, 3, j.Stats().Held)
				control := legacyTaskControl(j, xid, 7)
				if fail {
					count := 0
					j.removeLegacyRecord = func(id uint64) error {
						count++
						if count == 2 {
							return errors.New("injected second unlink failure")
						}
						return j.removeRecord(id)
					}
				}
				outcome, err := j.Revoke(control)
				if fail {
					require.Error(t, err)
					require.Equal(t, securestore.Uncertain, outcome)
					require.Error(t, j.Close())
				} else {
					require.NoError(t, err)
					require.Equal(t, securestore.Committed, outcome)
					require.NoError(t, j.Close())
				}
				j, err = OpenJournal(cfg)
				require.NoError(t, err)
				defer func() { require.NoError(t, j.Close()) }()
				outcome, err = j.Revoke(control)
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, outcome)
				require.Equal(t, 1, j.Stats().Held)
				var kept []uuid.UUID
				require.NoError(t, j.VisitHeld(func(r JournalRecord) error { kept = append(kept, r.XID); return nil }))
				require.Equal(t, []uuid.UUID{other}, kept)
				require.GreaterOrEqual(t, j.next, uint64(3), "record highwater survives deletion")
				require.NotEmpty(t, j.sequences, "sequence checkpoints survive conflict")
				_, err = j.Admit(record(xid, 2), nil)
				require.Error(t, err, "pending/future stale generation must stay blocked")
				repeated, err := j.Revoke(control)
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, repeated)
				changed := copyDeliveryControl(control)
				changed.CoveredRecordHighwater--
				_, err = j.Revoke(changed)
				require.Error(t, err, "stable control identity must not change")
			})
		}
	}
}

func TestLegacyJournalConflictRevocationDrainsPendingAdmission(t *testing.T) {
	cfg := journalTestConfig(t)
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, j.Close()) }()
	xid, did := uuid.New(), uuid.New()
	entered, release := make(chan struct{}), make(chan struct{})
	original := j.writeFile
	var once sync.Once
	j.writeFile = func(path string, data []byte) error {
		if filepath.Ext(path) == ".x2" {
			once.Do(func() { close(entered); <-release })
		}
		return original(path, data)
	}
	done := make(chan error, 1)
	_, err = j.Admit(JournalRecord{XID: xid, DID: did, TaskGeneration: 7, Data: []byte("synthetic")}, func(_ uint64, err error) { done <- err })
	require.NoError(t, err)
	<-entered
	control := legacyTaskControl(j, xid, 7)
	revoked := make(chan error, 1)
	go func() { _, err := j.Revoke(control); revoked <- err }()
	require.Eventually(t, func() bool { j.mu.Lock(); defer j.mu.Unlock(); return len(j.legacyRevocations) == 1 }, time.Second, time.Millisecond)
	select {
	case err := <-revoked:
		t.Fatalf("revocation returned before persistence: %v", err)
	default:
	}
	_, err = j.Admit(JournalRecord{XID: xid, DID: did, TaskGeneration: 7, Data: []byte("late")}, nil)
	require.Error(t, err)
	close(release)
	require.NoError(t, <-done)
	select {
	case err := <-revoked:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("revocation failed to drain admission")
	}
	require.Zero(t, j.Stats().Retained)
	require.Zero(t, j.Stats().Pending)
}

//go:build li && linux

package delivery

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func taskRetirementControl(j *Journal, r JournalRecord) *li.StateRevocation {
	high, admission := j.Highwaters()
	return &li.StateRevocation{Version: 1, ControlID: uuid.New(), JournalUUID: j.UUID(), StateIncarnation: j.cfg.StateIncarnation, Scope: li.StateRevokeTask, XID: &r.XID, TaskGeneration: &r.TaskGeneration, CoveredRecordHighwater: high, CoveredAdmissionHighwater: admission, RevokedAt: li.NewStateTimestamp(time.Now())}
}

func taskControlPresent(j *Journal, control *li.StateRevocation) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, exists := j.segments.(*journalSegments).controls["revoke/"+control.ControlID.String()]
	return exists
}

func TestJournalTaskControlRetirementRequiresDischargedObligations(t *testing.T) {
	for _, authoritative := range []bool{false, true} {
		name := "legacy"
		if authoritative {
			name = "authoritative"
		}
		t.Run(name, func(t *testing.T) {
			cfg := productionJournalConfig(t, PDUTypeX3)
			cfg.AuthoritativeTaskAuthorization = authoritative
			j, err := OpenJournal(cfg)
			require.NoError(t, err)
			r := productionRecord(t, cfg, 100)
			journalAdmit(t, j, r)
			control := taskRetirementControl(j, r)
			reservation, err := j.ReserveAdmission(100)
			require.NoError(t, err)
			func() {
				s := j.segments.(*journalSegments)
				s.ioMu.Lock()
				defer s.ioMu.Unlock()
				out, err := s.writeControls([]journalControl{{Kind: "revoke", Revocation: control}})
				require.NoError(t, err)
				require.Equal(t, securestore.Committed, out)
				require.NoError(t, s.compactControls())
				require.True(t, taskControlPresent(j, control), "prepared admissions still own revocation obligations")
				reservation.Release()
				require.NoError(t, s.compactControls())
				require.True(t, taskControlPresent(j, control), "terminal bytes remain in selected data extents")
				require.NoError(t, s.compactData(s.activeData))
				require.Equal(t, !authoritative, taskControlPresent(j, control))
			}()
			require.Zero(t, j.Stats().Retained)
			require.NoError(t, j.Close())
			j, err = OpenJournal(cfg)
			require.NoError(t, err)
			require.Zero(t, j.Stats().Retained, "retired bytes cannot return on recovery")
			require.Equal(t, !authoritative, taskControlPresent(j, control))
			if !authoritative {
				_, err = j.Admit(r, nil)
				require.Error(t, err, "metadata-only API must retain permanent rejection")
			}
			require.NoError(t, j.Close())
		})
	}
}

func TestJournalTaskControlRetirementRejectsPendingOldGeneration(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	cfg.AuthoritativeTaskAuthorization = true
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	r := productionRecord(t, cfg, 100)
	done := make(chan error, 1)
	var control *li.StateRevocation
	func() {
		s := j.segments.(*journalSegments)
		s.ioMu.Lock()
		defer s.ioMu.Unlock()
		_, err := j.Admit(r, func(_ uint64, err error) { done <- err })
		require.NoError(t, err)
		control = taskRetirementControl(j, r)
		out, err := s.writeControls([]journalControl{{Kind: "revoke", Revocation: control}})
		require.NoError(t, err)
		require.Equal(t, securestore.Committed, out)
		require.NoError(t, s.pruneTaskControls())
		require.True(t, taskControlPresent(j, control))
	}()
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrJournalClosed)
	case <-time.After(5 * time.Second):
		t.Fatal("pending admission worker did not finish")
	}
	func() {
		s := j.segments.(*journalSegments)
		s.ioMu.Lock()
		defer s.ioMu.Unlock()
		require.NoError(t, s.reclaimEmpty())
		require.NoError(t, s.pruneTaskControls())
		require.False(t, taskControlPresent(j, control))
	}()
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Zero(t, j.Stats().Retained)
	require.NoError(t, j.Close())
}

func TestJournalTaskControlRetirementKeepsRemainingSelectedFragments(t *testing.T) {
	cfg := productionJournalConfig(t, PDUTypeX3)
	cfg.AuthoritativeTaskAuthorization = true
	j, err := OpenJournal(cfg)
	require.NoError(t, err)
	// One product crosses a production data-extent boundary. Retiring its first
	// extent must not discharge the remaining selected ciphertext's obligation.
	r := productionRecord(t, cfg, securestore.FixedSegmentBytes+1<<20)
	id := journalAdmit(t, j, r)
	control := taskRetirementControl(j, r)
	func() {
		s := j.segments.(*journalSegments)
		s.ioMu.Lock()
		defer s.ioMu.Unlock()
		first := s.extents[s.locations[id].chunks[0].segment]
		require.NotEqual(t, first.ref.ID, s.locations[id].chunks[len(s.locations[id].chunks)-1].segment)
		out, err := s.writeControls([]journalControl{{Kind: "revoke", Revocation: control}})
		require.NoError(t, err)
		require.Equal(t, securestore.Committed, out)
		require.NoError(t, s.compactData(first))
		require.NotEmpty(t, s.locations[id].chunks)
		require.True(t, taskControlPresent(j, control))
		require.NoError(t, s.reclaimEmpty())
		require.Empty(t, s.locations[id].chunks)
		require.False(t, taskControlPresent(j, control))
	}()
	require.NoError(t, j.Close())
	j, err = OpenJournal(cfg)
	require.NoError(t, err)
	require.Zero(t, j.Stats().Retained)
	require.NoError(t, j.Close())
}

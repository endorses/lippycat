//go:build li

package delivery

import (
	"fmt"
	"reflect"
	"sort"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

// The per-record X2 owner has no segmented control log. Its durable revocation
// boundary is the existing unlink + directory fsync for every affected product.
// Administrative intents persist the stable control until that whole boundary
// completes; partial retirement is retryable against remaining held records.
// Stateless X2 recovery always holds records and cannot approve historical replay.
// No new storage format, key usage, migration, or minimum spool size is needed.
func (j *Journal) revokeLegacy(control *li.StateRevocation) (securestore.Outcome, error) {
	if j.readOnly {
		return securestore.NotCommitted, ErrJournalMigrationRequired
	}
	j.mu.Lock()
	if control == nil || control.Version != 1 || control.ControlID == uuid.Nil || control.JournalUUID != j.UUID() || control.StateIncarnation != j.cfg.StateIncarnation || control.Scope != li.StateRevokeTask || control.DID != nil || control.DestinationGeneration != nil || control.CallIncarnation != nil || control.CallGeneration != nil || control.RevokedAt.Nanos >= 1e9 || control.RevokedAt.Seconds < -62135596800 || control.RevokedAt.Seconds > 253402300799 || !validDeliveryControl(control) || control.CoveredRecordHighwater > j.next || control.CoveredAdmissionHighwater > j.next {
		j.mu.Unlock()
		return securestore.NotCommitted, fmt.Errorf("invalid per-record task revocation binding")
	}
	if j.closed || j.lastErr != nil {
		j.mu.Unlock()
		return securestore.NotCommitted, ErrJournalClosed
	}
	if previous := j.legacyRevocations[control.ControlID]; previous != nil && !reflect.DeepEqual(previous, control) {
		j.mu.Unlock()
		return securestore.NotCommitted, fmt.Errorf("revocation control identity cannot change")
	}
	if j.legacyRevocations == nil {
		j.legacyRevocations = make(map[uuid.UUID]*li.StateRevocation)
	}
	if j.legacyRevocations[control.ControlID] == nil && len(j.legacyRevocations) >= maxDeliveryGateIdentities {
		j.mu.Unlock()
		return securestore.NotCommitted, ErrJournalFull
	}
	// Reject later matching admissions before waiting for earlier callbacks.
	j.legacyRevocations[control.ControlID] = copyDeliveryControl(control)
	j.mu.Unlock()
	if err := j.Flush(); err != nil {
		// Earlier cancellation checkpoints may already have durably retired some
		// products before this barrier reported a write or sync failure.
		return securestore.Uncertain, &securestore.CommitError{Outcome: securestore.Uncertain, Op: "drain per-record revocation", Err: err}
	}

	// Flush must precede these locks: callbacks and queued checkpoints may need
	// them. Block held replay and other retirement paths while scanning one record
	// at a time; keep directory ownership alive through every deletion sync.
	j.controlMu.Lock()
	defer j.controlMu.Unlock()
	j.purgeMu.RLock()
	defer j.purgeMu.RUnlock()
	j.legacyDiskMu.Lock()
	defer j.legacyDiskMu.Unlock()
	j.mu.Lock()
	if j.closed || j.lastErr != nil {
		j.mu.Unlock()
		return securestore.Uncertain, &securestore.CommitError{Outcome: securestore.Uncertain, Op: "complete per-record revocation drain", Err: ErrJournalClosed}
	}
	ids := make([]uint64, 0, len(j.entries))
	for id, entry := range j.entries {
		if entry.persisted {
			ids = append(ids, id)
		}
	}
	j.mu.Unlock()
	sort.Slice(ids, func(a, b int) bool { return ids[a] < ids[b] })
	fail := func(err error) (securestore.Outcome, error) {
		outcome := securestore.Uncertain // earlier drained checkpoints may also have retired matching products
		wrapped := &securestore.CommitError{Outcome: outcome, Op: "revoke per-record X2 products", Err: err}
		j.fault(wrapped)
		return outcome, wrapped
	}
	for _, id := range ids {
		record, err := j.readRecord(id)
		if err != nil {
			return fail(err)
		}
		if !legacyControlMatches(control, record) {
			continue
		}
		remove := j.removeLegacyRecord
		if remove == nil {
			remove = j.removeRecord
		}
		if err := remove(id); err != nil {
			return fail(err)
		}
		j.mu.Lock()
		if entry := j.entries[id]; entry != nil {
			j.stats.Bytes -= entry.size
			j.stats.Persisted--
			j.stats.Revoked++
			if entry.held {
				j.stats.Held--
				j.decrementHeldLocked(entry.did)
			}
			if entry.authorized {
				j.stats.ReplayPending--
			}
			delete(j.entries, id)
		}
		j.mu.Unlock()
	}
	return securestore.Committed, nil
}

func legacyControlMatches(control *li.StateRevocation, record JournalRecord) bool {
	// Per-record encoding predates StateIncarnation and does not serialize it.
	// The control binds to the authenticated owner above; task identity remains
	// the original XID plus activation generation stored in every product.
	return control.Scope == li.StateRevokeTask && control.XID != nil && control.TaskGeneration != nil && record.XID == *control.XID && record.TaskGeneration == *control.TaskGeneration
}

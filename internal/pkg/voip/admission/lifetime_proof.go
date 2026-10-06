package admission

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

// Retired wire proof is protected for a configured monotonic window. Exact
// guards have a separate budget; unrecordable retirements conservatively block
// the domain until one window after the last failure, never until restart.
type lifetimeProofHistory struct {
	initiators   map[[32]byte]retiredInitiatorProof
	blockedUntil time.Time
	unrecorded   uint64
	lastWarning  time.Time
}

type retiredInitiatorProof struct {
	lifetime callregistry.Lifetime
	maximum  uint64
	blocked  bool
	expires  time.Time
}

// The reservation includes the fixed entry and conservative map allocation
// overhead. Every distinct retired Call-ID/initiator consumes a configured
// context as well as bytes; no uncharged, ever-growing collision list exists.
const lifetimeProofEntryBytes = 128

func lifetimeInitiatorHash(callID, initiator string) [32]byte {
	data := make([]byte, 0, 16+len(callID)+len(initiator))
	for _, value := range []string{callID, initiator} {
		data = binary.BigEndian.AppendUint64(data, uint64(len(value)))
		data = append(data, value...)
	}
	return sha256.Sum256(data)
}

// rememberLifetimeLocked snapshots the greatest observed request sequence per
// initiator. A response belongs to its request initiator's sequence space,
// never to the media sender's sequence space.
// PRACK's own sequence and acknowledged request sequence are kept separately
// by normal derivation, but both delimit replay for that request initiator.
// Callers hold b.mu and invoke this before deleting the old derivations.
func (b *Bridge) rememberLifetimeLocked(callID string, old *selectedCall) error {
	if old == nil {
		return nil
	}
	candidates := make(map[[32]byte]retiredInitiatorProof)
	if old.contextLost || old.replayEvidenceMissing {
		// Missing initiator/bounds can affect any reused transaction of this call,
		// but cannot poison an unrelated Call-ID. An empty initiator is a domain-
		// separated call-level marker, not a valid SIP request identity.
		candidates[lifetimeInitiatorHash(callID, "")] = retiredInitiatorProof{lifetime: old.lifetime, blocked: true}
	} else {
		for side, state := range old.derivations {
			if side.initiator == "" {
				continue
			}
			hash := lifetimeInitiatorHash(callID, side.initiator)
			candidate := candidates[hash]
			candidate.lifetime = old.lifetime
			for current := state; current != nil; current = current.previous {
				maximum := current.cseq
				if current.prackCSeq > maximum {
					maximum = current.prackCSeq
				}
				if current.repeatedAckSequence > maximum {
					maximum = current.repeatedAckSequence
				}
				if current.conflictBoundValid && current.conflictMaximum > maximum {
					maximum = current.conflictMaximum
				}
				if maximum > candidate.maximum {
					candidate.maximum = maximum
				}
				if current.conflict && !current.conflictBoundValid {
					// This initiator has no usable old bound; other participants retain
					// their own sequence spaces and unrelated calls remain unaffected.
					candidate.blocked = true
				}
			}
			candidates[hash] = candidate
		}
	}
	now := time.Now()
	b.expireLifetimeProofLocked(now)
	if b.proofHistory.initiators == nil {
		b.proofHistory.initiators = make(map[[32]byte]retiredInitiatorProof)
	}
	var capacityErr error

	for hash, candidate := range candidates {
		previous, exists := b.proofHistory.initiators[hash]
		var reservationErr error
		if !exists {
			reservationErr = b.cfg.Metadata.ReserveReplayGuards(mediaadmission.SelectedDerivationUsage{}, mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: lifetimeProofEntryBytes})
		}
		if reservationErr != nil {
			b.proofHistory.unrecorded++
			b.proofHistory.blockedUntil = now.Add(b.cfg.Limits.ReplayWindow)
			b.needsSnapshot = true
			capacityErr = errors.Join(mediaadmission.ErrCapacity, b.cfg.Controller.MarkUnsynchronized(b.cfg.Domain, mediaadmission.ErrCapacity))
			if b.proofHistory.lastWarning.IsZero() || now.Sub(b.proofHistory.lastWarning) >= b.cfg.Limits.RetryInterval {
				logger.Warn("Replay guard capacity exhausted", "domain", b.cfg.Domain, "guards", len(b.proofHistory.initiators), "window", b.cfg.Limits.ReplayWindow)
				b.proofHistory.lastWarning = now
			}
			continue
		}
		candidate.expires = now.Add(b.cfg.Limits.ReplayWindow)
		if previous.maximum > candidate.maximum {
			candidate.maximum = previous.maximum
		}
		candidate.blocked = candidate.blocked || previous.blocked
		b.proofHistory.initiators[hash] = candidate
	}

	return capacityErr
}

// checkKeyLifetimeLocked rejects explicitly bound evidence from another
// lifetime, including records observed before retirement and consumed later.
// Capture timestamps alone are insufficient: a replay can have a fresh stamp.
func (b *Bridge) checkKeyLifetimeLocked(call *selectedCall, key mediaadmission.DialogKey) bool {
	if call == nil {
		return false
	}
	explicit := key.LifetimeSession != 0 || key.LifetimeGeneration != 0
	if explicit && (key.LifetimeSession != call.lifetime.Session || key.LifetimeGeneration != call.lifetime.Generation) {
		call.lifetimeAmbiguous = true
		return false
	}
	return b.observeLifetimeKeyLocked(call, key)
}

func (b *Bridge) observeLifetimeKeyLocked(call *selectedCall, key mediaadmission.DialogKey) bool {
	if call == nil {
		return false
	}
	b.expireLifetimeProofLocked(time.Now())
	if time.Now().Before(b.proofHistory.blockedUntil) {
		call.replayBlockedUntil = b.proofHistory.blockedUntil
		call.replayEvidenceMissing = true
		call.replayMissingCutoff = b.nextMetadata
		return false
	}
	if b.retiredCallBlockedLocked(key.CallID) {
		call.lifetimeAmbiguous = true
		return false
	}
	previous, exists := b.proofHistory.initiators[lifetimeInitiatorHash(key.CallID, key.FromTag)]
	if !exists {
		return true
	}
	if previous.blocked {
		call.lifetimeAmbiguous = true
		return false
	}
	if previous.lifetime == call.lifetime {
		return true
	}
	sequence := key.CSeq
	if strings.EqualFold(key.CSeqMethod, "PRACK") {
		if !key.RAckValid {
			call.lifetimeAmbiguous = true
			return false
		}
		sequence = uint64(key.RAckCSeq)
	}
	if sequence <= previous.maximum {
		call.lifetimeAmbiguous = true
		return false
	}
	return true
}

// canConfirmedLifetimeLocked is only a freshness guard. The caller must still
// prove exact dialog, matching offer/answer and confirmation, and leave other
// uncertainty untouched. A missing opposite-side watermark is not by itself
// authority to accept an old or unconfirmed transaction.
func (b *Bridge) canConfirmedLifetimeLocked(call *selectedCall, key mediaadmission.DialogKey) bool {
	if call == nil || time.Now().Before(b.proofHistory.blockedUntil) || b.retiredCallBlockedLocked(key.CallID) || !key.CSeqValid || key.HeaderConflict || key.FromTag == "" || key.CallID == "" {
		return false
	}
	if key.LifetimeSession != 0 || key.LifetimeGeneration != 0 {
		if key.LifetimeSession != call.lifetime.Session || key.LifetimeGeneration != call.lifetime.Generation {
			return false
		}
	}
	if !strings.EqualFold(key.CSeqMethod, "INVITE") && !strings.EqualFold(key.CSeqMethod, "UPDATE") {
		return false
	}
	previous, exists := b.proofHistory.initiators[lifetimeInitiatorHash(key.CallID, key.FromTag)]
	return !exists || (!previous.blocked && (previous.lifetime == call.lifetime || key.CSeq > previous.maximum))
}

func (b *Bridge) releaseLifetimeProofLocked() error {
	count := len(b.proofHistory.initiators)
	if err := b.cfg.Metadata.ReserveReplayGuards(mediaadmission.SelectedDerivationUsage{Contexts: count, Bytes: count * lifetimeProofEntryBytes}, mediaadmission.SelectedDerivationUsage{}); err != nil {
		return err
	}
	b.proofHistory = lifetimeProofHistory{}
	return nil
}

// Expiry clears only pressure introduced by missing replay storage. Recompute
// active calls from their remaining derivations; missing proof is not invented.
// Caller holds b.mu. A delayed worker may retain protection longer, never shorter.
func (b *Bridge) expireLifetimeProofLocked(now time.Time) {
	for hash, guard := range b.proofHistory.initiators {
		if !now.Before(guard.expires) {
			if err := b.cfg.Metadata.ReserveReplayGuards(mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: lifetimeProofEntryBytes}, mediaadmission.SelectedDerivationUsage{}); err != nil {
				b.needsSnapshot = true
				if publicationErr := b.cfg.Controller.MarkUnsynchronized(b.cfg.Domain, err); publicationErr != nil {
					logger.Error("Replay guard release failed", "domain", b.cfg.Domain, "error", publicationErr)
				}
				continue
			}
			delete(b.proofHistory.initiators, hash)
		}
	}
	if len(b.proofHistory.initiators) == 0 {
		b.proofHistory.initiators = nil
	}
	if !b.proofHistory.blockedUntil.IsZero() && !now.Before(b.proofHistory.blockedUntil) {
		b.proofHistory.blockedUntil = time.Time{}
	}
	for _, call := range b.selected {
		if !call.replayBlockedUntil.IsZero() && !now.Before(call.replayBlockedUntil) {
			call.replayBlockedUntil = time.Time{}
			call.known, call.unknown, call.mediaSet = b.derivationSummary(call)
			call.retry = true
			b.needsSnapshot = true
		}
	}
}

// retireLifetimeLocked transfers the old selected-context reservation into its
// smaller anti-replay history without temporarily double charging both. The
// shallow snapshot is bounded by the already charged derivation count; releasing
// descriptors deletes map entries but never mutates the pointed-to states.
// Callers hold b.mu. Reporting errors belongs after unlocking, not here.
func (b *Bridge) retireLifetimeLocked(callID string, old *selectedCall) error {
	if old == nil {
		return nil
	}
	snapshot := *old
	snapshot.derivations = make(map[derivationSide]*derivationState, len(old.derivations))
	for side, state := range old.derivations {
		snapshot.derivations[side] = state
	}
	b.releaseDerivations(old)
	return b.rememberLifetimeLocked(callID, &snapshot)
}

func (b *Bridge) retiredCallBlockedLocked(callID string) bool {
	marker, exists := b.proofHistory.initiators[lifetimeInitiatorHash(callID, "")]
	return exists && marker.blocked
}

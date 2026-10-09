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
	initiators     map[[32]byte]retiredInitiatorProof
	overflow       map[[32]byte]time.Time
	generation     uint64
	invalidThrough uint64
	blockedUntil   time.Time
	pressureCutoff uint64
	unrecorded     uint64
	lastWarning    time.Time
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
	now := b.now()
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
			generationExhausted := false
			if !now.Before(b.proofHistory.blockedUntil) {
				b.proofHistory.pressureCutoff = b.nextMetadata
				if b.proofHistory.generation == ^uint64(0) {
					generationExhausted = true
				} else {
					b.proofHistory.generation++
				}
			}
			b.proofHistory.blockedUntil = now.Add(b.cfg.Limits.ReplayWindow)
			retainedIdentity := b.rememberOverflowIdentityLocked(callID, b.proofHistory.blockedUntil)
			if !retainedIdentity || generationExhausted {
				b.proofHistory.invalidThrough = b.proofHistory.generation
				// History loss invalidates every observation from this pressure
				// generation, including metadata not yet selected. Retained healthy
				// authoritative derivations remain independent of this quarantine.
				for _, call := range b.selected {
					if call.quarantine != nil {
						b.releaseDerivations(call.quarantine)
						call.quarantine = nil
					}
				}
			}
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
	if key.ReplayReceiptMissing {
		call.replayEvidenceMissing = true
		call.replayMissingCutoff = max(call.replayMissingCutoff, key.Generation)
		return false
	}
	if key.ReplayRejected {
		call.lifetimeAmbiguous = true
		return false
	}
	if key.ReplayPressureGeneration != 0 && key.ReplayPressureGeneration <= b.proofHistory.invalidThrough && b.newMediaProofLocked(call, key) {
		call.replayEvidenceMissing = true
		call.replayMissingCutoff = max(call.replayMissingCutoff, key.Generation)
		call.replayBlockedUntil = b.proofHistory.blockedUntil
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
	if b.retiredCallBlockedLocked(key.CallID) {
		call.lifetimeAmbiguous = true
		return false
	}
	previous, exists := b.proofHistory.initiators[lifetimeInitiatorHash(key.CallID, key.FromTag)]
	if !exists || !b.now().Before(previous.expires) {
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
	if call == nil || b.now().Before(b.proofHistory.blockedUntil) || b.retiredCallBlockedLocked(key.CallID) || !key.CSeqValid || key.HeaderConflict || key.FromTag == "" || key.CallID == "" {
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
	return !exists || !b.now().Before(previous.expires) || (!previous.blocked && (previous.lifetime == call.lifetime || key.CSeq > previous.maximum))
}

func (b *Bridge) releaseLifetimeProofLocked() error {
	count := len(b.proofHistory.initiators)
	if err := b.cfg.Metadata.ReserveReplayGuards(mediaadmission.SelectedDerivationUsage{Contexts: count, Bytes: count * lifetimeProofEntryBytes}, mediaadmission.SelectedDerivationUsage{}); err != nil {
		return err
	}
	count = len(b.proofHistory.overflow)
	if err := b.cfg.Metadata.ReserveReplayOverflow(mediaadmission.SelectedDerivationUsage{Contexts: count, Bytes: count * lifetimeProofEntryBytes}, mediaadmission.SelectedDerivationUsage{}); err != nil {
		return err
	}
	b.proofHistory = lifetimeProofHistory{}
	return nil
}

// Expiry clears only pressure introduced by missing replay storage. Recompute
// active calls from their remaining derivations; missing proof is not invented.
// Caller holds b.mu. A delayed worker may retain protection longer, never shorter.
func (b *Bridge) expireLifetimeProofLocked(now time.Time) {
	for hash, expires := range b.proofHistory.overflow {
		if !now.Before(expires) {
			if err := b.cfg.Metadata.ReserveReplayOverflow(mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: lifetimeProofEntryBytes}, mediaadmission.SelectedDerivationUsage{}); err != nil {
				b.needsSnapshot = true
				if publicationErr := b.cfg.Controller.MarkUnsynchronized(b.cfg.Domain, err); publicationErr != nil {
					logger.Error("Replay identity release failed", "domain", b.cfg.Domain, "error", publicationErr)
				}
				logger.Error("Replay identity release failed", "domain", b.cfg.Domain, "error", err)
				continue
			}
			delete(b.proofHistory.overflow, hash)
		}
	}
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
	for id, call := range b.selected {
		b.recoverPressureCallLocked(id, call, now)
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
	return exists && marker.blocked && b.now().Before(marker.expires)
}

func (b *Bridge) rememberOverflowIdentityLocked(callID string, expires time.Time) bool {
	hash := lifetimeInitiatorHash(callID, "")
	if _, exists := b.proofHistory.overflow[hash]; !exists {
		if err := b.cfg.Metadata.ReserveReplayOverflow(mediaadmission.SelectedDerivationUsage{}, mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: lifetimeProofEntryBytes}); err != nil {
			return false
		}
		if b.proofHistory.overflow == nil {
			b.proofHistory.overflow = make(map[[32]byte]time.Time)
		}
	}
	b.proofHistory.overflow[hash] = expires
	return true
}

// Stamp receipt-time rejection into metadata. Promotion-time expiry must never
// rehabilitate an observation received inside the retired identity's window.
func (b *Bridge) stampReplayEligibilityLocked(key *mediaadmission.DialogKey) {
	now := b.now()
	if now.Before(b.proofHistory.blockedUntil) {
		key.ReplayPressureGeneration = b.proofHistory.generation
	}
	if expires, exists := b.proofHistory.overflow[lifetimeInitiatorHash(key.CallID, "")]; exists && now.Before(expires) {
		key.ReplayRejected = true
	}
	if b.retiredCallBlockedLocked(key.CallID) {
		key.ReplayRejected = true
	}
	if guard, exists := b.proofHistory.initiators[lifetimeInitiatorHash(key.CallID, key.FromTag)]; exists && now.Before(guard.expires) && (guard.lifetime.Session != key.LifetimeSession || guard.lifetime.Generation != key.LifetimeGeneration) {
		sequence := key.CSeq
		if strings.EqualFold(key.CSeqMethod, "PRACK") {
			if !key.RAckValid {
				key.ReplayRejected = true
			}
			sequence = uint64(key.RAckCSeq)
		}
		key.ReplayRejected = key.ReplayRejected || guard.blocked || sequence <= guard.maximum
	}
}

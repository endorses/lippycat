package admission

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

// newMediaProofLocked separates new negotiation/endpoint evidence from a
// proof-free message or an exact retransmission of already retained proof.
func (b *Bridge) newMediaProofLocked(call *selectedCall, key mediaadmission.DialogKey) bool {
	if key.HeaderConflict {
		return true
	}
	if key.DescriptorOnly && key.CSeqMethod != "INVITE" && key.CSeqMethod != "UPDATE" && key.CSeqMethod != "PRACK" && key.CSeqMethod != "ACK" {
		return false
	}
	key = b.bindRequestKey(call, key)
	side, valid := sideFor(key)
	if !valid {
		return !key.DescriptorOnly || key.CSeqMethod == "INVITE" || key.CSeqMethod == "UPDATE" || key.CSeqMethod == "PRACK"
	}
	state := call.derivations[side]
	if key.DescriptorOnly && key.CSeqValid && !key.ReliableEvidence && !key.ReliableResponse && key.FromTag != "" && key.ToTag != "" && key.Branch != "" {
		request := call.derivations[derivationSide{key.FromTag, key.ToTag, key.FromTag, false}]
		response := call.derivations[derivationSide{key.ToTag, key.FromTag, key.FromTag, false}]
		if request != nil && response != nil && request.cseq == key.CSeq && response.cseq == key.CSeq && request.method == "INVITE" && response.method == "INVITE" && request.accepted && response.accepted && response.responseCode >= 200 && response.responseCode < 300 && !request.missing && !response.missing && !request.conflict && !response.conflict {
			// ACK to a final 2xx INVITE has its own branch. A bodyless ACK
			// cannot answer a delayed offer or alter retained media proof.
			if key.CSeqMethod == "ACK" && key.ResponseCode == 0 {
				return false
			}
			if key.CSeqMethod == "INVITE" && key.ResponseCode > 100 && key.ResponseCode < 200 && key.Branch == request.branch && key.Branch == response.branch {
				return false
			}
		}
	}
	if state == nil {
		return true
	}
	if key.CSeq < state.cseq {
		return false
	}
	if key.CSeq != state.cseq || key.Branch != state.branch || key.CSeqMethod != state.method {
		return true
	}
	if key.DescriptorOnly {
		return key.ResponseCode != state.responseCode
	}
	return !state.hasSDP || key.ResponseCode != state.responseCode || key.SDPDigest != state.digest
}

func (b *Bridge) observeSelectedRecordLocked(call *selectedCall, record mediaadmission.MetadataRecord) bool {
	if record.Key.Generation == 0 {
		b.stampReplayEligibilityLocked(&record.Key)
	}
	if !b.checkKeyLifetimeLocked(call, record.Key) {
		b.observeRejectedConflictLocked(call, record)
		return false
	}
	if !b.now().Before(b.proofHistory.blockedUntil) && call.quarantine != nil && record.Key.ResponseCode == 0 && (record.Key.CSeqMethod == "INVITE" || record.Key.CSeqMethod == "UPDATE") && !record.Key.HeaderConflict && record.Key.CSeqValid && !call.quarantine.contextLost && !call.quarantine.forkAmbiguous {
		// A fresh higher transaction may replace incomplete pressure-only
		// evidence. Preserve conflicting or independently unresolved obligations.
		replaces := len(call.quarantine.derivations) > 0
		for side, state := range call.quarantine.derivations {
			if side.initiator != record.Key.FromTag || state.cseq >= record.Key.CSeq || state.conflict || state.missing || unresolvedState(state.previous) {
				replaces = false
			}
		}
		if replaces {
			b.releaseDerivations(call.quarantine)
			call.quarantine = nil
			call.replayBlockedUntil = time.Time{}
		}
	}
	if (b.now().Before(b.proofHistory.blockedUntil) || call.quarantine != nil) && b.newMediaProofLocked(call, record.Key) {
		if record.Key.HeaderConflict || !record.Key.CSeqValid {
			// Storage pressure must not hide independent malformed/conflicting
			// evidence behind a quarantine that will later be discarded.
			b.observeDerivation(call, record)
		}
		b.quarantineRecordLocked(call, record)
		return false
	}
	return b.observeDerivation(call, record)
}

func (b *Bridge) observeRejectedConflictLocked(call *selectedCall, record mediaadmission.MetadataRecord) {
	key := record.Key
	if key.LifetimeSession != 0 || key.LifetimeGeneration != 0 {
		if key.LifetimeSession != call.lifetime.Session || key.LifetimeGeneration != call.lifetime.Generation {
			return
		}
	}
	if key.HeaderConflict || !key.CSeqValid {
		// Storage loss cannot erase independent malformed evidence. This path
		// supplies uncertainty only, never endpoints from a rejected observation.
		record.Endpoints = nil
		b.observeDerivation(call, record)
	}
}

// Quarantine uses the same charged descriptor/endpoint pool as selected proof.
// It cannot promote registry endpoints. Its lifetime is fixed on first evidence,
// bounded by one replay window plus PendingTTL; later pressure never renews it.
func (b *Bridge) quarantineRecordLocked(call *selectedCall, record mediaadmission.MetadataRecord) {
	if !call.replayEvidenceMissing {
		call.replayEvidenceMissing = true
		call.replayMissingCutoff = b.proofHistory.pressureCutoff
		call.quarantineExpires = time.Time{}
	}
	if !b.proofHistory.blockedUntil.IsZero() {
		call.replayBlockedUntil = b.proofHistory.blockedUntil
	}
	if call.quarantine == nil && !call.quarantineExpires.IsZero() && !b.now().Before(call.quarantineExpires) {
		return
	}
	if call.quarantine == nil {
		call.quarantine = &selectedCall{lifetime: call.lifetime, owner: call.owner, replayMissingCutoff: call.replayMissingCutoff}
		call.quarantineGeneration = record.Key.ReplayPressureGeneration
		call.quarantineExpires = b.now().Add(b.cfg.Limits.ReplayWindow + b.cfg.Limits.PendingTTL)
	}
	if !b.now().Before(call.quarantineExpires) {
		return
	}
	b.observeDerivation(call.quarantine, record)
	// Validate timely reliable-answer linkage while it is still within PendingTTL.
	// This caches proof inside quarantine; it grants no endpoint ownership.
	call.quarantine.known, call.quarantine.unknown, _ = b.derivationSummary(call.quarantine)
}

func (b *Bridge) requireRequestDerivationForResponseLocked(call *selectedCall, result pipeline.SIPResult) {
	if result.ResponseCode > 100 && result.ResponseCode < 300 && (result.CSeqMethod == "INVITE" || result.CSeqMethod == "UPDATE") {
		b.requireRequestDerivation(call, result)
	}
}

// At expiry, only an exact complete accepted exchange observed in quarantine
// may repair missing evidence. Time passing alone never supplies an exchange.
// Retired exact guards and explicit lifetime binding are checked again here.
func (b *Bridge) recoverPressureCallLocked(id string, call *selectedCall, now time.Time) {
	if call.quarantine != nil && !now.Before(call.quarantineExpires) {
		b.releaseDerivations(call.quarantine)
		call.quarantine = nil
	}
	if call.replayBlockedUntil.IsZero() || now.Before(call.replayBlockedUntil) {
		return
	}
	if now.Before(b.proofHistory.blockedUntil) {
		call.replayBlockedUntil = b.proofHistory.blockedUntil
		return
	}
	active, ok := b.cfg.Registry.Call(id)
	q := call.quarantine
	if q != nil && call.quarantineGeneration != 0 && call.quarantineGeneration <= b.proofHistory.invalidThrough {
		b.releaseDerivations(q)
		call.quarantine = nil
		q = nil
	}
	if ok && active.Lifetime == call.lifetime && q != nil {
		keys, valid := b.validQuarantineLocked(id, call, q)
		if valid {
			// Snapshot charged descriptors, release their quarantine reservation,
			// then transfer into the authoritative derivation pool. A failed
			// transfer leaves contextLost/missing intact and never opens media.
			states := make(map[derivationSide]*derivationState, len(q.derivations))
			for side, state := range q.derivations {
				copy := *state
				states[side] = &copy
			}
			b.releaseDerivations(q)
			call.quarantine = nil
			transferred := true
			for side, state := range states {
				if old := call.derivations[side]; old != nil {
					// Quarantine cannot erase an unrelated malformed or unresolved
					// predecessor. Ordinary supersession must discharge it.
					state.previous = rollbackDerivation(old)
					state.recoveryPending = old.recoveryPending || unresolvedState(old)
					state.recoveryEligible = old.dialogConfirmed
				}
				if !b.putDerivation(call, side, state) {
					transferred = false
				}
			}
			if transferred {
				for _, key := range keys {
					b.finishConfirmedNegotiation(call, key)
				}
			}
			if !call.replayEvidenceMissing && len(call.repairRetire) > 0 {
				if err := b.scheduleRetirementsLocked(call, call.repairRetire, now); err != nil {
					call.contextLost = true
					logger.Error("Quarantined media recovery retention failed", "domain", b.cfg.Domain, "error", err)
				}
				call.repairRetire = nil
				if err := b.cancelRequiredRetirementsLocked(call); err != nil {
					call.contextLost = true
					logger.Error("Quarantined media recovery retention failed", "domain", b.cfg.Domain, "error", err)
				}
			}
		}
	}
	// Keep the recovery marker while eligible incomplete quarantine may still
	// receive its exact response after pressure ends. Expiry/fresh authoritative
	// proof are the other ways to discharge it.
	if call.quarantine == nil {
		call.replayBlockedUntil = time.Time{}
	}
	call.known, call.unknown, call.mediaSet = b.derivationSummary(call)
	call.mediaRevision++
	call.activeMedia = len(call.mediaSet) > 0
	if !call.unknown {
		for endpoint := range call.mediaSet {
			call.promote = append(call.promote, endpoint)
		}
		call.promote = uniqueEndpoints(call.promote, b.cfg.Limits.MaxEndpointsPerOwner+1)
	}
	call.retry = true
	b.needsSnapshot = true
}

// Every retained quarantine descriptor must belong to a complete exchange.
// One good pair cannot discharge another incomplete/conflicting obligation.
func (b *Bridge) validQuarantineLocked(id string, call, q *selectedCall) ([]mediaadmission.DialogKey, bool) {
	known, unknown, _ := b.derivationSummary(q)
	if !known || unknown {
		return nil, false
	}
	covered := make(map[derivationSide]bool)
	var keys []mediaadmission.DialogKey
	for side, request := range q.derivations {
		if side.prack || side.sender != side.initiator || side.peer == "" || request.method != "INVITE" && request.method != "UPDATE" {
			continue
		}
		responseSide := derivationSide{side.peer, side.sender, side.initiator, false}
		response := q.derivations[responseSide]
		key := mediaadmission.DialogKey{CallID: id, FromTag: side.sender, ToTag: side.peer, Branch: request.branch, CSeq: request.cseq, CSeqMethod: request.method, CSeqValid: true, LifetimeSession: call.lifetime.Session, LifetimeGeneration: call.lifetime.Generation}
		if !acceptedTransaction(request, key) || !acceptedTransaction(response, key) || !request.complete || !response.complete || !request.hasSDP || !response.hasSDP || request.missing || response.missing || request.conflict || response.conflict || request.observed <= call.replayMissingCutoff || response.observed <= call.replayMissingCutoff || !b.canConfirmedLifetimeLocked(call, key) {
			return nil, false
		}
		keys = append(keys, key)
		covered[side], covered[responseSide] = true, true
		ackSide := side
		ackSide.prack = true
		if answer := q.derivations[ackSide]; answer != nil && b.reliableAnswerMatches(q, ackSide, answer, b.now()) {
			covered[ackSide] = true
		}
	}
	for side, state := range q.derivations {
		if !covered[side] || state.observed <= call.replayMissingCutoff {
			return nil, false
		}
	}
	return keys, len(keys) > 0
}

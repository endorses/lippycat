package admission

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"time"
)

// cloneEarlyForkLocked reconstructs the original request role for another tag
// on the same initial transaction. A prior fork's PRACK answer is not the new
// fork's initiating offer. Each descriptor uses the existing charged pool.
func (b *Bridge) cloneEarlyForkLocked(call *selectedCall, key mediaadmission.DialogKey) {
	if key.ToTag == "" || key.FromTag == "" || key.CSeqMethod != "INVITE" || !key.CSeqValid || key.HeaderConflict {
		return
	}
	bound := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
	if call.derivations[bound] != nil {
		return
	}
	for side, source := range call.derivations {
		if side.prack || side.sender != key.FromTag || side.initiator != key.FromTag || side.peer == "" || source.cseq != key.CSeq || source.branch != key.Branch || source.method != "INVITE" || source.conflict || source.forkRetired {
			continue
		}
		next := *source
		next.accepted, next.dialogConfirmed, next.recoveryEligible, next.recoveryPending = false, false, false, false
		next.previous, next.retirementEndpoints, next.retainedEndpoints = nil, nil, nil
		next.prackRecovery, next.prackRecoveryCSeq = false, 0
		next.prackCSeq, next.prackBranch = 0, ""
		if source.reliableAnswered {
			next.reliableAnswered, next.hasSDP, next.complete = false, false, true
			next.endpoints = nil
			next.digest = [32]byte{}
		}
		// A newly discovered losing fork still needs a charged watermark. Its SDP
		// cannot reopen proof once another exact initial dialog was confirmed.
		if source.dialogConfirmed && source.accepted {
			next = derivationState{cseq: key.CSeq, branch: key.Branch, method: "INVITE", complete: true, rejected: true, forkRetired: true}
		}
		b.putDerivation(call, bound, &next)
		return
	}
}

// forkDispositionLocked rejects late evidence for a retired early dialog. A
// valid second success is preserved as ambiguity rather than picking a winner.
func (b *Bridge) forkDispositionLocked(call *selectedCall, key mediaadmission.DialogKey) bool {
	return b.observeRetiredForkLocked(call, mediaadmission.MetadataRecord{Key: key})
}

func (b *Bridge) observeRetiredForkLocked(call *selectedCall, record mediaadmission.MetadataRecord) bool {
	key := record.Key
	side := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
	request := call.derivations[side]
	if request == nil || !request.forkRetired {
		return false
	}
	active, exists := b.cfg.Registry.Call(key.CallID)
	if !exists || active.Lifetime != call.lifetime || !b.checkKeyLifetimeLocked(call, key) {
		return true
	}
	if key.CSeqValid && !key.HeaderConflict && key.CSeqMethod == "INVITE" && key.ResponseCode >= 200 && key.ResponseCode < 300 && key.CSeq == request.cseq && key.Branch == request.branch {
		call.forkAmbiguous = true
		// A second success may arrive after losing-fork grace already expired. Keep
		// bounded safe media provenance so a bodyless success can restore ownership.
		next := *request
		keys := append([]mediaadmission.EndpointKey(nil), request.retainedEndpoints...)
		keys = append(keys, request.retirementEndpoints...)
		keys = append(keys, record.Endpoints...)
		keys = uniqueEndpoints(keys, b.cfg.Limits.MaxEndpointsPerOwner+1)
		if len(keys) > b.cfg.Limits.MaxEndpointsPerOwner {
			call.contextLost = true
			return true
		}
		next.retainedEndpoints, next.retirementEndpoints = keys, nil
		if !b.putDerivation(call, side, &next) {
			return true
		}
		if err := b.releaseRetirementsLocked(call); err != nil {
			call.contextLost = true
		}
		call.repairRetire = nil
		pending := uniqueEndpoints(append(append([]mediaadmission.EndpointKey(nil), call.promote...), keys...), b.cfg.Limits.MaxEndpointsPerOwner+1)
		if len(pending) > b.cfg.Limits.MaxEndpointsPerOwner {
			call.contextLost = true
		} else {
			call.promote = pending
		}
	}
	return true
}

// Replace all sibling proof with its inert ownership archive in one charged
// transaction. Temporary double-accounting must not reject a fitting archive.
func (b *Bridge) archiveForkLocked(call *selectedCall, key mediaadmission.DialogKey, peer string, endpoints []mediaadmission.EndpointKey) bool {
	endpoints = uniqueEndpoints(endpoints, b.cfg.Limits.MaxEndpointsPerOwner+1)
	if len(endpoints) > b.cfg.Limits.MaxEndpointsPerOwner {
		call.contextLost = true
		return false
	}
	oldUsage := mediaadmission.SelectedDerivationUsage{}
	var sides []derivationSide
	var acknowledgmentMaximum uint64
	for side, state := range call.derivations {
		sibling := side.peer
		if side.sender != side.initiator {
			sibling = side.sender
		}
		if side.initiator != key.FromTag || sibling != peer {
			continue
		}
		if side.sender == side.initiator {
			for _, prior := range []*derivationState{state, state.previous} {
				if prior == nil {
					continue
				}
				acknowledgmentMaximum = max(acknowledgmentMaximum, prior.prackCSeq, prior.repeatedAckSequence)
				if side.prack {
					acknowledgmentMaximum = max(acknowledgmentMaximum, prior.cseq)
				}
			}
		}
		bytes, count := derivationCost(side, state)
		oldUsage.Contexts++
		oldUsage.Bytes += bytes
		oldUsage.Endpoints += count
		sides = append(sides, side)
	}
	side := derivationSide{key.FromTag, peer, key.FromTag, false}
	next := &derivationState{cseq: key.CSeq, branch: key.Branch, method: "INVITE", complete: true, rejected: true, forkRetired: true, retirementEndpoints: endpoints, prackCSeq: acknowledgmentMaximum}
	bytes, count := derivationCost(side, next)
	usage := mediaadmission.SelectedDerivationUsage{Contexts: 1, Bytes: bytes, Endpoints: count}
	if err := b.cfg.Metadata.ReserveSelectedDerivation(oldUsage, usage); err != nil {
		call.contextLost = true
		return false
	}
	for _, side := range sides {
		delete(call.derivations, side)
	}
	b.storeDerivation(call, side, next)
	b.derivationCount += usage.Contexts - oldUsage.Contexts
	b.derivationBytes += usage.Bytes - oldUsage.Bytes
	b.derivationEndpoints += usage.Endpoints - oldUsage.Endpoints
	return true
}

// confirmForkLocked removes only sibling proof from the exact initial INVITE.
// Existing independent requirements and shared media remain protected; exclusive
// sibling ownership is handed to the same grace scheduler as ordinary recovery.
func (b *Bridge) confirmForkLocked(call *selectedCall, key mediaadmission.DialogKey) {
	if key.CSeqMethod != "INVITE" || !key.CSeqValid || key.HeaderConflict || key.ToTag == "" {
		return
	}
	winnerSide := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
	winner := call.derivations[winnerSide]
	response := call.derivations[derivationSide{key.ToTag, key.FromTag, key.FromTag, false}]
	if acceptedTransaction(winner, key) && !winner.hasSDP {
		// Another unresolved fork must not short-circuit validation of this exact
		// accepted dialog's independently observed answer.
		if b.bodylessReliablyAnswered(call, winnerSide, winner, time.Now()) {
			winner = call.derivations[winnerSide]
		}
	}
	if !acceptedTransaction(winner, key) || !acceptedTransaction(response, key) || !winner.complete || !response.complete || !winner.hasSDP || !response.hasSDP || winner.missing || response.missing {
		return
	}
	losing := make(map[string]*derivationState)
	for side, state := range call.derivations {
		if side.prack || side.sender != key.FromTag || side.initiator != key.FromTag || side.peer == "" || side.peer == key.ToTag || state.cseq != key.CSeq || state.branch != key.Branch || state.method != "INVITE" {
			continue
		}
		if state.dialogConfirmed && state.accepted && !state.forkRetired {
			call.forkAmbiguous = true
			return
		}
		if !state.forkRetired {
			losing[side.peer] = state
		}
	}
	if len(losing) == 0 {
		return
	}
	obsolete := make(map[mediaadmission.EndpointKey]bool)
	archives := make(map[string][]mediaadmission.EndpointKey)
	for peer := range losing {
		archives[peer] = nil
	}
	for side, state := range call.derivations {
		if side.initiator != key.FromTag {
			continue
		}
		peer := side.peer
		if side.sender != side.initiator {
			peer = side.sender
		}
		if losing[peer] == nil {
			continue
		}
		for _, prior := range []*derivationState{state, state.previous} {
			if prior == nil {
				continue
			}
			for _, endpoints := range [][]mediaadmission.EndpointKey{prior.endpoints, prior.retirementEndpoints, prior.retainedEndpoints} {
				for _, endpoint := range endpoints {
					obsolete[endpoint] = true
					archives[peer] = append(archives[peer], endpoint)
				}
			}
		}
	}
	for peer, endpoints := range archives {
		if !b.archiveForkLocked(call, key, peer, endpoints) {
			return
		}
	}
	for _, state := range call.derivations {
		for _, prior := range []*derivationState{state, state.previous} {
			if prior == nil {
				continue
			}
			for _, endpoints := range [][]mediaadmission.EndpointKey{prior.endpoints, prior.retainedEndpoints} {
				for _, endpoint := range endpoints {
					delete(obsolete, endpoint)
				}
			}
		}
	}
	keys := append([]mediaadmission.EndpointKey(nil), call.repairRetire...)
	for endpoint := range obsolete {
		keys = append(keys, endpoint)
	}
	keys = uniqueEndpoints(keys, b.cfg.Limits.MaxEndpointsPerOwner+1)
	if len(keys) > b.cfg.Limits.MaxEndpointsPerOwner {
		call.contextLost = true
		return
	}
	call.repairRetire = keys
}

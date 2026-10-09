package admission

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

func sameDialog(side derivationSide, key mediaadmission.DialogKey) bool {
	return side.peer != "" && ((side.sender == key.FromTag && side.peer == key.ToTag) ||
		(side.sender == key.ToTag && side.peer == key.FromTag))
}

func unresolvedState(state *derivationState) bool {
	if state == nil || state.rejected {
		return false
	}
	return state.conflict || !state.complete || state.missing || state.recoveryPending || state.repeatedPending
}

// Conflicting linkage is add-only evidence, never a negotiation watermark that
// can prove acceptance. Its validated maximum bounds later same-initiator repair.
func (b *Bridge) observeConflict(call *selectedCall, record mediaadmission.MetadataRecord) bool {
	key := record.Key
	if key.FromTag == "" || key.Branch == "" || key.CSeqMethod == "" {
		call.contextLost = true
		return false
	}
	b.bindEarlyDerivation(call, key)
	side := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
	if key.ResponseCode != 0 {
		side.sender, side.peer = side.peer, side.sender
	}
	maximum := key.CSeq
	if key.CSeqBoundsValid {
		maximum = key.CSeqMaximum
	}
	next := &derivationState{cseq: maximum, branch: key.Branch, method: key.CSeqMethod,
		hasSDP: !key.DescriptorOnly, endpoints: record.Endpoints, conflict: true,
		conflictBoundValid: key.CSeqBoundsValid, conflictMaximum: maximum, observed: key.Generation}
	if old := call.derivations[side]; old != nil {
		// Conflicting messages cannot certify bounds for earlier unavailable
		// evidence. Keep that obligation when flattening the bounded predecessor.
		for prior := old; prior != nil; prior = prior.previous {
			if !prior.conflict {
				continue
			}
			if !prior.conflictBoundValid {
				next.conflictBoundValid = false
			}
			if prior.conflictMaximum > next.conflictMaximum {
				next.cseq, next.conflictMaximum = prior.cseq, prior.conflictMaximum
			}
		}
		next.dialogConfirmed = old.dialogConfirmed
		next.previous = rollbackDerivation(old)
		if !b.retainRetirementEndpoints(call, next, old) {
			return false
		}
		next.endpoints = uniqueEndpoints(append(append([]mediaadmission.EndpointKey(nil), old.endpoints...), record.Endpoints...), b.cfg.Limits.MaxEndpointsPerOwner+1)
		if len(next.endpoints) > b.cfg.Limits.MaxEndpointsPerOwner {
			call.contextLost = true
			return false
		}
	}
	return b.putDerivation(call, side, next)
}

// Supersession is committed only with a complete accepted exchange. Each
// initiator's sequence space is independent; a new participant must contribute
// both observations after the uncertain context instead of borrowing a watermark.
func (b *Bridge) supersedeUncertainty(call *selectedCall, key mediaadmission.DialogKey) bool {
	requestSide := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
	responseSide := derivationSide{key.ToTag, key.FromTag, key.FromTag, false}
	request, response := call.derivations[requestSide], call.derivations[responseSide]
	if !acceptedTransaction(request, key) || !acceptedTransaction(response, key) ||
		!request.complete || !request.hasSDP || request.missing || request.conflict ||
		!response.complete || !response.hasSDP || response.missing || response.conflict {
		return false
	}
	var affected []derivationSide
	groups := make(map[string]bool)
	needsEstablished := false
	for side, state := range call.derivations {
		if !sameDialog(side, key) || side.initiator == "" {
			continue
		}
		prior := state
		if side == requestSide || side == responseSide {
			prior = state.previous
		}
		uncertain := unresolvedState(prior)
		delayed := prior != nil && !prior.hasSDP && prior.method == "INVITE" && side.sender == side.initiator && !prior.rejected
		uncertain = uncertain || delayed
		if side.prack {
			uncertain = !b.reliableAnswerMatches(call, side, state, b.now())
			initiating := call.derivations[derivationSide{side.sender, side.peer, side.initiator, false}]
			if initiating != nil {
				for _, established := range []*derivationState{initiating, initiating.previous} {
					if established != nil && established.reliableAnswered && established.complete && !established.rejected &&
						state.complete && !state.rejected && state.rackValid && state.rackCSeq == uint32(established.cseq) &&
						established.prackCSeq == state.cseq && established.prackBranch == state.branch {
						uncertain = false
					}
				}
			}
		}
		if !uncertain {
			continue
		}
		if prior != nil && prior.conflict && !prior.conflictBoundValid {
			return false
		}
		if side.initiator == key.FromTag {
			if prior != nil && key.CSeq <= prior.cseq {
				return false
			}
		} else if prior != nil && (request.observed <= prior.observed || response.observed <= prior.observed) {
			return false
		}
		groups[side.initiator] = true
		needsEstablished = needsEstablished || side.prack || delayed || (prior != nil && prior.prackRecovery)
	}
	if len(groups) == 0 {
		return false
	}
	if needsEstablished {
		established := request.previous != nil && request.previous.dialogConfirmed
		for side, state := range call.derivations {
			if side != requestSide && sameDialog(side, key) && side.sender == side.initiator && state.dialogConfirmed {
				established = true
			}
		}
		if !established {
			return false
		}
	}
	for side := range call.derivations {
		if sameDialog(side, key) && groups[side.initiator] {
			affected = append(affected, side)
		}
	}
	protected := make(map[mediaadmission.EndpointKey]bool)
	for _, state := range call.derivations {
		for _, endpoint := range state.retainedEndpoints {
			protected[endpoint] = true
		}
		if state.endpointsHealthy {
			for _, endpoint := range state.endpoints {
				protected[endpoint] = true
			}
		}
	}
	for _, state := range []*derivationState{request, response} {
		for _, endpoint := range state.endpoints {
			protected[endpoint] = true
		}
	}
	for _, side := range affected {
		state := call.derivations[side]
		prior := state
		if side == requestSide || side == responseSide {
			prior = state.previous
		}
		for _, evidence := range []*derivationState{prior, state.previous} {
			if evidence == nil {
				continue
			}
			for _, endpoint := range append(append([]mediaadmission.EndpointKey(nil), evidence.endpoints...), state.retirementEndpoints...) {
				if !protected[endpoint] {
					call.repairRetire = append(call.repairRetire, endpoint)
				}
			}
		}
		if side != requestSide && side != responseSide {
			b.removeDerivation(call, side)
		}
	}
	call.repairRetire = uniqueEndpoints(call.repairRetire, b.cfg.Limits.MaxEndpointsPerOwner+1)
	if len(call.repairRetire) > b.cfg.Limits.MaxEndpointsPerOwner {
		call.contextLost = true
	}
	return true
}

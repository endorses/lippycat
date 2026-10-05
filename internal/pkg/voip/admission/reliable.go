package admission

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

// One separately charged answer descriptor permits capture-order reversal
// without confusing PRACK's transaction with the INVITE it acknowledges. It
// never becomes an offer merely because it carries a complete SDP body.
func (b *Bridge) observePRACK(call *selectedCall, record mediaadmission.MetadataRecord) bool {
	key := record.Key
	side, valid := sideFor(key)
	if !valid || side.peer == "" || key.DescriptorOnly {
		call.contextLost = true
		return true // Independently validated endpoints may still be promoted.
	}
	if current := call.derivations[side]; current != nil && key.RAckValid && current.cseq > uint64(key.RAckCSeq) && current.cseq >= key.CSeq {
		return false // A later observed negotiation already superseded this answer.
	}
	side.prack = true
	next := &derivationState{
		cseq: key.CSeq, branch: key.Branch, method: key.CSeqMethod,
		complete: record.Complete, hasSDP: true, digest: key.SDPDigest,
		endpoints: record.Endpoints, rackValid: key.RAckValid,
		rackRSeq: key.RAckRSeq, rackCSeq: key.RAckCSeq,
		proofExpires: time.Now().Add(b.cfg.Limits.PendingTTL),
	}
	if old := call.derivations[side]; old != nil {
		// This implementation retains one answer, not a PRACK exchange history.
		// Identical retransmissions do not extend the proof lifetime. Conflicting
		// bodies, references or transactions remain unknown for this context.
		if next.cseq != old.cseq || next.branch != old.branch || (old.hasSDP && (next.digest != old.digest || next.rackValid != old.rackValid || next.rackRSeq != old.rackRSeq || next.rackCSeq != old.rackCSeq)) {
			call.contextLost = true
			return true
		}
		next.complete = old.complete && next.complete && sameDerivationEndpoints(old.endpoints, next.endpoints)
		next.rejected = old.rejected
		next.proofExpires = old.proofExpires
	}
	b.putDerivation(call, side, next)
	return true
}

func (b *Bridge) reliableAnswerMatches(call *selectedCall, side derivationSide, answer *derivationState, now time.Time) bool {
	requestSide := side
	requestSide.prack = false
	request := call.derivations[requestSide]
	if request == nil || request.method != "INVITE" || (request.hasSDP && !request.reliableAnswered) || request.missing || request.rejected || !answer.rackValid || !answer.complete || answer.rackCSeq != uint32(request.cseq) || answer.cseq <= request.cseq {
		return false
	}
	response := call.derivations[derivationSide{side.peer, side.sender, side.initiator, false}]
	if response == nil || !response.reliable || !response.complete || !response.hasSDP || response.rejected || response.cseq != request.cseq || response.branch != request.branch || response.method != "INVITE" || response.rseq != answer.rackRSeq || response.rseq >= 1<<31 {
		return false
	}
	// Expiry cannot supply a previously missing observation. Once established,
	// the bounded proof remains part of this exact lifetime's current context;
	// identical final-response retransmissions do not reopen the answer role.
	if !request.reliableAnswered && (!now.Before(answer.proofExpires) || !now.Before(response.proofExpires)) {
		return false
	}
	if !request.reliableAnswered {
		// Preserve the validated answer in the initiating context so the existing
		// single rollback predecessor remains complete if a later UPDATE fails.
		// The additional owned endpoints are charged before publishing the copy.
		next := *request
		next.reliableAnswered, next.hasSDP, next.complete = true, true, true
		next.prackCSeq, next.prackBranch = answer.cseq, answer.branch
		next.endpoints = answer.endpoints
		if !b.putDerivation(call, requestSide, &next) {
			return false
		}
	}
	return true
}

func (b *Bridge) rejectPRACK(call *selectedCall, key mediaadmission.DialogKey) {
	_, valid := sideFor(key)
	if !valid {
		return
	}
	// Responses reverse media sender, but retain the request's initiator tags.
	side := derivationSide{key.FromTag, key.ToTag, key.FromTag, true}
	requestSide := side
	requestSide.prack = false
	request := call.derivations[requestSide]
	matched := false
	if request != nil {
		next := *request
		if exactPRACKProvenance(request, key) {
			next.complete, matched = false, true
		}
		if exactPRACKProvenance(request.previous, key) {
			prior := *request.previous
			prior.complete, matched = false, true
			next.previous = &prior
		}
		if matched {
			b.putDerivation(call, requestSide, &next)
		}
	}
	answer := call.derivations[side]
	if answer != nil {
		if answer.cseq == key.CSeq && answer.branch == key.Branch {
			next := *answer
			next.complete, next.rejected = false, true
			b.putDerivation(call, side, &next)
		}
		return
	}
	if matched || (request != nil && request.cseq >= key.CSeq) {
		return // Retained rollback proof was updated, or negotiation superseded it.
	}
	// Capture may deliver a rejection before its request. Retain one exact
	// transaction watermark in the same bounded answer slot; a delayed SDP
	// request can add safe endpoints but cannot turn rejection into completeness.
	b.putDerivation(call, side, &derivationState{cseq: key.CSeq, branch: key.Branch, method: "PRACK", rejected: true, proofExpires: time.Now().Add(b.cfg.Limits.PendingTTL)})
}

func exactPRACKProvenance(state *derivationState, key mediaadmission.DialogKey) bool {
	return state != nil && state.reliableAnswered && state.prackBranch != "" && state.prackCSeq == key.CSeq && state.prackBranch == key.Branch
}

func (b *Bridge) bodylessReliablyAnswered(call *selectedCall, side derivationSide, request *derivationState, now time.Time) bool {
	answerSide := side
	answerSide.prack = true
	answer := call.derivations[answerSide]
	return answer != nil && request.method == "INVITE" && b.reliableAnswerMatches(call, answerSide, answer, now)
}

package admission

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"time"
)

// repeatReliableResponseLocked keeps an already validated body answer separate
// from a later reliable acknowledgment of identical content. The new RSeq is
// retained, but never substituted into the original PRACK's body proof.
func (b *Bridge) repeatReliableResponseLocked(call *selectedCall, side derivationSide, old, next *derivationState, key mediaadmission.DialogKey) bool {
	if side.prack || side.sender == side.initiator || key.ResponseCode <= 100 || key.ResponseCode >= 200 || !key.ReliableResponse || key.HeaderConflict || !key.CSeqValid || key.RSeq == 0 || !old.reliable || !old.complete || !next.complete || old.cseq != key.CSeq || old.branch != key.Branch || old.method != key.CSeqMethod || old.digest != next.digest || !sameDerivationEndpoints(old.endpoints, next.endpoints) {
		return false
	}
	requestSide := derivationSide{side.initiator, side.sender, side.initiator, false}
	request := call.derivations[requestSide]
	if request == nil || !request.complete || request.missing || request.rejected || request.conflict {
		return false
	}
	answerSide := requestSide
	answerSide.prack = true
	answer := request
	if request.reliableAnswered {
		answer = call.derivations[answerSide]
		if answer == nil || !b.reliableAnswerMatches(call, answerSide, answer, time.Now()) {
			return false
		}
	} else if !request.hasSDP || request.prackCSeq <= request.cseq {
		return false
	}
	latest := max(old.rseq, old.repeatedRSeq)
	if key.RSeq <= old.rseq {
		return false
	}
	if key.RSeq > latest && (latest == ^uint32(0) || key.RSeq != latest+1 || old.repeatedPending) {
		return false // A skipped or unacknowledged reliable transaction is not a valid repeat.
	}
	// Older reliable retransmissions cannot rewind a newer outstanding RSeq.
	next.reliable, next.rseq, next.proofExpires = old.reliable, old.rseq, old.proofExpires
	next.repeatedRSeq, next.repeatedPending = old.repeatedRSeq, old.repeatedPending
	if key.RSeq > old.repeatedRSeq {
		next.repeatedRSeq, next.repeatedPending = key.RSeq, true
	}
	if repeatedAckMatches(request, next, answer, time.Now()) {
		next.repeatedPending = false
	}
	return true
}

func repeatedAckMatches(request, response, answer *derivationState, now time.Time) bool {
	return answer.repeatedAckValid && now.Before(answer.repeatedAckExpires) && answer.repeatedAckRSeq == response.repeatedRSeq && uint64(answer.repeatedAckCSeq) == request.cseq && answer.repeatedAckSequence > request.prackCSeq
}

// observeRepeatedPRACKLocked retains one separately validated acknowledgment in
// the charged canonical answer descriptor. A bodyless ACK never supplies SDP.
// This supports response/PRACK reversal without forgetting the original proof.
func (b *Bridge) observeRepeatedPRACKLocked(call *selectedCall, key mediaadmission.DialogKey) bool {
	if !key.DescriptorOnly || key.CSeqMethod != "PRACK" || key.ResponseCode != 0 {
		return false
	}
	requestSide := derivationSide{key.FromTag, key.ToTag, key.FromTag, false}
	request := call.derivations[requestSide]
	answerSide := requestSide
	answerSide.prack = true
	answer := request
	if request == nil || !request.complete || request.rejected || request.missing || request.conflict {
		return true
	}
	responseSide := derivationSide{key.ToTag, key.FromTag, key.FromTag, false}
	response := call.derivations[responseSide]
	if request.reliableAnswered {
		answer = call.derivations[answerSide]
		if answer == nil || !answer.complete || !answer.hasSDP {
			return true
		}
	} else {
		// An offered INVITE's SDP answer belongs to the response; its bodyless
		// PRACK acknowledges transport of that answer without replacing either
		// canonical body. Store the acknowledgement on the existing request.
		answerSide = requestSide
		if !request.hasSDP || response == nil || !response.reliable || !response.complete ||
			!response.hasSDP || response.conflict || response.rejected || response.cseq != request.cseq ||
			response.branch != request.branch || response.method != "INVITE" ||
			(response.repeatedRSeq == 0 && key.RAckRSeq != response.rseq &&
				(!answer.repeatedAckValid || response.rseq == ^uint32(0) || key.RAckRSeq != response.rseq+1)) {
			return true
		}
	}
	if response == nil || !response.reliable || !response.complete || response.conflict || response.rejected || response.rseq >= 1<<31 {
		return true
	}
	latest := max(response.rseq, response.repeatedRSeq)
	if key.RAckRSeq != latest && (response.repeatedPending || latest == ^uint32(0) || key.RAckRSeq != latest+1) {
		return true
	}
	// Invalid, stale, or unrelated references leave both the original body proof
	// and any outstanding acknowledgment untouched.
	if !key.CSeqValid || key.HeaderConflict || !key.RAckValid || uint64(key.RAckCSeq) != request.cseq || (request.reliableAnswered && key.RAckRSeq <= answer.rackRSeq) || key.CSeq <= request.cseq || (request.reliableAnswered && key.CSeq <= request.prackCSeq) {
		return true
	}
	if answer.repeatedAckSequence != 0 && key.CSeq <= answer.repeatedAckSequence {
		return true
	}
	next := *answer
	if !request.reliableAnswered && next.prackCSeq == 0 {
		next.prackCSeq, next.prackBranch = key.CSeq, key.Branch
	}
	next.repeatedAckValid = true
	next.repeatedAckRSeq, next.repeatedAckCSeq = key.RAckRSeq, key.RAckCSeq
	next.repeatedAckSequence, next.repeatedAckBranch = key.CSeq, key.Branch
	next.repeatedAckExpires = time.Now().Add(b.cfg.Limits.PendingTTL)
	if !b.putDerivation(call, answerSide, &next) {
		return true
	}
	if response != nil && response.repeatedPending && repeatedAckMatches(request, response, &next, time.Now()) {
		confirmed := *response
		confirmed.repeatedPending = false
		b.putDerivation(call, responseSide, &confirmed)
	}
	return true
}

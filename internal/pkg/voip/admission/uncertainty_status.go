package admission

import (
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
)

// Occurrences count duplicate-bearing singleton header groups per message, not
// raw repeated lines. Valid identical groups are diagnostics, not unknown calls.
func (b *Bridge) countDuplicateGroupsLocked(result pipeline.SIPResult) {
	duplicates := result.DuplicateReliableHeaders
	conflicts := result.ReliableHeaderEvidence.Conflicts
	for _, group := range [][2]bool{{duplicates.CSeq, conflicts.CSeq}, {duplicates.RSeq, conflicts.RSeq}, {duplicates.RAck, conflicts.RAck}} {
		if !group[0] {
			continue
		}
		if group[1] {
			b.conflictingDuplicateGroups++
		} else {
			b.identicalDuplicateGroups++
		}
	}
}

func (b *Bridge) publishUncertaintyLocked() {
	stats := mediaadmission.UncertaintyStats{IdenticalDuplicates: b.identicalDuplicateGroups, ConflictingDuplicates: b.conflictingDuplicateGroups}
	for _, call := range b.selected {
		if !call.unknown && !call.contextLost && !call.lifetimeAmbiguous && !call.forkAmbiguous && !call.retirementFailed {
			continue
		}
		stats.UnknownCalls++
		var reasons [mediaadmission.UncertaintyReasonCount]bool
		reasons[mediaadmission.ReasonEvidenceLoss] = call.contextLost || call.lifetimeAmbiguous || call.retirementFailed
		reasons[mediaadmission.ReasonForkAmbiguity] = call.forkAmbiguous
		for side, state := range call.derivations {
			if side.initiator == "" || state.forkRetired {
				continue
			}
			for _, evidence := range []*derivationState{state, state.previous} {
				if evidence == nil || evidence.rejected {
					continue
				}
				reasons[mediaadmission.ReasonConflictingHeaders] = reasons[mediaadmission.ReasonConflictingHeaders] || evidence.conflict
				reasons[mediaadmission.ReasonPartialSDP] = reasons[mediaadmission.ReasonPartialSDP] || (evidence.hasSDP && !evidence.complete && !evidence.conflict)
				reasons[mediaadmission.ReasonDelayedOffer] = reasons[mediaadmission.ReasonDelayedOffer] || evidence.missing || (!evidence.hasSDP && !evidence.reliableAnswered && evidence.method == "INVITE" && side.sender == side.initiator)
			}
			if state.prackRecovery {
				reasons[mediaadmission.ReasonFaultyPRACK] = true
			}
			if side.prack {
				requestSide := side
				requestSide.prack = false
				request := call.derivations[requestSide]
				_, faulty := b.unresolvedPRACKContext(call, requestSide, request)
				reasons[mediaadmission.ReasonFaultyPRACK] = reasons[mediaadmission.ReasonFaultyPRACK] || request == nil || faulty
			}
		}
		any := false
		for reason, present := range reasons {
			if present {
				stats.Reasons[reason]++
				any = true
			}
		}
		if !any {
			stats.Reasons[mediaadmission.ReasonEvidenceLoss]++
		}
	}
	b.cfg.Controller.UpdateUncertainty(b.cfg.Domain, stats)
}

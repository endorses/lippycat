//go:build li

package processor

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/li"
)

func (p *Processor) populateLICallCorrelationStats(dst *management.ProcessorStats) {
	if dst == nil || p.liStorage == nil || p.liStorage.correlation == nil {
		return
	}
	dst.LiCallCorrelation = mapLICallCorrelationStats(p.liStorage.correlation.Stats())
	if p.liStorage.correlationStore != nil {
		dst.LiCallCorrelation.Storage = storageStatusProto(p.liStorage.correlationStore.StorageStatus())
	}
}
func mapLICallCorrelationStats(s li.CallCorrelationStats) *management.LICallCorrelationStats {
	return &management.LICallCorrelationStats{
		Adopted: copyLICorrelationStatsMap(s.Adopted), Standalone: copyLICorrelationStatsMap(s.Standalone), Sdp: copyLICorrelationStatsMap(s.SDP),
		Records: uint64(max(0, s.Records)), Candidates: uint64(max(0, s.Candidates)), Transactions: uint64(max(0, s.Transactions)), Origins: uint64(max(0, s.Origins)), SuspendedOrigins: uint64(max(0, s.SuspendedOrigins)),
		GroupsTwo: uint64(max(0, s.GroupsTwo)), GroupsThree: uint64(max(0, s.GroupsThree)), GroupsFourOrMore: uint64(max(0, s.GroupsFourOrMore)),
		MaxRecords: uint64(max(0, s.MaxRecords)), MaxCandidates: uint64(max(0, s.MaxCandidates)), MaxOrigins: uint64(max(0, s.MaxOrigins)),
		Blind: s.Blind, BlindCause: s.BlindCause, BlindRemainingNs: int64(s.BlindRemaining), Persistence: s.Persistence, UncertainWrites: s.UncertainWrites, UnresolvedWrites: s.UnresolvedWrites, SdpDisabled: s.SDPDisabled, UnrecordedDecisions: s.UnrecordedDecisions,
		DeferredPackets: uint64(max(0, s.DeferredPackets)), DeferredBytes: uint64(max(0, s.DeferredBytes)), DeferredRejected: s.DeferredRejected,
	}
}
func copyLICorrelationStatsMap(source map[string]uint64) map[string]uint64 {
	if source == nil {
		return nil
	}
	result := make(map[string]uint64, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

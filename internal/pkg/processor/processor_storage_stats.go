//go:build processor || tap || all

package processor

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/securestore"
)

func storageStatusProto(s securestore.StorageStatus) *management.StorageStatus {
	p := &management.StorageStatus{Mode: s.Mode, State: s.State, AdmissionBlocked: s.AdmissionBlocked,
		FaultCode: s.FaultCode, PolicyFaultCode: s.PolicyFaultCode, LastOutcome: s.LastOutcome,
		LastErrorCode: s.LastErrorCode, Commits: s.Commits, DefiniteFailures: s.DefiniteFailures,
		Uncertain: s.Uncertain, CommittedCleanupWarnings: s.CleanupWarnings,
		ActiveKeyId: s.ActiveKeyID, PriorKeyIds: s.PriorKeyIDs}
	if u := s.Usage; u != nil {
		p.KeyUsage = &management.EncryptionUsageStats{ReservedInvocations: u.Invocations, ReservedBlocks: u.Blocks,
			OrdinaryInvocationsRemaining: u.OrdinaryInvocationsRemaining, OrdinaryBlocksRemaining: u.OrdinaryBlocksRemaining,
			TotalInvocationsRemaining: u.TotalInvocationsRemaining, TotalBlocksRemaining: u.TotalBlocksRemaining,
			RotationRecommended: u.RotateRecommended, AccountingFaulted: u.Faulted, Closed: u.Closed,
			ReservationOutcome: u.ReservationOutcome, InvocationLimit: securestore.MaxKeyInvocations, BlockLimit: securestore.MaxKeyBlocks}
	}
	return p
}

func (p *Processor) populateStorageStats(dst *management.ProcessorStats) {
	if dst == nil {
		return
	}
	dst.Storage = &management.ProcessorStorageStats{}
	if p.filterManager != nil {
		dst.Storage.Filters = storageStatusProto(p.filterManager.StorageStatus())
	}
	p.populateLIStorageStats(dst.Storage)
}

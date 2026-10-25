//go:build processor || tap || all

package processor

import "github.com/endorses/lippycat/api/gen/management"

func (p *Processor) dnsNoticeStatusProto() *management.DNSNoticeStats {
	if p.config.EventAnalysis == nil || !p.config.EventAnalysis.EffectiveDNS().DetectTunneling {
		return nil
	}
	stats := p.GetNoticeStats()
	result := &management.DNSNoticeStats{Enabled: p.canonicalDNSOwner(), Emitted: stats.Emitted, Suppressed: stats.Suppressed, Dropped: stats.Dropped, ActionDropped: stats.ActionDropped, CommandCompleted: stats.Commands.Completed, CommandFailed: stats.Commands.Failed, CommandDropped: stats.Commands.Dropped, CommandDuplicate: stats.Commands.Duplicate, CommandQueued: uint64(stats.Commands.Queued), CommandIdentities: uint64(stats.Commands.Identities)}
	// Sink counters cover every stream registered on the shared sink, not just
	// notices. Their names intentionally do not claim per-notice attribution.
	if p.logSink != nil {
		logs := p.logSink.Stats()
		result.LogDropped = logs.Dropped
		result.LogErrors = logs.Errors
	}
	if p.eventDispatcher != nil {
		dispatcher := p.eventDispatcher.Stats()
		result.DispatcherSinkDropped = dispatcher.SinkDropped
		result.DispatcherSinkErrors = dispatcher.SinkErrors
	}
	return result
}

//go:build processor || tap || all

package processor

import "github.com/endorses/lippycat/api/gen/management"

func (p *Processor) mediaRulesStatusProto() *management.MediaRuleStatus {
	r := p.mediaControl
	if r == nil {
		return nil
	}
	state := r.store.Status()
	return &management.MediaRuleStatus{Enabled: true, Ready: state.Ready, Generation: state.Session.Generation, Revision: uint64(state.Revision), Sequence: state.Sequence, Rules: uint64(state.Rules), Endpoints: uint64(state.Endpoints), Bytes: uint64(state.Bytes), Subscribers: uint64(state.Subscribers), Expired: state.Expired, StaleUpdates: state.StaleUpdates, Resyncs: state.Resyncs, ActiveCalls: uint64(len(r.tracker.Snapshot()))}
}

func (p *Processor) remoteMediaRuleStatus(hunterID string) *management.MediaRuleStatus {
	r := p.mediaControl
	if r == nil {
		return nil
	}
	application := r.service.Application(hunterID)
	if application == nil {
		return &management.MediaRuleStatus{Enabled: true}
	}
	return &management.MediaRuleStatus{Enabled: true, Ready: application.Synchronized, Generation: application.Session.Generation, Revision: application.AppliedRevision, Rules: uint64(application.ActiveRules), Endpoints: uint64(application.ActiveEndpoints), ApplicationFailed: application.Error != ""}
}

func (p *Processor) packetDuplicateStatusProto() *management.PacketDuplicateStatus {
	if p.packetDuplicates == nil {
		return nil
	}
	s := p.packetDuplicates.Stats()
	return &management.PacketDuplicateStatus{Attempts: s.Attempts, Committed: s.Commits, Duplicates: s.Duplicates, InFlight: s.InFlight, RepeatsRetained: s.Repeats, UnsupportedRetained: s.Unsupported, AmbiguousRetained: s.Ambiguous, CapacityRetained: s.Capacity, OutsideWindowRetained: s.OutsideWindow, Aborted: s.Aborts, Entries: uint64(s.Entries), Contributors: uint64(s.Contributors), Bytes: uint64(s.Bytes)}
}

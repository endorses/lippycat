//go:build processor || tap || all

package processor

import (
	learnedpb "github.com/endorses/lippycat/api/gen/learnedrules"
	"github.com/endorses/lippycat/api/gen/management"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
)

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
	if generic := r.genericService.Application(hunterID); generic != nil {
		result := &management.MediaRuleStatus{Enabled: true, Ready: generic.Synchronized, Generation: generic.Session.Generation, Revision: generic.AppliedRevision, ApplicationFailed: generic.Error != ""}
		for _, adapter := range generic.AdapterApplications {
			if adapter.AdapterId == "voip" && adapter.ContextVersion == 1 {
				result.Rules = uint64(adapter.ActiveBindings)
				result.Endpoints = uint64(adapter.ActiveSelectors)
			}
		}
		return result
	}
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

func learnedStatus(store *core.Store) *management.LearnedRuleStatus {
	if store == nil {
		return nil
	}
	s := store.Status()
	return &management.LearnedRuleStatus{Enabled: true, Ready: s.Ready, Generation: s.Session.Generation, Revision: uint64(s.Revision), Sequence: s.Sequence, Bindings: uint64(s.Rules), Selectors: uint64(s.Endpoints), Bytes: uint64(s.Bytes), Subscribers: uint64(s.Subscribers), Expired: s.Expired, StaleUpdates: s.StaleUpdates, Resyncs: s.Resyncs, DesiredRevision: s.Sequence, CandidateOverflows: s.CandidateOverflows, CapacityRejections: s.CapacityRejections}
}
func registryCapabilityStatus(store *core.Store) []*management.LearnedRuleCapabilityStatus {
	if store == nil {
		return nil
	}
	var result []*management.LearnedRuleCapabilityStatus
	for _, adapter := range store.Configuration().Registry.Adapters() {
		c := &management.LearnedRuleCapabilityStatus{SupportedProtocols: []uint32{uint32(core.TCP), uint32(core.UDP)}, AdapterId: adapter.ID, ContextVersion: adapter.Version, EndpointSelectorVersions: []uint32{learnedwire.EndpointSelectorVersion}, EvidenceVersions: []uint32{learnedwire.EvidenceVersion}}
		if adapter.ID == "voip" {
			c.SupportedProtocols = []uint32{uint32(core.UDP)}
		}
		for _, q := range adapter.Qualifiers {
			c.Qualifiers = append(c.Qualifiers, &management.LearnedRuleQualifierStatus{Id: q.ID, Version: q.Version})
		}
		result = append(result, c)
	}
	return result
}
func negotiatedCapabilityStatus(capabilities []*learnedpb.LearnedCapability) []*management.LearnedRuleCapabilityStatus {
	var result []*management.LearnedRuleCapabilityStatus
	for _, c := range capabilities {
		view := &management.LearnedRuleCapabilityStatus{SupportedProtocols: append([]uint32(nil), c.SupportedProtocols...), AdapterId: c.AdapterId, ContextVersion: c.ContextVersion, EndpointSelectorVersions: append([]uint32(nil), c.EndpointSelectorVersions...), EvidenceVersions: append([]uint32(nil), c.EvidenceVersions...)}
		for _, q := range c.Qualifiers {
			view.Qualifiers = append(view.Qualifiers, &management.LearnedRuleQualifierStatus{Id: q.Id, Version: q.Version})
		}
		result = append(result, view)
	}
	return result
}
func (p *Processor) learnedRulesStatusProto() *management.LearnedRuleStatus {
	store := p.learnedRuleStore()
	result := learnedStatus(store)
	if result != nil {
		result.Capabilities = registryCapabilityStatus(store)
	}
	return result
}
func (p *Processor) remoteLearnedRuleStatus(hunterID string) *management.LearnedRuleStatus {
	store := p.learnedRuleStore()
	if store == nil {
		return nil
	}
	state := store.Status()
	result := &management.LearnedRuleStatus{Enabled: true, Generation: state.Session.Generation, DesiredRevision: state.Sequence}
	var service *learnedwire.Service
	if p.mediaControl != nil {
		service = p.mediaControl.genericService
	} else if p.learnedControl != nil {
		service = p.learnedControl.service
	}
	if service == nil {
		return result
	}
	result.Capabilities = negotiatedCapabilityStatus(service.Capabilities(hunterID))
	application := service.Application(hunterID)
	if application == nil {
		return result
	}
	result.ApplicationReported = true
	result.Ready = application.Synchronized && application.AppliedRevision == state.Sequence
	result.Generation = application.Session.Generation
	result.Revision = application.AppliedRevision
	result.EffectiveRevision = application.AppliedRevision
	result.Bindings = uint64(application.ActiveBindings)
	result.Selectors = uint64(application.ActiveSelectors)
	result.ApplicationFailed = application.Error != ""
	result.Bytes = application.RetainedBytes
	result.Expired = application.Expired
	result.StaleUpdates = application.StaleUpdates
	result.Resyncs = application.Resyncs
	result.CandidateOverflows = application.CandidateOverflows
	result.CapacityRejections = application.CapacityRejections
	return result
}

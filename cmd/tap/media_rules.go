//go:build tap || all

package tap

import (
	"context"
	"errors"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/admissionadapter"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
	"github.com/google/gopacket"
	"google.golang.org/protobuf/proto"
)

// tapMediaRules consumes the same publisher snapshots locally. It owns no
// loopback connection and never turns a remote registry lifetime into a local
// admission-controller capability.
type tapMediaRules struct {
	store               *mediarules.Store
	runtime             *core.Runtime
	maxCandidates       int
	subscription        *mediarules.Subscription
	genericSubscription *core.Subscription
	projection          *admissionadapter.Projection
	control             mediarules.Control
	domains             map[string]mediaadmission.DomainID
	hunterID            string
	interval            time.Duration
	validateMediaRule   func(*management.MediaRule, string, uint32, gopacket.Packet, time.Time) bool
}

func newTapMediaRules(p *processor.Processor, cfg processor.MediaRulesConfig, domains map[string]mediaadmission.DomainID, controller *mediaadmission.Controller) (_ *tapMediaRules, err error) {
	if p == nil || !cfg.Enabled || len(domains) == 0 {
		return nil, errors.New("tap processor media requires publication and explicit interface domains")
	}
	r := &tapMediaRules{validateMediaRule: p.ValidateLocalMediaRule, domains: make(map[string]mediaadmission.DomainID, len(domains)), hunterID: cfg.ProcessorID + "-local", interval: cfg.RuleTTL / 3, maxCandidates: min(cfg.MaxRules, learnedwire.DefaultEvidenceLimits.MaxCandidates)}
	set := make(map[mediaadmission.DomainID]bool)
	for iface, domain := range domains {
		if iface == "" {
			return nil, errors.New("empty tap media interface")
		}
		r.domains[iface] = domain
		set[domain] = true
	}
	var ids []mediaadmission.DomainID
	for domain := range set {
		ids = append(ids, domain)
	}
	var observer mediarules.Observer
	if controller != nil {
		r.projection, err = admissionadapter.NewForSource(context.Background(), controller, r.hunterID, ids, func(err error) { logger.Error("Tap remote media projection failed", "error", err) })
		if err != nil {
			return nil, err
		}
		observer = r.projection
	}
	legacyConfig := cfg.StoreConfig(cfg.ProcessorID, r.hunterID, ids, observer)
	engineConfig, err := mediarules.EngineConfig(legacyConfig, p.LearnedRuleAdapters()...)
	engineConfig.SupportedProtocols = []core.Protocol{core.UDP}
	if err != nil {
		return nil, err
	}
	interfaces := make(map[string]core.DomainID, len(r.domains))
	for iface, domain := range r.domains {
		interfaces[iface] = core.DomainID(domain)
	}
	r.runtime, err = core.NewRuntime(engineConfig, interfaces, min(cfg.MaxRules, learnedwire.DefaultEvidenceLimits.MaxCandidates), nil)
	if err == nil {
		r.store = mediarules.Wrap(r.runtime.Store, legacyConfig)
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.Close())
		}
	}()
	r.genericSubscription, err = p.SubscribeLocalLearnedRules()
	if err != nil {
		return nil, err
	}
	initial := r.genericSubscription.Initial
	if !initial.Ready {
		return nil, errors.New("local learned publisher is not ready")
	}
	r.control, err = r.store.StartSession(cfg.ProcessorID, initial.Session)
	if err != nil {
		return nil, err
	}
	if err = r.applyLearned(initial.Snapshot); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *tapMediaRules) apply(snapshot mediarules.Snapshot) error {
	if !snapshot.Ready {
		return errors.New("local media publisher requires synchronization")
	}
	if snapshot.Session != r.store.Status().Session {
		return mediarules.ErrAuthority
	}
	var rules []mediarules.Rule
	for _, rule := range snapshot.Rules {
		var scopes []mediarules.Scope
		allowed := make(map[mediaadmission.DomainID]bool)
		for _, scope := range rule.Scope {
			if scope.HunterID == r.hunterID {
				scopes = append(scopes, scope)
				allowed[scope.Domain] = true
			}
		}
		if len(scopes) == 0 {
			continue
		}
		var endpoints []mediarules.Endpoint
		for _, endpoint := range rule.Endpoints {
			if allowed[endpoint.Key.Domain] {
				endpoints = append(endpoints, endpoint)
			}
		}
		if len(rule.Call.SelectionGrants) > 0 {
			rules = append(rules, rule)
			continue
		}
		rule.Scope = scopes
		rule.Endpoints = endpoints
		rule.Revision = mediarules.Revision(snapshot.Sequence)
		rules = append(rules, rule)
	}
	return r.store.ApplySnapshot(r.control, mediarules.Revision(snapshot.Sequence), rules)
}

// applyLearned retains the publisher's immutable revisions and complete proof.
// Only placement membership is selected here; matching enforces local scope.
func (r *tapMediaRules) applyLearned(snapshot core.Snapshot) error {
	if !snapshot.Ready {
		return errors.New("local learned publisher requires synchronization")
	}
	if snapshot.Session != r.store.Status().Session {
		return mediarules.ErrAuthority
	}
	var bindings []core.Binding
	for _, binding := range snapshot.Rules {
		for _, scope := range binding.Scope {
			if scope.HunterID == r.hunterID {
				if !learnedwire.EvidenceRepresentable(binding) {
					return core.ErrUnsupported
				}
				bindings = append(bindings, binding)
				break
			}
		}
	}
	return r.store.Core().ApplySnapshot(r.control, core.Revision(snapshot.Sequence), bindings)
}

func (r *tapMediaRules) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	defer func() {
		if err := r.Close(); err != nil {
			logger.Error("Close tap media rules", "error", err)
		}
	}()
	var genericEvents <-chan core.Change
	var legacyEvents <-chan mediarules.Change
	if r.genericSubscription != nil {
		genericEvents = r.genericSubscription.Events
	}
	if r.subscription != nil {
		legacyEvents = r.subscription.Events
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case change, ok := <-genericEvents:
			if !ok || change.ResyncRequired {
				return errors.New("local media subscription requires resynchronization")
			}
			if err := r.applyLearned(change.Snapshot); err != nil {
				return err
			}
		case change, ok := <-legacyEvents:
			if !ok || change.ResyncRequired {
				return errors.New("local media subscription requires resynchronization")
			}
			if err := r.apply(change.Snapshot); err != nil {
				return err
			}
		case <-ticker.C:
			if err := r.store.Sweep(); err != nil {
				return err
			}
			if r.projection != nil {
				if err := r.projection.Retry(); err != nil {
					logger.Error("Retry tap media projection", "error", err)
				}
			}
		}
	}
}

func (r *tapMediaRules) Close() error {
	if r == nil {
		return nil
	}
	if r.genericSubscription != nil {
		r.genericSubscription.Close()
	}
	if r.subscription != nil {
		r.subscription.Close()
	}
	if r.store != nil {
		return r.store.Close()
	}
	return nil
}

func (r *tapMediaRules) ready(sequence uint64) bool {
	state := r.store.Status()
	return state.Ready && state.Sequence == sequence
}

func tapRemoteAssociation(call mediarules.CallAssociation, session mediarules.Session) voip.RemoteCallAssociation {
	return voip.RemoteCallAssociation{CallID: call.CallID, Lifetime: call.Lifetime, SelectionRevision: call.SelectionRevision, CapturePolicyRevision: call.CapturePolicyRevision, ProcessorID: session.ProcessorID, ControlGeneration: session.Generation, InheritedFilterIDs: append([]string(nil), call.FilterIDs...)}
}

func (r *tapMediaRules) ResolveMedia(packet gopacket.Packet, iface string) (voip.RemoteCallAssociation, bool) {
	domain, mapped := r.domains[iface]
	sequence := r.store.Status().Sequence
	if !mapped || !r.ready(sequence) || packet == nil || packet.NetworkLayer() == nil {
		return voip.RemoteCallAssociation{}, false
	}
	facts, ok := core.PacketFacts(packet, core.DomainID(domain))
	if !ok {
		return voip.RemoteCallAssociation{}, false
	}
	resolved := voiprules.ResolvePacket(r.store.Core(), facts, max(1, r.maxCandidates))
	if !resolved.Resolved || resolved.Rule == nil {
		return voip.RemoteCallAssociation{}, false
	}
	rule := resolved.Rule
	association := tapRemoteAssociation(rule.Call, rule.Session)
	if len(rule.Call.SelectionGrants) > 0 {
		encoded := wire.EncodeRule(*rule)
		if r.validateMediaRule == nil || !r.validateMediaRule(encoded, r.hunterID, uint32(domain), packet, time.Now()) {
			return voip.RemoteCallAssociation{}, false
		}
		proof, err := (proto.MarshalOptions{Deterministic: true}).Marshal(encoded)
		if err != nil {
			return voip.RemoteCallAssociation{}, false
		}
		association.CaptureSelectionProof = proof
		for _, ref := range rule.Call.SelectionGrants {
			association.InheritedFilterIDs = append(association.InheritedFilterIDs, ref.ID)
		}
	}
	if !r.ready(sequence) {
		return voip.RemoteCallAssociation{}, false
	}
	return association, true
}

func (r *tapMediaRules) ResolveSignalling(event sip.Event, packet gopacket.Packet, iface string) (voip.RemoteCallAssociation, bool) {
	domain, mapped := r.domains[iface]
	sequence := r.store.Status().Sequence
	if !mapped || !r.ready(sequence) || event.CallID == "" || event.FromTag == "" || event.ToTag == "" || event.CSeqMethod == "" || packet == nil || packet.NetworkLayer() == nil || (event.Method != "RESPONSE" && event.Method != event.CSeqMethod) {
		return voip.RemoteCallAssociation{}, false
	}
	resolved := r.store.ResolveDialogInDomain(domain, event.CallID, event.FromTag, event.ToTag)
	if resolved.Resolved && r.ready(sequence) {
		return tapRemoteAssociation(resolved.Call, r.store.Status().Session), true
	}
	return voip.RemoteCallAssociation{}, false
}

// ValidateMediaProof preserves original capture time during queued release.
func (r *tapMediaRules) ValidateMediaProof(packet gopacket.Packet, iface string, proof []byte, at time.Time) bool {
	domain, ok := r.domains[iface]
	if !ok || r.validateMediaRule == nil || len(proof) == 0 || len(proof) > filterpolicy.MaxMediaRuleBytes {
		return false
	}
	rule := &management.MediaRule{}
	return proto.Unmarshal(proof, rule) == nil && r.validateMediaRule(rule, r.hunterID, uint32(domain), packet, at)
}

// ValidateLearnedProof checks each protected candidate's original artifact at
// its immutable capture time. Generic reference checks remain with the runtime.
func (r *tapMediaRules) ValidateLearnedProof(envelope *pipeline.PacketEnvelope) bool {
	if envelope == nil || envelope.LearnedCaptureEvidence == nil || envelope.Source.NodeID != r.hunterID || !envelope.Source.ObservationDomainKnown || pipeline.ValidateCaptureEvidence(envelope) != nil {
		return false
	}
	domain, ok := r.domains[envelope.Source.InterfaceName]
	if !ok || uint32(domain) != envelope.Source.ObservationDomain {
		return false
	}
	for _, candidate := range envelope.LearnedCaptureEvidence.Candidates {
		if len(candidate.GetLegacyMediaRule()) == 0 {
			continue
		}
		_, rule, err := voiprules.BindingFromLegacyCandidate(candidate)
		if err != nil || r.validateMediaRule == nil || !r.validateMediaRule(rule, r.hunterID, uint32(domain), envelope.Packet(), envelope.CaptureTime) {
			return false
		}
	}
	return true
}

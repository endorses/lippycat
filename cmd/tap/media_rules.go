//go:build tap || all

package tap

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/admissionadapter"
	"github.com/endorses/lippycat/internal/pkg/processor"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// tapMediaRules consumes the same publisher snapshots locally. It owns no
// loopback connection and never turns a remote registry lifetime into a local
// admission-controller capability.
type tapMediaRules struct {
	store        *mediarules.Store
	subscription *mediarules.Subscription
	projection   *admissionadapter.Projection
	control      mediarules.Control
	domains      map[string]mediaadmission.DomainID
	hunterID     string
	interval     time.Duration
}

func newTapMediaRules(p *processor.Processor, cfg processor.MediaRulesConfig, domains map[string]mediaadmission.DomainID, controller *mediaadmission.Controller) (_ *tapMediaRules, err error) {
	if p == nil || !cfg.Enabled || len(domains) == 0 {
		return nil, errors.New("tap processor media requires publication and explicit interface domains")
	}
	r := &tapMediaRules{domains: make(map[string]mediaadmission.DomainID, len(domains)), hunterID: cfg.ProcessorID + "-local", interval: cfg.RuleTTL / 3}
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
		r.projection, err = admissionadapter.New(context.Background(), controller, ids, func(err error) { logger.Error("Tap remote media projection failed", "error", err) })
		if err != nil {
			return nil, err
		}
		observer = r.projection
	}
	r.store, err = mediarules.New(cfg.StoreConfig(cfg.ProcessorID, r.hunterID, ids, observer))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.Close())
		}
	}()
	r.subscription, err = p.SubscribeLocalMediaRules()
	if err != nil {
		return nil, err
	}
	initial := r.subscription.Initial
	if !initial.Ready {
		return nil, errors.New("local media publisher is not ready")
	}
	r.control, err = r.store.StartSession(cfg.ProcessorID, initial.Session)
	if err != nil {
		return nil, err
	}
	if err = r.apply(initial.Snapshot); err != nil {
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
		rule.Scope = scopes
		rule.Endpoints = endpoints
		rule.Revision = mediarules.Revision(snapshot.Sequence)
		rules = append(rules, rule)
	}
	return r.store.ApplySnapshot(r.control, mediarules.Revision(snapshot.Sequence), rules)
}

func (r *tapMediaRules) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	defer func() {
		if err := r.Close(); err != nil {
			logger.Error("Close tap media rules", "error", err)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case change, ok := <-r.subscription.Events:
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
	udp, ok := packet.TransportLayer().(*layers.UDP)
	if !ok || len(udp.Payload) < 8 || udp.Payload[0]>>6 != 2 {
		return voip.RemoteCallAssociation{}, false
	}
	rtcp := udp.Payload[1] >= 192 && udp.Payload[1] <= 223
	if !rtcp && len(udp.Payload) < 12 {
		return voip.RemoteCallAssociation{}, false
	}
	src, err := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Src().String())
	if err != nil {
		return voip.RemoteCallAssociation{}, false
	}
	dst, err := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Dst().String())
	if err != nil {
		return voip.RemoteCallAssociation{}, false
	}
	left, err := mediaadmission.NewEndpoint(domain, src, uint16(udp.SrcPort))
	if err != nil {
		return voip.RemoteCallAssociation{}, false
	}
	right, err := mediaadmission.NewEndpoint(domain, dst, uint16(udp.DstPort))
	if err != nil {
		return voip.RemoteCallAssociation{}, false
	}
	resolved := r.store.Resolve(left, right)
	if !resolved.Resolved {
		return voip.RemoteCallAssociation{}, false
	}
	for _, rule := range r.store.ActiveRules() {
		if rule.Call.CallID != resolved.Call.CallID || rule.Call.Lifetime != resolved.Call.Lifetime {
			continue
		}
		for _, endpoint := range rule.Endpoints {
			if endpoint.Key != left && endpoint.Key != right {
				continue
			}
			if endpoint.Kind == mediarules.RTPAndRTCP || (rtcp && endpoint.Kind == mediarules.RTCP) || (!rtcp && endpoint.Kind == mediarules.RTP) {
				if r.ready(sequence) {
					return tapRemoteAssociation(resolved.Call, r.store.Status().Session), true
				}
			}
		}
	}
	return voip.RemoteCallAssociation{}, false
}

func (r *tapMediaRules) ResolveSignalling(event sip.Event, packet gopacket.Packet, iface string) (voip.RemoteCallAssociation, bool) {
	domain, mapped := r.domains[iface]
	sequence := r.store.Status().Sequence
	if !mapped || !r.ready(sequence) || event.CallID == "" || event.FromTag == "" || event.ToTag == "" || event.CSeqMethod == "" || packet == nil || packet.NetworkLayer() == nil || (event.Method != "RESPONSE" && event.Method != event.CSeqMethod) {
		return voip.RemoteCallAssociation{}, false
	}
	var found *mediarules.CallAssociation
	for _, rule := range r.store.ActiveRules() {
		call := rule.Call
		if call.CallID != event.CallID || !((call.FromTag == event.FromTag && call.ToTag == event.ToTag) || (call.FromTag == event.ToTag && call.ToTag == event.FromTag)) {
			continue
		}
		for _, scope := range rule.Scope {
			if scope.HunterID != r.hunterID || scope.Domain != domain {
				continue
			}
			if found != nil && (found.Lifetime != call.Lifetime || found.CallID != call.CallID) {
				return voip.RemoteCallAssociation{}, false
			}
			copy := call
			found = &copy
		}
	}
	if found != nil && r.ready(sequence) {
		return tapRemoteAssociation(*found, r.store.Status().Session), true
	}
	return voip.RemoteCallAssociation{}, false
}

//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/callselection"
	sharedfilter "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/mediarules/wire"
	"github.com/endorses/lippycat/internal/pkg/packetdedup"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/sip"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type processorMediaControl struct {
	mu                sync.Mutex
	store             *mediarules.Store
	service           *wire.Service
	tracker           *callselection.Tracker
	control           mediarules.Control
	session           mediarules.Session
	revision          mediarules.Revision
	selectionRevision uint64
	filterDigest      [sha256.Size]byte
	matcher           *sharedfilter.SIPMatcher
	rules             []mediarules.Rule
	lastPublish       time.Time
	started           time.Time
}

func (p *Processor) initMediaControl() error {
	settings, err := p.config.PacketDedup.Normalize()
	if err != nil {
		return fmt.Errorf("packet duplicate settings: %w", err)
	}
	p.config.PacketDedup = settings
	if settings.Enabled {
		p.packetDuplicates, err = packetdedup.New(settings.Config())
		if err != nil {
			return err
		}
	}
	cfg, err := p.config.MediaRules.normalize(p.config.ProcessorID)
	if err != nil {
		return err
	}
	p.config.MediaRules = cfg
	if !cfg.Enabled {
		return nil
	}
	// Local tap subscriptions do not use transport. Remote control always
	// requires a verified mutual TLS connection, checked again per request.
	if cfg.ProcessorID == "" {
		return errors.New("media control requires a stable processor ID")
	}
	var seed [8]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return fmt.Errorf("media control generation: %w", err)
	}
	generation := binary.BigEndian.Uint64(seed[:])
	if generation == 0 {
		generation = 1
	}
	r := &processorMediaControl{session: mediarules.Session{ProcessorID: cfg.ProcessorID, Generation: generation}, started: time.Now()}
	r.store, err = mediarules.New(cfg.StoreConfig(cfg.ProcessorID, "", nil, nil))
	if err != nil {
		return err
	}
	p.mediaControl = r // Constructor cleanup owns partially initialized state.
	r.control, err = r.store.StartSession(cfg.ProcessorID, r.session)
	if err != nil {
		return err
	}
	r.revision = 1
	if err = r.store.ApplySnapshot(r.control, r.revision, nil); err != nil {
		return err
	}
	domainSet := make(map[mediaadmission.DomainID]bool)
	for _, mapping := range cfg.Sources {
		domainSet[mapping.Domain] = true
	}
	domains := make([]mediaadmission.DomainID, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i] < domains[j] })
	limits := mediaadmission.DefaultConfig()
	limits.OwnerCapacity = cfg.MaxRules
	limits.EndpointCapacity = cfg.MaxEndpoints
	limits.MaxEndpointsPerOwner = cfg.MaxEndpointsPerRule
	limits.PendingBytes = cfg.MaxBytes
	if err = r.refreshMatcherLocked(p); err != nil {
		return err
	}
	r.tracker, err = callselection.New(callselection.Config{
		Domains: domains, Limits: limits, TrailingGrace: cfg.TrailingGrace,
		Processor: voipprocessor.Config{MaxCalls: cfg.MaxRules, MaxEndpointsPerCall: cfg.MaxEndpointsPerRule, MaxEndpointAssociations: cfg.MaxEndpoints, CallTimeout: cfg.CallTimeout},
		Authorize: func(source callselection.Source) error {
			if _, ok := p.mediaMapping(source.NodeID, source.InterfaceName); !ok {
				return callselection.ErrSource
			}
			return nil
		},
		Match: func(event sip.Event, _ *pipeline.PacketEnvelope, source callselection.Source) (callselection.Selection, error) {
			ids, err := r.matcher.Match(event, source.NodeID)
			return callselection.Selection{Selected: len(ids) > 0, FilterIDs: ids, Revision: r.selectionRevision}, err
		},
	})
	if err != nil {
		return err
	}
	r.service, err = wire.NewService(r.store, wire.Limits{MaxMessageBytes: cfg.MaxMessageBytes, MaxSnapshotBytes: cfg.MaxSnapshotBytes, MaxRules: cfg.MaxRules}, cfg.MaxSubscribers, func(ctx context.Context, id string) error {
		if !p.config.TLSEnabled || !p.config.TLSClientAuth || !radiusStreamSourceTrusted(ctx, id) {
			return status.Error(codes.PermissionDenied, "media control requires a verified hunter certificate")
		}
		if _, ok := p.hunterManager.Get(id); !ok {
			return status.Error(codes.FailedPrecondition, "media control requires current hunter registration")
		}
		for _, mapping := range cfg.Sources {
			if mapping.HunterID == id || mapping.HunterID == "*" {
				if err := p.reconcileMediaSelection(); err != nil {
					return status.Error(codes.Unavailable, "media selection is not ready")
				}
				return nil
			}
		}
		return status.Error(codes.PermissionDenied, "hunter has no media source mapping")
	})
	return err
}

func (r *processorMediaControl) refreshMatcherLocked(p *Processor) error {
	filters := p.filterManager.GetAll()
	sort.Slice(filters, func(i, j int) bool { return filters[i].Id < filters[j].Id })
	h := sha256.New()
	for _, filter := range filters {
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(filter)
		if err != nil {
			return fmt.Errorf("current filter snapshot: %w", err)
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(encoded)))
		h.Write(size[:])
		h.Write(encoded)
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	if r.matcher != nil && digest == r.filterDigest {
		return nil
	}
	matcher, err := sharedfilter.CompileSIPFilters(filters)
	if err != nil {
		return errors.Join(err, r.withdrawLocked())
	}
	r.matcher = matcher
	r.filterDigest = digest
	r.selectionRevision++
	if r.tracker != nil {
		return r.tracker.Reevaluate(func(_ callselection.Call, event sip.Event, source callselection.Source) (callselection.Selection, error) {
			ids, err := matcher.Match(event, source.NodeID)
			return callselection.Selection{Selected: len(ids) > 0, FilterIDs: ids, Revision: r.selectionRevision}, err
		})
	}
	return nil
}

func (p *Processor) mediaMapping(node, iface string) (MediaSourceMapping, bool) {
	// Specific node mappings take precedence over the explicit all-hunter profile.
	for _, id := range []string{node, "*"} {
		for _, mapping := range p.config.MediaRules.Sources {
			if mapping.HunterID == id && mapping.Interface == iface {
				return mapping, true
			}
		}
	}
	return MediaSourceMapping{}, false
}

// mediaSourceDomain is also used by independent consumer duplicate boundaries.
// It conveys domain mapping only; the ingress owner must separately prove trust.
func (p *Processor) mediaSourceDomain(envelope *pipeline.PacketEnvelope) (mediaadmission.DomainID, bool) {
	if envelope == nil {
		return 0, false
	}
	mapping, ok := p.mediaMapping(envelope.Source.NodeID, envelope.Source.InterfaceName)
	if ok && envelope.Source.ObservationDomainKnown && envelope.Source.ObservationDomain != uint32(mapping.HunterDomain) {
		return 0, false
	}
	return mapping.Domain, ok
}

func (p *Processor) processMediaControl(batch *source.PacketBatch) {
	r := p.mediaControl
	if r == nil || !batch.MediaSourceTrusted {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refreshMatcherLocked(p); err != nil {
		logger.Error("Media selection snapshot rejected", "error", err)
		return
	}
	for _, envelope := range batch.Envelopes {
		if envelope == nil {
			continue
		}
		domain, ok := p.mediaSourceDomain(envelope)
		if !ok {
			continue
		}
		// Historical retained traffic remains output evidence, never bootstrap
		// authority for a new current capture session. It cannot refresh rules.
		if batch.HistoricalReplay || envelope.CaptureTime.IsZero() || time.Since(envelope.CaptureTime) > p.config.MediaRules.RuleTTL || envelope.CaptureTime.After(time.Now().Add(p.config.MediaRules.ClockUncertainty)) {
			continue
		}
		result, err := r.tracker.Process(envelope, callselection.Source{NodeID: envelope.Source.NodeID, InterfaceName: envelope.Source.InterfaceName, Domain: domain, Local: envelope.Source.Kind == pipeline.SourceLiveCapture})
		if err != nil {
			logger.Debug("Central call observation rejected", "error", err, "source_id", batch.SourceID)
		}
		if result.Process == nil {
			if err != nil {
				envelope.CallLifecycleRejected = true
			}
			continue
		}
		if result.Process.PacketType == voipprocessor.PacketTypeRTP {
			if packet := envelope.Packet(); packet != nil && packet.NetworkLayer() != nil {
				src, srcErr := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Src().String())
				dst, dstErr := netip.ParseAddr(packet.NetworkLayer().NetworkFlow().Dst().String())
				if srcErr != nil || dstErr != nil {
					logger.Error("Malformed normalized packet addresses", "error", errors.Join(srcErr, dstErr))
					continue
				}
				ids, matchErr := r.matcher.MatchPacketIPs(src, dst, envelope.Source.NodeID)
				if matchErr != nil {
					logger.Error("Central packet selector failed", "error", matchErr)
					continue
				}
				result.DirectFilterIDs = ids
			}
		}
		envelope.DirectMatchedFilterIDs = append([]string(nil), result.DirectFilterIDs...)
		envelope.InheritedMatchedFilterIDs = append([]string(nil), result.InheritedFilterIDs...)
		envelope.MatchedFilterIDs = append(append([]string(nil), result.DirectFilterIDs...), result.InheritedFilterIDs...)
		if result.Process.Metadata != nil {
			metadata, conversionErr := grpcadapter.MetadataFromProto(result.Process.Metadata)
			if conversionErr != nil {
				logger.Error("Central call metadata conversion failed", "error", conversionErr)
				continue
			}
			envelope.Metadata = metadata
		}
	}
	if err := r.publishLocked(p, false); err != nil {
		logger.Error("Media rule publication failed", "error", err)
	}
}

func (r *processorMediaControl) publishLocked(p *Processor, renew bool) error {
	if p.filterProcessingBlocked() {
		return r.withdrawLocked()
	}
	now := time.Now()
	var rules []mediarules.Rule
	for _, call := range r.tracker.Snapshot() {
		if len(call.Endpoints) == 0 {
			continue
		}
		expires := now.Add(p.config.MediaRules.RuleTTL)
		if call.Completing && call.CompletionDeadline.Before(expires) {
			expires = call.CompletionDeadline
		}
		if !expires.After(now) {
			continue
		}
		var scopes []mediarules.Scope
		domains := make(map[mediaadmission.DomainID]bool)
		seenScopes := make(map[mediarules.Scope]bool)
		for _, mapping := range p.config.MediaRules.Sources {
			if mapping.Domain != call.Domain {
				continue
			}
			ids := []string{mapping.HunterID}
			if mapping.HunterID == "*" {
				ids = nil
				for _, hunter := range p.hunterManager.GetAll("") {
					ids = append(ids, hunter.ID)
				}
			}
			for _, id := range ids {
				scope := mediarules.Scope{HunterID: id, Domain: mapping.HunterDomain}
				if !seenScopes[scope] {
					scopes = append(scopes, scope)
					seenScopes[scope] = true
					domains[scope.Domain] = true
				}
			}
		}
		if len(scopes) == 0 {
			continue
		}
		sort.Slice(scopes, func(i, j int) bool {
			if scopes[i].HunterID != scopes[j].HunterID {
				return scopes[i].HunterID < scopes[j].HunterID
			}
			return scopes[i].Domain < scopes[j].Domain
		})
		var endpoints []mediarules.Endpoint
		for domain := range domains {
			for _, endpoint := range call.Endpoints {
				endpoint.Domain = domain
				endpoints = append(endpoints, mediarules.Endpoint{Key: endpoint, Kind: mediarules.RTPAndRTCP})
			}
		}
		sort.Slice(endpoints, func(i, j int) bool {
			a, b := endpoints[i].Key, endpoints[j].Key
			if a.Domain != b.Domain {
				return a.Domain < b.Domain
			}
			if a.Addr != b.Addr {
				return a.Addr.Less(b.Addr)
			}
			return a.Port < b.Port
		})
		dialogs := call.Dialogs
		if len(dialogs) == 0 {
			dialogs = []callselection.Dialog{{FromTag: call.FromTag, ToTag: call.ToTag}}
		}
		for index, dialog := range dialogs {
			rules = append(rules, mediarules.Rule{
				ID: fmt.Sprintf("%d/%d/%d/%d", call.Domain, call.Info.Lifetime.Session, call.Info.Lifetime.Generation, index), Session: r.session,
				Call:  mediarules.CallAssociation{Lifetime: call.Info.Lifetime, CallID: call.Info.CallID, FromTag: dialog.FromTag, ToTag: dialog.ToTag, SelectionRevision: call.SelectionRevision, CapturePolicyRevision: p.currentCapturePolicyRevision(), FilterIDs: append([]string(nil), call.FilterIDs...)},
				Scope: scopes, Endpoints: endpoints, NotBefore: now, ExpiresAt: expires,
			})
		}
	}
	var scopeErr error
	rules, scopeErr = p.scopedCaptureRules(rules)
	if scopeErr != nil {
		return errors.Join(scopeErr, r.withdrawLocked())
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	unchanged := len(rules) == len(r.rules)
	if unchanged {
		for i, rule := range rules {
			old := r.rules[i]
			if rule.ExpiresAt.Before(old.ExpiresAt) {
				unchanged = false
				break
			}
			old.Revision = 0
			old.CaptureSignature = nil
			old.NotBefore = rule.NotBefore
			old.ExpiresAt = rule.ExpiresAt
			if !reflect.DeepEqual(old, rule) {
				unchanged = false
				break
			}
		}
	}
	if unchanged && !renew {
		return nil
	}
	r.revision++
	for i := range rules {
		rules[i].Revision = r.revision
		if err := p.signCaptureRule(&rules[i]); err != nil {
			return errors.Join(err, r.withdrawLocked())
		}
	}
	if err := r.store.ApplySnapshot(r.control, r.revision, rules); err != nil {
		// A partial new selection cannot leave an old, broader snapshot live.
		r.revision++
		clearErr := r.store.ApplySnapshot(r.control, r.revision, nil)
		r.rules = nil
		return errors.Join(err, clearErr)
	}
	r.rules = rules
	r.lastPublish = now
	return nil
}

func (r *processorMediaControl) withdrawLocked() error {
	r.revision++
	r.rules = nil
	return r.store.ApplySnapshot(r.control, r.revision, nil)
}

func (p *Processor) reconcileMediaSelection() error {
	r := p.mediaControl
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.filterProcessingBlocked() {
		return r.withdrawLocked()
	}
	if err := r.refreshMatcherLocked(p); err != nil {
		return err
	}
	return r.publishLocked(p, false)
}

func (p *Processor) startMediaControl(ctx context.Context) {
	r := p.mediaControl
	if r == nil {
		return
	}
	interval := p.config.MediaRules.RuleTTL / 3
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.mu.Lock()
				err := r.refreshMatcherLocked(p)
				if p.filterProcessingBlocked() {
					err = errors.Join(err, r.withdrawLocked())
				} else if err == nil {
					r.tracker.Sweep()
					err = r.publishLocked(p, true)
				}
				r.mu.Unlock()
				if err != nil {
					logger.Error("Media rule maintenance failed", "error", err)
				}
			}
		}
	}()
}

func (p *Processor) closeMediaControl() error {
	r := p.mediaControl
	if r == nil {
		return nil
	}
	var err error
	if r.tracker != nil {
		err = r.tracker.Close()
	}
	return errors.Join(err, r.store.Close())
}

// SubscribeLocalMediaRules is the in-process tap control boundary. It performs
// no transport and exposes only bounded immutable publisher snapshots.
func (p *Processor) SubscribeLocalMediaRules() (*mediarules.Subscription, error) {
	if p.mediaControl == nil {
		return nil, errors.New("processor media rules are disabled")
	}
	return p.mediaControl.store.Subscribe()
}

func (p *Processor) MediaRulesStatus() mediarules.Status {
	if p.mediaControl == nil {
		return mediarules.Status{}
	}
	return p.mediaControl.store.Status()
}

func (p *Processor) MediaRuleConfiguration() MediaRulesConfig {
	config := p.config.MediaRules
	config.Sources = append([]MediaSourceMapping(nil), config.Sources...)
	return config
}

func (p *Processor) MediaRuleApplication(hunterID string) *management.MediaRuleApplication {
	if p.mediaControl == nil {
		return nil
	}
	return p.mediaControl.service.Application(hunterID)
}

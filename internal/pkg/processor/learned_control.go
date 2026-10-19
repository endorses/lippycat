//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/learnedevidence"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/captureadapter"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// LearnedSourceMapping is an explicit authorized source/interface namespace.
// Its domain is the source's numbering; no protocol-specific identity is needed.
type LearnedSourceMapping struct {
	SourceID, Interface string
	Domain              core.DomainID
}

// LearnedRulesConfig constructs an ordinary learned publisher without VoIP mode.
// MediaRules deployments register additional adapters on their existing engine.
type LearnedRulesConfig struct {
	Engine  core.Config
	Sources []LearnedSourceMapping
	Limits  learnedwire.Limits
}

type processorLearnedControl struct {
	mu      sync.Mutex
	store   *core.Store
	control core.Control
	session core.Session
	service *learnedwire.Service
	config  LearnedRulesConfig
}

func (p *Processor) initLearnedControl() error {
	if p.config.LearnedRules == nil {
		return nil
	}
	if p.mediaControl != nil {
		return errors.New("VoIP and learned rules must share the existing engine through LearnedAdapters")
	}
	cfg := *p.config.LearnedRules
	cfg.Sources = append([]LearnedSourceMapping(nil), cfg.Sources...)
	if cfg.Engine.ProcessorID == "" {
		cfg.Engine.ProcessorID = p.config.ProcessorID
	}
	if cfg.Engine.ProcessorID == "" || cfg.Engine.ProcessorID != p.config.ProcessorID || cfg.Engine.HunterID != "" || len(cfg.Sources) == 0 || len(cfg.Sources) > cfg.Engine.MaxEndpoints {
		return core.ErrScope
	}
	if cfg.Engine.Registry == nil {
		var err error
		cfg.Engine.Registry, err = core.NewRegistry(p.config.LearnedAdapters...)
		if err != nil {
			return err
		}
	}
	seen := make(map[string]bool)
	for _, scope := range cfg.Sources {
		key := scope.SourceID + "\x00" + scope.Interface
		if scope.SourceID == "" || scope.SourceID == "*" || scope.Interface == "" || seen[key] {
			return core.ErrScope
		}
		seen[key] = true
	}
	if cfg.Limits.MaxMessageBytes == 0 {
		cfg.Limits = learnedwire.Limits{MaxMessageBytes: cfg.Engine.MaxBytes, MaxSnapshotBytes: cfg.Engine.MaxBytes, MaxRules: cfg.Engine.MaxRules}
	}
	store, err := core.New(cfg.Engine)
	if err != nil {
		return err
	}
	r := &processorLearnedControl{store: store, config: cfg}
	p.learnedControl = r
	var seed [8]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return fmt.Errorf("learned authority epoch: %w", err)
	}
	generation := binary.BigEndian.Uint64(seed[:])
	if generation == 0 {
		generation = 1
	}
	r.session = core.Session{ProcessorID: cfg.Engine.ProcessorID, Generation: generation}
	r.control, err = store.StartSession(r.session.ProcessorID, r.session)
	if err != nil {
		return err
	}
	if err = store.ApplySnapshot(r.control, 1, nil); err != nil {
		return err
	}
	r.service, err = learnedwire.NewService(store, cfg.Limits, cfg.Engine.MaxSubscribers, func(ctx context.Context, id string) error {
		if !p.config.TLSEnabled || !p.config.TLSClientAuth || !radiusStreamSourceTrusted(ctx, id) {
			return status.Error(codes.PermissionDenied, "learned control requires a verified source certificate")
		}
		if _, ok := p.hunterManager.Get(id); !ok {
			return status.Error(codes.FailedPrecondition, "learned control requires current source registration")
		}
		for _, scope := range cfg.Sources {
			if scope.SourceID == id {
				return nil
			}
		}
		return status.Error(codes.PermissionDenied, "source has no learned capture mapping")
	})
	return err
}

func (p *Processor) learnedRuleStore() *core.Store {
	if p.mediaControl != nil {
		return p.mediaControl.store.Core()
	}
	if p.learnedControl != nil {
		return p.learnedControl.store
	}
	return nil
}

func (p *Processor) LearnedRulesSession() core.Session {
	if store := p.learnedRuleStore(); store != nil {
		return store.Status().Session
	}
	return core.Session{}
}

func (p *Processor) LearnedRulesStatus() core.Status {
	if store := p.learnedRuleStore(); store != nil {
		return store.Status()
	}
	return core.Status{}
}

// PublishLearnedBindings replaces one registered adapter's desired relationships
// atomically while preserving all other adapters on the single authoritative store.
func (p *Processor) PublishLearnedBindings(adapterID string, bindings []core.Binding) error {
	if adapterID == "" || adapterID == "voip" {
		return core.ErrInvalid
	}
	var mu *sync.Mutex
	var store *core.Store
	var control core.Control
	if r := p.mediaControl; r != nil {
		mu, store, control = &r.mu, r.store.Core(), r.control
	} else if r := p.learnedControl; r != nil {
		mu, store, control = &r.mu, r.store, r.control
	} else {
		return core.ErrNotReady
	}
	mu.Lock()
	defer mu.Unlock()
	snapshot := store.Snapshot()
	var next []core.Binding
	for _, binding := range snapshot.Rules {
		if binding.AdapterID != adapterID {
			next = append(next, binding)
		}
	}
	for _, binding := range bindings {
		if binding.AdapterID != adapterID {
			return core.ErrInvalid
		}
		for _, scope := range binding.Scope {
			if !p.learnedPlacementAllowed(scope) {
				return core.ErrScope
			}
		}
		binding = core.CloneBinding(binding)
		if binding.Session == (core.Session{}) {
			binding.Session = snapshot.Session
		}
		next = append(next, binding)
	}
	if snapshot.Revision == ^core.Revision(0) {
		return core.ErrRevision
	}
	return store.ApplySnapshot(control, snapshot.Revision+1, next)
}

func (p *Processor) learnedSourceMapped(packet *pipeline.PacketEnvelope, sourceID string) bool {
	if packet == nil || packet.Source.NodeID != sourceID || !packet.Source.ObservationDomainKnown {
		return false
	}
	if p.mediaControl != nil {
		mapping, ok := p.mediaMapping(sourceID, packet.Source.InterfaceName)
		return ok && uint32(mapping.HunterDomain) == packet.Source.ObservationDomain
	}
	if p.learnedControl != nil {
		for _, mapping := range p.learnedControl.config.Sources {
			if mapping.SourceID == sourceID && mapping.Interface == packet.Source.InterfaceName && uint32(mapping.Domain) == packet.Source.ObservationDomain {
				return true
			}
		}
	}
	return false
}

// validateLearnedBatch runs before subject-dependent analysis and every output.
// Direct selection survives an unresolved learned reference, without inheriting
// its subject or intent. Original protected proofs retain their separate path.
func (p *Processor) validateLearnedBatch(batch *source.PacketBatch) {
	if batch == nil {
		return
	}
	kept := batch.Envelopes[:0]
	for _, packet := range batch.Envelopes {
		if packet == nil || packet.LearnedCaptureEvidence == nil {
			kept = append(kept, packet)
			continue
		}
		valid := pipeline.ValidateCaptureEvidence(packet) == nil && batch.MediaSourceTrusted && packet.Source.NodeID == batch.SourceID && packet.Source.ObservationDomainKnown
		selected := false
		voipClaim, validVoIP := false, false
		protectedVoIP := false
		capturedCallID := ""
		var capturedInherited []string
		if valid {
			raw, err := grpcadapter.ToCapturedPacket(packet)
			if err != nil {
				valid = false
			} else if _, err = capturedMediaProofs(raw); err != nil {
				valid = false
			} else {
				for _, candidate := range packet.LearnedCaptureEvidence.Candidates {
					if candidate.AdapterId == voiprules.AdapterID {
						voipClaim = true
					}
					if len(candidate.GetLegacyMediaRule()) > 0 {
						_, rule, err := voiprules.BindingFromLegacyCandidate(candidate)
						if err == nil && p.validateLearnedMediaArtifact(batch.SignedCapturePolicy, raw, batch.SourceID, rule) == nil {
							selected = true
							validVoIP = true
							protectedVoIP = true
							capturedCallID = rule.Call.CallId
							capturedInherited = append([]string(nil), rule.Call.FilterIds...)
							for _, ref := range rule.Call.SelectionGrants {
								capturedInherited = append(capturedInherited, ref.Id)
							}
						} else {
							valid = false
						}
						continue
					}
					// An unresolved ordinary reference remains forensic evidence;
					// it confers no current subject or output eligibility.
					if batch.HistoricalReplay || !p.learnedSourceMapped(packet, batch.SourceID) {
						continue
					}
					observed := &pipeline.PacketEnvelope{Data: packet.Data, LinkType: packet.LinkType, CaptureTime: packet.CaptureTime, Source: packet.Source, LearnedCaptureEvidence: proto.Clone(packet.LearnedCaptureEvidence).(*learnedevidence.LearnedCaptureEvidence)}
					observed.LearnedCaptureEvidence.Candidates = []*learnedevidence.LearnedCandidate{candidate}
					if captureadapter.ValidateCurrent(p.learnedRuleStore(), observed, batch.SourceID) {
						selected = true
						if candidate.AdapterId == voiprules.AdapterID {
							validVoIP = true
						}
					}
				}
			}
		}
		if validVoIP && !protectedVoIP {
			facts, ok := core.PacketFacts(packet.Packet(), core.DomainID(packet.Source.ObservationDomain))
			store := p.learnedRuleStore()
			if !ok || store == nil {
				validVoIP = false
			} else {
				resolved := voiprules.ResolvePacketForSource(store, batch.SourceID, facts, max(1, store.Status().Rules+1))
				if !resolved.Resolved || resolved.Rule == nil {
					validVoIP = false
				} else {
					capturedCallID = resolved.Call.CallID
					capturedInherited = append([]string(nil), resolved.Call.FilterIDs...)
					for _, ref := range resolved.Rule.Call.SelectionGrants {
						capturedInherited = append(capturedInherited, ref.ID)
					}
				}
			}
		}
		if valid && selected {
			if validVoIP {
				packet.InheritedMatchedFilterIDs = append([]string(nil), capturedInherited...)
				packet.MatchedFilterIDs = joinLearnedFilterIDs(packet.DirectMatchedFilterIDs, capturedInherited)
				p.setLearnedCallMetadata(packet, capturedCallID)
			} else {
				packet.InheritedMatchedFilterIDs = nil
				packet.MatchedFilterIDs = append([]string(nil), packet.DirectMatchedFilterIDs...)
				if voipClaim {
					packet.CallLifecycleRejected = true
				}
				p.setLearnedCallMetadata(packet, "")
			}
			kept = append(kept, packet)
			continue
		}
		packet.LearnedCaptureEvidence = nil
		packet.InheritedMatchedFilterIDs = nil
		packet.MatchedFilterIDs = append([]string(nil), packet.DirectMatchedFilterIDs...)
		packet.CallLifecycleRejected = true
		p.setLearnedCallMetadata(packet, "")
		if len(packet.DirectMatchedFilterIDs) > 0 {
			kept = append(kept, packet)
		}
	}
	clear(batch.Envelopes[len(kept):])
	batch.Envelopes = kept
}

func (p *Processor) learnedPlacementAllowed(scope core.Scope) bool {
	if scope.HunterID == "" || scope.HunterID == "*" {
		return false
	}
	if p.mediaControl != nil {
		for _, mapping := range p.config.MediaRules.Sources {
			if (mapping.HunterID == scope.HunterID || mapping.HunterID == "*") && core.DomainID(mapping.HunterDomain) == scope.Domain {
				return true
			}
		}
	}
	if p.learnedControl != nil {
		for _, mapping := range p.learnedControl.config.Sources {
			if mapping.SourceID == scope.HunterID && mapping.Domain == scope.Domain {
				return true
			}
		}
	}
	return false
}

// startLearnedControl maintains generic-only lifecycle state even when sources
// are idle. The media publisher already owns its own maintenance goroutine.
func (p *Processor) startLearnedControl(ctx context.Context) {
	r := p.learnedControl
	if r == nil {
		return
	}
	interval := r.config.Engine.MaxLifetime / 3
	if interval > time.Second {
		interval = time.Second
	}
	if interval <= 0 {
		interval = time.Nanosecond
	}
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
				if err := r.store.Sweep(); err != nil && !errors.Is(err, core.ErrClosed) {
					logger.Error("Learned binding maintenance failed", "error", err)
				}
			}
		}
	}()
}

// LearnedCapturePolicySnapshot returns the actual current signed capture policy
// for a trusted local producer. The producer retains these exact bytes at capture.
func (p *Processor) LearnedCapturePolicySnapshot() ([]byte, error) {
	if p.sharedPolicy == nil {
		return nil, nil
	}
	snapshot := p.sharedPolicy.state.Latest()
	if snapshot == nil {
		return nil, core.ErrNotReady
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode local learned capture policy: %w", err)
	}
	return encoded, nil
}

func joinLearnedFilterIDs(direct, inherited []string) []string {
	var ids []string
	seen := make(map[string]bool)
	for _, group := range [][]string{direct, inherited} {
		for _, id := range group {
			if id != "" && !seen[id] {
				ids = append(ids, id)
				seen[id] = true
			}
		}
	}
	return ids
}

// A candidate may establish capture without establishing VoIP ownership. Only
// adapter-validated identity is allowed into the legacy single-call metadata.
func (p *Processor) setLearnedCallMetadata(packet *pipeline.PacketEnvelope, callID string) {
	raw, err := grpcadapter.ToCapturedPacket(packet)
	if err != nil {
		logger.Error("Decode learned packet metadata", "error", err)
		packet.Metadata = nil
		packet.CallLifecycleRejected = true
		return
	}
	if raw.Metadata == nil {
		if callID == "" {
			return
		}
		raw.Metadata = &data.PacketMetadata{}
	}
	raw.Metadata.Sip = nil
	if callID != "" {
		raw.Metadata.Sip = &data.SIPMetadata{CallId: callID}
	}
	metadata, err := grpcadapter.MetadataFromProto(raw.Metadata)
	if err != nil {
		logger.Error("Encode learned packet metadata", "error", err)
		packet.Metadata = nil
		packet.CallLifecycleRejected = true
		return
	}
	packet.Metadata = metadata
}

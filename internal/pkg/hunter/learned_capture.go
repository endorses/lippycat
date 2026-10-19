//go:build hunter || all

package hunter

import (
	"errors"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/mediarules"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
	"google.golang.org/protobuf/proto"
)

func (h *Hunter) configureLearnedCapture() error {
	runtime := h.config.LearnedRuntime
	if len(h.config.LearnedAdapters) > 0 && h.config.BPFFilter != "" {
		return errors.New("mixed learned capture cannot advertise a restrictive capture filter")
	}
	if runtime == nil {
		return nil
	}
	if h.config.BPFFilter != "" || h.config.RADIUSOnly || h.config.RADIUSMatcher != nil {
		return errors.New("generic learned capture requires an unrestricted generic capture path")
	}
	if h.config.MediaAdmission != nil {
		return errors.New("generic learned capture does not support a specialized capture admission profile")
	}
	if h.config.ForwardMode == "events" {
		return errors.New("learned packet evidence requires packet forwarding")
	}
	if !h.config.TLSEnabled || h.config.TLSSkipVerify || h.config.TLSCertFile == "" || h.config.TLSKeyFile == "" {
		return errors.New("learned capture requires verified mutual TLS")
	}
	if h.mediaRules != nil {
		if h.mediaRules.runtime != runtime {
			return errors.New("VoIP and learned capture must share one runtime")
		}
		return nil
	}
	cfg := runtime.Configuration()
	if cfg.HunterID != h.config.HunterID || cfg.ProcessorID == "" {
		return core.ErrScope
	}
	settings, err := (mediarules.Settings{}).Normalize()
	if err != nil {
		return err
	}
	settings.ProcessorID = cfg.ProcessorID
	settings.MaxRules, settings.MaxBytes, settings.MaxEndpoints, settings.MaxEndpointsPerRule = cfg.MaxRules, cfg.MaxBytes, cfg.MaxEndpoints, cfg.MaxEndpointsPerRule
	settings.MaxLifetime, settings.ClockUncertainty = cfg.MaxLifetime, cfg.ClockUncertainty
	domains := mediaadmission.DefaultConfig()
	domains.InterfaceDomains = make(map[string]mediaadmission.DomainID)
	for _, iface := range h.config.Interfaces {
		if domain, ok := runtime.Domain(iface); ok {
			domains.InterfaceDomains[iface] = mediaadmission.DomainID(domain)
		}
	}
	legacy := settings.StoreConfig(cfg.ProcessorID, cfg.HunterID, domains.Domains(), nil)
	h.mediaRules = &hunterMediaRules{runtime: runtime, store: mediarules.Wrap(runtime.Store, legacy), settings: settings, hunterID: cfg.HunterID, domains: domains}
	return nil
}

func (h *Hunter) learnedCaptureRuntime() *core.Runtime {
	if h.config.LearnedRuntime != nil {
		return h.config.LearnedRuntime
	}
	if len(h.config.LearnedAdapters) > 0 && h.mediaRules != nil {
		return h.mediaRules.runtime
	}
	return nil
}

func (h *Hunter) learnedCaptureEnvelope(info capture.PacketInfo) (*pipeline.PacketEnvelope, error) {
	runtime := h.learnedCaptureRuntime()
	if runtime == nil {
		return nil, nil
	}
	envelope := h.convertPacket(info)
	selected, err := captureadapter.Select(runtime, envelope)
	if err != nil {
		fallback := h.independentLearnedFallback(info, envelope)
		if fallback == nil {
			return nil, err
		}
		return fallback, nil
	}
	if !selected {
		return nil, nil
	}
	envelope.Source.NodeID = h.config.HunterID
	if h.applicationFilter != nil {
		if selected, ids := h.applicationFilter.MatchPacketWithIDs(info.Packet); selected {
			envelope.DirectMatchedFilterIDs = append([]string(nil), ids...)
		}
	}
	metadata := protocolmeta.Enrich(info.Packet, nil, false)
	if h.config.VoIPMode && h.mediaRules != nil {
		if association, ok := h.mediaRules.ResolveMedia(info.Packet, info.Interface); ok {
			if metadata == nil {
				metadata = &data.PacketMetadata{}
			}
			metadata.Sip = &data.SIPMetadata{CallId: association.CallID}
			envelope.InheritedMatchedFilterIDs = append([]string(nil), association.InheritedFilterIDs...)
		}
	}
	if metadata != nil {
		encoded, err := grpcadapter.MetadataFromProto(metadata)
		if err != nil {
			return nil, err
		}
		envelope.Metadata = encoded
	}
	envelope.MatchedFilterIDs = stableFilterIDUnion(envelope.DirectMatchedFilterIDs, envelope.InheritedMatchedFilterIDs)
	envelope.CurrentCaptureSelection = func() bool { return h.learnedCaptureAllowed(envelope) }
	return envelope, nil
}

func (h *Hunter) learnedCaptureAllowed(envelope *pipeline.PacketEnvelope) bool {
	runtime := h.learnedCaptureRuntime()
	if runtime == nil || !captureadapter.ValidateCurrent(runtime.Store, envelope, h.config.HunterID) {
		return false
	}
	protected := false
	for _, candidate := range envelope.LearnedCaptureEvidence.Candidates {
		proof := candidate.GetLegacyMediaRule()
		if len(proof) == 0 {
			continue
		}
		if _, _, err := voiprules.BindingFromLegacyCandidate(candidate); err != nil {
			return false
		}
		rule := &management.MediaRule{}
		if proto.Unmarshal(proof, rule) != nil || rule.Call == nil || h.filterManager == nil {
			return false
		}
		inherited := append([]string(nil), envelope.InheritedMatchedFilterIDs...)
		for _, ref := range rule.Call.SelectionGrants {
			inherited = stableFilterIDUnion(inherited, []string{ref.Id})
		}
		selected := &pipeline.PacketEnvelope{Data: envelope.Data, LinkType: envelope.LinkType, CaptureTime: envelope.CaptureTime, Source: envelope.Source, CaptureSelectionProof: proof, DirectMatchedFilterIDs: envelope.DirectMatchedFilterIDs, InheritedMatchedFilterIDs: inherited, MatchedFilterIDs: stableFilterIDUnion(envelope.DirectMatchedFilterIDs, inherited)}
		if !h.filterManager.CaptureSelectionProofAllowed(selected) {
			return false
		}
		protected = true
	}
	// An ordinary binding is not a new LI capture grant. Preserve the existing
	// independently selected filter boundary when no exact protected proof exists.
	if h.config.FilterPolicy.Owner == "li" && !protected {
		return h.filterManager != nil && h.filterManager.CaptureSelectionAllowed(envelope.MatchedFilterIDs)
	}
	return true
}

func validateGenericCaptureFilters(filters []*management.Filter) error {
	for _, filter := range filters {
		if filter != nil && filter.Enabled && filter.Type == management.FilterType_FILTER_BPF {
			return errors.New("generic learned capture cannot install a restrictive dynamic BPF filter")
		}
	}
	return nil
}

// Independent selectors may still retain raw traffic after learned overflow,
// but cannot recover the legacy resolver's truncated call ownership.
func (h *Hunter) independentLearnedFallback(info capture.PacketInfo, envelope *pipeline.PacketEnvelope) *pipeline.PacketEnvelope {
	if h.applicationFilter == nil {
		return nil
	}
	matched, ids := h.applicationFilter.MatchPacketWithIDs(info.Packet)
	if !matched {
		return nil
	}
	envelope.CaptureSelectionProof = nil
	envelope.LearnedCaptureEvidence = nil
	envelope.InheritedMatchedFilterIDs = nil
	envelope.DirectMatchedFilterIDs = append([]string(nil), ids...)
	envelope.MatchedFilterIDs = append([]string(nil), ids...)
	envelope.CallLifecycleRejected = true
	envelope.CurrentCaptureSelection = func() bool { matched, _ := h.applicationFilter.MatchPacketWithIDs(info.Packet); return matched }
	return envelope
}

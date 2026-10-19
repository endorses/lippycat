package source

import (
	"bytes"
	"errors"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"strings"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/learnedrules/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
)

// SetLearnedRuntime installs the same typed runtime used by remote hunters.
// validate is additionally required whenever a binding carries protected proof.
func (s *LocalSource) SetLearnedRuntime(runtime *core.Runtime, validate func(*pipeline.PacketEnvelope) bool, policy ...func() ([]byte, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if (s.config.BPFFilter != "" && !s.learnedBaseUnrestricted) || (s.config.ProtocolMode != "" && s.config.ProtocolMode != "generic" && s.config.ProtocolMode != "voip") {
		return errors.New("generic learned runtime requires an unrestricted generic local capture path")
	}
	if runtime == nil || runtime.Configuration().HunterID != s.SourceID() {
		return core.ErrScope
	}
	if s.config.BPFFilter != "" {
		protocols := runtime.Configuration().SupportedProtocols
		if s.config.ProtocolMode != "voip" || len(protocols) != 1 || protocols[0] != core.UDP {
			return errors.New("transport exclusion is only supported for UDP learned capture")
		}
	}
	if s.started {
		return errors.New("learned runtime must be configured before local capture starts")
	}
	if len(policy) > 1 {
		return core.ErrInvalid
	}
	s.learnedRuntime, s.validateLearnedProof = runtime, validate
	s.learnedPolicySnapshot = nil
	if len(policy) == 1 {
		s.learnedPolicySnapshot = policy[0]
	}
	domains := make(map[string]mediaadmission.DomainID)
	for _, list := range s.config.Interfaces {
		for _, name := range strings.Split(list, ",") {
			name = strings.TrimSpace(name)
			if domain, ok := runtime.Domain(name); ok {
				domains[name] = mediaadmission.DomainID(domain)
			}
		}
	}
	s.SetObservationDomains(domains)
	return nil
}

func (s *LocalSource) learnedPacket(info capture.PacketInfo) (*policyCapture, error) {
	s.mu.Lock()
	runtime, proofValidator, filter, remote, policy := s.learnedRuntime, s.validateLearnedProof, s.appFilter, s.remoteMediaResolver, s.learnedPolicySnapshot
	s.mu.Unlock()
	if runtime == nil {
		return nil, nil
	}
	packet := convertPacketInfo(info)
	packet.Metadata = protocolmeta.Enrich(info.Packet, packet.Metadata, s.config.IncludeHTTPHeaders)
	envelope, err := s.normalizeLocalPacket(packet)
	if err != nil {
		return nil, err
	}
	selected, err := captureadapter.Select(runtime, envelope)
	if err != nil {
		return s.independentLearnedFallback(info, filter), nil
	}
	if !selected {
		return nil, nil
	}
	if s.config.ProtocolMode == "voip" && remote != nil {
		if association, ok := remote.ResolveMedia(info.Packet, info.Interface); ok {
			if packet.Metadata == nil {
				packet.Metadata = &data.PacketMetadata{}
			}
			packet.Metadata.Sip = &data.SIPMetadata{CallId: association.CallID}
			envelope.InheritedMatchedFilterIDs = composeFilterIDs(association.InheritedFilterIDs, nil)
			metadata, err := grpcadapter.MetadataFromProto(packet.Metadata)
			if err != nil {
				return nil, err
			}
			envelope.Metadata = metadata
		}
	}
	if filter != nil {
		if selected, ids := filter.MatchPacketWithIDs(info.Packet); selected {
			envelope.DirectMatchedFilterIDs = composeFilterIDs(ids, nil)
			envelope.MatchedFilterIDs = composeFilterIDs(ids, envelope.InheritedMatchedFilterIDs)
		}
	}
	if len(envelope.MatchedFilterIDs) == 0 {
		envelope.MatchedFilterIDs = composeFilterIDs(envelope.DirectMatchedFilterIDs, envelope.InheritedMatchedFilterIDs)
	}
	var capturedPolicy []byte
	if policy != nil {
		var err error
		capturedPolicy, err = policy()
		if err != nil {
			return nil, err
		}
		if len(capturedPolicy) > filterpolicy.MaxSnapshotBytes {
			return nil, core.ErrCapacity
		}
		capturedPolicy = append([]byte(nil), capturedPolicy...)
	}
	valid := func(current *pipeline.PacketEnvelope) bool {
		if !captureadapter.ValidateCurrent(runtime.Store, current, s.SourceID()) {
			return false
		}
		for _, candidate := range current.LearnedCaptureEvidence.Candidates {
			if len(candidate.GetLegacyMediaRule()) > 0 {
				if policy == nil || len(capturedPolicy) == 0 {
					return false
				}
				currentPolicy, err := policy()
				if err != nil || !bytes.Equal(currentPolicy, capturedPolicy) {
					return false
				}
				return proofValidator != nil && proofValidator(current)
			}
		}
		return true
	}
	if !valid(envelope) {
		return nil, nil
	}
	encoded, err := grpcadapter.ToCapturedPacket(envelope)
	if err != nil {
		return nil, err
	}
	return &policyCapture{packet: encoded, check: valid, signedCapturePolicy: capturedPolicy}, nil
}

func (s *LocalSource) independentLearnedFallback(info capture.PacketInfo, filter ApplicationFilter) *policyCapture {
	if filter == nil {
		return &policyCapture{check: func(*pipeline.PacketEnvelope) bool { return false }}
	}
	matched, ids := filter.MatchPacketWithIDs(info.Packet)
	if !matched {
		return &policyCapture{check: func(*pipeline.PacketEnvelope) bool { return false }}
	}
	packet := convertPacketInfo(info)
	packet.DirectMatchedFilterIds = composeFilterIDs(ids, nil)
	packet.MatchedFilterIds = composeFilterIDs(ids, nil)
	return &policyCapture{packet: packet, check: func(*pipeline.PacketEnvelope) bool {
		matched, _ := filter.MatchPacketWithIDs(info.Packet)
		return matched
	}}
}

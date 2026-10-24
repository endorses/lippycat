package source

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// SetCapturePolicies configures VoIP source selection independently of central
// call tracking. It must run before source capture starts.
func (s *LocalSource) SetCapturePolicies(p capturepolicy.CapturePolicies, resolver capturepolicy.RemoteMediaResolver) error {
	normalized, err := p.Normalize()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("VoIP capture policies must be configured before source start")
	}
	if s.config.ProtocolMode != "voip" {
		return errors.New("independent signalling/media policies require VoIP source mode")
	}
	s.voipPolicies = normalized
	s.remoteMediaResolver = resolver
	return nil
}

func policySIPMetadata(event sharedsip.Event) *data.PacketMetadata {
	return &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: event.CallID, FromUser: event.FromUser, ToUser: event.ToUser, FromTag: event.FromTag, ToTag: event.ToTag, FromUri: event.FromURI, ToUri: event.ToURI, Method: event.Method, CseqMethod: event.CSeqMethod, CseqNumber: event.CSeqNumber, ViaBranch: event.ViaBranch, ResponseCode: uint32(event.ResponseCode), MediaPorts: sharedsip.MediaPorts(event.SDP), PAssertedIdentity: event.PAssertedIdentity}}
}

// policyPacket consumes non-default VoIP policies before legacy local ownership
// and packet-level selectors can create an independent media allowance.
type policyCapture struct {
	signedCapturePolicy []byte
	packet              *data.CapturedPacket
	check               func(*pipeline.PacketEnvelope) bool
}

func (s *LocalSource) policyPacket(info capture.PacketInfo, injected *InjectedPacket) (bool, *policyCapture) {
	s.mu.Lock()
	policies, remote, filter, voipProc := s.voipPolicies, s.remoteMediaResolver, s.appFilter, s.voipProcessor
	s.mu.Unlock()
	if policies == (capturepolicy.CapturePolicies{}) || policies == (capturepolicy.CapturePolicies{Signalling: capturepolicy.SignallingMatched, Media: capturepolicy.MediaLocal}) {
		return false, nil
	}
	packet := info.Packet
	if packet == nil || packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return true, nil
	}
	transport := packet.TransportLayer()
	payload := transport.LayerPayload()
	isMedia := false
	if _, udp := transport.(*layers.UDP); udp && len(payload) >= 8 && payload[0]>>6 == 2 {
		isMedia = len(payload) >= 12 || payload[1] >= 192 && payload[1] <= 223
	}
	if isMedia {
		if policies.Media != capturepolicy.MediaProcessor {
			return false, nil
		}
		if remote == nil {
			return true, nil
		}
		association, ok := remote.ResolveMedia(packet, info.Interface)
		if !ok || association.CallID == "" {
			return true, nil
		}
		association = association.Clone()
		result := convertPacketInfo(info)
		result.Metadata = &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: association.CallID}}
		if len(payload) >= 12 && !(payload[1] >= 192 && payload[1] <= 223) {
			result.Metadata.Rtp = &data.RTPMetadata{Ssrc: binary.BigEndian.Uint32(payload[8:12]), PayloadType: uint32(payload[1] & 0x7f), Sequence: uint32(binary.BigEndian.Uint16(payload[2:4])), Timestamp: binary.BigEndian.Uint32(payload[4:8])}
		}
		result.CaptureSelectionProof = append([]byte(nil), association.CaptureSelectionProof...)
		result.InheritedMatchedFilterIds = composeFilterIDs(association.InheritedFilterIDs, nil)
		result.MatchedFilterIds = append([]string(nil), result.InheritedMatchedFilterIds...)
		return true, &policyCapture{packet: result, check: s.policyReleaseCheck(info, nil, &association, true)}
	}
	options := sharedsip.ParseOptions{Timestamp: packet.Metadata().Timestamp, SourceIP: packet.NetworkLayer().NetworkFlow().Src().String(), DestinationIP: packet.NetworkLayer().NetworkFlow().Dst().String()}
	event, err := sharedsip.Parse(payload, options)
	if err != nil || event.CallID == "" || len(event.CallID) > 1024 || strings.ContainsAny(event.CallID, "\x00\r\n") {
		if policies.Media == capturepolicy.MediaProcessor {
			return true, nil
		}
		return false, nil
	}
	direct := true
	var directIDs, inherited []string
	if filter != nil {
		direct, directIDs = filter.MatchPacketWithIDs(packet)
	}
	selected := direct
	var lifetime callregistry.Lifetime
	var proof *capturepolicy.RemoteCallAssociation
	if policies.Media == capturepolicy.MediaLocal {
		if injected != nil {
			lifetime = injected.CallLifetime
			selected = direct || lifetime != (callregistry.Lifetime{})
		} else if voipProc != nil {
			result := voipProc.ProcessPacketInfo(info)
			selected = result != nil && result.IsVoIPPacket() && result.GetMetadata() != nil && result.GetMetadata().Sip != nil
			if result != nil {
				lifetime = result.GetCallLifetime()
				if evaluated, matched, ids := result.FilterVerdict(); evaluated {
					direct, directIDs = matched, ids
				}
			}
		}
		key := s.filterCacheKey(event.CallID, info.Interface, lifetime)
		if selected && direct && len(directIDs) > 0 && key != "" {
			s.storeCallSelection(key, composeFilterIDs(s.cachedFilterIDsForCall(key), directIDs), packet)
		}
		if selected {
			inherited = s.cachedFilterIDsForCall(key)
		}
	} else if remote != nil {
		if association, ok := remote.ResolveSignalling(event, packet, info.Interface); ok && association.CallID == event.CallID {
			selected = true
			inherited = association.InheritedFilterIDs
			current := association
			proof = &current
		}
	}
	if policies.Signalling == capturepolicy.SignallingNone || policies.Signalling == capturepolicy.SignallingMatched && !selected {
		return true, nil
	}
	result := convertPacketInfo(info)
	result.Metadata = policySIPMetadata(event)
	result.DirectMatchedFilterIds = composeFilterIDs(directIDs, nil)
	result.InheritedMatchedFilterIds = composeFilterIDs(inherited, nil)
	result.MatchedFilterIds = composeFilterIDs(directIDs, inherited)
	accepted := &policyCapture{packet: result}
	if policies.Media == capturepolicy.MediaProcessor {
		accepted.check = s.policyReleaseCheck(info, &event, proof, !direct && policies.Signalling == capturepolicy.SignallingMatched)
	}
	return true, accepted
}

func (s *LocalSource) appendPolicyPacket(accepted *policyCapture, after func()) {
	var packet *data.CapturedPacket
	if accepted != nil {
		packet = accepted.packet
	}
	if packet == nil {
		if after != nil {
			after()
		}
		return
	}
	envelope, err := s.normalizeLocalPacket(packet)
	if err != nil {
		s.stats.AddDropped(1)
		logger.Error("Normalize local policy packet", "error", err)
		if after != nil {
			after()
		}
		return
	}
	s.appendEnvelope(envelope, accepted.signedCapturePolicy, after, accepted.check)
}

// Each check lives only as long as its queued packet. A replacement rule for the
// same visible Call-ID cannot relabel that packet as a new call incarnation.
func (s *LocalSource) policyReleaseCheck(info capture.PacketInfo, event *sharedsip.Event, proof *capturepolicy.RemoteCallAssociation, required bool) func(*pipeline.PacketEnvelope) bool {
	s.mu.Lock()
	resolver := s.remoteMediaResolver
	s.mu.Unlock()
	return func(envelope *pipeline.PacketEnvelope) bool {
		var current capturepolicy.RemoteCallAssociation
		valid := false
		if resolver != nil {
			if event == nil {
				current, valid = resolver.ResolveMedia(info.Packet, info.Interface)
			} else {
				current, valid = resolver.ResolveSignalling(*event, info.Packet, info.Interface)
			}
		}
		valid = valid && proof != nil && proof.SameSelection(current)
		if valid && event == nil && len(proof.CaptureSelectionProof) > 0 {
			verifier, ok := resolver.(capturepolicy.RemoteMediaProofValidator)
			valid = ok && bytes.Equal(envelope.CaptureSelectionProof, proof.CaptureSelectionProof) && verifier.ValidateMediaProof(info.Packet, info.Interface, proof.CaptureSelectionProof, envelope.CaptureTime)
		}
		if !valid && required {
			return false
		}
		envelope.InheritedMatchedFilterIDs = nil
		if !valid {
			envelope.CaptureSelectionProof = nil
		}
		if valid {
			envelope.InheritedMatchedFilterIDs = composeFilterIDs(current.InheritedFilterIDs, nil)
		}
		envelope.MatchedFilterIDs = composeFilterIDs(envelope.DirectMatchedFilterIDs, envelope.InheritedMatchedFilterIDs)
		return true
	}
}

func (s *LocalSource) storeCallSelection(key string, ids []string, packet gopacket.Packet) {
	cached := cachedFilterIDs{filterIDs: ids, storedAt: time.Now()}
	if matcher, ok := s.appFilter.(capturepolicy.SelectionProofMatcher); ok {
		matched, currentIDs, proof := matcher.MatchPacketWithSelectionProof(packet)
		if !matched {
			return
		}
		prior, _ := s.callFilterCache.Load(key)
		cached.proof = capturepolicy.MergeCurrentProofs(matcher, prior.proof, proof)
		cached.filterIDs = composeFilterIDs(currentIDs, s.cachedFilterIDsForCall(key))
	}
	s.callFilterCache.Store(key, cached)
}

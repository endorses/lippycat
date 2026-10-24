package source

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/smsflow"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	"github.com/google/gopacket"
	"google.golang.org/protobuf/proto"
)

// SetSMSConfig configures optional filtering and assembly before capture starts.
func (s *LocalSource) SetSMSConfig(config smsflow.Config) error {
	config.Keywords = append([]string(nil), config.Keywords...)
	controller, err := smsflow.New(config)
	if err != nil {
		return fmt.Errorf("configure local SMS: %w", err)
	}
	s.mu.Lock()
	if s.started || s.stopped {
		s.mu.Unlock()
		controller.Close()
		return errors.New("SMS must be configured before source start")
	}
	s.smsMu.Lock()
	previous := s.smsFlow
	s.smsConfig, s.smsFlow = config, controller
	s.smsFiltering = controller.Enabled()
	s.smsMu.Unlock()
	s.mu.Unlock()
	if previous != nil {
		previous.Close()
	}
	return nil
}

func (s *LocalSource) smsController() (*smsflow.Controller, error) {
	s.smsMu.Lock()
	defer s.smsMu.Unlock()
	if s.smsFlow == nil {
		controller, err := smsflow.New(s.smsConfig)
		if err != nil {
			return nil, err
		}
		s.smsFlow = controller
	}
	return s.smsFlow, nil
}

func (s *LocalSource) closeSMS() {
	s.smsBoundaryTime.Store(time.Now().UnixNano())
	s.smsGeneration.Add(1)
	s.smsMu.Lock()
	previous := s.smsFlow
	s.smsFlow = nil
	s.smsMu.Unlock()
	if previous != nil {
		previous.Close()
	}
}

func (s *LocalSource) expireSMS(now time.Time) {
	s.smsMu.Lock()
	controller := s.smsFlow
	s.smsMu.Unlock()
	if controller != nil {
		controller.Expire(now)
	}
}

// SMSStats reports content-free pressure and decision counters.
func (s *LocalSource) SMSStats() smsflow.Stats {
	s.smsMu.Lock()
	controller := s.smsFlow
	s.smsMu.Unlock()
	if controller == nil {
		return smsflow.Stats{}
	}
	return controller.Stats()
}

// appendEnvelope is the final local source gateway. Every eligible UDP,
// reassembled TCP, and independent policy path passes here before any output.
func (s *LocalSource) appendEnvelope(envelope *pipeline.PacketEnvelope, policy []byte, after func(), check func(*pipeline.PacketEnvelope) bool) {
	if s.config.ProtocolMode != "voip" || envelope == nil {
		s.appendEnvelopeDirect(envelope, policy, after, check)
		return
	}
	result, metadata, ok, err := localSMSResult(envelope)
	if err != nil {
		logger.Error("Decode local SMS metadata", "error", err)
	}
	if !ok || err != nil {
		s.appendEnvelopeDirect(envelope, policy, after, check)
		return
	}
	controller, err := s.smsController()
	if err != nil {
		logger.Error("Initialize local SMS", "error", err)
		if after != nil {
			after()
		}
		s.stats.AddDropped(1)
		return
	}
	// A UDP datagram cannot release one approved message while retaining a
	// second message in the same raw packet. TCP adapters synthesize one frame.
	// A successful parse is required to prove the first body's binary extent.
	if controller.Enabled() && result.Headers != nil {
		packet := gopacket.NewPacket(envelope.Data, envelope.LinkType, gopacket.Default)
		if transport := packet.TransportLayer(); transport != nil && smsflow.HasTrailingPayload(transport.LayerPayload(), len(result.Body)) {
			if after != nil {
				after()
			}
			return
		}
	}
	// Packets admitted by a retiring handle may still be queued after that
	// handle closes. Their capture time cannot seed the replacement assembly.
	if boundary := s.smsBoundaryTime.Load(); boundary != 0 && !envelope.CaptureTime.IsZero() && envelope.CaptureTime.UnixNano() < boundary {
		if controller.Enabled() {
			if after != nil {
				after()
			}
			return
		}
		if err := writeLocalSMSMetadata(envelope, metadata, result); err != nil {
			logger.Error("Preserve retired local SMS metadata", "error", err)
		}
		s.appendEnvelopeDirect(envelope, policy, after, check)
		return
	}
	generation := s.smsGeneration.Load()
	// SMS capture lifetime is separate from learned-capture authorization.
	// Preserve the original envelope generation used by its release check.
	scope := envelope.Source
	scope.CaptureEpoch = fmt.Sprintf("%s:sms:%d", scope.CaptureEpoch, generation)
	result.Packet = &pipeline.PacketEnvelope{Source: scope}
	// The raw packet, policy, and metadata remain owned by this entry until its
	// final decision. AfterProcess transfers to the batch or runs on discard.
	policy = append([]byte(nil), policy...)
	var once sync.Once
	completed := func() {
		once.Do(func() {
			if after != nil {
				after()
			}
		})
	}
	current := func() bool {
		s.mu.Lock()
		stopped := s.stopped
		s.mu.Unlock()
		return !stopped && generation == s.smsGeneration.Load() && s.hasPacketDemand() && (check == nil || check(envelope))
	}
	var releaseCheck func() bool
	if controller.Enabled() {
		releaseCheck = current
	}
	size := len(envelope.Data) + len(policy) + 256
	if envelope.Metadata != nil {
		size += len(envelope.Metadata.Payload)
	}
	_, err = controller.Process(smsflow.Entry{Result: result, Size: size, Current: releaseCheck, Discard: completed, Deliver: func(updated pipeline.SIPResult) error {
		if err := writeLocalSMSMetadata(envelope, metadata, updated); err != nil {
			completed()
			return err
		}
		s.appendEnvelopeDirect(envelope, policy, completed, check)
		return nil
	}})
	if err != nil {
		logger.Error("Process local SMS output", "error", err)
	}
}

func writeLocalSMSMetadata(envelope *pipeline.PacketEnvelope, metadata *data.PacketMetadata, result pipeline.SIPResult) error {
	if metadata.Sip == nil {
		metadata.Sip = &data.SIPMetadata{CallId: result.CallID, Method: result.Method, CseqMethod: result.CSeqMethod, CseqNumber: result.CSeqNumber, ViaBranch: result.ViaBranch, FromUri: result.FromURI, ToUri: result.ToURI, FromUser: result.FromUser, ToUser: result.ToUser, FromTag: result.FromTag, ToTag: result.ToTag, PAssertedIdentity: result.PAssertedIdentity, ResponseCode: uint32(result.ResponseCode)}
	}
	metadata.Sip.Sms = grpcadapter.ToProtoSMS(result.SMS)
	normalized, err := grpcadapter.MetadataFromProto(metadata)
	if err != nil {
		return err
	}
	envelope.Metadata = normalized
	return nil
}

func localSMSResult(envelope *pipeline.PacketEnvelope) (pipeline.SIPResult, *data.PacketMetadata, bool, error) {
	metadata := &data.PacketMetadata{}
	if envelope.Metadata != nil {
		if envelope.Metadata.Encoding != pipeline.MetadataProtobuf {
			return pipeline.SIPResult{}, nil, false, errors.New("unsupported local metadata encoding")
		}
		if err := proto.Unmarshal(envelope.Metadata.Payload, metadata); err != nil {
			return pipeline.SIPResult{}, nil, false, fmt.Errorf("read local SMS metadata: %w", err)
		}
	}
	var result pipeline.SIPResult
	packet := gopacket.NewPacket(envelope.Data, envelope.LinkType, gopacket.Default)
	if transport := packet.TransportLayer(); transport != nil {
		event, err := sharedsip.Parse(transport.LayerPayload(), sharedsip.ParseOptions{Timestamp: envelope.CaptureTime})
		if err == nil {
			var supplied *sms.Message
			if metadata.Sip != nil && metadata.Sip.Sms != nil {
				supplied = grpcadapter.FromProtoSMS(metadata.Sip.Sms)
			}
			result = pipeline.SIPResultFromEventWithSMS(event, envelope, supplied)
		}
	}
	if m := metadata.Sip; m != nil {
		if result.CallID == "" {
			result = pipeline.SIPResult{Timestamp: envelope.CaptureTime, Packet: envelope, CallID: m.CallId, Method: m.Method, CSeqMethod: m.CseqMethod, CSeqNumber: m.CseqNumber, ViaBranch: m.ViaBranch, FromURI: m.FromUri, ToURI: m.ToUri, FromUser: m.FromUser, ToUser: m.ToUser, ResponseCode: int(m.ResponseCode)}
		}
		if m.Sms != nil && result.SMS == nil {
			result.SMS = grpcadapter.FromProtoSMS(m.Sms)
		}
	}
	return result, metadata, result.Method == "MESSAGE" || result.CSeqMethod == "MESSAGE", nil
}

// smsSelectionCheck captures the authority already used by legacy source
// selection. It never grants a new owner or media authorization.
func (s *LocalSource) smsSelectionCheck(info capture.PacketInfo, lifetime callregistry.Lifetime) func(*pipeline.PacketEnvelope) bool {
	s.smsMu.Lock()
	enabled := s.smsFiltering
	s.smsMu.Unlock()
	if !enabled || info.Packet == nil || info.Packet.TransportLayer() == nil {
		return nil
	}
	event, err := sharedsip.Parse(info.Packet.TransportLayer().LayerPayload(), sharedsip.ParseOptions{})
	if err != nil || event.Method != "MESSAGE" && event.CSeqMethod != "MESSAGE" {
		return nil
	}
	s.mu.Lock()
	filter := s.appFilter
	s.mu.Unlock()
	if filter == nil {
		return nil
	}
	cacheKey := s.filterCacheKey(event.CallID, info.Interface, lifetime)
	var directProof, inheritedProof capturepolicy.FilterSelectionProof
	if matcher, ok := filter.(capturepolicy.SelectionProofMatcher); ok {
		_, _, directProof = matcher.MatchPacketWithSelectionProof(info.Packet)
		if cached, ok := s.callFilterCache.Load(cacheKey); ok {
			inheritedProof = capturepolicy.MergeProofs(nil, cached.proof)
		}
	}
	return func(envelope *pipeline.PacketEnvelope) bool {
		s.mu.Lock()
		current, selection := s.appFilter, s.selectionPolicy
		s.mu.Unlock()
		if current == nil {
			return false
		} // Original configured authority was removed.
		direct, directIDs := current.MatchPacketWithIDs(info.Packet)
		inheritedIDs := s.cachedFilterIDsForCall(cacheKey)
		if matcher, ok := current.(capturepolicy.SelectionProofMatcher); ok {
			direct, directIDs = matcher.CurrentSelection(directProof)
			_, inheritedIDs = matcher.CurrentSelection(inheritedProof)
		}
		if !selection.Select(callregistry.SelectionInput{FilterConfigured: true, DirectMatch: direct, PreviouslySelected: len(inheritedIDs) > 0}) {
			return false
		}
		envelope.DirectMatchedFilterIDs = composeFilterIDs(directIDs, nil)
		envelope.InheritedMatchedFilterIDs = composeFilterIDs(inheritedIDs, nil)
		envelope.MatchedFilterIDs = composeFilterIDs(directIDs, inheritedIDs)
		return true
	}
}

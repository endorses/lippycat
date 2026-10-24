//go:build hunter || all

package voip

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	mediaadaptor "github.com/endorses/lippycat/internal/pkg/voip/admission"
	"github.com/endorses/lippycat/internal/pkg/voip/capturepolicy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketForwarder is an interface for forwarding packets (implemented by Hunter)
type PacketForwarder interface {
	// ForwardPacketWithMetadata forwards a packet with embedded metadata, interface name, and link type
	ForwardPacketWithMetadata(packet gopacket.Packet, metadata *data.PacketMetadata, interfaceName string, linkType layers.LinkType) error
}

// PacketForwarderWithObservedCaptureBoundary serializes asynchronous state mutation
// with capture-policy replacement and rejects stale source observations.
type PacketForwarderWithObservedCaptureBoundary interface {
	WithObservedCaptureBoundary(uint64, func() bool) bool
}

// PacketForwarderWithFilterProvenance is implemented by forwarders that can
// preserve direct versus call-inherited filter evidence across gRPC.
type PacketForwarderWithFilterProvenance interface {
	ForwardPacketWithFilterProvenance(packet gopacket.Packet, metadata *data.PacketMetadata, interfaceName string, linkType layers.LinkType, directFilterIDs, inheritedFilterIDs []string) error
}

// PacketForwarderWithSelectionCheck preserves a current temporary selection
// check until the forwarding producer seals a batch or durable spool record.
type PacketForwarderWithSelectionCheck interface {
	ForwardPacketWithSelectionCheck(gopacket.Packet, *data.PacketMetadata, string, layers.LinkType, []string, []string, func() bool) error
}

func forwardPacketWithSelectionCheck(forwarder PacketForwarder, packet gopacket.Packet, metadata *data.PacketMetadata, iface string, link layers.LinkType, direct, inherited []string, current func() bool) error {
	if checked, ok := forwarder.(PacketForwarderWithSelectionCheck); ok {
		return checked.ForwardPacketWithSelectionCheck(packet, metadata, iface, link, direct, inherited, current)
	}
	if current != nil && !current() {
		return nil
	}
	return forwardPacketWithFilterProvenance(forwarder, packet, metadata, iface, link, direct, inherited)
}

// PacketForwarderWithCaptureSelectionProof preserves signed public selection
// evidence and its current-state callback together until producer acceptance.
type PacketForwarderWithCaptureSelectionProof interface {
	ForwardPacketWithCaptureSelectionProof(gopacket.Packet, *data.PacketMetadata, string, layers.LinkType, []string, []string, []byte, func() bool) error
}

func forwardPacketWithCaptureSelectionProof(forwarder PacketForwarder, packet gopacket.Packet, metadata *data.PacketMetadata, iface string, link layers.LinkType, direct, inherited []string, proof []byte, current func() bool) error {
	if len(proof) == 0 {
		return forwardPacketWithSelectionCheck(forwarder, packet, metadata, iface, link, direct, inherited, current)
	}
	if typed, ok := forwarder.(PacketForwarderWithCaptureSelectionProof); ok {
		return typed.ForwardPacketWithCaptureSelectionProof(packet, metadata, iface, link, direct, inherited, append([]byte(nil), proof...), current)
	}
	return fmt.Errorf("forwarder cannot preserve capture-selection proof")
}

type packetFilterWithIDs interface {
	MatchPacketWithIDs(gopacket.Packet) (bool, []string)
}

func matchPacketWithIDs(filter ApplicationFilter, packet gopacket.Packet) (bool, []string) {
	if filter == nil {
		return false, nil
	}
	if withIDs, ok := filter.(packetFilterWithIDs); ok {
		return withIDs.MatchPacketWithIDs(packet)
	}
	return filter.MatchPacket(packet), nil
}

func setHunterFilterProvenance(env *pipeline.PacketEnvelope, direct, inherited []string) {
	if env == nil {
		return
	}
	env.DirectMatchedFilterIDs = stableFilterIDs(direct)
	env.InheritedMatchedFilterIDs = stableFilterIDs(inherited)
	combined := append(append([]string(nil), direct...), inherited...)
	env.MatchedFilterIDs = stableFilterIDs(combined)
}

func forwardPacketWithFilterProvenance(forwarder PacketForwarder, packet gopacket.Packet, metadata *data.PacketMetadata, interfaceName string, linkType layers.LinkType, directFilterIDs, inheritedFilterIDs []string) error {
	if provenanceForwarder, ok := forwarder.(PacketForwarderWithFilterProvenance); ok {
		return provenanceForwarder.ForwardPacketWithFilterProvenance(packet, metadata, interfaceName, linkType, directFilterIDs, inheritedFilterIDs)
	}
	return forwarder.ForwardPacketWithMetadata(packet, metadata, interfaceName, linkType)
}

// HunterForwardHandler handles SIP messages for hunter mode (lc hunt voip)
// It checks filters, extracts metadata, and forwards matched calls to processor
type HunterForwardHandler struct {
	capturePolicy    *hunterCapturePolicy
	admission        *mediaadaptor.Bridge
	captureInterface string
	tracker          *CallTracker
	forwarder        PacketForwarder
	bufferMgr        *BufferManager
	appFilter        ApplicationFilter // Optional: for proper filter matching (supports phone_number, sip_user, etc.)
	selectionPolicy  *hunterSelectionPolicy
	orchestrator     *sipflow.Orchestrator
}

// NewHunterForwardHandler creates a handler for hunter packet forwarding
func NewHunterForwardHandler(tracker *CallTracker, forwarder PacketForwarder, bufferMgr *BufferManager) *HunterForwardHandler {
	if tracker != nil && bufferMgr != nil {
		bufferMgr.BindRegistry(tracker.AdmissionRegistry(), tracker.config.MaxEndpointsPerCall)
		tracker.sdpReporter.Disable()
	}
	h := &HunterForwardHandler{
		capturePolicy:   defaultHunterCapturePolicy(),
		tracker:         tracker,
		forwarder:       forwarder,
		bufferMgr:       bufferMgr,
		selectionPolicy: newHunterSelectionPolicy(),
	}
	store := newHunterSelectionStore()
	if bufferMgr != nil {
		store.current = bufferMgr.SelectionProofCurrent
	}
	h.orchestrator = newHunterPolicySIPOrchestrator(forwarder, h.selectionPolicy, h.capturePolicy, store)
	return h
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
// This supports all filter types including phone_number, sip_user, sipuri, ip_address, etc.
func (h *HunterForwardHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
	if h.bufferMgr != nil {
		h.bufferMgr.SetSelectionProofMatcher(filter)
	}
}

func (h *HunterForwardHandler) SetSelectionPolicy(policy callregistry.SelectionPolicy) {
	h.selectionPolicy.set(policy)
}

// Close drains accepted SIP forwarding and stops the handler-owned sink.
func (h *HunterForwardHandler) Close() {
	h.orchestrator.Close()
	if h.capturePolicy.sms != nil {
		h.capturePolicy.sms.Close()
	}
}

func (h *HunterForwardHandler) SIPStats() map[string]sipflow.SinkStats { return h.orchestrator.Stats() }

// HandleSIPMessage processes a complete SIP message for hunter forwarding.
// srcEndpoint and dstEndpoint are in "IP:port" format (e.g., "192.168.1.1:5060").
// netFlow is used for TCP packet buffer lookup.
//
// Per-message semantics: the TCP reassembly loop invokes this once for EACH
// complete SIP message reassembled from the stream. Each message is synthesized
// into a single packet carrying exactly that message's bytes (with the
// connection's real 5-tuple) and treated as an independent, matchable,
// forwardable unit — so every message on a long-lived TCP connection (e.g. five
// MT SMS-DELIVER, or an MO leg whose target only appears in From /
// P-Asserted-Identity) is matched and forwarded, not just the first. Matching
// runs against THIS message's SIP (not the first buffered packet of the flow),
// and forwarding delivers this message's own packet (not a drained whole-flow
// buffer), so there is no match-once-per-connection and no double-forwarding.
func (h *HunterForwardHandler) HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow) bool {
	return h.HandleSIPMessageAt(sipMessage, callID, srcEndpoint, dstEndpoint, netFlow, transportFlow, time.Now())
}

func (h *HunterForwardHandler) HandleSIPMessageAt(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow, capturedAt time.Time) bool {
	return h.handleSIPMessage(sipMessage, nil, callID, srcEndpoint, dstEndpoint, netFlow, transportFlow, capturedAt, pipeline.SourceProvenance{})
}

func (h *HunterForwardHandler) HandleParsedSIPMessage(sipMessage []byte, event sharedsip.Event, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow) bool {
	return h.HandleParsedSIPMessageFromSource(sipMessage, event, srcEndpoint, dstEndpoint, netFlow, transportFlow, pipeline.SourceProvenance{})
}

// HandleParsedSIPMessageFromSource preserves the completing segment source even
// when several interfaces share one observation-domain reassembly context.
func (h *HunterForwardHandler) HandleParsedSIPMessageFromSource(message []byte, event sharedsip.Event, src, dst string, nf, tf gopacket.Flow, source pipeline.SourceProvenance) bool {
	return h.handleSIPMessage(message, &event, event.CallID, src, dst, nf, tf, event.Timestamp, source)
}

func (h *HunterForwardHandler) handleSIPMessage(sipMessage []byte, event *sharedsip.Event, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow, capturedAt time.Time, source pipeline.SourceProvenance) bool {
	if guarded, ok := h.forwarder.(PacketForwarderWithObservedCaptureBoundary); ok {
		return guarded.WithObservedCaptureBoundary(source.CapturePolicyGeneration, func() bool {
			return h.handleObservedSIPMessage(sipMessage, event, callID, srcEndpoint, dstEndpoint, netFlow, transportFlow, capturedAt, source)
		})
	}
	return h.handleObservedSIPMessage(sipMessage, event, callID, srcEndpoint, dstEndpoint, netFlow, transportFlow, capturedAt, source)
}

func (h *HunterForwardHandler) handleObservedSIPMessage(sipMessage []byte, event *sharedsip.Event, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow, capturedAt time.Time, source pipeline.SourceProvenance) bool {
	if callID == "" {
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	// Synthesize a packet carrying exactly this reassembled SIP message so both
	// matching and forwarding operate on THIS message rather than on the first
	// raw packet buffered for the whole flow.
	pkt, ok := buildSIPPacketInfo(sipMessage, srcEndpoint, dstEndpoint, netFlow, capturedAt)
	if !ok {
		logger.Warn("TCP SIP: failed to synthesize packet for message, dropping",
			"call_id", SanitizeCallIDForLogging(callID),
			"flow", srcEndpoint+"->"+dstEndpoint)
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	pkt.Interface = source.InterfaceName
	if pkt.Interface == "" {
		pkt.Interface = h.captureInterface
	}
	pkt.SourceInterfaceID = source.InterfaceIndex
	pkt.SourcePath = source.InputFile
	pkt.SourceIndex = source.ArgumentIndex
	pkt.SourceSequence = source.LogicalSequence
	capture.StampCapturePolicy(pkt.Packet, source.CapturePolicyGeneration)
	if handled, forwarded := h.capturePolicy.policySIP(pkt, event, sipMessage, callID, sharedsip.OptionsForEndpoints(capturedAt, srcEndpoint, dstEndpoint), h.appFilter, h.orchestrator, h.tracker, h.bufferMgr, h.admission); handled {
		discardTCPBufferedPackets(netFlow, transportFlow)
		return forwarded
	}
	directMatch, directFilterIDs, selectionProof := matchPacketWithSelectionProof(h.appFilter, pkt.Packet)
	var inheritedFilterIDs []string
	if h.bufferMgr != nil {
		inheritedFilterIDs = h.bufferMgr.MatchedFilterIDs(callID)
	}
	envelope := h.capturePolicy.envelope(pkt)
	setHunterFilterProvenance(envelope, directFilterIDs, inheritedFilterIDs)
	analysis := h.orchestrator.Analyze(sipflow.Message{
		Payload: sipMessage, Event: event, ExpectedCallID: callID, Envelope: envelope,
		ParseOptions:     sharedsip.OptionsForEndpoints(capturedAt, srcEndpoint, dstEndpoint),
		FilterConfigured: true, DirectMatch: directMatch,
		Match: func(event sharedsip.Event) bool {
			return h.appFilter == nil && containsUserInHeaders(event.Headers)
		},
		Validate: func(event sharedsip.Event) error {
			return ValidateCallIDForSecurity(event.CallID)
		},
	})
	if analysis.Stage.Outcome != pipeline.OutcomeAccepted || analysis.SIP.CallID != callID {
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}
	if directMatch && h.bufferMgr != nil {
		h.bufferMgr.StoreMatchedSelection(callID, directFilterIDs, selectionProof)
	}
	result, method := analysis.SIP, analysis.SIP.Method
	if method == "MESSAGE" || result.CSeqMethod == "MESSAGE" {
		freezeSMSSelection(envelope, h.appFilter, h.bufferMgr, pkt.Packet, callID, directMatch, selectionProof, false)
	}
	h.orchestrator.Dispatch(analysis)
	// Every selected TCP dialog needs an immutable registry lifetime, including
	// delayed-offer messages without SDP and captures with kernel admission off.
	if call := h.tracker.GetOrCreateCall(callID, pkt.LinkType); call != nil {
		call.SetCallInfoState(method)
		if h.admission != nil {
			if err := h.admission.Selected(result); err != nil {
				logger.Debug("Hunter TCP admission publication incomplete", "error", err)
			}
		}
	}

	metadata := &CallMetadata{
		CallID:            callID,
		From:              result.FromUser,
		To:                result.ToUser,
		FromTag:           result.FromTag,
		ToTag:             result.ToTag,
		PAssertedIdentity: result.PAssertedIdentity,
		Method:            method,
		CSeqMethod:        result.CSeqMethod,
		CSeqNumber:        result.CSeqNumber,
		ViaBranch:         result.ViaBranch,
		MediaPorts:        sharedsip.MediaPorts(result.SDP),
		ResponseCode:      uint32(result.ResponseCode),
		SDPBody:           string(result.SDP),
	}

	logger.Info("TCP SIP message matched filter, forwarding to processor",
		"call_id", SanitizeCallIDForLogging(callID),
		"from", metadata.From,
		"to", metadata.To,
		"method", method)

	// Extract RTP ports from SDP for future RTP packet association
	if len(result.SDP) > 0 {
		h.tracker.ExtractPortFromSDP(string(result.SDP), callID)
	}

	// Register the call as matched so its RTP media and later in-dialog messages
	// (BYE/CANCEL) are forwarded too.
	if h.bufferMgr != nil && !analysis.Terminal {
		h.bufferMgr.MarkCallMatched(callID, metadata, "", layers.LinkTypeEthernet)
	}

	discardTCPBufferedPackets(netFlow, transportFlow)
	return true
}

// matchesMessage checks if a single reassembled SIP message matches any
// configured filter. It runs the ApplicationFilter against the synthesized
// per-message packet (whose application payload is exactly this SIP message),
// so matching reflects the identity headers of THIS message. Falls back to the
// legacy containsUserInHeaders() check when no ApplicationFilter is configured.
func (h *HunterForwardHandler) matchesMessage(pkt capture.PacketInfo, headers map[string]string) bool {
	if h.appFilter != nil && pkt.Packet != nil {
		return h.appFilter.MatchPacket(pkt.Packet)
	}
	// Legacy fallback: use sipusers.IsSurveiled() via containsUserInHeaders()
	return containsUserInHeaders(headers)
}

// SetCapturePolicies configures independent source policies before capture starts.
func (h *HunterForwardHandler) SetCapturePolicies(p CapturePolicies, resolver RemoteMediaResolver) error {
	return h.capturePolicy.set(p, resolver)
}

func matchPacketWithSelectionProof(filter ApplicationFilter, packet gopacket.Packet) (bool, []string, capturepolicy.FilterSelectionProof) {
	if matcher, ok := filter.(capturepolicy.SelectionProofMatcher); ok {
		return matcher.MatchPacketWithSelectionProof(packet)
	}
	matched, ids := matchPacketWithIDs(filter, packet)
	return matched, ids, nil
}

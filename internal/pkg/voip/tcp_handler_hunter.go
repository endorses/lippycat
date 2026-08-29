//go:build hunter || all

package voip

import (
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketForwarder is an interface for forwarding packets (implemented by Hunter)
type PacketForwarder interface {
	// ForwardPacketWithMetadata forwards a packet with embedded metadata, interface name, and link type
	ForwardPacketWithMetadata(packet gopacket.Packet, metadata *data.PacketMetadata, interfaceName string, linkType layers.LinkType) error
}

// HunterForwardHandler handles SIP messages for hunter mode (lc hunt voip)
// It checks filters, extracts metadata, and forwards matched calls to processor
type HunterForwardHandler struct {
	tracker         *CallTracker
	forwarder       PacketForwarder
	bufferMgr       *BufferManager
	appFilter       ApplicationFilter // Optional: for proper filter matching (supports phone_number, sip_user, etc.)
	selectionPolicy *hunterSelectionPolicy
	orchestrator    *sipflow.Orchestrator
}

// NewHunterForwardHandler creates a handler for hunter packet forwarding
func NewHunterForwardHandler(tracker *CallTracker, forwarder PacketForwarder, bufferMgr *BufferManager) *HunterForwardHandler {
	h := &HunterForwardHandler{
		tracker:         tracker,
		forwarder:       forwarder,
		bufferMgr:       bufferMgr,
		selectionPolicy: newHunterSelectionPolicy(),
	}
	h.orchestrator = newHunterSIPOrchestrator(forwarder, h.selectionPolicy)
	return h
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
// This supports all filter types including phone_number, sip_user, sipuri, ip_address, etc.
func (h *HunterForwardHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
}

func (h *HunterForwardHandler) SetSelectionPolicy(policy callregistry.SelectionPolicy) {
	h.selectionPolicy.set(policy)
}

// Close drains accepted SIP forwarding and stops the handler-owned sink.
func (h *HunterForwardHandler) Close() { h.orchestrator.Close() }

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
	return h.handleSIPMessage(sipMessage, nil, callID, srcEndpoint, dstEndpoint, netFlow, transportFlow, capturedAt)
}

func (h *HunterForwardHandler) HandleParsedSIPMessage(sipMessage []byte, event sharedsip.Event, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow) bool {
	return h.handleSIPMessage(sipMessage, &event, event.CallID, srcEndpoint, dstEndpoint, netFlow, transportFlow, event.Timestamp)
}

func (h *HunterForwardHandler) handleSIPMessage(sipMessage []byte, event *sharedsip.Event, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow, capturedAt time.Time) bool {
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

	directMatch := h.appFilter != nil && h.matchesMessage(pkt, nil)
	analysis := h.orchestrator.Process(sipflow.Message{
		Payload: sipMessage, Event: event, ExpectedCallID: callID, Envelope: envelopeForHunterPacket(pkt),
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
	result, method := analysis.SIP, analysis.SIP.Method

	metadata := &CallMetadata{
		CallID:            callID,
		From:              result.FromUser,
		To:                result.ToUser,
		FromTag:           result.FromTag,
		ToTag:             result.ToTag,
		PAssertedIdentity: result.PAssertedIdentity,
		Method:            method,
		CSeqMethod:        result.CSeqMethod,
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

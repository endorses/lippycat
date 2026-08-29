//go:build hunter || all

package voip

import (
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
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
	selectionPolicy callregistry.SelectionPolicy
}

// NewHunterForwardHandler creates a handler for hunter packet forwarding
func NewHunterForwardHandler(tracker *CallTracker, forwarder PacketForwarder, bufferMgr *BufferManager) *HunterForwardHandler {
	return &HunterForwardHandler{
		tracker:         tracker,
		forwarder:       forwarder,
		bufferMgr:       bufferMgr,
		selectionPolicy: callregistry.StickySelectionPolicy{},
	}
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
// This supports all filter types including phone_number, sip_user, sipuri, ip_address, etc.
func (h *HunterForwardHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
}

func (h *HunterForwardHandler) SetSelectionPolicy(policy callregistry.SelectionPolicy) {
	if policy != nil {
		h.selectionPolicy = policy
	}
}

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
	if callID == "" {
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	event, err := sharedsip.Parse(sipMessage, sharedsip.OptionsForEndpoints(capturedAt, srcEndpoint, dstEndpoint))
	if err != nil || event.CallID != callID {
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}
	headers, method := event.Headers, event.Method

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

	metadata := &CallMetadata{
		CallID:            callID,
		From:              event.FromUser,
		To:                event.ToUser,
		FromTag:           event.FromTag,
		ToTag:             event.ToTag,
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            method,
		CSeqMethod:        event.CSeqMethod,
		ResponseCode:      uint32(event.ResponseCode),
		SDPBody:           string(event.SDP),
	}

	pbMetadata := &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId:            callID,
			FromUser:          metadata.From, // username only
			ToUser:            metadata.To,   // username only
			FromTag:           metadata.FromTag,
			ToTag:             metadata.ToTag,
			FromUri:           event.FromURI,
			ToUri:             event.ToURI,
			Method:            metadata.Method,
			CseqMethod:        metadata.CSeqMethod,
			ResponseCode:      metadata.ResponseCode,
			PAssertedIdentity: metadata.PAssertedIdentity,
		},
	}

	previouslySelected := h.bufferMgr != nil && h.bufferMgr.IsCallMatched(callID)
	directMatch := h.matchesMessage(pkt, headers)
	selected := h.selectionPolicy.Select(callregistry.SelectionInput{
		FilterConfigured:   true,
		DirectMatch:        directMatch,
		PreviouslySelected: previouslySelected,
	})

	// Call termination (BYE/CANCEL): only forward if selected by policy.
	if method == "BYE" || method == "CANCEL" {
		if selected {
			if err := h.forwarder.ForwardPacketWithMetadata(pkt.Packet, pbMetadata, "", layers.LinkTypeEthernet); err != nil {
				logger.Error("Failed to forward TCP call termination packet",
					"call_id", SanitizeCallIDForLogging(callID),
					"method", method,
					"error", err)
			} else {
				logger.Info("Forwarded TCP call termination packet",
					"call_id", SanitizeCallIDForLogging(callID),
					"method", method)
			}
			discardTCPBufferedPackets(netFlow, transportFlow)
			return true
		}
		// Call not tracked, discard
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	// Check if THIS message matches the filter (using the synthesized packet's SIP).
	if !selected {
		discardTCPBufferedPackets(netFlow, transportFlow)
		logger.Debug("TCP SIP message filtered out",
			"call_id", SanitizeCallIDForLogging(callID),
			"method", method,
			"flow", srcEndpoint+"->"+dstEndpoint)
		return false
	}

	logger.Info("TCP SIP message matched filter, forwarding to processor",
		"call_id", SanitizeCallIDForLogging(callID),
		"from", metadata.From,
		"to", metadata.To,
		"method", method)

	// Forward this message's synthesized packet.
	if err := h.forwarder.ForwardPacketWithMetadata(pkt.Packet, pbMetadata, "", layers.LinkTypeEthernet); err != nil {
		logger.Error("Failed to forward TCP SIP packet",
			"call_id", SanitizeCallIDForLogging(callID),
			"error", err)
	}

	// Extract RTP ports from SDP for future RTP packet association
	if len(event.SDP) > 0 {
		h.tracker.ExtractPortFromSDP(string(event.SDP), callID)
	}

	// Register the call as matched so its RTP media and later in-dialog messages
	// (BYE/CANCEL) are forwarded too.
	if h.bufferMgr != nil {
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

//go:build hunter || all

package voip

import (
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
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
	forwarder PacketForwarder
	bufferMgr *BufferManager
	appFilter ApplicationFilter // Optional: for proper filter matching (supports phone_number, sip_user, etc.)
}

// NewHunterForwardHandler creates a handler for hunter packet forwarding
func NewHunterForwardHandler(forwarder PacketForwarder, bufferMgr *BufferManager) *HunterForwardHandler {
	return &HunterForwardHandler{
		forwarder: forwarder,
		bufferMgr: bufferMgr,
	}
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
// This supports all filter types including phone_number, sip_user, sipuri, ip_address, etc.
func (h *HunterForwardHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
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
func (h *HunterForwardHandler) HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow gopacket.Flow) bool {
	if callID == "" {
		discardTCPBufferedPackets(netFlow)
		return false
	}

	// Parse SIP headers and method
	headers, body := parseSipHeaders(sipMessage)
	method := detectSipMethod(string(sipMessage))

	// Synthesize a packet carrying exactly this reassembled SIP message so both
	// matching and forwarding operate on THIS message rather than on the first
	// raw packet buffered for the whole flow.
	pkt, ok := buildSIPPacketInfo(sipMessage, srcEndpoint, dstEndpoint, netFlow, time.Now())
	if !ok {
		logger.Warn("TCP SIP: failed to synthesize packet for message, dropping",
			"call_id", SanitizeCallIDForLogging(callID),
			"flow", srcEndpoint+"->"+dstEndpoint)
		discardTCPBufferedPackets(netFlow)
		return false
	}

	metadata := &CallMetadata{
		CallID:            callID,
		From:              extractUserFromSIPURI(headers["from"]),
		To:                extractUserFromSIPURI(headers["to"]),
		FromTag:           extractTagFromHeader(headers["from"]),
		ToTag:             extractTagFromHeader(headers["to"]),
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            method,
		CSeqMethod:        extractCSeqMethod(headers["cseq"]),
		ResponseCode:      extractSipResponseCode(sipMessage),
		SDPBody:           body,
	}

	pbMetadata := &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId:            callID,
			FromUser:          metadata.From, // username only
			ToUser:            metadata.To,   // username only
			FromTag:           metadata.FromTag,
			ToTag:             metadata.ToTag,
			FromUri:           extractFullSIPURI(headers["from"]),
			ToUri:             extractFullSIPURI(headers["to"]),
			Method:            metadata.Method,
			CseqMethod:        metadata.CSeqMethod,
			ResponseCode:      metadata.ResponseCode,
			PAssertedIdentity: metadata.PAssertedIdentity,
		},
	}

	// Call termination (BYE/CANCEL): only forward if the call was already matched.
	if method == "BYE" || method == "CANCEL" {
		if h.bufferMgr != nil && h.bufferMgr.IsCallMatched(callID) {
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
			discardTCPBufferedPackets(netFlow)
			return true
		}
		// Call not tracked, discard
		discardTCPBufferedPackets(netFlow)
		return false
	}

	// Check if THIS message matches the filter (using the synthesized packet's SIP).
	if !h.matchesMessage(pkt, headers) {
		discardTCPBufferedPackets(netFlow)
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
	if body != "" {
		ExtractPortFromSdp(body, callID)
	}

	// Register the call as matched so its RTP media and later in-dialog messages
	// (BYE/CANCEL) are forwarded too. AddSIPPacket seeds the buffer metadata;
	// CheckFilterWithCallback (filter already satisfied) records it in the
	// persistent matchedCalls set.
	if h.bufferMgr != nil {
		h.bufferMgr.AddSIPPacket(callID, nil, metadata, "", layers.LinkTypeEthernet)
		h.bufferMgr.CheckFilterWithCallback(callID,
			func(m *CallMetadata) bool { return true }, // already matched
			nil, // already forwarded above
		)
	}

	discardTCPBufferedPackets(netFlow)
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

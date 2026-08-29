//go:build tap || all

package voip

import (
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket"
)

// TapTCPHandler handles SIP messages for tap mode (lc tap voip).
// It extracts SIP metadata and sends processed TCP packets to a channel
// for integration with LocalSource's batch processing.
type TapTCPHandler struct {
	// packetChan receives TCP packets with metadata for batch processing
	packetChan chan<- source.InjectedPacket
	// appFilter is optional for proper filter matching
	appFilter ApplicationFilter
	// callRegistry owns tap-local call state and RTP associations. Keeping this explicit avoids
	// writing TCP SDP into the legacy package-global tracker used by sniff/hunt.
	callRegistry interface {
		ProcessReassembledSIP(packet gopacket.Packet) *data.PacketMetadata
		CompleteCall(callID string)
	}
}

// SetCallRegistry routes complete reassembled TCP SIP through the tap's
// processor-owned call registry.
func (h *TapTCPHandler) SetCallRegistry(registry interface {
	ProcessReassembledSIP(packet gopacket.Packet) *data.PacketMetadata
	CompleteCall(callID string)
}) {
	h.callRegistry = registry
}

// NewTapTCPHandler creates a handler for tap mode TCP SIP processing.
// The packetChan receives TCP packets with metadata when SIP messages are matched.
func NewTapTCPHandler(packetChan chan<- source.InjectedPacket) *TapTCPHandler {
	return &TapTCPHandler{
		packetChan: packetChan,
	}
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
func (h *TapTCPHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
}

// HandleSIPMessage processes a complete SIP message for tap mode.
// srcEndpoint and dstEndpoint are in "IP:port" format (e.g., "192.168.1.1:5060").
// netFlow is used for TCP packet buffer lookup.
//
// Per-message semantics: the TCP reassembly loop (processSIPFromReader) invokes
// this method once for EACH complete SIP message reassembled from the stream.
// Each invocation is treated as an independent, matchable, forwardable unit:
//
//   - We synthesize a single packet carrying exactly THIS message's bytes (using
//     the connection's 5-tuple) and run the target filter against it, so matching
//     reflects the identity headers of the specific message (From/To/
//     P-Asserted-Identity/...), not the first buffered packet of the flow.
//   - We forward that one synthesized packet as this message's own X2 IRI.
//
// This is what lets every SIP message on a long-lived TCP connection (e.g. five
// MT SMS-DELIVER, or an MO leg whose target only appears in From/
// P-Asserted-Identity) be delivered — not just the first. Because each message
// is dispatched exactly once by the reassembler and forwarded as a single unit,
// there is no whole-flow "drain-and-forget" and no double-forwarding.
func (h *TapTCPHandler) HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow) bool {
	return h.HandleSIPMessageAt(sipMessage, callID, srcEndpoint, dstEndpoint, netFlow, transportFlow, time.Now())
}

func (h *TapTCPHandler) HandleSIPMessageAt(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow, capturedAt time.Time) bool {
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

	// Synthesize a packet carrying exactly this reassembled SIP message so that
	// both filter matching and forwarding operate on THIS message rather than on
	// the first raw packet buffered for the whole flow. Preserve the connection's
	// real 5-tuple (IPs from netFlow, ports from the endpoint strings) so the
	// downstream LI correlation (MatchPacketWithIDs) and delivery see correct
	// addressing.
	pkt, ok := buildSIPPacketInfo(sipMessage, srcEndpoint, dstEndpoint, netFlow, capturedAt)
	if !ok {
		logger.Warn("TCP SIP: failed to synthesize packet for message, dropping",
			"call_id", SanitizeCallIDForLogging(callID),
			"flow", srcEndpoint+"->"+dstEndpoint)
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	// Route complete messages through the registry when available. Its selection
	// policy admits later in-dialog messages for an already selected call even
	// when identity headers no longer match directly. The fallback is retained
	// for non-tap consumers that do not inject a registry.
	var registryMetadata *data.PacketMetadata
	accepted := h.matchesMessage(pkt, headers)
	if h.callRegistry != nil {
		registryMetadata = h.callRegistry.ProcessReassembledSIP(pkt.Packet)
		accepted = registryMetadata != nil && registryMetadata.Sip != nil
	}
	if !accepted {
		// Message doesn't match filter - release any per-flow buffered packets.
		discardTCPBufferedPackets(netFlow, transportFlow)
		logger.Debug("TCP SIP message filtered out (tap mode)",
			"call_id", SanitizeCallIDForLogging(callID),
			"method", method,
			"flow", srcEndpoint+"->"+dstEndpoint)
		return false
	}

	logger.Info("TCP SIP message matched filter (tap mode), forwarding",
		"call_id", SanitizeCallIDForLogging(callID),
		"from", headers["from"],
		"to", headers["to"],
		"method", method)

	// Create protobuf metadata for SIP. When a tap-local registry is wired, run
	// the complete reassembled message through its normal SIP selection/state
	// path so SDP-less dialogs and all identity/activity updates are retained.
	pbMetadata := &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId:            callID,
			FromUser:          event.FromUser,
			ToUser:            event.ToUser,
			FromTag:           event.FromTag,
			ToTag:             event.ToTag,
			FromUri:           event.FromURI,
			ToUri:             event.ToURI,
			Method:            method,
			CseqMethod:        event.CSeqMethod,
			ResponseCode:      uint32(event.ResponseCode),
			PAssertedIdentity: headers["p-asserted-identity"],
		},
	}
	if registryMetadata != nil {
		pbMetadata = registryMetadata
	}

	var afterProcess func()
	if h.callRegistry != nil && event.ResponseCode >= 200 && (event.CSeqMethod == "BYE" || event.CSeqMethod == "CANCEL") {
		afterProcess = func() { h.callRegistry.CompleteCall(callID) }
	}

	// Forward exactly one packet for this SIP message.
	select {
	case h.packetChan <- source.InjectedPacket{PacketInfo: pkt, Metadata: pbMetadata, AfterProcess: afterProcess}:
		// Sent successfully
	default:
		// The packet cannot reach processor output, so finish any deferred
		// lifecycle transition on this deterministic drop path.
		if afterProcess != nil {
			afterProcess()
		}
		logger.Warn("TCP packet channel full, dropping SIP message",
			"call_id", SanitizeCallIDForLogging(callID))
	}

	// The synthesized packet is self-contained; the per-flow raw buffer is no
	// longer needed to deliver this message. Release it so a long-lived,
	// multi-message connection does not accumulate buffered packets. Subsequent
	// messages on this connection are re-buffered as their packets arrive and
	// handled by their own HandleSIPMessage invocation.
	discardTCPBufferedPackets(netFlow, transportFlow)

	return true
}

// matchesMessage checks if a single reassembled SIP message matches any
// configured filter. It runs the ApplicationFilter against the synthesized
// per-message packet (whose application payload is exactly this SIP message),
// so matching reflects the identity headers of THIS message. Falls back to the
// legacy containsUserInHeaders() check when no ApplicationFilter is configured.
func (h *TapTCPHandler) matchesMessage(pkt capture.PacketInfo, headers map[string]string) bool {
	if h.appFilter != nil && pkt.Packet != nil {
		return h.appFilter.MatchPacket(pkt.Packet)
	}
	// Legacy fallback: use sipusers.IsSurveiled() via containsUserInHeaders()
	return containsUserInHeaders(headers)
}

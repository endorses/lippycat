package voip

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

// LocalFileHandler handles SIP messages for local capture mode (lc sniff voip)
// It writes matched calls to local PCAP files
type LocalFileHandler struct{}

// NewLocalFileHandler creates a handler for local file writing
func NewLocalFileHandler() *LocalFileHandler {
	return &LocalFileHandler{}
}

// HandleSIPMessage processes a complete SIP message for local file writing.
// srcEndpoint and dstEndpoint are in "IP:port" format (e.g., "192.168.1.1:5060").
// netFlow is used for TCP packet buffer lookup.
//
// Per-message semantics, matching the tap and hunter TCP handlers: the
// reassembler invokes this once for EACH complete SIP message, and we write one
// synthesized packet carrying exactly that message. The raw per-flow buffer is
// NOT written, because it is keyed by network flow (IP pair) and therefore holds
// every connection and every call between the two hosts — flushing it under one
// Call-ID wrote other calls' packets, and filtered-out traffic, into that call's
// PCAP, while a segment shared by two pipelined messages reached only the first.
//
// Matching is per message but the decision is remembered per call: once a call
// has matched, its later in-dialog messages are written without having to match
// on their own headers. Otherwise a target identified only by
// P-Asserted-Identity on the INVITE would have the rest of its dialog dropped.
func (h *LocalFileHandler) HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow gopacket.Flow) bool {
	logger.Debug("TCP HandleSIPMessage called",
		"call_id", SanitizeCallIDForLogging(callID),
		"message_len", len(sipMessage),
		"flow", srcEndpoint+"->"+dstEndpoint)

	if callID == "" {
		logger.Debug("Empty call-ID, skipping")
		discardTCPBufferedPackets(netFlow)
		return false
	}

	// Take the capture timestamp before releasing the raw buffer: those are the
	// segments that carried this message, so their time is the message's time.
	// Falling back to wall-clock would stamp an offline PCAP replay with today.
	ts := time.Now()
	if raw, ok := peekFirstTCPBufferedPacket(netFlow); ok && raw.Packet != nil {
		if bufTS := raw.Packet.Metadata().Timestamp; !bufTS.IsZero() {
			ts = bufTS
		}
	}

	// The buffer manager is where a call's match decision is remembered across
	// messages; startProcessor initializes it before any packet is dispatched.
	if globalBufferMgr == nil {
		logger.Debug("No VoIP buffer manager: TCP SIP matching falls back to per-message",
			"call_id", SanitizeCallIDForLogging(callID))
	}
	alreadyMatched := globalBufferMgr != nil && globalBufferMgr.IsCallMatched(callID)

	// Always run the per-message check: besides matching, it updates call state
	// and extracts RTP ports from any SDP body.
	matched := handleSipMessage(sipMessage, getCurrentLinkType())

	logger.Debug("TCP SIP filter check result",
		"call_id", SanitizeCallIDForLogging(callID),
		"matched", matched,
		"already_matched", alreadyMatched)

	if !matched && !alreadyMatched {
		// Release this message's packets rather than leaving them buffered,
		// where a later matching call would have written them into its PCAP.
		discardTCPBufferedPackets(netFlow)
		logger.Debug("Message didn't match filter, not writing")
		return false
	}

	// Synthesize a packet carrying exactly this SIP message, using the
	// connection's real 5-tuple, so the PCAP contains one complete message per
	// frame and nothing belonging to another call.
	pkt, ok := buildSIPPacketInfo(sipMessage, srcEndpoint, dstEndpoint, netFlow, ts)
	if !ok {
		logger.Warn("TCP SIP: failed to synthesize packet for message, dropping",
			"call_id", SanitizeCallIDForLogging(callID),
			"flow", srcEndpoint+"->"+dstEndpoint)
		discardTCPBufferedPackets(netFlow)
		return false
	}

	// The synthesized frame is Ethernet, so the call's writers must be too.
	call := GetOrCreateCall(callID, layers.LinkTypeEthernet)
	if call == nil {
		logger.Warn("Failed to create call for TCP SIP message", "call_id", SanitizeCallIDForLogging(callID))
		discardTCPBufferedPackets(netFlow)
		return false
	}

	// Remember the decision so the rest of this dialog is written even when an
	// individual message carries no matchable identity.
	if globalBufferMgr != nil && !alreadyMatched {
		headers, body := parseSipHeaders(sipMessage)
		globalBufferMgr.MarkCallMatched(callID, &CallMetadata{
			CallID:            callID,
			From:              headers["from"],
			To:                headers["to"],
			FromTag:           extractTagFromHeader(headers["from"]),
			ToTag:             extractTagFromHeader(headers["to"]),
			PAssertedIdentity: headers["p-asserted-identity"],
			Method:            detectSipMethod(string(sipMessage)),
			CSeqMethod:        extractCSeqMethod(headers["cseq"]),
			ResponseCode:      extractSipResponseCode(sipMessage),
			SDPBody:           body,
		}, "", layers.LinkTypeEthernet)
	}

	injectPacketToVirtualInterface(pkt)

	if viper.GetViper().GetBool("writeVoip") {
		WriteSIP(callID, pkt.Packet)
	}

	// The synthesized packet is self-contained; release the raw buffer so a
	// long-lived, multi-message connection does not accumulate packets.
	discardTCPBufferedPackets(netFlow)

	logger.Info("TCP SIP message matched filter and written to file",
		"call_id", SanitizeCallIDForLogging(callID),
		"flow", srcEndpoint+"->"+dstEndpoint)

	return true
}

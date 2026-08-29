package voip

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LocalFileHandler handles SIP messages for local capture mode (lc sniff voip)
// It writes matched calls to local PCAP files
type LocalFileHandler struct {
	tracker       *CallTracker
	buffer        *BufferManager
	packetOutputs *pipeline.PacketFanout
}

// NewLocalFileHandler creates a handler for local file writing
func NewLocalFileHandler(tracker *CallTracker) *LocalFileHandler {
	return &LocalFileHandler{tracker: tracker, buffer: globalBufferMgr}
}

func newLocalFileHandlerWithBuffer(tracker *CallTracker, buffer *BufferManager) *LocalFileHandler {
	return &LocalFileHandler{tracker: tracker, buffer: buffer}
}

func newLocalFileHandlerWithOutputs(tracker *CallTracker, buffer *BufferManager, outputs *pipeline.PacketFanout) *LocalFileHandler {
	return &LocalFileHandler{tracker: tracker, buffer: buffer, packetOutputs: outputs}
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
func (h *LocalFileHandler) HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow) bool {
	return h.HandleSIPMessageAt(sipMessage, callID, srcEndpoint, dstEndpoint, netFlow, transportFlow, time.Now())
}

func (h *LocalFileHandler) HandleSIPMessageAt(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow, capturedAt time.Time) bool {
	return h.handleSIPMessage(sipMessage, nil, callID, srcEndpoint, dstEndpoint, netFlow, transportFlow, capturedAt)
}

func (h *LocalFileHandler) HandleParsedSIPMessage(sipMessage []byte, event sharedsip.Event, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow) bool {
	return h.handleSIPMessage(sipMessage, &event, event.CallID, srcEndpoint, dstEndpoint, netFlow, transportFlow, event.Timestamp)
}

func (h *LocalFileHandler) handleSIPMessage(sipMessage []byte, event *sharedsip.Event, callID string, srcEndpoint, dstEndpoint string, netFlow, transportFlow gopacket.Flow, capturedAt time.Time) bool {
	logger.Debug("TCP HandleSIPMessage called",
		"call_id", SanitizeCallIDForLogging(callID),
		"message_len", len(sipMessage),
		"flow", srcEndpoint+"->"+dstEndpoint)

	if callID == "" {
		logger.Debug("Empty call-ID, skipping")
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	// Take the capture timestamp before releasing the raw buffer: those are the
	// segments that carried this message, so their time is the message's time.
	// Falling back to wall-clock would stamp an offline PCAP replay with today.
	ts := capturedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	if raw, ok := peekFirstTCPBufferedPacket(netFlow, transportFlow); ok && raw.Packet != nil {
		if bufTS := raw.Packet.Metadata().Timestamp; !bufTS.IsZero() {
			ts = bufTS
		}
	}

	// Synthesize a packet carrying exactly this SIP message, using the
	// connection's real 5-tuple, so the PCAP contains one complete message per
	// frame and nothing belonging to another call.
	pkt, ok := buildSIPPacketInfo(sipMessage, srcEndpoint, dstEndpoint, netFlow, ts)
	if !ok {
		logger.Warn("TCP SIP: failed to synthesize packet for message, dropping",
			"call_id", SanitizeCallIDForLogging(callID),
			"flow", srcEndpoint+"->"+dstEndpoint)
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	envelope := &pipeline.PacketEnvelope{
		Data: pkt.Packet.Data(), LinkType: layers.LinkTypeEthernet, CaptureTime: ts,
		CaptureLength: len(pkt.Packet.Data()), OriginalLength: len(pkt.Packet.Data()),
	}
	flow := newSniffSIPFlowWithOutputs(h.tracker, true, true, h.packetOutputs, h.buffer)
	defer flow.Close()
	analysis := flow.Analyze(sipflow.Message{
		Payload: sipMessage, Event: event, ExpectedCallID: callID, Envelope: envelope,
		ParseOptions:     sharedsip.OptionsForEndpoints(ts, srcEndpoint, dstEndpoint),
		FilterConfigured: true,
		Match:            func(event sharedsip.Event) bool { return containsUserInHeaders(event.Headers) },
		Validate:         func(event sharedsip.Event) error { return ValidateCallIDForSecurity(event.CallID) },
	})
	if analysis.Stage.Outcome != pipeline.OutcomeAccepted {
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	analysis.Attachment = pkt
	delivery := flow.Dispatch(analysis)
	if delivery.Sinks[sniffSIPSinkName].Outcome != pipeline.OutcomeAccepted {
		discardTCPBufferedPackets(netFlow, transportFlow)
		return false
	}

	// The synthesized packet is self-contained; release the raw buffer so a
	// long-lived, multi-message connection does not accumulate packets.
	discardTCPBufferedPackets(netFlow, transportFlow)

	logger.Info("TCP SIP message matched filter and written to file",
		"call_id", SanitizeCallIDForLogging(callID),
		"flow", srcEndpoint+"->"+dstEndpoint)

	return true
}

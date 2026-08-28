//go:build cli || all

package voip

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// tcpSIPHarness drives LocalFileHandler (the lc sniff voip TCP path) against a
// temporary per-call PCAP. Packets are buffered per network flow exactly as
// handleTcpPackets does, then a complete SIP message is dispatched the way the
// reassembler dispatches it.
type tcpSIPHarness struct {
	t       *testing.T
	tracker *CallTracker
	handler *LocalFileHandler
	tmpDir  string
}

func newTCPSIPHarness(t *testing.T) *tcpSIPHarness {
	t.Helper()

	tmpDir := t.TempDir()

	// viper.Reset() drops the registered defaults too, so re-register them:
	// without them MaxFilenameLength is 0 and sanitize() collapses every
	// Call-ID to one filename, putting all calls in a single PCAP.
	viper.Reset()
	initConfigDefaults()
	ResetConfigOnce()
	t.Cleanup(ResetConfigOnce)

	viper.Set("writeVoip", true)
	viper.Set("voip.output_file", filepath.Join(tmpDir, "capture.pcap"))
	cfg := *GetConfig()
	cfg.WriteVoIP = true
	cfg.OutputFile = filepath.Join(tmpDir, "capture.pcap")
	SetConfig(&cfg)
	t.Cleanup(func() { viper.Reset() })

	setCurrentLinkType(layers.LinkTypeEthernet)

	// The call tracker is a process global shared with every other test in the
	// package; leftover calls can evict this test's call between queueing a
	// write and the writer draining it, silently losing the packet.
	tracker := TestCallTracker(t)
	resetCallTracker(tracker)
	t.Cleanup(func() { resetCallTracker(tracker) })

	// tcpPacketBuffers is a process global keyed by network and transport flow; a previous
	// test's unflushed packets would otherwise land in this test's PCAP.
	resetTCPBuffers()
	t.Cleanup(resetTCPBuffers)

	// startProcessor always initializes this before any SIP message can be
	// dispatched; it is where a matched call is remembered across messages.
	prevMgr := globalBufferMgr
	globalBufferMgr = NewBufferManager(60*time.Second, 1000)
	t.Cleanup(func() {
		globalBufferMgr.Close()
		globalBufferMgr = prevMgr
	})

	return &tcpSIPHarness{t: t, tracker: tracker, handler: NewLocalFileHandler(tracker), tmpDir: tmpDir}
}

// resetCallTracker drops every tracked call and rearms the async writer pool,
// so a test's writes cannot be affected by what ran before it.
func resetCallTracker(tracker *CallTracker) {
	tracker.shuttingDown.Store(0)

	tracker.mu.Lock()
	for id, call := range tracker.callMap {
		_ = call.Close()
		delete(tracker.callMap, id)
	}
	tracker.mu.Unlock()

	asyncWriterOnce = sync.Once{}
	globalAsyncWriter = nil
}

func resetTCPBuffers() {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()
	tcpPacketBuffers = make(map[tcpBufferKey]*TCPPacketBuffer)
}

func (h *tcpSIPHarness) sipPath(callID string) string {
	return filepath.Join(h.tmpDir, fmt.Sprintf("capture_sip_%s.pcap", sanitize(callID)))
}

// buffer records one raw TCP packet for its network flow, mirroring
// handleTcpPackets. Returns the flow the reassembler would report.
func (h *tcpSIPHarness) buffer(payload string, srcIP, dstIP string) (gopacket.Flow, gopacket.Flow) {
	h.t.Helper()
	return h.bufferWithPorts(payload, srcIP, dstIP, 5060, 5060)
}

func (h *tcpSIPHarness) bufferWithPorts(payload string, srcIP, dstIP string, srcPort, dstPort layers.TCPPort) (gopacket.Flow, gopacket.Flow) {
	h.t.Helper()

	pkt := createTCPSIPPacketWithPorts(h.t, payload, srcIP, dstIP, srcPort, dstPort)
	flow := pkt.NetworkLayer().NetworkFlow()
	transportFlow := pkt.TransportLayer().TransportFlow()
	BufferTCPPacket(flow, transportFlow, capture.PacketInfo{
		Packet:   pkt,
		LinkType: layers.LinkTypeEthernet,
	})
	return flow, transportFlow
}

// dispatch delivers a fully reassembled SIP message, as processSipMessage does.
func (h *tcpSIPHarness) dispatch(msg, callID string, flow, transportFlow gopacket.Flow) bool {
	h.t.Helper()
	return h.handler.HandleSIPMessage([]byte(msg), callID, "192.168.1.100:5060", "192.168.1.101:5060", flow, transportFlow)
}

func (h *tcpSIPHarness) dispatchWithEndpoints(msg, callID, srcEndpoint, dstEndpoint string, flow, transportFlow gopacket.Flow) bool {
	h.t.Helper()
	return h.handler.HandleSIPMessage([]byte(msg), callID, srcEndpoint, dstEndpoint, flow, transportFlow)
}

func createTCPSIPPacket(t *testing.T, payload, srcIP, dstIP string) gopacket.Packet {
	t.Helper()
	return createTCPSIPPacketWithPorts(t, payload, srcIP, dstIP, 5060, 5060)
}

func createTCPSIPPacketWithPorts(t *testing.T, payload, srcIP, dstIP string, srcPort, dstPort layers.TCPPort) gopacket.Packet {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       []byte{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    parseTestIP(t, srcIP),
		DstIP:    parseTestIP(t, dstIP),
	}
	tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: 1000, Window: 8192, PSH: true, ACK: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload([]byte(payload))))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	md := pkt.Metadata()
	md.CaptureLength = len(pkt.Data())
	md.Length = len(pkt.Data())
	md.Timestamp = time.Unix(1700000000, 0)
	return pkt
}

func parseTestIP(t *testing.T, s string) []byte {
	t.Helper()
	var a, b, c, d byte
	_, err := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)
	require.NoError(t, err)
	return []byte{a, b, c, d}
}

func tcpSIPMsg(startLine, callID, from, pai string) string {
	msg := startLine + "\r\n" +
		"Via: SIP/2.0/TCP 192.168.1.100:5060;branch=z9hG4bK1\r\n" +
		"From: " + from + ";tag=1\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n"
	if pai != "" {
		msg += "P-Asserted-Identity: " + pai + "\r\n"
	}
	return msg + "Content-Length: 0\r\n\r\n"
}

// A target identified only by P-Asserted-Identity matches the INVITE, which
// carries PAI, but not the in-dialog messages that do not. The local TCP path
// re-runs the filter per message with no memory of the call having matched, so
// the rest of the dialog is never written.
//
// This is the TCP analogue of the UDP SDP-gating bug: once a call is matched,
// every message of that dialog belongs in its PCAP.
func TestTCPLocalPath_WritesInDialogMessagesOfMatchedCall(t *testing.T) {
	h := newTCPSIPHarness(t)
	callID := "tcp-pai@example.com"

	resetVoipWriteState(h.tracker, callID)
	t.Cleanup(func() { resetVoipWriteState(h.tracker, callID) })

	// Carrier-style CLIR call: the real identity is only in P-Asserted-Identity,
	// the From header is anonymized.
	sipusers.ClearAll()
	sipusers.AddSipUser("alice", &sipusers.SipUser{})
	t.Cleanup(sipusers.ClearAll)

	anon := "<sip:anonymous@anonymous.invalid>"
	pai := "<sip:alice@example.com>"

	invite := tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", callID, anon, pai)
	flow, transportFlow := h.buffer(invite, "192.168.1.100", "192.168.1.101")
	require.True(t, h.dispatch(invite, callID, flow, transportFlow), "INVITE carrying PAI should match")

	bye := tcpSIPMsg("BYE sip:bob@example.com SIP/2.0", callID, anon, "")
	flow, transportFlow = h.buffer(bye, "192.168.1.100", "192.168.1.101")
	h.dispatch(bye, callID, flow, transportFlow)

	CloseWriters()
	require.Equal(t, []string{
		"INVITE sip:bob@example.com SIP/2.0",
		"BYE sip:bob@example.com SIP/2.0",
	}, sipStartLinesFromPcap(t, h.sipPath(callID)),
		"every message of a matched dialog should be written, not just the ones that independently match")
}

// The TCP buffer is keyed by network flow (IP pair), so one buffer is shared by
// every call and every connection between two hosts. Flushing on a match writes
// whatever else happens to be buffered into that call's PCAP.
func TestTCPLocalPath_DoesNotWriteOtherCallsPacketsIntoMatchedCall(t *testing.T) {
	h := newTCPSIPHarness(t)
	callA := "tcp-call-a@example.com"
	callB := "tcp-call-b@example.com"

	for _, id := range []string{callA, callB} {
		resetVoipWriteState(h.tracker, id)
		t.Cleanup(func() { resetVoipWriteState(h.tracker, id) })
	}
	sipusers.ClearAll() // promiscuous: every message matches

	alice := "<sip:alice@example.com>"

	// Two calls multiplexed over the same host pair, as on a SIP trunk.
	inviteB := tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", callB, alice, "")
	h.buffer(inviteB, "192.168.1.100", "192.168.1.101")

	inviteA := tcpSIPMsg("INVITE sip:carol@example.com SIP/2.0", callA, alice, "")
	flow, transportFlow := h.buffer(inviteA, "192.168.1.100", "192.168.1.101")

	// Call A's message completes first and flushes the shared flow buffer.
	require.True(t, h.dispatch(inviteA, callA, flow, transportFlow))

	CloseWriters()
	require.Equal(t, []string{
		"INVITE sip:carol@example.com SIP/2.0",
	}, sipStartLinesFromPcap(t, h.sipPath(callA)),
		"call A's PCAP should not contain call B's packets")
}

func TestTCPBuffersAreIsolatedPerConnection(t *testing.T) {
	h := newTCPSIPHarness(t)
	callA := "tcp-conn-a@example.com"
	callB := "tcp-conn-b@example.com"

	for _, id := range []string{callA, callB} {
		resetVoipWriteState(h.tracker, id)
		t.Cleanup(func() { resetVoipWriteState(h.tracker, id) })
	}
	sipusers.ClearAll() // promiscuous: every message matches

	alice := "<sip:alice@example.com>"
	inviteA := tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", callA, alice, "")
	inviteB := tcpSIPMsg("INVITE sip:carol@example.com SIP/2.0", callB, alice, "")

	netFlowA, transportFlowA := h.bufferWithPorts(inviteA, "192.168.1.100", "192.168.1.101", 5060, 5060)
	netFlowB, transportFlowB := h.bufferWithPorts(inviteB, "192.168.1.100", "192.168.1.101", 5070, 5060)

	require.True(t, h.dispatchWithEndpoints(inviteA, callA, "192.168.1.100:5060", "192.168.1.101:5060", netFlowA, transportFlowA))

	tcpPacketBuffersMu.RLock()
	_, aExists := tcpPacketBuffers[newTCPBufferKey(netFlowA, transportFlowA)]
	_, bExists := tcpPacketBuffers[newTCPBufferKey(netFlowB, transportFlowB)]
	tcpPacketBuffersMu.RUnlock()

	require.False(t, aExists, "dispatching connection A should release only connection A's buffer")
	require.True(t, bExists, "connection B's buffer must survive connection A cleanup")

	require.True(t, h.dispatchWithEndpoints(inviteB, callB, "192.168.1.100:5070", "192.168.1.101:5060", netFlowB, transportFlowB))

	CloseWriters()
	require.Equal(t, []string{"INVITE sip:bob@example.com SIP/2.0"}, sipStartLinesFromPcap(t, h.sipPath(callA)))
	require.Equal(t, []string{"INVITE sip:carol@example.com SIP/2.0"}, sipStartLinesFromPcap(t, h.sipPath(callB)))
}

// A message that does not match the filter leaves its packets in the shared
// per-flow buffer (the local handler returns without discarding), so they are
// written into whichever call matches next.
func TestTCPLocalPath_DoesNotWriteFilteredOutMessageIntoNextMatchedCall(t *testing.T) {
	h := newTCPSIPHarness(t)
	callID := "tcp-leak@example.com"

	resetVoipWriteState(h.tracker, callID)
	t.Cleanup(func() { resetVoipWriteState(h.tracker, callID) })

	sipusers.ClearAll()
	sipusers.AddSipUser("alice", &sipusers.SipUser{})
	t.Cleanup(sipusers.ClearAll)

	// An unrelated subscriber's traffic on the same host pair: filtered out.
	other := tcpSIPMsg("REGISTER sip:example.com SIP/2.0", "other@example.com", "<sip:mallory@example.com>", "")
	flow, transportFlow := h.buffer(other, "192.168.1.100", "192.168.1.101")
	require.False(t, h.dispatch(other, "other@example.com", flow, transportFlow), "unrelated REGISTER should not match")

	invite := tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", callID, "<sip:alice@example.com>", "")
	flow, transportFlow = h.buffer(invite, "192.168.1.100", "192.168.1.101")
	require.True(t, h.dispatch(invite, callID, flow, transportFlow))

	CloseWriters()
	require.Equal(t, []string{
		"INVITE sip:bob@example.com SIP/2.0",
	}, sipStartLinesFromPcap(t, h.sipPath(callID)),
		"a filtered-out message must not be written into an unrelated matched call")
}

// One TCP segment can carry the tail of one SIP message and the head of the
// next (pipelining on a persistent connection). Each message must reach its own
// call's PCAP; the shared segment must not be consumed by whichever message
// completes first.
func TestTCPLocalPath_SharedSegmentReachesBothCalls(t *testing.T) {
	h := newTCPSIPHarness(t)
	callA := "tcp-seg-a@example.com"
	callB := "tcp-seg-b@example.com"

	sipusers.ClearAll() // promiscuous: every message matches

	alice := "<sip:alice@example.com>"
	msgA := tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", callA, alice, "")
	msgB := tcpSIPMsg("INVITE sip:carol@example.com SIP/2.0", callB, alice, "")

	// Both messages arrive coalesced in a single segment.
	flow, transportFlow := h.buffer(msgA+msgB, "192.168.1.100", "192.168.1.101")

	require.True(t, h.dispatch(msgA, callA, flow, transportFlow))
	require.True(t, h.dispatch(msgB, callB, flow, transportFlow))

	CloseWriters()
	require.Equal(t, []string{"INVITE sip:bob@example.com SIP/2.0"},
		sipStartLinesFromPcap(t, h.sipPath(callA)), "call A should have its own message")
	require.Equal(t, []string{"INVITE sip:carol@example.com SIP/2.0"},
		sipStartLinesFromPcap(t, h.sipPath(callB)), "call B should have its own message")
}

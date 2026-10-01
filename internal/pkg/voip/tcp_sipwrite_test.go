//go:build cli || all

package voip

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

type inspectTCPAssembler func(gopacket.Flow, *layers.TCP, time.Time) error

func (f inspectTCPAssembler) AssembleTCP(flow gopacket.Flow, tcp *layers.TCP, at time.Time) error {
	return f(flow, tcp, at)
}

func TestTCPLocalCaptureDoesNotRetainTupleBuffer(t *testing.T) {
	resetTCPBuffers()
	t.Cleanup(resetTCPBuffers)
	packet := createTCPSIPPacket(t, tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", "bufferless", "<sip:alice@example.com>", ""), "192.0.2.1", "192.0.2.2")
	tcp := packet.TransportLayer().(*layers.TCP)
	called := false
	assembler := inspectTCPAssembler(func(flow gopacket.Flow, segment *layers.TCP, at time.Time) error {
		called = true
		tcpPacketBuffersMu.RLock()
		defer tcpPacketBuffersMu.RUnlock()
		require.Empty(t, tcpPacketBuffers, "raw buffering must be absent before asynchronous stream processing")
		require.Equal(t, packet.NetworkLayer().NetworkFlow(), flow)
		require.Equal(t, tcp, segment)
		require.Equal(t, packet.Metadata().Timestamp, at)
		return nil
	})
	handleTcpPackets(capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet}, tcp, assembler)
	require.True(t, called)
}

func TestTCPLocalPath_CaptureAndLegacyTimestampFallback(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprintf("legacy=%t", legacy), func(t *testing.T) {
			h := newTCPSIPHarness(t)
			const callID = "tcp-bufferless-timestamp@example.com"
			resetVoipWriteState(h.tracker, callID)
			t.Cleanup(func() { resetVoipWriteState(h.tracker, callID) })
			sipusers.ClearAll()
			t.Cleanup(sipusers.ClearAll)
			message := tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", callID, "<sip:alice@example.com>", "")
			packet := createTCPSIPPacket(t, message, "192.168.1.100", "192.168.1.101")
			packet.Metadata().Timestamp = time.Unix(1711111111, 123000000)
			info := capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet}
			if legacy {
				flow, ports := packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow()
				BufferTCPPacket(flow, ports, info)
				require.True(t, h.dispatch(message, callID, flow, ports))
			} else {
				factory := NewSipStreamFactory(t.Context(), h.handler).(*sipStreamFactory)
				assembler := capture.NewTCPAssembler(factory)
				t.Cleanup(func() { assembler.FlushAll(); require.NoError(t, factory.Shutdown()) })
				handleTcpPackets(info, packet.TransportLayer().(*layers.TCP), assembler)
				assembler.FlushAll()
				require.Eventually(t, func() bool { return factory.GetActiveGoroutines() == 0 }, time.Second, time.Millisecond)
			}
			h.tracker.closeAsyncWriter()
			require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callID))
			file, err := os.Open(h.sipPath(callID))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, file.Close()) })
			reader, err := pcapgo.NewReader(file)
			require.NoError(t, err)
			data, ci, err := reader.ReadPacketData()
			require.NoError(t, err)
			require.True(t, ci.Timestamp.Equal(packet.Metadata().Timestamp), "timestamp: %s", ci.Timestamp)
			written := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
			require.Equal(t, message, string(written.TransportLayer().(*layers.TCP).Payload))
			_, _, err = reader.ReadPacketData()
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestTCPLocalPath_ResponseUsesItsOwnCaptureTimestamp(t *testing.T) {
	h := newTCPSIPHarness(t)
	const callID = "tcp-response-timestamp@example.com"
	resetVoipWriteState(h.tracker, callID)
	t.Cleanup(func() { resetVoipWriteState(h.tracker, callID) })
	sipusers.ClearAll()
	t.Cleanup(sipusers.ClearAll)

	from := "<sip:alice@example.com>"
	invite := tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", callID, from, "")
	flow, ports := h.bufferWithPorts(invite, "192.0.2.10", "198.51.100.20", 9202, 63781)
	require.True(t, h.handler.HandleSIPMessageAt([]byte(invite), callID, "192.0.2.10:9202", "198.51.100.20:63781", flow, ports, time.Unix(100, 0)))

	// A buffered packet from the first half precedes the complete response.
	// Buffer lookup is connection-wide, so using its first timestamp here would
	// incorrectly stamp the response with that other packet's capture time.
	h.bufferWithPorts(invite, "192.0.2.10", "198.51.100.20", 9202, 63781)
	response := tcpSIPMsg("SIP/2.0 200 OK", callID, from, "")
	responseAt := time.Unix(1700000020, 0)
	require.True(t, h.handler.HandleSIPMessageAt([]byte(response), callID, "198.51.100.20:63781", "192.0.2.10:9202", flow.Reverse(), ports.Reverse(), responseAt))

	h.tracker.closeAsyncWriter()
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callID))
	file, err := os.Open(h.sipPath(callID))
	require.NoError(t, err)
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)
	found := false
	for {
		data, info, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if strings.HasPrefix(string(tcp.Payload), "SIP/2.0 200 OK\r\n") {
			found = true
			require.True(t, info.Timestamp.Equal(responseAt), "response timestamp = %s, want %s", info.Timestamp, responseAt)
		}
	}
	require.True(t, found, "response must be present in the per-call SIP PCAP")
}

// tcpSIPHarness drives LocalFileHandler (the lc sniff voip TCP path) against a
// temporary per-call PCAP. Its explicit buffer helpers exercise the legacy
// timestamp fallback; production capture uses per-message reassembly metadata.
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
	output := NewSessionOutputManager(&cfg)
	tracker.replaceOutputForTest(output)
	t.Cleanup(func() { require.NoError(t, output.Shutdown()) })
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

// resetCallTracker drops every tracked call and rearms its async writer pool,
// so a test's writes cannot be affected by what ran before it.
func resetCallTracker(tracker *CallTracker) {
	tracker.shuttingDown.Store(0)

	tracker.mu.Lock()
	calls := make([]*CallInfo, 0, len(tracker.callMap))
	for id := range tracker.callMap {
		calls = append(calls, tracker.detachCallLocked(id))
	}
	tracker.mu.Unlock()
	for _, call := range calls {
		if call != nil {
			_ = tracker.notifyCallEnded(call)
		}
	}

	tracker.closeAsyncWriter()
}

func resetTCPBuffers() {
	tcpPacketBuffersMu.Lock()
	defer tcpPacketBuffersMu.Unlock()
	tcpPacketBuffers = make(map[tcpBufferKey]*TCPPacketBuffer)
}

func (h *tcpSIPHarness) sipPath(callID string) string {
	return filepath.Join(h.tmpDir, fmt.Sprintf("capture_sip_%s.pcap", sanitize(callID)))
}

// buffer records a legacy raw TCP packet for its network flow and returns the
// flow the reassembler would report.
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

	h.tracker.closeAsyncWriter()
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callID))
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

	h.tracker.closeAsyncWriter()
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callA))
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

	h.tracker.closeAsyncWriter()
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callA))
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callB))
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

	h.tracker.closeAsyncWriter()
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callID))
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

	h.tracker.closeAsyncWriter()
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callA))
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callB))
	require.Equal(t, []string{"INVITE sip:bob@example.com SIP/2.0"},
		sipStartLinesFromPcap(t, h.sipPath(callA)), "call A should have its own message")
	require.Equal(t, []string{"INVITE sip:carol@example.com SIP/2.0"},
		sipStartLinesFromPcap(t, h.sipPath(callB)), "call B should have its own message")
}

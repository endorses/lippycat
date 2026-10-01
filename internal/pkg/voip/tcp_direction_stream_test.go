//go:build tap || all

package voip

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/reassembly"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type directionMessage struct {
	callID string
	src    string
	dst    string
	flow   gopacket.Flow
	ports  gopacket.Flow
	stamp  time.Time
}

type directionMessageHandler struct {
	mu       sync.Mutex
	messages []directionMessage
}

func (h *directionMessageHandler) HandleSIPMessage(_ []byte, callID, src, dst string, flow, ports gopacket.Flow) bool {
	return h.HandleSIPMessageAt(nil, callID, src, dst, flow, ports, time.Time{})
}

func (h *directionMessageHandler) HandleSIPMessageAt(_ []byte, callID, src, dst string, flow, ports gopacket.Flow, capturedAt time.Time) bool {
	h.mu.Lock()
	h.messages = append(h.messages, directionMessage{callID: callID, src: src, dst: dst, flow: flow, ports: ports, stamp: capturedAt})
	h.mu.Unlock()
	return true
}

func (h *directionMessageHandler) find(callID string) (directionMessage, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, message := range h.messages {
		if message.callID == callID {
			return message, true
		}
	}
	return directionMessage{}, false
}

func sipDirectionMessage(start, callID string) []byte {
	return []byte(start + "\r\nCall-ID: " + callID + "\r\nContent-Length: 0\r\n\r\n")
}

func TestTCPDirectionPartialRequestDoesNotBlockResponse(t *testing.T) {
	handler := &directionMessageHandler{}
	stream := newLiveStream(t, handler, 60421, 5060)
	forward := sipDirectionMessage("INVITE sip:bob@example.test SIP/2.0", "forward-partial")
	response := sipDirectionMessage("SIP/2.0 100 Trying", "reverse-complete")

	stream.ReassembledSG(&fakeScatterGather{data: forward[:len(forward)-2], dir: reassembly.TCPDirClientToServer}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: response, dir: reassembly.TCPDirServerToClient}, nil)
	waitFor(t, func() bool { _, ok := handler.find("reverse-complete"); return ok }, "reverse response while forward request is incomplete")
	if _, ok := handler.find("forward-partial"); ok {
		t.Fatal("incomplete forward request dispatched")
	}
	stream.ReassembledSG(&fakeScatterGather{data: forward[len(forward)-2:], dir: reassembly.TCPDirClientToServer}, nil)
	waitFor(t, func() bool { _, ok := handler.find("forward-partial"); return ok }, "completed forward request")

	got, _ := handler.find("reverse-complete")
	if got.src != "10.0.0.2:5060" || got.dst != "10.0.0.1:60421" {
		t.Fatalf("reverse endpoints = %s -> %s", got.src, got.dst)
	}
	if got.flow != stream.netFlow.Reverse() || got.ports != stream.transportFlow.Reverse() {
		t.Fatal("reverse message received forward network or transport flow")
	}
	stream.ReassemblyComplete(nil)
}

func TestTCPDirectionCaptureTimestampsStayInTheirHalf(t *testing.T) {
	handler := &directionMessageHandler{}
	stream := newLiveStream(t, handler, 60421, 5060)
	forwardTime := time.Unix(100, 0)
	reverseTime := time.Unix(200, 0)
	start := false
	stream.Accept(&layers.TCP{}, gopacket.CaptureInfo{Timestamp: forwardTime}, reassembly.TCPDirClientToServer, 0, &start, nil)
	stream.Accept(&layers.TCP{}, gopacket.CaptureInfo{Timestamp: reverseTime}, reassembly.TCPDirServerToClient, 0, &start, nil)
	stream.ReassembledSG(&fakeScatterGather{data: sipDirectionMessage("INVITE sip:bob@example.test SIP/2.0", "timestamp-forward"), dir: reassembly.TCPDirClientToServer}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: sipDirectionMessage("SIP/2.0 200 OK", "timestamp-reverse"), dir: reassembly.TCPDirServerToClient}, nil)
	waitFor(t, func() bool { _, ok := handler.find("timestamp-forward"); return ok }, "forward timestamp message")
	waitFor(t, func() bool { _, ok := handler.find("timestamp-reverse"); return ok }, "reverse timestamp message")
	forward, _ := handler.find("timestamp-forward")
	reverse, _ := handler.find("timestamp-reverse")
	if !forward.stamp.Equal(forwardTime) || !reverse.stamp.Equal(reverseTime) {
		t.Fatalf("capture timestamps crossed directions: forward=%s reverse=%s", forward.stamp, reverse.stamp)
	}
	stream.ReassemblyComplete(nil)
}

func TestTCPDirectionAssemblerReverseFirst(t *testing.T) {
	handler := &directionMessageHandler{}
	factory := NewSipStreamFactory(t.Context(), handler).(*sipStreamFactory)
	t.Cleanup(factory.Close)
	assembler := capture.NewTCPAssemblerWithLimits(factory, 3, 64)
	t.Cleanup(func() { assembler.FlushAll() })

	feed := func(message []byte, srcIP, dstIP string, srcPort, dstPort layers.TCPPort, seq uint32) {
		t.Helper()
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: net.ParseIP(srcIP).To4(), DstIP: net.ParseIP(dstIP).To4(),
		}
		tcp := &layers.TCP{SrcPort: srcPort, DstPort: dstPort, Seq: seq, ACK: true, PSH: true, Window: 8192}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(message)); err != nil {
			t.Fatal(err)
		}
		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
		assembler.Assemble(packet.NetworkLayer().NetworkFlow(), packet.Layer(layers.LayerTypeTCP).(*layers.TCP), time.Unix(300, 0))
	}

	// The first observed tuple is the responder. The assembler assigns that
	// tuple c2s, so SIP request/response roles cannot determine TCP direction.
	feed(sipDirectionMessage("SIP/2.0 183 Session Progress", "reverse-first-response"), "10.0.0.2", "10.0.0.1", 5060, 60421, 1000)
	feed(sipDirectionMessage("ACK sip:bob@example.test SIP/2.0", "reverse-first-request"), "10.0.0.1", "10.0.0.2", 60421, 5060, 2000)
	waitFor(t, func() bool { _, ok := handler.find("reverse-first-response"); return ok }, "first-observed response")
	waitFor(t, func() bool { _, ok := handler.find("reverse-first-request"); return ok }, "subsequent request on opposite half")
	response, _ := handler.find("reverse-first-response")
	request, _ := handler.find("reverse-first-request")
	if response.src != "10.0.0.2:5060" || response.dst != "10.0.0.1:60421" {
		t.Fatalf("response endpoints = %s -> %s", response.src, response.dst)
	}
	if request.src != "10.0.0.1:60421" || request.dst != "10.0.0.2:5060" {
		t.Fatalf("request endpoints = %s -> %s", request.src, request.dst)
	}
}

func TestTCPDirectionGapStaysInItsHalf(t *testing.T) {
	handler := &directionMessageHandler{}
	stream := newLiveStream(t, handler, 60421, 5060)
	partial := []byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: damaged\r\nContent-Length: 10\r\n\r\nx")
	stream.ReassembledSG(&fakeScatterGather{data: partial, dir: reassembly.TCPDirClientToServer}, nil)
	stream.ReassembledSG(&fakeScatterGather{skip: 17, dir: reassembly.TCPDirClientToServer}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: sipDirectionMessage("SIP/2.0 183 Session Progress", "reverse-unaffected"), dir: reassembly.TCPDirServerToClient}, nil)
	waitFor(t, func() bool { _, ok := handler.find("reverse-unaffected"); return ok }, "reverse response after forward gap")
	if stream.reverse.pendingGap.reason != streamGapNone {
		t.Fatalf("forward gap leaked to reverse half: %+v", stream.reverse.pendingGap)
	}
	stream.ReassembledSG(&fakeScatterGather{data: sipDirectionMessage("ACK sip:bob@example.test SIP/2.0", "forward-recovered"), dir: reassembly.TCPDirClientToServer}, nil)
	waitFor(t, func() bool { _, ok := handler.find("forward-recovered"); return ok }, "forward recovery after gap")
	stream.ReassemblyComplete(nil)
}

func TestTCPDirectionOverflowMarkerStaysInItsHalf(t *testing.T) {
	stream := &bufferedSIPStream{dataChan: make(chan streamChunk, 1)}
	stream.reverse = &bufferedSIPStream{root: stream, dataChan: make(chan streamChunk, 1)}
	stream.dataChan <- streamChunk{data: []byte("occupied")}
	stream.ReassembledSG(&fakeScatterGather{data: []byte("dropped"), dir: reassembly.TCPDirClientToServer}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: []byte("response"), dir: reassembly.TCPDirServerToClient}, nil)

	if stream.pendingGap.reason&streamGapQueueOverflow == 0 {
		t.Fatal("forward queue overflow marker was not retained")
	}
	reverse := <-stream.reverse.dataChan
	if reverse.gap.reason != streamGapNone || string(reverse.data) != "response" {
		t.Fatalf("reverse chunk inherited forward overflow: %+v", reverse)
	}
}

func TestTCPDirectionRearmKeepsConnectionSlotAndAcceptsCRLF(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxStreams = 1
	handler := &directionMessageHandler{}
	factory := NewSipStreamFactoryWithConfig(t.Context(), handler, *cfg, nil).(*sipStreamFactory)
	t.Cleanup(func() { _ = factory.Shutdown() })
	netFlow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
	src := layers.NewTCPPortEndpoint(60421)
	dst := layers.NewTCPPortEndpoint(5060)
	ports := gopacket.NewFlow(layers.EndpointTCPPort, src.Raw(), dst.Raw())
	stream := factory.New(netFlow, ports, &layers.TCP{}, nil).(*bufferedSIPStream)

	stream.reverse.cancel()
	waitFor(t, func() bool { return atomic.LoadInt32(&stream.reverse.finished) == 1 }, "reverse half exit")
	if got := factory.GetActiveGoroutines(); got != 1 {
		t.Fatalf("one live half uses %d connection slots, want 1", got)
	}
	before := GetTCPStreamMetrics()
	stream.ReassembledSG(&fakeScatterGather{data: []byte("\r"), dir: reassembly.TCPDirServerToClient}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: []byte("\n\r\n"), dir: reassembly.TCPDirServerToClient}, nil)
	if got := GetTCPStreamMetrics().RearmKeepaliveChunks - before.RearmKeepaliveChunks; got != 1 {
		t.Fatalf("finished-half keepalive count = %d, want 1", got)
	}
	if got := GetTCPStreamMetrics().RearmRejectedChunks - before.RearmRejectedChunks; got != 0 {
		t.Fatalf("keepalive rejection count = %d, want 0", got)
	}
	response := append([]byte("\r\n"), sipDirectionMessage("SIP/2.0 200 OK", "reverse-rearmed")...)
	stream.ReassembledSG(&fakeScatterGather{data: response, dir: reassembly.TCPDirServerToClient}, nil)
	waitFor(t, func() bool { _, ok := handler.find("reverse-rearmed"); return ok }, "CRLF-prefixed reverse response after rearm")
	if got := factory.GetActiveGoroutines(); got != 1 {
		t.Fatalf("rearmed half uses %d connection slots, want 1", got)
	}
	stream.reverse.cancel()
	waitFor(t, func() bool { return atomic.LoadInt32(&stream.reverse.finished) == 1 }, "reverse half exit before split start")
	before = GetTCPStreamMetrics()
	for _, part := range [][]byte{
		[]byte("\r"),
		[]byte("\n\r\nINV"),
		[]byte("ITE sip:bob@example.test SIP/2.0\r\nCall-ID: split-rearm\r\nContent-Length: 0\r\n\r\n"),
	} {
		stream.ReassembledSG(&fakeScatterGather{data: part, dir: reassembly.TCPDirServerToClient}, nil)
	}
	waitFor(t, func() bool { _, ok := handler.find("split-rearm"); return ok }, "SIP start split across reverse chunks")
	if got := GetTCPStreamMetrics().RearmRejectedChunks - before.RearmRejectedChunks; got != 0 {
		t.Fatalf("split start rejected %d times, want 0", got)
	}
	if got := factory.GetActiveGoroutines(); got != 1 {
		t.Fatalf("split-start rearm uses %d connection slots, want 1", got)
	}
	stream.reverse.cancel()
	waitFor(t, func() bool { return atomic.LoadInt32(&stream.reverse.finished) == 1 }, "reverse half exit before plain split")
	stream.ReassembledSG(&fakeScatterGather{data: []byte("INV"), dir: reassembly.TCPDirServerToClient}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: []byte("ITE sip:bob@example.test SIP/2.0\r\nCall-ID: plain-split-rearm\r\nContent-Length: 0\r\n\r\n"), dir: reassembly.TCPDirServerToClient}, nil)
	waitFor(t, func() bool { _, ok := handler.find("plain-split-rearm"); return ok }, "plain SIP start split across chunks")
	stream.ReassemblyComplete(nil)
	waitFor(t, func() bool { return factory.GetActiveGoroutines() == 0 }, "both halves release connection slot")
}

func TestTCPDirectionRearmGapClearsPartialPrefix(t *testing.T) {
	handler := &directionMessageHandler{}
	stream := newLiveStream(t, handler, 60421, 5060)
	stream.reverse.cancel()
	waitFor(t, func() bool { return atomic.LoadInt32(&stream.reverse.finished) == 1 }, "reverse half exit before gap")
	stream.ReassembledSG(&fakeScatterGather{data: []byte("INVITE sip:bob@example.test SIP/2."), dir: reassembly.TCPDirServerToClient}, nil)
	stream.ReassembledSG(&fakeScatterGather{skip: 5, dir: reassembly.TCPDirServerToClient}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: []byte("0\r\nCall-ID: broken\r\nContent-Length: 0\r\n\r\n"), dir: reassembly.TCPDirServerToClient}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: sipDirectionMessage("SIP/2.0 200 OK", "after-gap"), dir: reassembly.TCPDirServerToClient}, nil)
	waitFor(t, func() bool { _, ok := handler.find("after-gap"); return ok }, "complete response after split-prefix gap")
	if _, ok := handler.find("broken"); ok {
		t.Fatal("start line spanning a transport gap was dispatched")
	}
	stream.ReassemblyComplete(nil)
}

func TestTCPDirectionRearmPrefixIsBounded(t *testing.T) {
	half := &bufferedSIPStream{}
	before := GetTCPStreamMetrics().RearmRejectedChunks
	if _, ready := half.collectRearmStart(bytes.Repeat([]byte{'x'}, resyncWindowBytes+1)); ready {
		t.Fatal("non-SIP prefix rearmed reader")
	}
	if len(half.rearmPrefix) != 0 {
		t.Fatalf("oversized prefix retained %d bytes", len(half.rearmPrefix))
	}
	if got := GetTCPStreamMetrics().RearmRejectedChunks - before; got != 1 {
		t.Fatalf("oversized prefix rejection count = %d, want 1", got)
	}
	message := sipDirectionMessage("SIP/2.0 200 OK", "after-bounded-reject")
	if data, ready := half.collectRearmStart(message); !ready || !bytes.Equal(data, message) {
		t.Fatal("fresh SIP message was not accepted after bounded rejection")
	}
}

func TestTCPDirectionRearmAcceptsLongRequestLine(t *testing.T) {
	handler := &directionMessageHandler{}
	stream := newLiveStream(t, handler, 60421, 5060)
	// The parser's start-line bound exceeds its header-line bound. Both a full
	// chunk and a split chunk must pass rearm with the same accepted URI.
	start := "INVITE sip:" + strings.Repeat("u", maxSIPHeaderLineLength+100) + "@example.test SIP/2.0"
	for _, tc := range []struct {
		name   string
		parts  int
		callID string
	}{
		{name: "complete", parts: 1, callID: "long-complete"},
		{name: "split", parts: 2, callID: "long-split"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream.reverse.cancel()
			waitFor(t, func() bool { return atomic.LoadInt32(&stream.reverse.finished) == 1 }, "reverse half exit before long URI")
			message := sipDirectionMessage(start, tc.callID)
			if tc.parts == 1 {
				stream.ReassembledSG(&fakeScatterGather{data: message, dir: reassembly.TCPDirServerToClient}, nil)
			} else {
				cut := 300
				stream.ReassembledSG(&fakeScatterGather{data: message[:cut], dir: reassembly.TCPDirServerToClient}, nil)
				stream.ReassembledSG(&fakeScatterGather{data: message[cut:], dir: reassembly.TCPDirServerToClient}, nil)
			}
			waitFor(t, func() bool { _, ok := handler.find(tc.callID); return ok }, "long request URI after rearm")
		})
	}
	stream.ReassemblyComplete(nil)
}

func TestLooksLikeSIPStartAllowsLeadingCRLF(t *testing.T) {
	for _, start := range []string{"INVITE sip:bob@example.test SIP/2.0\r\n", "SIP/2.0 200 OK\r\n"} {
		if !looksLikeSIPStart([]byte(strings.Repeat("\r\n", 2) + start)) {
			t.Fatalf("CRLF-prefixed SIP start rejected: %q", start)
		}
	}
	if looksLikeSIPStart([]byte("\r\nGET / HTTP/1.1\r\n")) {
		t.Fatal("non-SIP start accepted after CRLF")
	}
	if !isSIPKeepaliveOnly([]byte("\r\n\r\n")) || isSIPKeepaliveOnly([]byte("\r\nINVITE")) {
		t.Fatal("CRLF-only chunk classification failed")
	}
}

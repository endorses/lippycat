//go:build tap || all

package voip

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// recordingSIPHandler records the Call-IDs of every SIP message dispatched to
// it, so a test can assert which reassembled messages actually reached
// HandleSIPMessage (i.e. were parsed rather than silently discarded).
type recordingSIPHandler struct {
	mu       sync.Mutex
	callIDs  []string
	payloads []string
}

func (r *recordingSIPHandler) HandleSIPMessage(sipMessage []byte, callID, src, dst string, netFlow gopacket.Flow) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callIDs = append(r.callIDs, callID)
	r.payloads = append(r.payloads, string(sipMessage))
	return true
}

func (r *recordingSIPHandler) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.callIDs)
}

func (r *recordingSIPHandler) has(callID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.callIDs {
		if c == callID {
			return true
		}
	}
	return false
}

// newResyncTestStream builds a bufferedSIPStream wired to the given handler,
// suitable for driving processSIPFromReader / readSIPStartLine directly without
// a real assembler.
func newResyncTestStream(t *testing.T, handler SIPMessageHandler) (*bufferedSIPStream, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	factory := &sipStreamFactory{
		ctx:     ctx,
		config:  GetConfig(),
		handler: handler,
	}
	netFlow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
	srcPort := layers.NewTCPPortEndpoint(layers.TCPPort(5060))
	dstPort := layers.NewTCPPortEndpoint(layers.TCPPort(5060))
	transportFlow := gopacket.NewFlow(layers.EndpointTCPPort, srcPort.Raw(), dstPort.Raw())
	s := &bufferedSIPStream{
		ctx:           ctx,
		cancel:        cancel,
		factory:       factory,
		netFlow:       netFlow,
		transportFlow: transportFlow,
		createdAt:     time.Now(),
		state:         TCPStateOpening,
	}
	return s, cancel
}

// TestResync_MidStreamJoinLocksOnSIP verifies the core fix: when the first bytes
// delivered on a TCP stream are NOT a SIP start line (we joined mid-message —
// e.g. an ESP-NULL tap start, an MT-direction connection, or a short-lived SMS
// leg), the reader must resync to the next SIP message boundary and parse+
// dispatch that message rather than permanently discarding the connection.
func TestResync_MidStreamJoinLocksOnSIP(t *testing.T) {
	rec := &recordingSIPHandler{}
	s, cancel := newResyncTestStream(t, rec)
	defer cancel()

	// Leading bytes: the tail of a SIP message we joined mid-flight (header
	// lines with no start line), terminated by a blank line, followed by a
	// complete SIP MESSAGE. This is exactly the pattern that previously set the
	// irreversible discard flag on the first parsed line.
	midJoinTail := "To: <sip:someone@ims.example>\r\n" +
		"Call-ID: partial-we-missed-the-start\r\n" +
		"CSeq: 1 MESSAGE\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	full := string(mtMessage("call-resync-1", "31600000000"))

	reader := strings.NewReader(midJoinTail + full)
	s.processSIPFromReader(reader)

	if !rec.has("call-resync-1") {
		t.Fatalf("mid-stream-join SIP MESSAGE was not parsed/dispatched (resync failed); got call IDs %v", rec.callIDs)
	}
	if d := loadDiscard(s); d != 0 {
		t.Errorf("stream was permanently discarded despite locking onto SIP (discard=%d)", d)
	}
}

// TestResync_GenuineNonSIPRejectedAfterBoundedScan verifies that genuine non-SIP
// TCP (a TLS ClientHello) is not dispatched, and that readSIPStartLine gives up
// with errNotSIP after scanning a bounded window rather than buffering forever.
func TestResync_GenuineNonSIPRejectedAfterBoundedScan(t *testing.T) {
	rec := &recordingSIPHandler{}
	s, cancel := newResyncTestStream(t, rec)
	defer cancel()

	// A TLS ClientHello record header + some handshake bytes. Contains no SIP
	// framing whatsoever.
	tls := []byte{
		0x16, 0x03, 0x01, 0x00, 0x2c, // TLS handshake, TLS 1.0, length 0x2c
		0x01, 0x00, 0x00, 0x28, 0x03, 0x03, // ClientHello, version TLS 1.2
	}
	tls = append(tls, bytes.Repeat([]byte{0x00, 0x11, 0x22, 0x33, 0x44}, 8)...)

	s.processSIPFromReader(bytes.NewReader(tls))
	if rec.count() != 0 {
		t.Fatalf("non-SIP (TLS) bytes were dispatched as SIP: %v", rec.callIDs)
	}

	// Directly exercise the bounded scan: a large non-SIP blob (many short
	// non-SIP lines) must return errNotSIP after scanning past the window, not
	// hang or scan unbounded.
	var big strings.Builder
	line := "GET /some/very/long/non-sip/path/that/is/not/a/start/line HTTP/1.1\r\n"
	for big.Len() < resyncWindowBytes*2 {
		big.WriteString(line)
	}
	_, scanned, err := s.readSIPStartLine(bufio.NewReader(strings.NewReader(big.String())))
	if !errors.Is(err, errNotSIP) {
		t.Fatalf("readSIPStartLine on non-SIP blob returned err=%v, want errNotSIP", err)
	}
	if scanned <= resyncWindowBytes {
		t.Errorf("scanned=%d, want > resyncWindowBytes(%d) — scan not reaching the bound", scanned, resyncWindowBytes)
	}
	if scanned > resyncWindowBytes+maxSIPHeaderLineLength+len(line) {
		t.Errorf("scanned=%d exceeds the bounded window by more than one line — scan not bounded", scanned)
	}
}

// TestResync_ReusedFourTupleReassembles verifies the eviction/reset behaviour:
// after one stream on a 4-tuple is discarded as non-SIP, a fresh stream on the
// SAME 4-tuple re-assembles SIP normally (no discard state leaks across
// connections); and a bare SYN on a discarded stream resets it so a reused inner
// port gets a clean chance to lock onto SIP.
func TestResync_ReusedFourTupleReassembles(t *testing.T) {
	// Stream 1: genuine non-SIP, never locks on.
	rec1 := &recordingSIPHandler{}
	s1, cancel1 := newResyncTestStream(t, rec1)
	defer cancel1()
	s1.processSIPFromReader(bytes.NewReader([]byte("\x16\x03\x01garbage-not-sip-at-all\r\nstill-not-sip\r\n")))
	if rec1.count() != 0 {
		t.Fatalf("stream 1 dispatched non-SIP data: %v", rec1.callIDs)
	}

	// Stream 2: a fresh stream on the same 4-tuple carrying real SIP must be
	// re-assembled and dispatched — discard state must not leak across streams.
	rec2 := &recordingSIPHandler{}
	s2, cancel2 := newResyncTestStream(t, rec2)
	defer cancel2()
	s2.processSIPFromReader(strings.NewReader(string(mtMessage("call-reuse-2", "31600000000"))))
	if !rec2.has("call-reuse-2") {
		t.Fatalf("reused 4-tuple fresh stream did not re-assemble SIP; got %v", rec2.callIDs)
	}

	// A bare SYN on a discarded stream resets it (reused inner port ⇒ fresh
	// chance to lock onto SIP).
	s3, cancel3 := newResyncTestStream(t, &recordingSIPHandler{})
	defer cancel3()
	storeDiscard(s3, 1)
	storeLocked(s3, 1)
	storeNonSIP(s3, maxNonSIPBytesBeforeDiscard)
	syn := &layers.TCP{SYN: true}
	start := false
	s3.Accept(syn, gopacket.CaptureInfo{}, reassembly.TCPDirClientToServer, reassembly.Sequence(0), &start, nil)
	if !start {
		t.Error("Accept did not force-start reassembly")
	}
	if loadDiscard(s3) != 0 || loadLocked(s3) != 0 || loadNonSIP(s3) != 0 {
		t.Errorf("SYN did not reset stream state: discard=%d locked=%d nonSIP=%d",
			loadDiscard(s3), loadLocked(s3), loadNonSIP(s3))
	}
}

// TestResync_EstablishedFirstLineUnchanged verifies the established case is
// untouched: when the first delivered line IS a SIP start line, the message is
// parsed with only that line consumed (no forward scan) and dispatched.
func TestResync_EstablishedFirstLineUnchanged(t *testing.T) {
	rec := &recordingSIPHandler{}
	s, cancel := newResyncTestStream(t, rec)
	defer cancel()

	full := string(mtMessage("call-established-1", "31600000000"))
	// Sanity: start line already valid.
	startLine, scanned, err := s.readSIPStartLine(bufio.NewReader(strings.NewReader(full)))
	if err != nil {
		t.Fatalf("readSIPStartLine on established SIP returned err=%v", err)
	}
	if !isSIPRequestLine(startLine) {
		t.Fatalf("returned start line is not a SIP request line: %q", startLine)
	}
	firstLineLen := strings.Index(full, "\n") + 1
	if scanned != firstLineLen {
		t.Errorf("scanned=%d for established start line, want %d (only the start line consumed)", scanned, firstLineLen)
	}

	s.processSIPFromReader(strings.NewReader(full))
	if !rec.has("call-established-1") {
		t.Fatalf("established SIP MESSAGE was not dispatched; got %v", rec.callIDs)
	}
}

// small atomic accessors so the tests read cleanly.
func loadDiscard(s *bufferedSIPStream) int32     { return atomic.LoadInt32(&s.discard) }
func loadLocked(s *bufferedSIPStream) int32      { return atomic.LoadInt32(&s.lockedOnSIP) }
func loadNonSIP(s *bufferedSIPStream) int64      { return atomic.LoadInt64(&s.nonSIPBytes) }
func storeDiscard(s *bufferedSIPStream, v int32) { atomic.StoreInt32(&s.discard, v) }
func storeLocked(s *bufferedSIPStream, v int32)  { atomic.StoreInt32(&s.lockedOnSIP, v) }
func storeNonSIP(s *bufferedSIPStream, v int64)  { atomic.StoreInt64(&s.nonSIPBytes, v) }

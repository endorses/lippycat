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

	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

type parsedEventRecordingHandler struct {
	parsedCalls int
	legacyCalls int
	event       sharedsip.Event
}

func (h *parsedEventRecordingHandler) HandleSIPMessage([]byte, string, string, string, gopacket.Flow, gopacket.Flow) bool {
	h.legacyCalls++
	return true
}

func (h *parsedEventRecordingHandler) HandleParsedSIPMessage(_ []byte, event sharedsip.Event, _, _ string, _, _ gopacket.Flow) bool {
	h.parsedCalls++
	h.event = event
	return true
}

func TestTCPStreamDispatchesSingleParsedEventToMigratedHandler(t *testing.T) {
	handler := &parsedEventRecordingHandler{}
	stream := &bufferedSIPStream{factory: &sipStreamFactory{handler: handler}}
	stream.processSipMessage([]byte("INVITE sip:bob@example.test SIP/2.0\r\nCall-ID: parsed-once\r\nContent-Length: 0\r\n\r\n"), time.Unix(123, 0))

	if handler.parsedCalls != 1 || handler.legacyCalls != 0 {
		t.Fatalf("parsed calls=%d legacy calls=%d", handler.parsedCalls, handler.legacyCalls)
	}
	if handler.event.CallID != "parsed-once" || !handler.event.Timestamp.Equal(time.Unix(123, 0)) {
		t.Fatalf("unexpected parsed event: %+v", handler.event)
	}
}

// recordingSIPHandler records the Call-IDs of every SIP message dispatched to
// it, so a test can assert which reassembled messages actually reached
// HandleSIPMessage (i.e. were parsed rather than silently discarded).
type recordingSIPHandler struct {
	mu       sync.Mutex
	callIDs  []string
	payloads []string
}

func (r *recordingSIPHandler) HandleSIPMessage(sipMessage []byte, callID, src, dst string, _, _ gopacket.Flow) bool {
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

func TestResync_EmbeddedCRReplaysCredibleResponse(t *testing.T) {
	rec := &recordingSIPHandler{}
	s, cancel := newResyncTestStream(t, rec)
	defer cancel()

	damaged := "INVITE sip:b@example.test SIP/2.0\r\n" +
		"Call-ID: incomplete\r\nContent-Length: 12\r" +
		"SIP/2.0 200 OK\r\nCall-ID: recovered\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
	s.processSIPFromReader(strings.NewReader(damaged))

	if rec.has("incomplete") || !rec.has("recovered") {
		t.Fatalf("embedded-CR recovery dispatched call IDs %v", rec.callIDs)
	}
}

func TestResync_CorrectlyFramedInvalidContentLengthIsPolicyRejection(t *testing.T) {
	tests := []string{"-1", "not-a-number", "999999999999"}
	for _, value := range tests {
		t.Run(value, func(t *testing.T) {
			s, cancel := newResyncTestStream(t, &recordingSIPHandler{})
			defer cancel()
			input := "INVITE sip:b@example.test SIP/2.0\r\nContent-Length: " + value + "\r\n\r\n"
			_, err := s.readCompleteSipMessageFromReader(bufio.NewReader(strings.NewReader(input)))
			var policyErr *contentLengthPolicyError
			if !errors.As(err, &policyErr) {
				t.Fatalf("error %v is not a Content-Length policy rejection", err)
			}
			var framingErr *recoverableFramingError
			if errors.As(err, &framingErr) {
				t.Fatalf("policy rejection was reclassified as recoverable: %v", err)
			}
		})
	}
}

func TestCredibleSIPAfterEmbeddedCRRejectsLoneAndFalseStarts(t *testing.T) {
	for _, input := range []string{
		"Content-Length: 3\r\n",
		"Content-Length: 3\rnot a SIP line\r\n",
		"Header: value\rINVITE missing-version\r\n",
	} {
		if got := credibleSIPAfterEmbeddedCR(input); got != "" {
			t.Fatalf("credibleSIPAfterEmbeddedCR(%q) = %q", input, got)
		}
	}
	input := "Content-Length: 3\rOPTIONS sip:a@example.test SIP/2.0\r\n"
	if got := credibleSIPAfterEmbeddedCR(input); got != "OPTIONS sip:a@example.test SIP/2.0\r\n" {
		t.Fatalf("unexpected replay suffix %q", got)
	}
}

func TestResync_RepeatedEmbeddedCRHonorsCumulativeBound(t *testing.T) {
	rec := &recordingSIPHandler{}
	s, cancel := newResyncTestStream(t, rec)
	defer cancel()

	// Each malformed header consumes bytes before replaying another credible
	// start. Repetition must stop at the cumulative 64 KiB limit.
	unit := "OPTIONS sip:a@example.test SIP/2.0\r\nX-Fill: " + strings.Repeat("x", 2048) + "\r"
	var input strings.Builder
	for input.Len() < maxNonSIPBytesBeforeDiscard*2 {
		input.WriteString(unit)
	}
	input.WriteString("OPTIONS sip:a@example.test SIP/2.0\r\nCall-ID: too-late\r\nContent-Length: 0\r\n\r\n")
	s.processSIPFromReader(strings.NewReader(input.String()))
	if rec.has("too-late") {
		t.Fatal("parser exceeded cumulative resynchronization limit")
	}
	if loadDiscard(s) == 0 {
		t.Fatal("stream was not discarded at cumulative resynchronization limit")
	}
}

func FuzzTCPFramingRecovery(f *testing.F) {
	seeds := [][]byte{
		[]byte("INVITE sip:a@example.test SIP/2.0\r\nContent-Length: 3\rSIP/2.0 200 OK\r\nCall-ID: recovered\r\nContent-Length: 0\r\n\r\n"),
		[]byte("INVITE sip:a@example.test SIP/2.0\r\nCall-ID: gap-header\r\n\r\nSIP/2.0 486 Busy Here\r\nContent-Length: 0\r\n\r\n"),
		[]byte("MESSAGE sip:a@example.test SIP/2.0\r\nContent-Length: 4\r\nbo\rSIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"),
		[]byte("SIP/2.0 100 Trying\rplausible-but-damaged\rSIP/2.0 180 Ringing\r\nContent-Length: 0\r\n\r\n"),
		[]byte(strings.Repeat("X: y\r\n", 256) + "\r\nOPTIONS sip:a@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxNonSIPBytesBeforeDiscard*2 {
			t.Skip()
		}
		s, cancel := newResyncTestStream(t, &recordingSIPHandler{})
		defer cancel()
		s.processSIPFromReader(bytes.NewReader(data))
	})
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

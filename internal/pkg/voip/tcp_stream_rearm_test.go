//go:build tap || all

package voip

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// fakeScatterGather is a minimal reassembly.ScatterGather that hands one chunk
// of reassembled bytes to ReassembledSG, so a test can drive the real
// ReassembledSG -> re-arm -> processLoop path without a full assembler.
type fakeScatterGather struct {
	data []byte
	dir  reassembly.TCPFlowDirection
	skip int
}

func (f *fakeScatterGather) Lengths() (int, int) { return len(f.data), 0 }
func (f *fakeScatterGather) Fetch(l int) []byte  { return f.data[:l] }
func (f *fakeScatterGather) KeepFrom(offset int) {}
func (f *fakeScatterGather) CaptureInfo(int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: time.Now()}
}
func (f *fakeScatterGather) Info() (reassembly.TCPFlowDirection, bool, bool, int) {
	return f.dir, false, false, f.skip
}

func TestSIPStreamFullQueueReportsDroppedChunkAndBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &bufferedSIPStream{ctx: ctx, dataChan: make(chan streamChunk, 1)}
	stream.dataChan <- streamChunk{data: []byte("occupied")}
	before := GetTCPStreamMetrics()
	payload := []byte("test-payload")
	stream.ReassembledSG(&fakeScatterGather{data: payload, skip: 4}, nil)
	after := GetTCPStreamMetrics()

	if got := after.PostReassemblyDroppedChunks - before.PostReassemblyDroppedChunks; got != 1 {
		t.Fatalf("dropped chunks delta = %d, want 1", got)
	}
	if got := after.PostReassemblyDroppedBytes - before.PostReassemblyDroppedBytes; got != int64(len(payload)) {
		t.Fatalf("dropped bytes delta = %d, want %d", got, len(payload))
	}
	if got := after.MissingSequenceBytes - before.MissingSequenceBytes; got != 4 {
		t.Fatalf("missing bytes delta = %d, want 4", got)
	}
}

func TestStreamChunkReaderBreaksFramingAtReassemblyGap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &bufferedSIPStream{ctx: ctx, dataChan: make(chan streamChunk, 2)}
	stream.dataChan <- streamChunk{data: []byte("INVITE sip:a@b SIP/2.0\r\nCall-ID: incomplete")}
	complete := []byte("OPTIONS sip:a@b SIP/2.0\r\nCall-ID: recovered\r\nContent-Length: 0\r\n\r\n")
	stream.dataChan <- streamChunk{
		data: complete,
		gap:  streamGap{reason: streamGapReassembly, missingBytes: 17},
	}

	reader := &streamChunkReader{stream: stream, state: TCPStateOpening}
	buffered := bufio.NewReader(reader)
	_, err := stream.readCompleteSipMessageFromReader(buffered)
	var framingErr *recoverableFramingError
	if !errors.As(err, &framingErr) {
		t.Fatalf("partial message error = %v, want recoverable framing error", err)
	}
	if framingErr.missingBytes != 17 {
		t.Fatalf("missing bytes = %d, want 17", framingErr.missingBytes)
	}

	message, err := stream.readCompleteSipMessageFromReader(bufio.NewReader(reader))
	if err != nil {
		t.Fatalf("read post-gap message: %v", err)
	}
	if string(message) != string(complete) {
		t.Fatalf("post-gap message = %q, want %q", message, complete)
	}
}

func TestQueueOverflowMarkerAttachesOnlyAfterSuccessfulEnqueue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &bufferedSIPStream{ctx: ctx, dataChan: make(chan streamChunk, 1)}
	stream.dataChan <- streamChunk{data: []byte("occupied")}

	stream.ReassembledSG(&fakeScatterGather{data: []byte("first-drop")}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: []byte("second-drop"), skip: 3}, nil)
	<-stream.dataChan
	stream.ReassembledSG(&fakeScatterGather{data: []byte("safe")}, nil)

	chunk := <-stream.dataChan
	if chunk.gap.reason&streamGapQueueOverflow == 0 || chunk.gap.reason&streamGapReassembly == 0 {
		t.Fatalf("gap reason = %d, want overflow and reassembly", chunk.gap.reason)
	}
	if chunk.gap.missingBytes != 3 {
		t.Fatalf("missing sequence bytes = %d, want 3", chunk.gap.missingBytes)
	}
	wantDropped := len("first-drop") + len("second-drop")
	if chunk.gap.droppedBytes != wantDropped {
		t.Fatalf("queue-dropped bytes = %d, want %d", chunk.gap.droppedBytes, wantDropped)
	}
	if stream.pendingGap.reason != streamGapNone {
		t.Fatalf("pending gap was not cleared after successful enqueue: %+v", stream.pendingGap)
	}
}

func TestEmptyReassemblyGapCarriesToNextData(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &bufferedSIPStream{ctx: ctx, dataChan: make(chan streamChunk, 1)}

	stream.ReassembledSG(&fakeScatterGather{skip: 9}, nil)
	stream.ReassembledSG(&fakeScatterGather{data: []byte("after-gap")}, nil)

	chunk := <-stream.dataChan
	if chunk.gap.reason&streamGapReassembly == 0 || chunk.gap.missingBytes != 9 {
		t.Fatalf("carried gap = %+v, want reassembly gap with 9 missing bytes", chunk.gap)
	}
}

func TestStreamChunkReaderReturnsOldThenBoundaryThenNew(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &bufferedSIPStream{ctx: ctx, dataChan: make(chan streamChunk, 2)}
	stream.dataChan <- streamChunk{data: []byte("old")}
	stream.dataChan <- streamChunk{
		data: []byte("new"),
		gap:  streamGap{reason: streamGapQueueOverflow, droppedBytes: 12},
	}
	reader := &streamChunkReader{stream: stream, state: TCPStateOpening}
	buf := make([]byte, 3)

	if n, err := reader.Read(buf); n != 3 || err != nil || string(buf) != "old" {
		t.Fatalf("first read = (%d, %v, %q), want (3, nil, old)", n, err, buf)
	}
	n, err := reader.Read(buf)
	var framingErr *recoverableFramingError
	if n != 0 || !errors.As(err, &framingErr) || framingErr.droppedBytes != 12 {
		t.Fatalf("boundary read = (%d, %v), dropped=%v; want recoverable boundary with 12 dropped", n, err, framingErr)
	}
	if n, err = reader.Read(buf); n != 3 || err != nil || string(buf) != "new" {
		t.Fatalf("post-gap read = (%d, %v, %q), want (3, nil, new)", n, err, buf)
	}
}

func runChunkRecovery(t *testing.T, chunks []streamChunk) (*recordingSIPHandler, TCPStreamMetrics, TCPStreamMetrics) {
	t.Helper()
	rec := &recordingSIPHandler{}
	stream, cancel := newResyncTestStream(t, rec)
	stream.dataChan = make(chan streamChunk, len(chunks))
	for _, chunk := range chunks {
		stream.dataChan <- chunk
	}
	close(stream.dataChan)
	before := GetTCPStreamMetrics()
	stream.processSIPFromReader(&streamChunkReader{stream: stream, state: TCPStateOpening})
	after := GetTCPStreamMetrics()
	cancel()
	return rec, before, after
}

func TestMissingMiddleSegmentRecoversNextCompleteMessage(t *testing.T) {
	complete := []byte("OPTIONS sip:a@b SIP/2.0\r\nCall-ID: skip-recovered\r\nContent-Length: 0\r\n\r\n")
	rec, before, after := runChunkRecovery(t, []streamChunk{
		{data: []byte("INVITE sip:a@b SIP/2.0\r\nCall-ID: incomplete\r\nContent-Length: 20\r\n\r\npart")},
		{data: complete, gap: streamGap{reason: streamGapReassembly, missingBytes: 11}},
	})
	if !rec.has("skip-recovered") || rec.has("incomplete") {
		t.Fatalf("missing-middle recovery dispatched %v", rec.callIDs)
	}
	if got := after.RecoverySuccesses - before.RecoverySuccesses; got != 1 {
		t.Fatalf("recovery successes delta = %d, want 1", got)
	}
	if got := after.ParserFramingDiscontinuities - before.ParserFramingDiscontinuities; got != 1 {
		t.Fatalf("parser discontinuities delta = %d, want 1", got)
	}
}

func TestQueueOverflowThenCompleteMessageRecovers(t *testing.T) {
	rec := &recordingSIPHandler{}
	stream, cancel := newResyncTestStream(t, rec)
	defer cancel()
	stream.dataChan = make(chan streamChunk, 2)
	stream.dataChan <- streamChunk{data: []byte("INVITE sip:a@b SIP/2.0\r\n")}
	stream.dataChan <- streamChunk{data: []byte("Call-ID: incomplete")}
	dropped := []byte("dropped-header-bytes")
	before := GetTCPStreamMetrics()
	stream.ReassembledSG(&fakeScatterGather{data: dropped}, nil)

	done := make(chan struct{})
	go func() {
		stream.processSIPFromReader(&streamChunkReader{stream: stream, state: TCPStateOpening})
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for len(stream.dataChan) == cap(stream.dataChan) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(stream.dataChan) == cap(stream.dataChan) {
		t.Fatal("stream reader did not drain saturated queue")
	}
	complete := []byte("SIP/2.0 200 OK\r\nCall-ID: overflow-recovered\r\nContent-Length: 0\r\n\r\n")
	stream.ReassembledSG(&fakeScatterGather{data: complete}, nil)
	stream.ReassemblyComplete(nil)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream processing did not stop")
	}
	after := GetTCPStreamMetrics()
	if !rec.has("overflow-recovered") || rec.has("incomplete") {
		t.Fatalf("overflow recovery dispatched %v", rec.callIDs)
	}
	if got := after.PostReassemblyDroppedChunks - before.PostReassemblyDroppedChunks; got != 1 {
		t.Fatalf("dropped chunks delta = %d, want 1", got)
	}
	if got := after.PostReassemblyDroppedBytes - before.PostReassemblyDroppedBytes; got != int64(len(dropped)) {
		t.Fatalf("dropped bytes delta = %d, want %d", got, len(dropped))
	}
	if got := after.RecoverySuccesses - before.RecoverySuccesses; got != 1 {
		t.Fatalf("recovery successes delta = %d, want 1", got)
	}
}

func TestTransportGapRecoveryAtMessageBoundaries(t *testing.T) {
	partialCases := map[string][]byte{
		"start-line":        []byte("INVITE sip:a@b"),
		"header":            []byte("INVITE sip:a@b SIP/2.0\r\nCall-ID: cut"),
		"header-terminator": []byte("INVITE sip:a@b SIP/2.0\r\nCall-ID: cut\r\nContent-Length: 0\r"),
		"body":              []byte("MESSAGE sip:a@b SIP/2.0\r\nCall-ID: cut\r\nContent-Length: 8\r\n\r\nabc"),
	}
	for name, partial := range partialCases {
		t.Run(name, func(t *testing.T) {
			complete := []byte("OPTIONS sip:a@b SIP/2.0\r\nCall-ID: boundary-" + name + "\r\nContent-Length: 0\r\n\r\n")
			rec, _, _ := runChunkRecovery(t, []streamChunk{
				{data: partial},
				{data: complete, gap: streamGap{reason: streamGapReassembly, missingBytes: 1}},
			})
			if !rec.has("boundary-" + name) {
				t.Fatalf("post-gap message not recovered; got %v", rec.callIDs)
			}
		})
	}
}

func FuzzTransportGapRecoveryAtMessageBoundaries(f *testing.F) {
	partials := [][]byte{
		[]byte("INVITE sip:a@b"),
		[]byte("INVITE sip:a@b SIP/2.0\r\nCall-ID: cut"),
		[]byte("INVITE sip:a@b SIP/2.0\r\nCall-ID: cut\r\nContent-Length: 0\r"),
		[]byte("MESSAGE sip:a@b SIP/2.0\r\nCall-ID: cut\r\nContent-Length: 8\r\n\r\nabc"),
	}
	for _, partial := range partials {
		f.Add(partial)
	}
	f.Fuzz(func(t *testing.T, partial []byte) {
		if len(partial) > resyncWindowBytes {
			t.Skip()
		}
		complete := []byte("OPTIONS sip:a@b SIP/2.0\r\nCall-ID: fuzz-gap-recovered\r\nContent-Length: 0\r\n\r\n")
		rec, _, _ := runChunkRecovery(t, []streamChunk{
			{data: partial},
			{data: complete, gap: streamGap{reason: streamGapReassembly, missingBytes: 1}},
		})
		if !rec.has("fuzz-gap-recovered") {
			t.Fatalf("post-gap message was not recovered; got %v", rec.callIDs)
		}
	})
}

func TestShutdownWithPendingTransportGapIsNotRecoveryFailure(t *testing.T) {
	rec := &recordingSIPHandler{}
	stream, cancel := newResyncTestStream(t, rec)
	stream.dataChan = make(chan streamChunk, 1)
	stream.dataChan <- streamChunk{
		data: []byte("OPTIONS sip:a@b SIP/2.0\r\nCall-ID: never-read\r\nContent-Length: 0\r\n\r\n"),
		gap:  streamGap{reason: streamGapQueueOverflow, droppedBytes: 5},
	}
	before := GetTCPStreamMetrics()
	done := make(chan struct{})
	go func() {
		stream.processSIPFromReader(&streamChunkReader{stream: stream, state: TCPStateOpening})
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for GetTCPStreamMetrics().ParserFramingDiscontinuities == before.ParserFramingDiscontinuities && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not stop pending recovery")
	}
	after := GetTCPStreamMetrics()
	if got := after.RecoveryFailures - before.RecoveryFailures; got != 0 {
		t.Fatalf("administrative shutdown recovery failures delta = %d, want 0", got)
	}
}

func TestRecoveryFailureCountedExactlyOnceAtNonSIPCap(t *testing.T) {
	stream, cancel := newResyncTestStream(t, &recordingSIPHandler{})
	defer cancel()
	line := make([]byte, resyncWindowBytes)
	for i := range line {
		line[i] = 'x'
	}
	line[len(line)-1] = '\n'
	input := make([]byte, 0, len(line)*5)
	for range 5 {
		input = append(input, line...)
	}
	before := GetTCPStreamMetrics()
	stream.processSIPFromReader(io.LimitReader(&oneByteReader{data: input}, int64(len(input))))
	after := GetTCPStreamMetrics()
	if got := after.RecoveryFailures - before.RecoveryFailures; got != 1 {
		t.Fatalf("recovery failures delta = %d, want exactly 1", got)
	}
}

type oneByteReader struct{ data []byte }

func (r *oneByteReader) Read(dst []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	dst[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}
func (f *fakeScatterGather) Stats() reassembly.TCPAssemblyStats {
	return reassembly.TCPAssemblyStats{}
}

func loadFinished(s *bufferedSIPStream) int32 { return atomic.LoadInt32(&s.finished) }

// newLiveStream builds a bufferedSIPStream with a real, running processLoop
// (like factory.New would), wired to the given handler.
func newLiveStream(t *testing.T, handler SIPMessageHandler, srcPort, dstPort uint16) *bufferedSIPStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	factory := &sipStreamFactory{
		ctx:     ctx,
		cancel:  cancel,
		config:  GetConfig(),
		handler: handler,
	}
	netFlow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
	sp := layers.NewTCPPortEndpoint(layers.TCPPort(srcPort))
	dp := layers.NewTCPPortEndpoint(layers.TCPPort(dstPort))
	transportFlow := gopacket.NewFlow(layers.EndpointTCPPort, sp.Raw(), dp.Raw())
	detector := NewCallIDDetector()
	return newBufferedSIPStream(ctx, factory, detector, netFlow, transportFlow)
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for: %s", msg)
}

// TestRearm_CompletedStreamReusedForNewSIP reproduces the ESP-NULL 4-tuple-reuse
// drop: a first SIP MESSAGE is parsed on a stream, the processing goroutine then
// finishes (idle/read-timeout — here simulated by cancelling the stream context
// and marking it discarded, exactly the zombie state a completed MO leg leaves
// behind), and a SECOND SIP MESSAGE arrives on the SAME Stream object because
// gopacket never evicted it (no SYN/FIN delivered). Before the fix that second
// message was dropped (no reader on the channel / discard set); after the fix
// ReassembledSG re-arms the stream and the second message is dispatched.
func TestRearm_CompletedStreamReusedForNewSIP(t *testing.T) {
	rec := &recordingSIPHandler{}
	s := newLiveStream(t, rec, 60421, 16413)

	// SMS #1 MO leg: first MESSAGE on the connection.
	s.ReassembledSG(&fakeScatterGather{data: moMessage("mo-sms-1", "4915215940608")}, nil)
	waitFor(t, func() bool { return rec.has("mo-sms-1") }, "SMS#1 MO message dispatched")

	// The MO leg completes and the connection goes idle; the processing
	// goroutine exits. Simulate that deterministically: cancel the stream ctx
	// (idle/read-timeout would do the same) and wait for the goroutine to mark
	// itself finished. Then set discard=1, which the idle-timeout exit path sets
	// — this is precisely the "zombie" state that dropped the reused connection.
	s.cancel()
	waitFor(t, func() bool { return loadFinished(s) == 1 }, "processing goroutine to finish")
	storeDiscard(s, 1)
	s.pendingGap = streamGap{reason: streamGapQueueOverflow, droppedBytes: 7}

	// SMS #2 MO leg ~seconds later reuses the SAME 4-tuple. gopacket routes it to
	// this finished Stream (no New()). It must re-arm and dispatch.
	s.ReassembledSG(&fakeScatterGather{data: moMessage("mo-sms-2", "4915215940608")}, nil)
	waitFor(t, func() bool { return rec.has("mo-sms-2") }, "SMS#2 MO message dispatched after re-arm")

	if loadDiscard(s) != 0 {
		t.Errorf("re-arm did not clear discard flag (discard=%d)", loadDiscard(s))
	}
	if s.pendingGap.reason != streamGapNone {
		t.Errorf("re-arm did not clear pending transport gap: %+v", s.pendingGap)
	}
}

// TestRearm_InProgressMultiMessageNotRearmed guards the regression boundary: on
// a single LIVE connection carrying several SIP MESSAGEs back-to-back (the
// already-working per-message path), every message must be dispatched through
// the existing read loop and the stream must NOT be treated as finished/re-armed
// while it is still in progress.
func TestRearm_InProgressMultiMessageNotRearmed(t *testing.T) {
	rec := &recordingSIPHandler{}
	s := newLiveStream(t, rec, 5555, 5060)

	// Two messages arrive on the live stream without any teardown in between.
	s.ReassembledSG(&fakeScatterGather{data: moMessage("live-msg-1", "4915215940608")}, nil)
	waitFor(t, func() bool { return rec.has("live-msg-1") }, "first live message dispatched")

	// Stream must still be live (never finished) — so no re-arm can occur.
	if loadFinished(s) != 0 {
		t.Fatalf("in-progress stream marked finished unexpectedly (finished=%d)", loadFinished(s))
	}

	s.ReassembledSG(&fakeScatterGather{data: moMessage("live-msg-2", "4915215940608")}, nil)
	waitFor(t, func() bool { return rec.has("live-msg-2") }, "second live message dispatched")

	if loadFinished(s) != 0 {
		t.Errorf("live multi-message stream should not be finished (finished=%d)", loadFinished(s))
	}
	if rec.count() < 2 {
		t.Errorf("expected both live messages dispatched, got %d: %v", rec.count(), rec.callIDs)
	}
}

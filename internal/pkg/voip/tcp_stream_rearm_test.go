//go:build tap || all

package voip

import (
	"context"
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
}

func (f *fakeScatterGather) Lengths() (int, int) { return len(f.data), 0 }
func (f *fakeScatterGather) Fetch(l int) []byte  { return f.data[:l] }
func (f *fakeScatterGather) KeepFrom(offset int) {}
func (f *fakeScatterGather) CaptureInfo(int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: time.Now()}
}
func (f *fakeScatterGather) Info() (reassembly.TCPFlowDirection, bool, bool, int) {
	return f.dir, false, false, 0
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

	// SMS #2 MO leg ~seconds later reuses the SAME 4-tuple. gopacket routes it to
	// this finished Stream (no New()). It must re-arm and dispatch.
	s.ReassembledSG(&fakeScatterGather{data: moMessage("mo-sms-2", "4915215940608")}, nil)
	waitFor(t, func() bool { return rec.has("mo-sms-2") }, "SMS#2 MO message dispatched after re-arm")

	if loadDiscard(s) != 0 {
		t.Errorf("re-arm did not clear discard flag (discard=%d)", loadDiscard(s))
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

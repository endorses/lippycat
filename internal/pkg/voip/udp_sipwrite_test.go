//go:build cli || all

package voip

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// sipWriteHarness wires up the buffered UDP path against a temporary per-call
// PCAP and returns a feed function plus a reader for what actually got written.
type sipWriteHarness struct {
	t       *testing.T
	tracker *CallTracker
	callID  string
	sipPath string
}

func newSIPWriteHarness(t *testing.T, callID string) *sipWriteHarness {
	t.Helper()

	tmpDir := t.TempDir()
	out := filepath.Join(tmpDir, "capture.pcap")

	// viper.Reset() drops the registered defaults too, so re-register them:
	// without them MaxFilenameLength is 0 and sanitize() collapses every
	// Call-ID to one filename, putting all calls in a single PCAP.
	viper.Reset()
	initConfigDefaults()
	ResetConfigOnce()
	t.Cleanup(ResetConfigOnce)

	viper.Set("writeVoip", true)
	viper.Set("voip.output_file", out)
	cfg := *GetConfig()
	cfg.WriteVoIP = true
	cfg.OutputFile = out
	SetConfig(&cfg)
	t.Cleanup(func() { viper.Reset() })

	// The call tracker and async writer pool are process globals that outlive
	// a single test, so reset the state this call depends on. Without this a
	// repeat run reuses the previous run's CallInfo, whose writers point at an
	// already-deleted temp directory.
	tracker := TestCallTracker(t)
	output := NewSessionOutputManager(&cfg)
	tracker.replaceOutputForTest(output)
	t.Cleanup(func() { require.NoError(t, output.Shutdown()) })
	resetVoipWriteState(tracker, callID)
	t.Cleanup(func() { resetVoipWriteState(tracker, callID) })

	// Fresh buffer manager so the buffered path is exercised, with a long
	// max age so the janitor does not interfere with the test.
	prevMgr := globalBufferMgr
	globalBufferMgr = NewBufferManager(60*time.Second, 1000)
	t.Cleanup(func() {
		globalBufferMgr.Close()
		globalBufferMgr = prevMgr
	})

	return &sipWriteHarness{
		t:       t,
		tracker: tracker,
		callID:  callID,
		sipPath: filepath.Join(tmpDir, fmt.Sprintf("capture_sip_%s.pcap", sanitize(callID))),
	}
}

// resetVoipWriteState drops any tracker entry for callID and rearms its writer.
func resetVoipWriteState(tracker *CallTracker, callID string) {

	// Another test in this package may have shut the global tracker down,
	// which makes every write a no-op. Same convention as writer_test.go.
	tracker.shuttingDown.Store(0)

	tracker.mu.Lock()
	call := tracker.detachCallLocked(callID)
	tracker.mu.Unlock()
	if call != nil {
		_ = tracker.notifyCallEnded(call)
	}

	tracker.closeAsyncWriter()
}

func (h *sipWriteHarness) feed(payload string) {
	h.t.Helper()

	pkt := createUDPPacket(5060, 5060, []byte(payload))
	// Populate CaptureInfo so pcapgo can write the packet.
	ci := pkt.Metadata()
	ci.CaptureLength = len(pkt.Data())
	ci.Length = len(pkt.Data())
	ci.Timestamp = time.Unix(1700000000, 0)

	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	handleUdpPackets(h.tracker, capture.PacketInfo{
		Packet:   pkt,
		LinkType: layers.LinkTypeEthernet,
	}, udp)
}

// writtenStartLines flushes the writers and returns the SIP start-line of every
// packet in the per-call PCAP, in file order.
func (h *sipWriteHarness) writtenStartLines() []string {
	h.t.Helper()

	h.tracker.closeAsyncWriter()
	require.NoError(h.t, trackerOutput(h.t, h.tracker).CloseSession(h.callID))
	return sipStartLinesFromPcap(h.t, h.sipPath)
}

// sipStartLinesFromPcap reads a per-call SIP pcap and returns the SIP start-line
// of every packet in it, in file order. Writers must already be flushed.
func sipStartLinesFromPcap(t *testing.T, path string) []string {
	t.Helper()

	f, err := os.Open(path)
	require.NoError(t, err, "per-call SIP pcap should exist at %s", path)
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)

	var lines []string
	for {
		data, _, err := r.ReadPacketData()
		if err != nil {
			break
		}
		p := gopacket.NewPacket(data, r.LinkType(), gopacket.Default)
		var payload []byte
		switch tl := p.TransportLayer().(type) {
		case *layers.UDP:
			payload = tl.Payload
		case *layers.TCP:
			payload = tl.Payload
		default:
			require.Fail(t, "written packet should have a UDP or TCP layer")
		}
		line, _, _ := strings.Cut(string(payload), "\r\n")
		lines = append(lines, line)
	}
	return lines
}

func sipMsg(startLine, callID, extra, body string) string {
	msg := startLine + "\r\n" +
		"Via: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK1\r\n" +
		"From: <sip:alice@example.com>;tag=1\r\n" +
		"To: <sip:bob@example.com>" + extra + "\r\n" +
		"Call-ID: " + callID + "\r\n" +
		"CSeq: 1 INVITE\r\n"
	if body != "" {
		msg += "Content-Type: application/sdp\r\n"
	}
	return msg + "Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

const testSDP = "v=0\r\no=alice 1 1 IN IP4 192.168.1.1\r\ns=-\r\n" +
	"c=IN IP4 192.168.1.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"

// Once a call has matched the filter, every subsequent SIP packet must be
// written, not just the ones carrying SDP. Regression test: the write trigger
// used to be gated on the packet containing "m=audio", so all non-SDP
// signalling was buffered and silently dropped.
func TestUDPBufferedPath_WritesNonSDPSipPackets(t *testing.T) {
	callID := "nosdp-regression@example.com"
	h := newSIPWriteHarness(t, callID)

	h.feed(sipMsg("INVITE sip:bob@example.com SIP/2.0", callID, "", testSDP))
	h.feed(sipMsg("SIP/2.0 100 Trying", callID, "", ""))
	h.feed(sipMsg("SIP/2.0 180 Ringing", callID, ";tag=2", ""))
	h.feed(sipMsg("ACK sip:bob@example.com SIP/2.0", callID, ";tag=2", ""))
	h.feed(sipMsg("BYE sip:bob@example.com SIP/2.0", callID, ";tag=2", ""))

	require.Equal(t, []string{
		"INVITE sip:bob@example.com SIP/2.0",
		"SIP/2.0 100 Trying",
		"SIP/2.0 180 Ringing",
		"ACK sip:bob@example.com SIP/2.0",
		"BYE sip:bob@example.com SIP/2.0",
	}, h.writtenStartLines(), "every SIP packet of a matched call should be written exactly once, in order")
}

// A second SDP-bearing packet must not re-flush packets that were already
// written. Regression test: the match callback used to read the buffer without
// draining it, so each flush re-emitted everything buffered so far.
func TestUDPBufferedPath_NoDuplicateOnSecondSDP(t *testing.T) {
	callID := "dup-regression@example.com"
	h := newSIPWriteHarness(t, callID)

	h.feed(sipMsg("INVITE sip:bob@example.com SIP/2.0", callID, "", testSDP))
	h.feed(sipMsg("SIP/2.0 100 Trying", callID, "", ""))
	h.feed(sipMsg("SIP/2.0 200 OK", callID, ";tag=2", testSDP))

	require.Equal(t, []string{
		"INVITE sip:bob@example.com SIP/2.0",
		"SIP/2.0 100 Trying",
		"SIP/2.0 200 OK",
	}, h.writtenStartLines(), "each SIP packet should be written exactly once")
}

// Buffers are reaped by age mid-call, but the call stays matched. Packets
// arriving after the reap must still be written rather than starting a fresh
// undecided buffer that never flushes.
func TestUDPBufferedPath_WritesAfterBufferReaped(t *testing.T) {
	callID := "reaped-regression@example.com"
	h := newSIPWriteHarness(t, callID)

	h.feed(sipMsg("INVITE sip:bob@example.com SIP/2.0", callID, "", testSDP))

	// Simulate the janitor discarding the temporary buffer mid-call.
	globalBufferMgr.DiscardBuffer(callID)
	require.True(t, globalBufferMgr.IsCallMatched(callID), "call should stay matched after buffer cleanup")

	h.feed(sipMsg("BYE sip:bob@example.com SIP/2.0", callID, ";tag=2", ""))

	require.Equal(t, []string{
		"INVITE sip:bob@example.com SIP/2.0",
		"BYE sip:bob@example.com SIP/2.0",
	}, h.writtenStartLines(), "BYE after buffer cleanup should still be written")
}

// A call that never matches the filter must not be written at all.
func TestUDPBufferedPath_UnmatchedCallNotWritten(t *testing.T) {
	callID := "unmatched-regression@example.com"
	h := newSIPWriteHarness(t, callID)

	// Restrict surveillance to a user this call does not involve. With no
	// users configured the filter runs in promiscuous mode and matches
	// everything, which would not exercise the reject path.
	sipusers.ClearAll()
	sipusers.AddSipUser("carol", &sipusers.SipUser{})
	t.Cleanup(sipusers.ClearAll)

	h.feed(sipMsg("INVITE sip:bob@example.com SIP/2.0", callID, "", testSDP))
	h.feed(sipMsg("SIP/2.0 100 Trying", callID, "", ""))
	h.feed(sipMsg("BYE sip:bob@example.com SIP/2.0", callID, ";tag=2", ""))

	h.tracker.closeAsyncWriter()
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callID))
	_, err := os.Stat(h.sipPath)
	require.True(t, os.IsNotExist(err), "no PCAP should be created for an unmatched call, got err=%v", err)
}

func TestReleaseBufferedSniffPacketsDispatchesEveryTypedSIPResult(t *testing.T) {
	callID := "typed-release@example.com"
	h := newSIPWriteHarness(t, callID)
	messages := []string{
		sipMsg("INVITE sip:bob@example.com SIP/2.0", callID, "", ""),
		sipMsg("SIP/2.0 200 OK", callID, ";tag=2", testSDP),
	}
	buffered := make([]BufferedSIPPacket, 0, len(messages))
	for _, message := range messages {
		packet := createUDPPacket(5060, 5060, []byte(message))
		packet.Metadata().CaptureLength = len(packet.Data())
		packet.Metadata().Length = len(packet.Data())
		packet.Metadata().Timestamp = time.Unix(1700000000, 0)
		event, err := sharedsip.Parse([]byte(message), sharedsip.ParseOptions{Timestamp: time.Unix(1700000000, 0)})
		require.NoError(t, err)
		buffered = append(buffered, BufferedSIPPacket{Packet: packet, Result: pipeline.SIPResultFromEvent(event, nil)})
	}

	stats := releaseBufferedSniffPackets(h.tracker, callID, buffered, nil, "eth0", layers.LinkTypeEthernet)
	require.Equal(t, uint64(len(buffered)), stats[sniffSIPSinkName].Accepted)
	require.Zero(t, stats[sniffSIPSinkName].Dropped)
	require.Equal(t, []string{
		"INVITE sip:bob@example.com SIP/2.0",
		"SIP/2.0 200 OK",
	}, h.writtenStartLines())
}

package reassembly

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type reuseStream struct {
	data        [2][]byte
	completions int
	keep        bool
}

func (s *reuseStream) Accept(t *layers.TCP, _ gopacket.CaptureInfo, _ TCPFlowDirection, _ Sequence, start *bool, _ AssemblerContext) bool {
	*start = t.SYN || len(t.Payload) > 0
	return true
}
func (s *reuseStream) ReassembledSG(sg ScatterGather, _ AssemblerContext) {
	dir, _, _, _ := sg.Info()
	n, _ := sg.Lengths()
	index := 0
	if dir == TCPDirServerToClient {
		index = 1
	}
	s.data[index] = append(s.data[index], sg.Fetch(n)...)
	if s.keep && n > 0 {
		sg.KeepFrom(0)
	}
}
func (s *reuseStream) ReassemblyComplete(AssemblerContext) bool { s.completions++; return true }

type reuseFactory struct {
	streams []*reuseStream
	keep    bool
}

func (f *reuseFactory) New(gopacket.Flow, gopacket.Flow, *layers.TCP, AssemblerContext) Stream {
	s := &reuseStream{keep: f.keep}
	f.streams = append(f.streams, s)
	return s
}

func reuseSegment(reverse bool, seq uint32, flags string, payload string) (gopacket.Flow, *layers.TCP) {
	flow := netFlow
	src, dst := layers.TCPPort(50123), layers.TCPPort(5060)
	if reverse {
		flow = flow.Reverse()
		src, dst = dst, src
	}
	tcp := &layers.TCP{SrcPort: src, DstPort: dst, Seq: seq, SYN: flags == "syn" || flags == "synack", ACK: flags == "ack" || flags == "synack" || payload != "", FIN: flags == "fin", RST: flags == "rst"}
	tcp.Payload = []byte(payload)
	tcp.SetInternalPortsForTesting()
	return flow, tcp
}
func reuseFeed(a *Assembler, reverse bool, seq uint32, flags, payload string) {
	flow, tcp := reuseSegment(reverse, seq, flags, payload)
	a.Assemble(flow, tcp)
}

func TestConnectionReuseAfterCloseAndOrphanControl(t *testing.T) {
	for _, orientation := range []bool{false, true} {
		for _, control := range []string{"rst", "fin", "ack"} {
			t.Run(fmt.Sprintf("reverse=%t/%s", orientation, control), func(t *testing.T) {
				f := &reuseFactory{}
				p := NewStreamPool(f)
				a := NewAssembler(p)
				reuseFeed(a, orientation, 100, "syn", "")
				reuseFeed(a, !orientation, 200, "synack", "")
				reuseFeed(a, orientation, 101, "ack", "first-request")
				reuseFeed(a, !orientation, 201, "ack", "first-response")
				reuseFeed(a, orientation, 114, "fin", "")
				reuseFeed(a, !orientation, 215, "fin", "")
				require.Empty(t, p.conns)
				require.Equal(t, 1, f.streams[0].completions)
				reuseFeed(a, !orientation, 216, control, "")
				require.Len(t, f.streams, 1)
				require.EqualValues(t, 1, p.OrphanControls())
				reuseFeed(a, orientation, 3000, "syn", "")
				reuseFeed(a, !orientation, 7000, "synack", "")
				reuseFeed(a, orientation, 3001, "ack", "next-request")
				reuseFeed(a, !orientation, 7001, "ack", "next-response")
				require.Len(t, f.streams, 2)
				require.Equal(t, "next-request", string(f.streams[1].data[0]))
				require.Equal(t, "next-response", string(f.streams[1].data[1]))
				a.FlushAll()
				assertRetiredStreamsReleased(t, p)
				require.Equal(t, 1, f.streams[1].completions)
				require.Zero(t, a.pc.used)
			})
		}
	}
}

func TestConnectionReuseReplacesMissedOrHalfClose(t *testing.T) {
	for _, orientation := range []bool{false, true} {
		for _, halfClose := range []bool{false, true} {
			t.Run(fmt.Sprintf("reverse=%t/halfClose=%t", orientation, halfClose), func(t *testing.T) {
				f := &reuseFactory{}
				p := NewStreamPool(f)
				a := NewAssembler(p)
				reuseFeed(a, false, 100, "syn", "")
				reuseFeed(a, true, 200, "synack", "")
				reuseFeed(a, false, 101, "ack", "old")
				reuseFeed(a, true, 201, "ack", "response")
				if halfClose {
					reuseFeed(a, orientation, map[bool]uint32{false: 104, true: 209}[orientation], "fin", "")
				}
				// Queue a page behind a gap. Replacement must release it, not deliver it
				// into the next session, and complete the old stream exactly once.
				reuseFeed(a, !orientation, 1000, "ack", "stale queued bytes")
				require.Positive(t, a.pc.used)
				reuseFeed(a, orientation, 9000, "syn", "")
				reuseFeed(a, !orientation, 10000, "synack", "")
				require.Len(t, f.streams, 2)
				require.Equal(t, 1, f.streams[0].completions)
				require.Zero(t, a.pc.used)
				reuseFeed(a, orientation, 9001, "ack", "fresh request")
				reuseFeed(a, !orientation, 10001, "ack", "fresh response")
				require.Equal(t, "fresh request", string(f.streams[1].data[0]))
				require.Equal(t, "fresh response", string(f.streams[1].data[1]))
				a.FlushAll()
				assertRetiredStreamsReleased(t, p)
				require.Equal(t, 1, f.streams[1].completions)
				require.Zero(t, a.pc.used)
			})
		}
	}
}

func TestConnectionSYNRetransmissionAndLateSYN(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprintf("late=%t", late), func(t *testing.T) {
			f := &reuseFactory{}
			p := NewStreamPool(f)
			a := NewAssembler(p)
			if !late {
				reuseFeed(a, false, 100, "syn", "")
			}
			reuseFeed(a, false, 101, "ack", "first")
			reuseFeed(a, false, 100, "syn", "")
			reuseFeed(a, false, 100, "syn", "")
			require.Len(t, f.streams, 1)
			require.Zero(t, f.streams[0].completions)
			reuseFeed(a, false, 106, "ack", "-next")
			reuseFeed(a, true, 200, "synack", "")
			reuseFeed(a, true, 201, "ack", "response")
			require.Equal(t, "first-next", string(f.streams[0].data[0]))
			require.Equal(t, "response", string(f.streams[0].data[1]))
			a.FlushCloseOlderThan(time.Now().Add(time.Hour))
			assertRetiredStreamsReleased(t, p)
			require.Equal(t, 1, f.streams[0].completions)
			reuseFeed(a, false, 600, "syn", "")
			reuseFeed(a, false, 601, "ack", "new call")
			require.Len(t, f.streams, 2)
			require.Equal(t, "new call", string(f.streams[1].data[0]))
			a.FlushAll()
			require.Zero(t, a.pc.used)
		})
	}
}

func TestConnectionReplacementReleasesRetainedPages(t *testing.T) {
	f := &reuseFactory{keep: true}
	p := NewStreamPool(f)
	a := NewAssembler(p)
	reuseFeed(a, false, 100, "syn", "")
	reuseFeed(a, false, 101, "ack", "saved data")
	require.Positive(t, a.pc.used)
	reuseFeed(a, false, 500, "syn", "")
	require.Len(t, f.streams, 2)
	require.Zero(t, a.pc.used)
	require.Equal(t, 1, f.streams[0].completions)
	a.FlushAll()
	assertRetiredStreamsReleased(t, p)
}

func TestConnectionSYNOnPreviouslyUnobservedHalf(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(fmt.Sprintf("late=%t", late), func(t *testing.T) {
			f := &reuseFactory{}
			p := NewStreamPool(f)
			a := NewAssembler(p)
			// Capture first sees only responder data. A later bare SYN in the unseen
			// client half can be correlated by the responder's acknowledgment.
			flow, tcp := reuseSegment(true, 201, "ack", "passive response")
			tcp.Ack = 101
			ctx := assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Unix(200, 0)})
			a.AssembleWithContext(flow, tcp, &ctx)
			clientISN := uint32(8000)
			if late {
				clientISN = 100
			}
			flow, tcp = reuseSegment(false, clientISN, "syn", "")
			ctx = assemblerSimpleContext(gopacket.CaptureInfo{Timestamp: time.Unix(201, 0)})
			a.AssembleWithContext(flow, tcp, &ctx)
			if late {
				require.Len(t, f.streams, 1)
				require.Zero(t, f.streams[0].completions)
				reuseFeed(a, false, 101, "ack", "late request")
				require.Equal(t, "late request", string(f.streams[0].data[1]))
			} else {
				require.Len(t, f.streams, 2)
				require.Equal(t, 1, f.streams[0].completions)
				reuseFeed(a, false, 8001, "ack", "new request")
				reuseFeed(a, true, 9000, "synack", "")
				reuseFeed(a, true, 9001, "ack", "new response")
				require.Equal(t, "new request", string(f.streams[1].data[0]))
				require.Equal(t, "new response", string(f.streams[1].data[1]))
			}
			a.FlushAll()
			assertRetiredStreamsReleased(t, p)
			require.Zero(t, a.pc.used)
		})
	}
}

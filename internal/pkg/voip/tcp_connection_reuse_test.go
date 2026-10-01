//go:build tap || all

package voip

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/reassembly"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestTCPSIPConnectionReuseRealAssembler(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, teardown := range []string{"clean", "rst", "fin", "ack", "missed-fin", "half-closed", "idle"} {
			t.Run(fmt.Sprintf("reverse=%t/%s", reverse, teardown), func(t *testing.T) {
				handler := &directionMessageHandler{}
				cfg := DefaultConfig()
				cfg.MaxStreams = 2
				factory := NewSipStreamFactoryWithConfig(t.Context(), handler, *cfg, nil).(*sipStreamFactory)
				assembler := capture.NewTCPAssembler(factory)
				t.Cleanup(func() {
					assembler.FlushAll()
					require.NoError(t, factory.Shutdown())
					require.Zero(t, factory.GetActiveGoroutines())
				})
				flow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
				feed := func(rev bool, seq uint32, flags string, data []byte) {
					net := flow
					src, dst := layers.TCPPort(60421), layers.TCPPort(5060)
					if rev {
						net = net.Reverse()
						src, dst = dst, src
					}
					tcp := &layers.TCP{SrcPort: src, DstPort: dst, Seq: seq, SYN: flags == "syn" || flags == "synack", ACK: flags == "ack" || flags == "synack", FIN: flags == "fin", RST: flags == "rst", BaseLayer: layers.BaseLayer{Payload: data}}
					tcp.SetInternalPortsForTesting()
					assembler.Assemble(net, tcp, time.Unix(100, 0))
				}
				request := sipDirectionMessage("INVITE sip:bob@example.test SIP/2.0", "old-request")
				response := sipDirectionMessage("SIP/2.0 180 Ringing", "old-response")
				feed(reverse, 100, "syn", nil)
				feed(!reverse, 200, "synack", nil)
				feed(reverse, 101, "ack", request)
				feed(!reverse, 201, "ack", response)
				waitFor(t, func() bool { _, ok := handler.find("old-request"); return ok }, "old request")
				waitFor(t, func() bool { _, ok := handler.find("old-response"); return ok }, "old response")
				if teardown != "missed-fin" && teardown != "idle" {
					feed(reverse, 101+uint32(len(request)), "fin", nil)
				}
				if teardown != "missed-fin" && teardown != "half-closed" && teardown != "idle" {
					feed(!reverse, 201+uint32(len(response)), "fin", nil)
				}
				if teardown == "rst" || teardown == "fin" || teardown == "ack" {
					feed(!reverse, 202+uint32(len(response)), teardown, nil)
					require.EqualValues(t, 1, assembler.OrphanControls())
				}
				if teardown == "idle" {
					assembler.FlushCloseOlderThan(time.Unix(200, 0))
				}
				before := GetTCPStreamMetrics().TotalStreamsCreated
				feed(reverse, 3000, "syn", nil)
				feed(!reverse, 7000, "synack", nil)
				nextRequest := sipDirectionMessage("INVITE sip:bob@example.test SIP/2.0", "next-request")
				nextResponse := sipDirectionMessage("SIP/2.0 302 Moved Temporarily", "next-response")
				feed(reverse, 3001, "ack", nextRequest)
				feed(!reverse, 7001, "ack", nextResponse)
				waitFor(t, func() bool { _, ok := handler.find("next-request"); return ok }, "next request")
				waitFor(t, func() bool { _, ok := handler.find("next-response"); return ok }, "next response")
				require.EqualValues(t, 1, GetTCPStreamMetrics().TotalStreamsCreated-before)
				requestGot, _ := handler.find("next-request")
				responseGot, _ := handler.find("next-response")
				require.Equal(t, requestGot.src, responseGot.dst)
				require.Equal(t, requestGot.dst, responseGot.src)
				require.Equal(t, requestGot.flow.Reverse(), responseGot.flow)
				require.Equal(t, requestGot.ports.Reverse(), responseGot.ports)
				require.LessOrEqual(t, factory.GetActiveGoroutines(), int64(cfg.MaxStreams))
			})
		}
	}
}

func TestTCPSIPLateSYNAndRetransmissionPreserveFraming(t *testing.T) {
	handler := &directionMessageHandler{}
	factory := NewSipStreamFactory(t.Context(), handler).(*sipStreamFactory)
	assembler := capture.NewTCPAssembler(factory)
	t.Cleanup(func() {
		assembler.FlushAll()
		require.NoError(t, factory.Shutdown())
		require.Zero(t, factory.GetActiveGoroutines())
	})
	flow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
	feed := func(seq uint32, syn bool, data []byte) {
		tcp := &layers.TCP{SrcPort: 60421, DstPort: 5060, Seq: seq, SYN: syn, ACK: !syn, BaseLayer: layers.BaseLayer{Payload: data}}
		tcp.SetInternalPortsForTesting()
		assembler.Assemble(flow, tcp, time.Unix(100, 0))
	}
	message := sipDirectionMessage("INVITE sip:bob@example.test SIP/2.0", "late-handshake")
	feed(101, false, message[:10])
	feed(100, true, nil)
	feed(100, true, nil)
	feed(111, false, message[10:])
	waitFor(t, func() bool { _, ok := handler.find("late-handshake"); return ok }, "message spanning delayed/retransmitted SYN")
	before := GetTCPStreamMetrics().TotalStreamsCreated
	feed(600, true, nil)
	feed(601, false, sipDirectionMessage("INVITE sip:bob@example.test SIP/2.0", "after-late"))
	waitFor(t, func() bool { _, ok := handler.find("after-late"); return ok }, "following connection")
	require.EqualValues(t, 1, GetTCPStreamMetrics().TotalStreamsCreated-before)
}

func TestTCPSIPOrphanControlsDoNotStartWorkers(t *testing.T) {
	handler := &directionMessageHandler{}
	factory := NewSipStreamFactory(t.Context(), handler).(*sipStreamFactory)
	assembler := capture.NewTCPAssembler(factory)
	t.Cleanup(func() { assembler.FlushAll(); require.NoError(t, factory.Shutdown()) })
	flow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
	before := GetTCPStreamMetrics().TotalStreamsCreated
	for _, flags := range []string{"ack", "fin", "rst"} {
		tcp := &layers.TCP{SrcPort: 60421, DstPort: 5060, Seq: 1, ACK: flags == "ack", FIN: flags == "fin", RST: flags == "rst"}
		tcp.SetInternalPortsForTesting()
		assembler.Assemble(flow, tcp, time.Now())
	}
	require.Equal(t, before, GetTCPStreamMetrics().TotalStreamsCreated)
	require.Zero(t, factory.GetActiveGoroutines())
	require.EqualValues(t, 3, assembler.OrphanControls())
	// Once a connection exists, an unseen half must not start from a bare ACK.
	stream := factory.New(flow, gopacket.NewFlow(layers.EndpointTCPPort, []byte{0, 1}, []byte{0, 2}), &layers.TCP{}, nil).(*bufferedSIPStream)
	start := false
	for _, tcp := range []*layers.TCP{{ACK: true}, {FIN: true}, {RST: true}} {
		require.False(t, stream.Accept(tcp, gopacket.CaptureInfo{}, reassembly.TCPDirServerToClient, -1, &start, nil))
		require.False(t, start)
	}
	stream.ReassemblyComplete(nil)
}

type blockedReuseHandler struct{ entered, release chan struct{} }

func (h *blockedReuseHandler) HandleSIPMessage([]byte, string, string, string, gopacket.Flow, gopacket.Flow) bool {
	select {
	case h.entered <- struct{}{}:
	default:
	}
	<-h.release
	return true
}

func TestTCPSIPReplacementPreservesMaxStreamsAdmission(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxStreams = 1
	h := &blockedReuseHandler{entered: make(chan struct{}, 1), release: make(chan struct{})}
	factory := NewSipStreamFactoryWithConfig(t.Context(), h, *cfg, nil).(*sipStreamFactory)
	assembler := capture.NewTCPAssembler(factory)
	t.Cleanup(func() {
		assembler.FlushAll()
		require.NoError(t, factory.Shutdown())
		require.Zero(t, factory.GetActiveGoroutines())
	})
	flow := testNetFlow(t, "10.0.0.1", "10.0.0.2")
	feed := func(seq uint32, syn bool, data []byte) {
		tcp := &layers.TCP{SrcPort: 60421, DstPort: 5060, Seq: seq, SYN: syn, ACK: !syn, BaseLayer: layers.BaseLayer{Payload: data}}
		tcp.SetInternalPortsForTesting()
		assembler.Assemble(flow, tcp, time.Now())
	}
	feed(100, true, nil)
	feed(101, false, sipDirectionMessage("INVITE sip:bob@example.test SIP/2.0", "blocked-old"))
	<-h.entered
	before := GetTCPStreamMetrics().DroppedStreams
	// Retirement closes its input, but the old worker is still delivering an
	// admitted message. The new generation must respect the configured limit.
	feed(500, true, nil)
	require.EqualValues(t, 1, factory.GetActiveGoroutines())
	require.EqualValues(t, 1, GetTCPStreamMetrics().DroppedStreams-before)
	close(h.release)
	waitFor(t, func() bool { return factory.GetActiveGoroutines() == 0 }, "retired generation releases its slot")
	// A discarded generation must not poison future SYNs once capacity recovers.
	before = GetTCPStreamMetrics().TotalStreamsCreated
	feed(900, true, nil)
	feed(901, false, sipDirectionMessage("INVITE sip:bob@example.test SIP/2.0", "after-cap"))
	require.EqualValues(t, 1, GetTCPStreamMetrics().TotalStreamsCreated-before)
	require.EqualValues(t, 1, factory.GetActiveGoroutines())
}

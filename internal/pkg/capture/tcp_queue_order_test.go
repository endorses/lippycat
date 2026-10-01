package capture

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/reassembly"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func orderedTCPPacket(t *testing.T, reverse bool, seq uint32, flags, payload string) PacketInfo {
	t.Helper()
	srcIP, dstIP := net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)
	src, dst := layers.TCPPort(40123), layers.TCPPort(5060)
	if reverse {
		srcIP, dstIP = dstIP, srcIP
		src, dst = dst, src
	}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: src, DstPort: dst, Seq: seq, SYN: flags == "syn" || flags == "synack", ACK: flags == "synack" || flags == "ack", FIN: flags == "fin", RST: flags == "rst"}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().CaptureInfo.Timestamp = time.Unix(100, int64(seq))
	return PacketInfo{Packet: pkt}
}

type orderedStream struct {
	data      [2]string
	completed int
}

func (*orderedStream) Accept(t *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	*start = t.SYN || len(t.Payload) > 0
	return true
}
func (s *orderedStream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	d, _, _, _ := sg.Info()
	index := 0
	if d == reassembly.TCPDirServerToClient {
		index = 1
	}
	n, _ := sg.Lengths()
	s.data[index] += string(sg.Fetch(n))
}
func (s *orderedStream) ReassemblyComplete(reassembly.AssemblerContext) bool {
	s.completed++
	return true
}

type orderedFactory struct{ streams []*orderedStream }

func (f *orderedFactory) New(gopacket.Flow, gopacket.Flow, *layers.TCP, reassembly.AssemblerContext) reassembly.Stream {
	s := &orderedStream{}
	f.streams = append(f.streams, s)
	return s
}

func TestTCPQueueOrderingCaptureToAssembler(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, teardown := range []string{"clean", "trailing-rst", "missed-fin", "half-closed"} {
			t.Run(fmt.Sprintf("reverse=%t/%s", reverse, teardown), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				pb := newDeterministicPacketBuffer(32, 8, nil)
				pb.ctx = ctx
				pb.cancel = cancel
				request := "INVITE sip:a@example.test SIP/2.0\r\nCall-ID: old\r\nContent-Length: 0\r\n\r\n"
				response := "SIP/2.0 180 Ringing\r\nCall-ID: old\r\nContent-Length: 0\r\n\r\n"
				nextRequest := "INVITE sip:a@example.test SIP/2.0\r\nCall-ID: next\r\nContent-Length: 0\r\n\r\n"
				nextResponse := "SIP/2.0 302 Moved\r\nCall-ID: next\r\nContent-Length: 0\r\n\r\n"
				send := func(rev bool, seq uint32, flags, data string) {
					require.True(t, pb.Send(orderedTCPPacket(t, rev, seq, flags, data)))
				}
				send(reverse, 100, "syn", "")
				send(!reverse, 200, "synack", "")
				send(reverse, 101, "ack", request)
				send(!reverse, 201, "ack", response)
				if teardown == "clean" || teardown == "trailing-rst" || teardown == "half-closed" {
					send(reverse, 101+uint32(len(request)), "fin", "")
				}
				if teardown == "clean" || teardown == "trailing-rst" {
					send(!reverse, 201+uint32(len(response)), "fin", "")
				}
				if teardown == "trailing-rst" {
					send(!reverse, 202+uint32(len(response)), "rst", "")
				}
				send(reverse, 5000, "syn", "")
				send(!reverse, 7000, "synack", "")
				send(reverse, 5001, "ack", nextRequest)
				send(!reverse, 7001, "ack", nextResponse)
				// This unrelated flow must still overtake regular TCP handshakes. The
				// same-flow SIP data stays FIFO behind those handshakes in the regular lane.
				priority := testUDPPacketInfo("OPTIONS sip:other@example.test SIP/2.0\r\n")
				priority.Interface = "unrelated priority"
				require.True(t, pb.Send(priority))
				require.Equal(t, 1, len(pb.sipCh))
				wantOrdered := int64(4)
				if teardown != "missed-fin" {
					wantOrdered++
				}
				require.Equal(t, wantOrdered, pb.SIPOrdered())
				require.LessOrEqual(t, pb.Snapshot().TotalLength(), pb.Snapshot().TotalCapacity())
				close(pb.sipCh)
				close(pb.ch)
				pb.mergerWg.Add(1)
				go pb.mergeChannels()
				f := &orderedFactory{}
				a := NewTCPAssembler(f)
				require.Equal(t, "unrelated priority", (<-pb.Receive()).Interface)
				for pkt := range pb.Receive() {
					tcp := pkt.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
					a.AssembleCaptureInfo(pkt.Packet.NetworkLayer().NetworkFlow(), tcp, pkt.Packet.Metadata().CaptureInfo)
				}
				pb.mergerWg.Wait()
				require.Empty(t, pb.tcpRegular)
				require.Len(t, f.streams, 2)
				require.Equal(t, [2]string{request, response}, f.streams[0].data)
				require.Equal(t, [2]string{nextRequest, nextResponse}, f.streams[1].data)
				require.Equal(t, 1, f.streams[0].completed)
				a.FlushAll()
				require.Equal(t, 1, f.streams[1].completed)
				if teardown == "trailing-rst" {
					require.EqualValues(t, 1, a.OrphanControls())
				}
			})
		}
	}
}

func TestTCPQueueOrderingFailedSendAndCancellationReleaseState(t *testing.T) {
	pb := newDeterministicPacketBuffer(1, 2, nil)
	require.True(t, pb.Send(orderedTCPPacket(t, false, 100, "syn", "")))
	require.False(t, pb.Send(orderedTCPPacket(t, false, 101, "ack", "INVITE sip:a@example.test SIP/2.0\r\n")))
	require.Len(t, pb.tcpRegular, 1)
	for _, flow := range pb.tcpRegular {
		require.Equal(t, 1, flow.pending, "a dropped send must release its ordering reference")
	}
	pkt := <-pb.ch
	pb.releaseRegularTCP(pkt)
	require.Empty(t, pb.tcpRegular)
	ctx, cancel := context.WithCancel(t.Context())
	pb.ctx = ctx
	require.True(t, pb.SendBlocking(orderedTCPPacket(t, false, 200, "syn", "")))
	done := make(chan bool, 1)
	go func() {
		done <- pb.SendBlocking(orderedTCPPacket(t, false, 201, "ack", "INVITE sip:a@example.test SIP/2.0\r\n"))
	}()
	cancel()
	require.False(t, <-done)
	pkt = <-pb.ch
	pb.releaseRegularTCP(pkt)
	require.Empty(t, pb.tcpRegular)
}

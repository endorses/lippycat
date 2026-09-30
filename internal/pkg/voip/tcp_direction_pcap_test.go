//go:build cli || all

package voip

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/voip/sipusers"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestTCPLocalPath_BidirectionalSIPPCAPUsesSenderAddresses(t *testing.T) {
	h := newTCPSIPHarness(t)
	const callID = "tcp-direction@example.com"
	resetVoipWriteState(h.tracker, callID)
	t.Cleanup(func() { resetVoipWriteState(h.tracker, callID) })
	sipusers.ClearAll()
	t.Cleanup(sipusers.ClearAll)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	factory := NewSipStreamFactory(ctx, h.handler).(*sipStreamFactory)
	t.Cleanup(factory.Close)
	assembler := capture.NewTCPAssemblerWithLimits(factory, 3, 64)
	before := GetTCPStreamMetrics().SIPMessagesDetected

	const ueIP, pcscfIP = "192.0.2.10", "198.51.100.20"
	const uePort, pcscfPort = layers.TCPPort(9202), layers.TCPPort(63781)
	from := "<sip:alice@example.com>"
	invite := tcpSIPMsg("INVITE sip:bob@example.com SIP/2.0", callID, from, "")
	trying := tcpSIPMsg("SIP/2.0 100 Trying", callID, from, "")
	progress := tcpSIPMsg("SIP/2.0 183 Session Progress", callID, from, "")
	ok := strings.Replace(tcpSIPMsg("SIP/2.0 200 OK", callID, from, ""), "Content-Length: 0", "Warning: 399 proxy INVITE check\r\nContent-Length: 0", 1)
	ack := strings.Replace(tcpSIPMsg("ACK sip:bob@example.com SIP/2.0", callID, from, ""), "CSeq: 1 INVITE", "CSeq: 1 ACK", 1)
	bye := strings.Replace(tcpSIPMsg("BYE sip:bob@example.com SIP/2.0", callID, from, ""), "CSeq: 1 INVITE", "CSeq: 2 BYE", 1)
	expectedMessages := map[string]string{
		"INVITE sip:bob@example.com SIP/2.0": invite,
		"SIP/2.0 100 Trying":                 trying,
		"SIP/2.0 183 Session Progress":       progress,
		"SIP/2.0 200 OK":                     ok,
		"ACK sip:bob@example.com SIP/2.0":    ack,
		"BYE sip:bob@example.com SIP/2.0":    bye,
	}

	ueSeq, pcscfSeq := uint32(1000), uint32(5000)
	feed := func(message, srcIP, dstIP string, srcPort, dstPort layers.TCPPort, sequence *uint32) {
		packet := createTCPSIPPacketWithPorts(t, message, srcIP, dstIP, srcPort, dstPort)
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		tcp.Seq = *sequence
		*sequence += uint32(len(message))
		assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp, time.Unix(1700000000, 0))
	}
	feed(invite, ueIP, pcscfIP, uePort, pcscfPort, &ueSeq)
	feed(trying, pcscfIP, ueIP, pcscfPort, uePort, &pcscfSeq)
	feed(progress, pcscfIP, ueIP, pcscfPort, uePort, &pcscfSeq)
	feed(ok, pcscfIP, ueIP, pcscfPort, uePort, &pcscfSeq)
	feed(ack, ueIP, pcscfIP, uePort, pcscfPort, &ueSeq)
	feed(bye, ueIP, pcscfIP, uePort, pcscfPort, &ueSeq)

	require.Eventually(t, func() bool {
		return GetTCPStreamMetrics().SIPMessagesDetected-before >= 6
	}, time.Second, time.Millisecond)
	assembler.FlushAll()
	factory.Close()
	h.tracker.closeAsyncWriter()
	require.NoError(t, trackerOutput(t, h.tracker).CloseSession(callID))

	file, err := os.Open(h.sipPath(callID))
	require.NoError(t, err)
	defer file.Close()
	reader, err := pcapgo.NewReader(file)
	require.NoError(t, err)

	type endpoints struct {
		srcIP, dstIP     string
		srcPort, dstPort layers.TCPPort
	}
	got := make(map[string]endpoints)
	for {
		data, _, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		start := strings.SplitN(string(tcp.Payload), "\r\n", 2)[0]
		require.Equal(t, expectedMessages[start], string(tcp.Payload), "PCAP payload for %q", start)
		got[start] = endpoints{ip.SrcIP.String(), ip.DstIP.String(), tcp.SrcPort, tcp.DstPort}
	}
	ueToPCSCF := endpoints{ueIP, pcscfIP, uePort, pcscfPort}
	pcscfToUE := endpoints{pcscfIP, ueIP, pcscfPort, uePort}
	require.Equal(t, map[string]endpoints{
		"INVITE sip:bob@example.com SIP/2.0": ueToPCSCF,
		"SIP/2.0 100 Trying":                 pcscfToUE,
		"SIP/2.0 183 Session Progress":       pcscfToUE,
		"SIP/2.0 200 OK":                     pcscfToUE,
		"ACK sip:bob@example.com SIP/2.0":    ueToPCSCF,
		"BYE sip:bob@example.com SIP/2.0":    ueToPCSCF,
	}, got)
}

//go:build all && li

package voip

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type tcpDirectionX2Record struct {
	srcIP, dstIP     string
	srcPort, dstPort string
	payload          []byte
	pdu              *x2x3.PDU
	err              error
}

type tcpDirectionX2Handler struct {
	mu      sync.Mutex
	encoder *x2x3.X2Encoder
	xid     uuid.UUID
	records map[string]tcpDirectionX2Record
}

func (h *tcpDirectionX2Handler) HandleSIPMessage(message []byte, callID, src, dst string, flow, ports gopacket.Flow) bool {
	synthetic, ok := buildSIPPacketInfo(message, src, dst, flow, time.Unix(1700000000, 0))
	if !ok {
		return false
	}
	ip := synthetic.Packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := synthetic.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	start := strings.SplitN(string(message), "\r\n", 2)[0]
	voip := &types.VoIPMetadata{CallID: callID, RawSIP: append([]byte(nil), message...)}
	if strings.HasPrefix(start, "SIP/2.0 ") {
		code, _ := strconv.Atoi(strings.Fields(start)[1])
		voip.Status = code
	} else {
		voip.Method = strings.Fields(start)[0]
	}
	display := &types.PacketDisplay{
		SrcIP: ip.SrcIP.String(), DstIP: ip.DstIP.String(),
		SrcPort: strconv.Itoa(int(tcp.SrcPort)), DstPort: strconv.Itoa(int(tcp.DstPort)),
		RawData: synthetic.Packet.Data(), VoIPData: voip,
	}
	pdu, err := h.encoder.EncodeIRI(display, h.xid)
	h.mu.Lock()
	h.records[start] = tcpDirectionX2Record{display.SrcIP, display.DstIP, display.SrcPort, display.DstPort, append([]byte(nil), message...), pdu, err}
	h.mu.Unlock()
	return err == nil
}

func TestTCPDirectionRealReassemblyCarriesSenderToX2(t *testing.T) {
	handler := &tcpDirectionX2Handler{encoder: x2x3.NewX2Encoder(), xid: uuid.New(), records: make(map[string]tcpDirectionX2Record)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	factory := NewSipStreamFactory(ctx, handler).(*sipStreamFactory)
	t.Cleanup(factory.Close)
	assembler := capture.NewTCPAssemblerWithLimits(factory, 3, 64)
	t.Cleanup(func() { assembler.FlushAll() })
	const callID = "tcp-direction-x2@example.test"
	from := "<sip:alice@example.test>"
	invite := tcpSIPMsg("INVITE sip:bob@example.test SIP/2.0", callID, from, "")
	trying := tcpSIPMsg("SIP/2.0 100 Trying", callID, from, "")
	progress := tcpSIPMsg("SIP/2.0 183 Session Progress", callID, from, "")
	ok := strings.Replace(tcpSIPMsg("SIP/2.0 200 OK", callID, from, ""), "Content-Length: 0", "Warning: 399 proxy INVITE check\r\nContent-Length: 0", 1)
	ack := strings.Replace(tcpSIPMsg("ACK sip:bob@example.test SIP/2.0", callID, from, ""), "CSeq: 1 INVITE", "CSeq: 1 ACK", 1)
	bye := strings.Replace(tcpSIPMsg("BYE sip:bob@example.test SIP/2.0", callID, from, ""), "CSeq: 1 INVITE", "CSeq: 2 BYE", 1)

	ueSeq, pcscfSeq := uint32(1000), uint32(5000)
	feed := func(message, srcIP, dstIP string, srcPort, dstPort layers.TCPPort, sequence *uint32) {
		packet := createTCPSIPPacketWithPorts(t, message, srcIP, dstIP, srcPort, dstPort)
		tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		tcp.Seq = *sequence
		*sequence += uint32(len(message))
		assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp, time.Unix(1700000000, 0))
	}
	feed(invite, "192.0.2.10", "198.51.100.20", 9202, 63781, &ueSeq)
	feed(trying, "198.51.100.20", "192.0.2.10", 63781, 9202, &pcscfSeq)
	feed(progress, "198.51.100.20", "192.0.2.10", 63781, 9202, &pcscfSeq)
	feed(ok, "198.51.100.20", "192.0.2.10", 63781, 9202, &pcscfSeq)
	feed(ack, "192.0.2.10", "198.51.100.20", 9202, 63781, &ueSeq)
	feed(bye, "192.0.2.10", "198.51.100.20", 9202, 63781, &ueSeq)

	require.Eventually(t, func() bool {
		handler.mu.Lock()
		defer handler.mu.Unlock()
		return len(handler.records) == 6
	}, time.Second, time.Millisecond)
	assembler.FlushAll()
	factory.Close()

	handler.mu.Lock()
	defer handler.mu.Unlock()
	for start, want := range map[string]struct {
		message          string
		srcIP, dstIP     string
		srcPort, dstPort string
	}{
		"INVITE sip:bob@example.test SIP/2.0": {invite, "192.0.2.10", "198.51.100.20", "9202", "63781"},
		"SIP/2.0 100 Trying":                  {trying, "198.51.100.20", "192.0.2.10", "63781", "9202"},
		"SIP/2.0 183 Session Progress":        {progress, "198.51.100.20", "192.0.2.10", "63781", "9202"},
		"SIP/2.0 200 OK":                      {ok, "198.51.100.20", "192.0.2.10", "63781", "9202"},
		"ACK sip:bob@example.test SIP/2.0":    {ack, "192.0.2.10", "198.51.100.20", "9202", "63781"},
		"BYE sip:bob@example.test SIP/2.0":    {bye, "192.0.2.10", "198.51.100.20", "9202", "63781"},
	} {
		got, found := handler.records[start]
		require.True(t, found, "missing %q", start)
		require.NoError(t, got.err)
		require.Equal(t, want.srcIP, got.srcIP)
		require.Equal(t, want.dstIP, got.dstIP)
		require.Equal(t, want.srcPort, got.srcPort)
		require.Equal(t, want.dstPort, got.dstPort)
		require.Equal(t, []byte(want.message), got.payload)
		require.NotNil(t, got.pdu)
		require.Equal(t, []byte(want.message), got.pdu.Payload)
		srcIPAttr := x2x3.FindAttribute(got.pdu.Attributes, x2x3.AttrSourceIPv4)
		dstIPAttr := x2x3.FindAttribute(got.pdu.Attributes, x2x3.AttrDestIPv4)
		srcPortAttr := x2x3.FindAttribute(got.pdu.Attributes, x2x3.AttrSourcePort)
		dstPortAttr := x2x3.FindAttribute(got.pdu.Attributes, x2x3.AttrDestPort)
		require.NotNil(t, srcIPAttr)
		require.NotNil(t, dstIPAttr)
		require.NotNil(t, srcPortAttr)
		require.NotNil(t, dstPortAttr)
		require.Equal(t, parseTestIP(t, want.srcIP), srcIPAttr.Value)
		require.Equal(t, parseTestIP(t, want.dstIP), dstIPAttr.Value)
		srcPort, err := strconv.Atoi(want.srcPort)
		require.NoError(t, err)
		dstPort, err := strconv.Atoi(want.dstPort)
		require.NoError(t, err)
		require.Equal(t, []byte{byte(srcPort >> 8), byte(srcPort)}, srcPortAttr.Value)
		require.Equal(t, []byte{byte(dstPort >> 8), byte(dstPort)}, dstPortAttr.Value)
	}
}

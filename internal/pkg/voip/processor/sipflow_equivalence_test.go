package processor

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func createTCPSIPPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("198.51.100.2").To4()}
	tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: 1, ACK: true, PSH: true, Window: 8192}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	packet.Metadata().Timestamp = time.Unix(1700000000, 42)
	return packet
}

func TestSharedSIPFlowUDPAndReassembledTCPSemanticsMatch(t *testing.T) {
	body := "hello"
	message := []byte("MESSAGE sip:bob@example.test SIP/2.0\r\n" +
		"From: <sip:alice@example.test>;tag=from\r\nTo: <sip:bob@example.test>;tag=to\r\n" +
		"P-Asserted-Identity: <sip:alice@example.test>\r\n" +
		"P-Access-Network-Info: 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=1234\r\n" +
		"P-Visited-Network-ID: visited.example.test\r\n" +
		"Call-ID: equivalent\r\nCSeq: 9 MESSAGE\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n" + body)
	udpPacket := createUDPPacket(t, message, 5060, 5060)
	udpPacket.Metadata().Timestamp = time.Unix(1700000000, 42)
	tcpPacket := createTCPSIPPacket(t, message)

	udpProcessor, tcpProcessor := New(DefaultConfig()), New(DefaultConfig())
	t.Cleanup(udpProcessor.Close)
	t.Cleanup(tcpProcessor.Close)
	udpResult := udpProcessor.Process(udpPacket)
	tcp := tcpPacket.TransportLayer().(*layers.TCP)
	tcpResult := tcpProcessor.detectSIPWithCompletion(tcpPacket, nil, tcp.Payload, false)
	require.NotNil(t, udpResult)
	require.NotNil(t, tcpResult)
	require.True(t, reflect.DeepEqual(udpResult.Metadata, tcpResult.Metadata), "protobuf SIP metadata differs: UDP=%+v TCP=%+v", udpResult.Metadata, tcpResult.Metadata)
	require.Equal(t, udpResult.CallMetadata, tcpResult.CallMetadata)
	require.Equal(t, udpResult.CallID, tcpResult.CallID)
	require.Equal(t, body, tcpResult.CallMetadata.Body)
}

func TestReassembledTCPTerminalCompletionRemainsDeferred(t *testing.T) {
	processor := New(DefaultConfig())
	t.Cleanup(processor.Close)
	invite := createTCPSIPPacket(t, []byte("INVITE sip:b@example.test SIP/2.0\r\nCall-ID: deferred\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"))
	require.NotNil(t, processor.ProcessReassembledSIP(invite))
	response := createTCPSIPPacket(t, []byte("SIP/2.0 200 OK\r\nCall-ID: deferred\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"))
	require.NotNil(t, processor.ProcessReassembledSIP(response))
	require.Len(t, processor.ActiveCalls(), 1, "reassembled TCP final response must remain until injection callback completes it")
	processor.CompleteCall("deferred")
	require.Empty(t, processor.ActiveCalls())
}

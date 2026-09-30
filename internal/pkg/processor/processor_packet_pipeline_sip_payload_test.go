//go:build processor || tap || all

package processor

import (
	"net"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func liTestSIPFrame(t *testing.T, payload []byte, useTCP bool) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	var transport gopacket.SerializableLayer
	if useTCP {
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: 1, ACK: true}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		transport = tcp
	} else {
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: 5060, DstPort: 5060}
		require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
		transport = udp
	}
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, transport, gopacket.Payload(payload)))
	return buf.Bytes()
}

func TestSIPMetadataForLIPreservesCompleteTransportMessage(t *testing.T) {
	response := []byte("SIP/2.0 200 OK\r\nSubject: INVITE sip:decoy@example.test SIP/2.0\r\nContent-Length: 7\r\n\r\nINVITE ")
	next := []byte("BYE sip:bob@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	request := []byte("INVITE sip:bob@example.test SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	for _, tc := range []struct {
		name    string
		payload []byte
		want    []byte
		tcp     bool
	}{
		{"TCP response followed by another message", append(append([]byte(nil), response...), next...), response, true},
		{"UDP request", request, request, false},
		{"incomplete TCP response", response[:len(response)-1], nil, true},
		{"unframed TCP message", []byte("INVITE sip:bob@example.test SIP/2.0\r\n\r\n"), nil, true},
		{"malformed Content-Length", []byte("INVITE sip:bob@example.test SIP/2.0\r\nContent-Length: bad\r\n\r\n"), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := &data.CapturedPacket{
				Data: liTestSIPFrame(t, tc.payload, tc.tcp), LinkType: uint32(layers.LinkTypeEthernet),
				Metadata: &data.PacketMetadata{Sip: &data.SIPMetadata{CallId: "call", ResponseCode: 200}},
			}
			meta := sipMetadataForLI(pkt)
			require.Equal(t, tc.want, meta.RawSIP)
			require.Equal(t, "call", meta.CallID)
		})
	}
}

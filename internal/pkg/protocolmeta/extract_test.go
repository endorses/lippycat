//go:build hunter || tap || all

package protocolmeta

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestEnrichHTTPHeadersOptIn(t *testing.T) {
	payload := []byte("GET /search?q=cat HTTP/1.1\r\nHost: example.test\r\nX-Secret: value\r\n\r\n")
	packet := testTCPPacket(t, payload)
	without := Enrich(packet, nil, false)
	require.Equal(t, "example.test", without.Http.Host)
	require.Empty(t, without.Http.Headers)
	with := Enrich(packet, nil, true)
	require.Equal(t, "value", with.Http.Headers["x-secret"])
	require.Equal(t, "192.0.2.1", with.SrcIp)
	require.Equal(t, uint32(50000), with.SrcPort)
}

func testTCPPacket(t *testing.T, payload []byte) gopacket.Packet {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	tcp := &layers.TCP{SrcPort: 50000, DstPort: 80}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: []byte{192, 0, 2, 1}, DstIP: []byte{192, 0, 2, 2}}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, &layers.Ethernet{SrcMAC: []byte{0, 1, 2, 3, 4, 5}, DstMAC: []byte{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}, ip, tcp, gopacket.Payload(payload)))
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

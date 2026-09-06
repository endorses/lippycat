//go:build tui || all

package tui

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestOfflineTCPDNSDecodedPacketMatchesRawBaseline(t *testing.T) {
	dnsWire := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(dnsWire, gopacket.SerializeOptions{FixLengths: true}, &layers.DNS{ID: 0x1234, RD: false}))
	payload := make([]byte, 2+len(dnsWire.Bytes()))
	binary.BigEndian.PutUint16(payload, uint16(len(dnsWire.Bytes())))
	copy(payload[2:], dnsWire.Bytes())
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 53, ACK: true, PSH: true}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	wire := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(wire, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(wire.Bytes(), layers.LinkTypeRaw, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
	want := parseDNSFromRawData(wire.Bytes(), layers.LinkTypeRaw)
	require.NotNil(t, want)
	require.EqualValues(t, 0x1234, want.TransactionID)
	require.Equal(t, want, parseOfflineDNSPacket(packet, layers.LinkTypeRaw))
}

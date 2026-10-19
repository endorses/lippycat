package learnedrules

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func transportFrame(t *testing.T, ipv6, tcp bool) ([]byte, gopacket.Decoder, int) {
	t.Helper()
	protocol := layers.IPProtocolUDP
	if tcp {
		protocol = layers.IPProtocolTCP
	}
	var network gopacket.NetworkLayer
	var header gopacket.SerializableLayer
	var decoder gopacket.Decoder = layers.LayerTypeIPv4
	headerBytes := 20
	if ipv6 {
		ip := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2"), NextHeader: protocol}
		network, header, decoder, headerBytes = ip, ip, layers.LayerTypeIPv6, 40
	} else {
		ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2), Protocol: protocol}
		network, header = ip, ip
	}
	var transport gopacket.SerializableLayer
	if tcp {
		h := &layers.TCP{SrcPort: 5060, DstPort: 45000, ACK: true, Window: 4096}
		require.NoError(t, h.SetNetworkLayerForChecksum(network))
		transport = h
	} else {
		h := &layers.UDP{SrcPort: 5060, DstPort: 45000}
		require.NoError(t, h.SetNetworkLayerForChecksum(network))
		transport = h
	}
	buffer := gopacket.NewSerializeBuffer()
	// Complete RTP-shaped bytes on a SIP port exercise application decoding's
	// truncated-line flag independently of IP and transport completeness.
	payload := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 42, 1, 2, 3, 4}
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, header, transport, gopacket.Payload(payload)))
	return append([]byte(nil), buffer.Bytes()...), decoder, headerBytes
}

func decodedFactsPacket(raw []byte, decoder gopacket.Decoder) gopacket.Packet {
	packet := gopacket.NewPacket(raw, decoder, gopacket.Default)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(raw), Length: len(raw)}
	return packet
}

func TestPacketFactsIgnoresApplicationTruncationForCompleteEndpoints(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6-%t", ipv6), func(t *testing.T) {
			raw, decoder, _ := transportFrame(t, ipv6, false)
			packet := decodedFactsPacket(raw, decoder)
			require.NotNil(t, packet.NetworkLayer())
			require.NotNil(t, packet.TransportLayer())
			require.True(t, packet.Metadata().Truncated, "the SIP application decoder marks its incomplete line, despite complete IP/UDP")
			facts, ok := PacketFacts(packet, 7)
			require.True(t, ok)
			require.Equal(t, UDP, facts.Protocol)
			require.EqualValues(t, 5060, facts.Source.Port)
			require.EqualValues(t, 45000, facts.Destination.Port)
			store, control, clock := setup(t)
			b := binding(clock, "complete-diagnostic")
			b.Selectors[0] = Selector{Domain: 7, Address: facts.Destination.Address, Port: facts.Destination.Port, Protocol: UDP, Direction: Destination}
			require.NoError(t, store.ApplySnapshot(control, 1, []Binding{b}))
			require.Len(t, store.Match(facts, 1).Bindings, 1, "an unqualified diagnostic endpoint does not require valid SIP")
		})
	}
}

func TestPacketFactsRejectsActualTransportTruncationAndFragments(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("ipv6-%t/tcp-%t", ipv6, tcp), func(t *testing.T) {
				raw, decoder, networkBytes := transportFrame(t, ipv6, tcp)
				_, ok := PacketFacts(decodedFactsPacket(raw, decoder), 7)
				require.True(t, ok)
				_, ok = PacketFacts(decodedFactsPacket(raw[:len(raw)-1], decoder), 7)
				require.False(t, ok, "advertised IP payload cannot exceed captured bytes")
				// Repair the IP length so only the missing transport header proves
				// incompleteness, rather than relying on the IP length check above.
				transportBytes := 7
				if tcp {
					transportBytes = 19
				}
				short := append([]byte(nil), raw[:networkBytes+transportBytes]...)
				if ipv6 {
					binary.BigEndian.PutUint16(short[4:6], uint16(transportBytes))
				} else {
					binary.BigEndian.PutUint16(short[2:4], uint16(len(short)))
				}
				_, ok = PacketFacts(decodedFactsPacket(short, decoder), 7)
				require.False(t, ok, "partial UDP/TCP header cannot establish an endpoint")
				if !tcp {
					badLength := append([]byte(nil), raw...)
					binary.BigEndian.PutUint16(badLength[networkBytes+4:networkBytes+6], uint16(len(raw)-networkBytes+4))
					_, ok = PacketFacts(decodedFactsPacket(badLength, decoder), 7)
					require.False(t, ok, "UDP length must fit the IP payload")
				}
				fragment := append([]byte(nil), raw...)
				if ipv6 {
					fragment = append(fragment[:40:40], make([]byte, 8)...)
					fragment = append(fragment, raw[40:]...)
					fragment[40], fragment[6] = raw[6], byte(layers.IPProtocolIPv6Fragment)
					binary.BigEndian.PutUint16(fragment[4:6], uint16(len(fragment)-40))
				} else {
					binary.BigEndian.PutUint16(fragment[6:8], 0x2000)
				}
				_, ok = PacketFacts(decodedFactsPacket(fragment, decoder), 7)
				require.False(t, ok, "fragment headers never establish inferred transport authority")
			})
		}
	}
}

func TestPacketFactsChecksIPv6HopByHopAndJumboPayloadLengths(t *testing.T) {
	raw, decoder, _ := transportFrame(t, true, false)
	withHop := func(jumbo bool, payloadBytes int) []byte {
		frame := append([]byte(nil), raw[:40]...)
		frame[6] = byte(layers.IPProtocolIPv6HopByHop)
		hop := []byte{byte(layers.IPProtocolUDP), 0, 1, 4, 0, 0, 0, 0}
		if jumbo {
			hop[2] = layers.IPv6HopByHopOptionJumbogram
			binary.BigEndian.PutUint32(hop[4:8], 65536)
			binary.BigEndian.PutUint16(frame[4:6], 0)
		} else {
			binary.BigEndian.PutUint16(frame[4:6], uint16(payloadBytes))
		}
		frame = append(frame, hop...)
		frame = append(frame, raw[40:]...)
		if payloadBytes > len(frame)-40 {
			frame = append(frame, make([]byte, payloadBytes-(len(frame)-40))...)
		}
		if jumbo {
			binary.BigEndian.PutUint16(frame[52:54], 0)
		}
		return frame
	}
	complete := withHop(false, 8+len(raw)-40)
	_, ok := PacketFacts(decodedFactsPacket(complete, decoder), 7)
	require.True(t, ok, "complete extension header remains part of the IP payload length")
	_, ok = PacketFacts(decodedFactsPacket(complete[:len(complete)-1], decoder), 7)
	require.False(t, ok)
	shortJumbo := withHop(true, 8+len(raw)-40)
	_, ok = PacketFacts(decodedFactsPacket(shortJumbo, decoder), 7)
	require.False(t, ok, "zero IPv6 length must not hide a truncated advertised jumbo payload")
	fullJumbo := withHop(true, 65536)
	_, ok = PacketFacts(decodedFactsPacket(fullJumbo, decoder), 7)
	require.True(t, ok, "an already decoded complete jumbogram retains its endpoint semantics")
}

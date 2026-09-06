package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestOfflinePCAPScanBufferOwnershipAndLargeFallback(t *testing.T) {
	frames := [][]byte{bytes.Repeat([]byte{1}, 128), bytes.Repeat([]byte{2}, 4096), bytes.Repeat([]byte{3}, 64)}
	capture := provenanceCapture(t, layers.LinkTypeEthernet, frames, false, false)
	reader, err := newOfflinePCAPReader(bytes.NewReader(capture))
	require.NoError(t, err)
	scratch := make([]byte, 2048)
	first, _, err := reader.readPacketDataInto(scratch)
	require.NoError(t, err)
	require.Same(t, &scratch[0], &first[0])
	require.Equal(t, len(first), cap(first))
	large, _, err := reader.readPacketDataInto(scratch)
	require.NoError(t, err)
	require.NotSame(t, &scratch[0], &large[0])
	last, _, err := reader.readPacketDataInto(scratch)
	require.NoError(t, err)
	require.Same(t, &scratch[0], &last[0])
	require.Equal(t, frames[1], large, "large fallback owns bytes across subsequent reads")
	require.Equal(t, frames[2], last)
	_, _, err = reader.readPacketDataInto(scratch)
	require.ErrorIs(t, err, io.EOF)

	// The existing public reader always returns independently owned records.
	reader, err = newOfflinePCAPReader(bytes.NewReader(capture))
	require.NoError(t, err)
	var retained [][]byte
	for range frames {
		raw, _, err := reader.ReadPacketData()
		require.NoError(t, err)
		retained = append(retained, raw)
	}
	require.Equal(t, frames, retained)
}

func TestOfflineScanBufferPreservesMixedFragmentInputs(t *testing.T) {
	common := offlineDecoderFixture(t, false, false, 4001, nil, bytes.Repeat([]byte{0xa5}, 128))
	large := offlineDecoderFixture(t, false, false, 4001, nil, bytes.Repeat([]byte{0x5a}, 4096))
	udp := make([]byte, 72)
	binary.BigEndian.PutUint16(udp[:2], 4000)
	binary.BigEndian.PutUint16(udp[2:4], 4001)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], bytes.Repeat([]byte{0x77}, 64))
	v6 := [][]byte{
		fragFrame(t, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 77, 0, true, udp[:32]),
		fragFrame(t, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 77, 4, false, udp[32:]),
	}
	full := offlineDecoderFixture(t, false, false, 4001, nil, bytes.Repeat([]byte{0x77}, 64))
	packet := gopacket.NewPacket(full, layers.LinkTypeEthernet, gopacket.Default)
	ip := packet.NetworkLayer().(*layers.IPv4)
	var v4 [][]byte
	for i, payload := range [][]byte{ip.Payload[:32], ip.Payload[32:]} {
		fragment := *ip
		fragment.Id = 78
		fragment.FragOffset = uint16(i * 4)
		if i == 0 {
			fragment.Flags = layers.IPv4MoreFragments
		}
		wire := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(wire, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packet.LinkLayer().(*layers.Ethernet), &fragment, gopacket.Payload(payload)))
		v4 = append(v4, append([]byte(nil), wire.Bytes()...))
	}
	for name, fragments := range map[string][][]byte{"ipv4": v4, "ipv6": v6} {
		t.Run(name, func(t *testing.T) {
			// The first fragment remains retained while both the reusable small
			// buffer and the independently allocated large-record path advance.
			compareLocatorTransform(t, context.Background(), layers.LinkTypeEthernet, [][]byte{fragments[0], common, large, fragments[1]}, "")
		})
	}
}

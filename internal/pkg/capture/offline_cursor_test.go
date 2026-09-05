package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func cursorFromBytes(t *testing.T, data []byte) (*offlineCursor, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.pcapng")
	require.NoError(t, os.WriteFile(path, data, 0600))
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	c, err := newOfflineCursor(context.Background(), pcaptypes.CreateOfflineInterface(f), "", 0)
	if c != nil {
		t.Cleanup(func() { require.NoError(t, c.Close()) })
	}
	return c, err
}

func TestOfflineCursorPCAPNGDomains(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		interfaces, sections bool
		want                 string
	}{
		{name: "single interface"}, {name: "multiple interfaces", interfaces: true, want: "multiple interfaces"}, {name: "multiple sections", sections: true, want: "multiple sections"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			w, err := pcapgo.NewNgWriter(&out, layers.LinkTypeEthernet)
			require.NoError(t, err)
			if tc.interfaces {
				_, err = w.AddInterface(pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: 65535})
				require.NoError(t, err)
			}
			frame := make([]byte, 60)
			frame[12] = 8
			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), CaptureLength: len(frame), Length: len(frame)}, frame))
			require.NoError(t, w.Flush())
			if tc.sections {
				out.Write(append([]byte(nil), out.Bytes()...))
			}
			c, err := cursorFromBytes(t, out.Bytes())
			if err == nil {
				for {
					_, err = c.Next(context.Background())
					if err != nil {
						break
					}
				}
			}
			if tc.want == "" {
				require.ErrorIs(t, err, io.EOF)
			} else {
				require.ErrorContains(t, err, tc.want)
			}
		})
	}
}

func TestOfflineCursorRejectsMalformedNGFrame(t *testing.T) {
	var out bytes.Buffer
	w, err := pcapgo.NewNgWriter(&out, layers.LinkTypeEthernet)
	require.NoError(t, err)
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), CaptureLength: 60, Length: 60}, make([]byte, 60)))
	require.NoError(t, w.Flush())
	original := out.Bytes()
	for _, kind := range []string{"trailer", "huge captured length", "huge block", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			data := append([]byte(nil), original...)
			off := 0
			for binary.LittleEndian.Uint32(data[off:]) != 6 {
				off += int(binary.LittleEndian.Uint32(data[off+4:]))
			}
			switch kind {
			case "trailer":
				data[len(data)-1] ^= 1
			case "huge captured length":
				binary.LittleEndian.PutUint32(data[off+20:], 0xffffffff)
			case "huge block":
				binary.LittleEndian.PutUint32(data[off+4:], 0xfffffffc)
			case "truncated":
				data = data[:len(data)-5]
			}
			c, err := cursorFromBytes(t, data)
			if err == nil {
				_, err = c.Next(context.Background())
			}
			require.Error(t, err)
			require.NotEqual(t, io.EOF, err)
		})
	}
}

func TestOfflineStreamRejectsPCAPNGTruncatedBlockBodies(t *testing.T) {
	var out bytes.Buffer
	w, err := pcapgo.NewNgWriter(&out, layers.LinkTypeEthernet)
	require.NoError(t, err)
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), CaptureLength: 60, Length: 60}, make([]byte, 60)))
	require.NoError(t, w.Flush())
	complete := append([]byte(nil), out.Bytes()...)
	packetOffset := 0
	for binary.LittleEndian.Uint32(complete[packetOffset:]) != 6 {
		packetOffset += int(binary.LittleEndian.Uint32(complete[packetOffset+4:]))
	}
	for _, tc := range []struct {
		name string
		tail []byte
	}{
		{"packet header without body", complete[packetOffset : packetOffset+8]},
		{"section header without byte order", complete[:8]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "truncated.pcapng")
			data := append(append([]byte(nil), complete...), tc.tail...)
			require.NoError(t, os.WriteFile(path, data, 0600))
			f, err := os.Open(path)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, f.Close()) })
			count := 0
			err = RunOfflineOrderedStream(context.Background(), []pcaptypes.PcapInterface{pcaptypes.CreateOfflineInterface(f)}, "", func(_ context.Context, packets <-chan PacketInfo) error {
				for range packets {
					count++
				}
				return nil
			})
			require.Equal(t, 1, count)
			require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			require.NotErrorIs(t, err, io.EOF, "a truncated block must never be mistaken for successful end of input")
		})
	}
}

func TestOfflineCursorFragmentBudget(t *testing.T) {
	c := &offlineCursor{path: "budget.pcap", ip4: NewIPv4Defragmenter(), ip6: NewIPv6Defragmenter()}
	for i := 0; i <= offlineMaxFragmentFlows; i++ {
		c.ip4.ipFlows[ipv4FlowKey{id: uint16(i)}] = &fragmentList{}
	}
	require.ErrorContains(t, c.checkFragments(), "fragment budget exceeded")
	c.ip4 = NewIPv4Defragmenter()
	f := &fragmentList{}
	f.List.PushBack(&layers.IPv4{BaseLayer: layers.BaseLayer{Payload: make([]byte, offlineMaxFragmentBytes+1)}})
	c.ip4.ipFlows[ipv4FlowKey{}] = f
	c.fragmentEstimate = offlineMaxFragmentBytes + 1
	require.ErrorContains(t, c.checkFragments(), "fragment budget exceeded")
}

func TestOfflineCursorTruncatedPCAPPayload(t *testing.T) {
	var out bytes.Buffer
	w := pcapgo.NewWriter(&out)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), CaptureLength: 60, Length: 60}, make([]byte, 60)))
	data := out.Bytes()
	data = data[:len(data)-60]
	c, err := cursorFromBytes(t, data)
	require.NoError(t, err)
	_, err = c.Next(context.Background())
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestCheckedNGReaderRejectsInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typ   uint32
		code  uint16
		value []byte
	}{
		{"filter", 1, 11, nil}, {"offset", 1, 14, []byte{1}}, {"decimal resolution", 1, 9, []byte{20}}, {"binary resolution", 1, 9, []byte{0xc0}},
		{"statistics start", 5, 2, nil}, {"statistics end", 5, 3, nil}, {"statistics received", 5, 4, nil}, {"statistics dropped", 5, 5, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := 16
			if tc.typ == 5 {
				base = 20
			}
			size := base + 4 + ((len(tc.value) + 3) &^ 3) + 4
			block := make([]byte, size)
			binary.LittleEndian.PutUint32(block, tc.typ)
			binary.LittleEndian.PutUint32(block[4:], uint32(size))
			binary.LittleEndian.PutUint16(block[base:], tc.code)
			binary.LittleEndian.PutUint16(block[base+2:], uint16(len(tc.value)))
			copy(block[base+4:], tc.value)
			binary.LittleEndian.PutUint32(block[size-4:], uint32(size))
			r := &checkedNGReader{reader: bytes.NewReader(block), ctx: context.Background(), order: binary.LittleEndian}
			_, err := io.ReadAll(r)
			require.Error(t, err)
		})
	}
}

func TestOfflineCursorSourceMetadataAndOwnership(t *testing.T) {
	var out bytes.Buffer
	w := pcapgo.NewWriter(&out)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i := 0; i < 2; i++ {
		data := bytes.Repeat([]byte{byte(i + 1)}, 60)
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(int64(i+100), 0), CaptureLength: 60, Length: 80}, data))
	}
	c, err := cursorFromBytes(t, out.Bytes())
	require.NoError(t, err)
	c.sourceIndex = 7
	a, err := c.Next(context.Background())
	require.NoError(t, err)
	b, err := c.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint32(7), a.SourceIndex)
	require.Equal(t, uint64(0), a.SourceSequence)
	require.Equal(t, uint64(1), b.SourceSequence)
	require.Equal(t, uint32(0), a.SourceInterfaceID)
	require.Equal(t, c.path, a.SourcePath)
	require.Equal(t, 60, a.Packet.Metadata().CaptureLength)
	require.Equal(t, 80, a.Packet.Metadata().Length)
	require.Equal(t, bytes.Repeat([]byte{1}, 60), a.Packet.Data())
	b.Packet.Data()[0] = 99
	require.Equal(t, byte(1), a.Packet.Data()[0])
	require.NoError(t, c.Close())
	require.NoError(t, c.Close())
	_, err = c.Next(context.Background())
	require.ErrorContains(t, err, "closed")
}

func TestOfflineCursorESPSourceIsolation(t *testing.T) {
	resetESPNullConfig()
	viper.Reset()
	viper.Set("esp_null", true)
	viper.Set("esp_icv_size", 12)
	t.Cleanup(func() { resetESPNullConfig(); viper.Reset() })
	const spi = uint32(0xa0ff3192)
	sip := []byte("INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	first := buildESPNullIPv6Packet(spi, buildMinimalTCPHeader(5060, 5060, sip), 6, 2, 12)
	// Only a previously confirmed SPI can interpret this continuation: its
	// trailer cannot independently identify TCP, and its body is not SIP.
	continuation := buildESPNullIPv6Packet(spi, buildMinimalTCPHeader(5060, 5060, []byte("continuation body")), 59, 2, 12)
	makeCursor := func(frames ...[]byte) *offlineCursor {
		var out bytes.Buffer
		w := pcapgo.NewWriter(&out)
		require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
		for i, frame := range frames {
			require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(int64(100+i), 0), CaptureLength: len(frame), Length: len(frame)}, frame))
		}
		c, err := cursorFromBytes(t, out.Bytes())
		require.NoError(t, err)
		return c
	}
	sourceA := makeCursor(first, continuation)
	sourceB := makeCursor(continuation)
	initialGlobalEntries := espNullSPICache.Len()
	a, err := sourceA.Next(context.Background())
	require.NoError(t, err)
	require.Nil(t, a.Packet.Layer(layers.LayerTypeIPSecESP))
	require.Equal(t, sip, a.Packet.Layer(layers.LayerTypeTCP).(*layers.TCP).Payload)
	require.Equal(t, layers.LinkTypeEthernet, a.LinkType)
	require.Equal(t, time.Unix(100, 0).UTC(), a.Packet.Metadata().Timestamp)
	require.Equal(t, len(a.Packet.Data()), a.Packet.Metadata().CaptureLength)
	require.Equal(t, len(a.Packet.Data()), a.Packet.Metadata().Length)
	require.Less(t, len(a.Packet.Data()), len(first))
	_, ok := sourceA.spiCache.Load(spi)
	require.True(t, ok)
	b, err := sourceB.Next(context.Background())
	require.NoError(t, err)
	require.NotNil(t, b.Packet.Layer(layers.LayerTypeIPSecESP), "another source cannot reuse source A's SPI confirmation")
	require.Equal(t, continuation, b.Packet.Data())
	require.Zero(t, sourceB.spiCache.Len())
	next, err := sourceA.Next(context.Background())
	require.NoError(t, err)
	require.Nil(t, next.Packet.Layer(layers.LayerTypeIPSecESP), "same-source continuation must use its own SPI cache")
	require.NotNil(t, next.Packet.Layer(layers.LayerTypeTCP))
	require.Equal(t, len(next.Packet.Data()), next.Packet.Metadata().CaptureLength)
	require.Equal(t, len(next.Packet.Data()), next.Packet.Metadata().Length)
	require.Equal(t, initialGlobalEntries, espNullSPICache.Len(), "offline processing must not populate the live SPI cache")
}

func TestOfflineCursorVXLANEffectiveMetadata(t *testing.T) {
	innerIP := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(10, 1, 0, 1), DstIP: net.IPv4(10, 1, 0, 2)}
	innerUDP := &layers.UDP{SrcPort: 5060, DstPort: 5060}
	require.NoError(t, innerUDP.SetNetworkLayerForChecksum(innerIP))
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{0, 1, 2, 3, 4, 6}, EthernetType: layers.EthernetTypeIPv4}
	inner := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	sip := []byte("INVITE sip:bob@example.com SIP/2.0\r\n\r\n")
	require.NoError(t, gopacket.SerializeLayers(inner, opts, eth, innerIP, innerUDP, gopacket.Payload(sip)))
	outerIP := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	outerUDP := &layers.UDP{SrcPort: 45000, DstPort: 4789}
	require.NoError(t, outerUDP.SetNetworkLayerForChecksum(outerIP))
	outer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(outer, opts, outerIP, outerUDP, &layers.VXLAN{ValidIDFlag: true, VNI: 42}, gopacket.Payload(inner.Bytes())))
	var out bytes.Buffer
	w := pcapgo.NewWriter(&out)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeRaw))
	stamp := time.Unix(200, 123000).UTC()
	require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(outer.Bytes()), Length: len(outer.Bytes())}, outer.Bytes()))
	c, err := cursorFromBytes(t, out.Bytes())
	require.NoError(t, err)
	packet, err := c.Next(context.Background())
	require.NoError(t, err)
	require.Equal(t, layers.LinkTypeEthernet, packet.LinkType, "VXLAN inner link type differs from raw-IP source")
	require.Equal(t, inner.Bytes(), packet.Packet.Data())
	require.Equal(t, sip, packet.Packet.Layer(layers.LayerTypeUDP).(*layers.UDP).Payload)
	require.Equal(t, stamp, packet.Packet.Metadata().Timestamp)
	require.Equal(t, len(inner.Bytes()), packet.Packet.Metadata().CaptureLength)
	require.Equal(t, len(inner.Bytes()), packet.Packet.Metadata().Length)
	require.Equal(t, c.path, packet.SourcePath)
}

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func offlineScanVLAN(raw []byte, tags int) []byte {
	result := make([]byte, len(raw)+tags*4)
	copy(result, raw[:12])
	for i := 0; i < tags; i++ {
		binary.BigEndian.PutUint16(result[12+i*4:], uint16(layers.EthernetTypeDot1Q))
		binary.BigEndian.PutUint16(result[14+i*4:], uint16(0xb000+i))
	}
	copy(result[12+tags*4:], raw[12:])
	return result
}

func TestOfflineScanSIPSkipsOnlyTerminalApplication(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			for tags := 0; tags <= 2; tags++ {
				for _, message := range [][]byte{[]byte("INVITE sip:alice@example.test SIP/2.0\r\nCall-ID: scan\r\nContent-Length: 0\r\n\r\n"), []byte("invalid SIP application"), nil} {
					raw := offlineScanVLAN(offlineDecoderFixture(t, ipv6, tcp, 5060, nil, message), tags)
					var decoder offlinePacketDecoder
					got := decoder.decodeScan(raw, layers.LinkTypeEthernet)
					if !tcp {
						require.Same(t, &decoder, got)
					}
					want := gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
					require.Equal(t, want.Data(), got.Data())
					require.Equal(t, want.LinkLayer(), got.LinkLayer())
					require.Equal(t, want.NetworkLayer(), got.NetworkLayer())
					require.Equal(t, want.TransportLayer(), got.TransportLayer())
					if !tcp {
						require.Nil(t, got.ApplicationLayer())
					}
					require.Nil(t, got.Layer(layers.LayerTypeIPv6Fragment))
					require.Nil(t, got.Layer(layers.LayerTypeVXLAN))
					require.Nil(t, got.Layer(layers.LayerTypeIPSecESP))
					// Public/replay decode still exposes the original application/error layer.
					requireOfflineScanFullParity(t, raw, layers.LinkTypeEthernet, decoder.decode(raw, layers.LinkTypeEthernet))
				}
			}
		}
	}
}

func TestOfflineScanSIPFallbackPreservesMalformedHeaders(t *testing.T) {
	full := offlineScanVLAN(offlineDecoderFixture(t, false, false, 5060, nil, []byte("bad SIP")), 2)
	for n := 0; n < 14+8+20+8; n++ {
		var decoder offlinePacketDecoder
		raw := full[:n]
		requireOfflineScanFullParity(t, raw, layers.LinkTypeEthernet, decoder.decodeScan(raw, layers.LinkTypeEthernet))
	}
	for _, raw := range [][]byte{offlineScanVLAN(offlineDecoderFixture(t, false, false, 5060, nil, []byte("bad SIP")), 3), offlineDecoderFixture(t, false, false, 53, nil, []byte("bad DNS")), offlineDecoderFixture(t, false, true, 443, nil, []byte("bad TLS"))} {
		var decoder offlinePacketDecoder
		requireOfflineScanFullParity(t, raw, layers.LinkTypeEthernet, decoder.decodeScan(raw, layers.LinkTypeEthernet))
	}
}

func TestOfflineScanSIPNormalizedReplayAndBPFAgree(t *testing.T) {
	var out bytes.Buffer
	writer := pcapgo.NewWriter(&out)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i := 0; i < 12; i++ {
		raw := offlineScanVLAN(offlineDecoderFixture(t, i%2 == 0, i%3 == 0, 5060, nil, []byte("INVITE sip:alice@example.test SIP/2.0\r\nCall-ID: scan\r\nContent-Length: 0\r\n\r\n")), i%3)
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(int64(100+i), 0), CaptureLength: len(raw), Length: len(raw) + 5}, raw))
	}
	path := filepath.Join(t.TempDir(), "sip-vlan.pcap")
	require.NoError(t, os.WriteFile(path, out.Bytes(), 0600))
	for _, filter := range []string{"", "udp port 5060", "vlan and udp port 5060", "vlan and vlan and port 5060"} {
		compareLocatorSorter(t, context.Background(), []string{path}, filter, "direct")
		compareOfflineScanKeys(t, path, filter)
	}
}

func BenchmarkOfflineScanSIP(b *testing.B) {
	raw := offlineScanVLAN(offlineDecoderFixture(b, false, false, 5060, nil, []byte("INVITE sip:alice@example.test SIP/2.0\r\nCall-ID: scan\r\nFrom: <sip:bob@example.test>\r\nTo: <sip:alice@example.test>\r\nContent-Length: 0\r\n\r\n")), 1)
	for _, scan := range []bool{false, true} {
		name := "full"
		if scan {
			name = "scan"
		}
		b.Run(name, func(b *testing.B) {
			var decoder offlinePacketDecoder
			b.ReportAllocs()
			for range b.N {
				if scan {
					decoder.decodeScan(raw, layers.LinkTypeEthernet)
				} else {
					decoder.decode(raw, layers.LinkTypeEthernet)
				}
			}
		})
	}
}

// Unlike the older single-layer fixture helper, compare repeated VLAN layers
// by position and compare Layer lookups against gopacket's first match.
func requireOfflineScanFullParity(t *testing.T, raw []byte, link layers.LinkType, got gopacket.Packet) {
	t.Helper()
	want := gopacket.NewPacket(raw, link, gopacket.DecodeOptions{NoCopy: true, DecodeStreamsAsDatagrams: true})
	require.Equal(t, want.Data(), got.Data())
	require.Equal(t, want.Metadata(), got.Metadata())
	require.Equal(t, want.String(), got.String())
	require.Equal(t, want.Dump(), got.Dump())
	require.Len(t, got.Layers(), len(want.Layers()))
	for i, layer := range want.Layers() {
		actual := got.Layers()[i]
		require.IsType(t, layer, actual)
		require.Equal(t, layer.LayerContents(), actual.LayerContents())
		require.Equal(t, layer.LayerPayload(), actual.LayerPayload())
		a, err := json.Marshal(layer)
		require.NoError(t, err)
		b, err := json.Marshal(actual)
		require.NoError(t, err)
		require.Equal(t, a, b)
		a, err = json.Marshal(want.Layer(layer.LayerType()))
		require.NoError(t, err)
		b, err = json.Marshal(got.Layer(layer.LayerType()))
		require.NoError(t, err)
		require.Equal(t, a, b)
	}
}

func compareOfflineScanKeys(t *testing.T, path, filter string) {
	t.Helper()
	var want []locatorKey
	for _, scan := range []bool{false, true} {
		registry := sortTestStorage(t, 4<<20).NewBackingRegistry()
		ctx := WithOfflineBackings(context.Background(), registry, offline.BackingSource)
		cursor, err := newOfflineCursor(ctx, offlineTestDevices(t, path)[0], filter, 0)
		require.NoError(t, err)
		var decoder offlinePacketDecoder
		var selected *offlinePacketDecoder
		if scan {
			selected = &decoder
			cursor.scanBuffer = make([]byte, 64<<10)
		}
		count := 0
		for {
			packet, err := cursor.next(ctx, selected)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			key, err := encodeLocatorKey(packet)
			require.NoError(t, err)
			if !scan {
				want = append(want, key)
			} else {
				require.Less(t, count, len(want))
				require.Equal(t, want[count], key)
			}
			count++
		}
		if scan {
			require.Equal(t, len(want), count)
		}
		require.NoError(t, cursor.Close())
		require.NoError(t, registry.Close())
	}
}

func TestOfflineScanSIPCandidateUsesRegisteredPortsAndPrecedence(t *testing.T) {
	const udpPort layers.UDPPort = 42060
	const tcpPort layers.TCPPort = 42061
	oldUDP, oldTCP := udpPort.LayerType(), tcpPort.LayerType()
	layers.RegisterUDPPortLayerType(udpPort, layers.LayerTypeSIP)
	layers.RegisterTCPPortLayerType(tcpPort, layers.LayerTypeSIP)
	t.Cleanup(func() {
		layers.RegisterUDPPortLayerType(udpPort, oldUDP)
		layers.RegisterTCPPortLayerType(tcpPort, oldTCP)
	})
	for _, tcp := range []bool{false, true} {
		port := uint16(udpPort)
		if tcp {
			port = uint16(tcpPort)
		}
		for _, ipv6 := range []bool{false, true} {
			for tags := 0; tags <= 2; tags++ {
				raw := offlineScanVLAN(offlineDecoderFixture(t, ipv6, tcp, port, nil, []byte("malformed SIP")), tags)
				require.True(t, offlineScanSIPCandidate(raw))
				var decoder offlinePacketDecoder
				require.Same(t, &decoder, decoder.decodeScan(raw, layers.LinkTypeEthernet))
				require.Nil(t, decoder.ApplicationLayer())
				offset := 14 + tags*4 + 20
				if ipv6 {
					offset += 20
				}
				// Registered source SIP cannot override a destination DNS decoder.
				binary.BigEndian.PutUint16(raw[offset:offset+2], port)
				binary.BigEndian.PutUint16(raw[offset+2:offset+4], 53)
				require.False(t, offlineScanSIPCandidate(raw))
				requireOfflineScanFullParity(t, raw, layers.LinkTypeEthernet, decoder.decodeScan(raw, layers.LinkTypeEthernet))
				// An unregistered destination does fall back to the source's registry.
				binary.BigEndian.PutUint16(raw[offset+2:offset+4], 42062)
				require.True(t, offlineScanSIPCandidate(raw))
			}
		}
	}
}

func BenchmarkOfflineScanOrdinaryPacket(b *testing.B) {
	raw := offlineDecoderFixture(b, false, true, 42063, nil, []byte("ordinary payload"))
	for _, scan := range []bool{false, true} {
		name := "full"
		if scan {
			name = "scan"
		}
		b.Run(name, func(b *testing.B) {
			var decoder offlinePacketDecoder
			b.ReportAllocs()
			for range b.N {
				if scan {
					decoder.decodeScan(raw, layers.LinkTypeEthernet)
				} else {
					decoder.decode(raw, layers.LinkTypeEthernet)
				}
			}
		})
	}
}

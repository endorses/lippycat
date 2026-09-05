package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineBPFNativeLinkTypes(t *testing.T) {
	for _, tc := range []struct {
		name     string
		linkType layers.LinkType
		ipv6     bool
		prefix   []byte
	}{
		{name: "raw IPv4", linkType: layers.LinkTypeRaw},
		{name: "raw IPv6", linkType: layers.LinkTypeRaw, ipv6: true},
		{name: "loopback", linkType: layers.LinkTypeLoop, prefix: []byte{0, 0, 0, 2}},
		{name: "ATM", linkType: layers.LinkTypeATM_RFC1483, prefix: []byte{0xaa, 0xaa, 3, 0, 0, 0, 8, 0}},
	} {
		for _, format := range []string{"pcap", "pcapng"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				udp := &layers.UDP{SrcPort: 1000, DstPort: 2000}
				var network gopacket.SerializableLayer
				if tc.ipv6 {
					ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
					require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
					network = ip
				} else {
					ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
					require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
					network = ip
				}
				buf := gopacket.NewSerializeBuffer()
				require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, network, udp, gopacket.Payload("accepted")))
				accepted := append(append([]byte(nil), tc.prefix...), buf.Bytes()...)
				rejected := append([]byte(nil), accepted...)
				// Change only the destination port; BPF does not validate checksums.
				binary.BigEndian.PutUint16(rejected[len(rejected)-len("accepted")-6:], 3000)
				var out bytes.Buffer
				var writePacket func(gopacket.CaptureInfo, []byte) error
				var flush func() error
				if format == "pcap" {
					w := pcapgo.NewWriter(&out)
					require.NoError(t, w.WriteFileHeader(65535, tc.linkType))
					writePacket = w.WritePacket
				} else {
					w, err := pcapgo.NewNgWriter(&out, tc.linkType)
					require.NoError(t, err)
					writePacket, flush = w.WritePacket, w.Flush
				}
				stamp := time.Unix(100, 0).UTC()
				for _, frame := range [][]byte{rejected, accepted, rejected} {
					require.NoError(t, writePacket(gopacket.CaptureInfo{Timestamp: stamp, CaptureLength: len(frame), Length: len(frame)}, frame))
				}
				if flush != nil {
					require.NoError(t, flush())
				}
				path := filepath.Join(t.TempDir(), "input."+format)
				require.NoError(t, os.WriteFile(path, out.Bytes(), 0600))
				var got []PacketInfo
				err := RunOfflineOrderedContext(context.Background(), offlineTestDevices(t, path), "udp dst port 2000", func(packets <-chan PacketInfo) {
					for packet := range packets {
						got = append(got, packet)
					}
				})
				require.NoError(t, err)
				require.Len(t, got, 1)
				require.Equal(t, accepted, got[0].Packet.Data())
				require.Equal(t, tc.linkType, got[0].LinkType)
				require.Equal(t, stamp, got[0].Packet.Metadata().Timestamp)
				if tc.linkType != layers.LinkTypeATM_RFC1483 { // No ATM decoder in gopacket.
					require.NotNil(t, got[0].Packet.Layer(layers.LayerTypeUDP))
				}
			})
		}
	}
}

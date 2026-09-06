//go:build tui || all

package tui

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// Exercise the complete compact index and raw export after nested normalization,
// beyond the locator reader's byte-only parity tests.
func TestOfflineCompactIndexerNormalizationOracle(t *testing.T) {
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(192, 0, 2, 1), DstIP: net.IPv4(192, 0, 2, 2)}
	udp := &layers.UDP{SrcPort: 45000, DstPort: 4789}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	outer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(outer, opts, ip, udp, &layers.VXLAN{ValidIDFlag: true, VNI: 42}, gopacket.Payload(goldenDNSPacket(t))))
	payload := outer.Bytes()[20:]
	var v4frags [][]byte
	for i, part := range [][]byte{payload[:32], payload[32:]} {
		fragment := *ip
		fragment.Id, fragment.FragOffset = 123, uint16(i*4)
		if i == 0 {
			fragment.Flags = layers.IPv4MoreFragments
		}
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, opts, &fragment, gopacket.Payload(part)))
		v4frags = append(v4frags, buf.Bytes())
	}
	v6udp := make([]byte, 40)
	binary.BigEndian.PutUint16(v6udp[0:2], 4000)
	binary.BigEndian.PutUint16(v6udp[2:4], 4001)
	binary.BigEndian.PutUint16(v6udp[4:6], uint16(len(v6udp)))
	copy(v6udp[8:], "offline fragmented IPv6 datagram")
	var v6frags [][]byte
	for i, part := range [][]byte{v6udp[:16], v6udp[16:]} {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv6}
		ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolIPv6Fragment, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
		header := make([]byte, 8)
		header[0] = byte(layers.IPProtocolUDP)
		if i == 0 {
			binary.BigEndian.PutUint16(header[2:4], 1)
		} else {
			binary.BigEndian.PutUint16(header[2:4], 16)
		}
		binary.BigEndian.PutUint32(header[4:], 42)
		buf := gopacket.NewSerializeBuffer()
		require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip6, gopacket.Payload(append(header, part...))))
		v6frags = append(v6frags, buf.Bytes())
	}
	for _, tc := range []struct {
		name   string
		link   layers.LinkType
		frames [][]byte
		filter string
	}{
		{"vxlan", layers.LinkTypeRaw, [][]byte{outer.Bytes()}, "udp dst port 4789"},
		{"fragment-vxlan", layers.LinkTypeRaw, v4frags, ""},
		{"ipv6-fragment", layers.LinkTypeEthernet, v6frags, ""},
	} {
		for _, ng := range []bool{false, true} {
			name := tc.name + "/pcap"
			if ng {
				name = tc.name + "/pcapng"
			}
			t.Run(name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "normalized.capture")
				f, err := os.Create(path)
				require.NoError(t, err)
				var write func(gopacket.CaptureInfo, []byte) error
				var flush func() error
				if ng {
					w, err := pcapgo.NewNgWriter(f, tc.link)
					require.NoError(t, err)
					write, flush = w.WritePacket, w.Flush
				} else {
					w := pcapgo.NewWriterNanos(f)
					require.NoError(t, w.WriteFileHeader(65535, tc.link))
					write = w.WritePacket
				}
				for i, data := range tc.frames {
					require.NoError(t, write(gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 123000), CaptureLength: len(data), Length: len(data)}, data))
				}
				if flush != nil {
					require.NoError(t, flush())
				}
				require.NoError(t, f.Close())
				runOfflineCompactOracle(t, OfflineAnalysisConfig{Inputs: []string{path}, BPFFilter: tc.filter, EventCapacity: 32}, indexOfflineCompactDataset)
			})
		}
	}
}

func TestOfflineCompactIndexerSIPExpiryOracle(t *testing.T) {
	at := time.Unix(100, 0)
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: expiry-call\r\nContent-Length: 0\r\n\r\n")
	split := len(message) / 2
	path := writeOfflineSIPExpiryCapture(t,
		offlineSIPPacket(t, 100, []byte("ignored\r\n"), at),
		offlineSIPPacket(t, 200, message[:split], at),
		offlineSIPPacket(t, uint32(200+split), message[split:], at),
		offlineSIPPacket(t, 100, []byte("ignored\r\n"), at),
		offlineSIPPacket(t, 1000, []byte("later\r\n"), at.Add(time.Hour)),
	)
	runOfflineCompactOracle(t, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 32, SIPConfig: *voip.GetConfig()}, indexOfflineCompactDataset)
}

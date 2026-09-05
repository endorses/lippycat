//go:build tui || all

package tui

import (
	"context"
	"net"
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

func TestOfflineIndexerPreservesPacketsWithoutFlowAnalysis(t *testing.T) {
	ethernet := func(kind layers.EthernetType) *layers.Ethernet {
		return &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: kind}
	}
	ipv4 := func(protocol layers.IPProtocol) *layers.IPv4 {
		return &layers.IPv4{Version: 4, TTL: 64, Protocol: protocol, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	}
	ipv6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	icmp6 := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	require.NoError(t, icmp6.SetNetworkLayerForChecksum(ipv6))
	cases := []struct {
		name   string
		packet []gopacket.SerializableLayer
	}{
		{"ARP", []gopacket.SerializableLayer{ethernet(layers.EthernetTypeARP), &layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest, SourceHwAddress: []byte{0, 1, 2, 3, 4, 5}, SourceProtAddress: []byte{192, 0, 2, 1}, DstHwAddress: []byte{0, 0, 0, 0, 0, 0}, DstProtAddress: []byte{192, 0, 2, 2}}}},
		{"unknown Ethernet", []gopacket.SerializableLayer{ethernet(layers.EthernetType(0x88b5)), gopacket.Payload("unknown protocol")}},
		{"ICMPv4", []gopacket.SerializableLayer{ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolICMPv4), &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}, gopacket.Payload("echo")}},
		{"ICMPv6", []gopacket.SerializableLayer{ethernet(layers.EthernetTypeIPv6), ipv6, icmp6, &layers.ICMPv6Echo{Identifier: 1}, gopacket.Payload("echo")}},
		{"IGMP", []gopacket.SerializableLayer{ethernet(layers.EthernetTypeIPv4), ipv4(layers.IPProtocolIGMP), gopacket.Payload([]byte{0x11, 0, 0, 0, 0, 0, 0, 0})}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := gopacket.NewSerializeBuffer()
			require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, tc.packet...))
			raw := append([]byte(nil), buf.Bytes()...)
			ip := ipv4(layers.IPProtocolUDP)
			udp := &layers.UDP{SrcPort: 10000, DstPort: 10001}
			require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
			require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet(layers.EthernetTypeIPv4), ip, udp, gopacket.Payload("ordinary UDP")))
			records := [][]byte{raw, append([]byte(nil), buf.Bytes()...), raw}
			path := filepath.Join(t.TempDir(), "mixed.pcap")
			f, err := os.Create(path)
			require.NoError(t, err)
			w := pcapgo.NewWriter(f)
			require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
			for i, record := range records {
				require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(100+int64(i), 0), CaptureLength: len(record), Length: len(record)}, record))
			}
			require.NoError(t, f.Close())
			session, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 1, OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: 8}, nil)
			require.NoError(t, err)
			defer func() { require.NoError(t, session.Close()) }()
			require.Equal(t, uint64(len(records)), session.Dataset.Count())
			require.Equal(t, uint64(len(records)), session.Dataset.Statistics().Packets)
			for i, record := range records {
				detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 1}, offline.PacketID(i))
				require.NoError(t, err)
				require.Equal(t, record, detail.Packet.RawData)
				require.Equal(t, layers.LinkTypeEthernet, detail.Packet.LinkType)
			}
			require.Positive(t, session.EventStore.Stats().Arrived, "supported UDP must still produce its EOF connection event")
			require.Zero(t, session.EventStore.Stats().TransportLost)
		})
	}
}

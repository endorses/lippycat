package eventanalysis

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/flowid"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func genericPacket(t *testing.T, ts time.Time, packetLayers ...gopacket.SerializableLayer) capture.PacketInfo {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packetLayers...))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	require.Nil(t, pkt.ErrorLayer())
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	return capture.PacketInfo{Packet: pkt, LinkType: layers.LinkTypeEthernet}
}

func genericEthernet(kind layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: kind}
}

func genericARP(t *testing.T, ts time.Time) capture.PacketInfo {
	return genericPacket(t, ts, genericEthernet(layers.EthernetTypeARP), &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: []byte{0, 1, 2, 3, 4, 5}, SourceProtAddress: []byte{192, 0, 2, 1}, DstHwAddress: make([]byte, 6), DstProtAddress: []byte{192, 0, 2, 2},
	})
}

func genericCaptured(info capture.PacketInfo) *data.CapturedPacket {
	return &data.CapturedPacket{
		Data: info.Packet.Data(), TimestampNs: info.Packet.Metadata().Timestamp.UnixNano(), LinkType: uint32(info.LinkType),
		CaptureLength: uint32(info.Packet.Metadata().CaptureLength), OriginalLength: uint32(info.Packet.Metadata().Length),
		Metadata: protocolmeta.Enrich(info.Packet, nil, false),
	}
}

func observeGeneric(t *testing.T, runtime *Runtime, local bool, info capture.PacketInfo) {
	t.Helper()
	source := Source{NodeID: "node", CaptureSource: "generic"}
	if local {
		require.NoError(t, runtime.ObservePacket(source, info))
		return
	}
	raw := genericCaptured(info)
	original := proto.Clone(raw)
	require.NoError(t, runtime.ObserveCaptured(source, []*data.CapturedPacket{raw}))
	require.True(t, proto.Equal(original, raw), "event analysis must not mutate transported metadata")
}

func TestGenericCaptureSkipsUnmodeledPacketsAndContinues(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(map[bool]string{true: "local", false: "transported"}[local], func(t *testing.T) {
			r, d, sink := testRuntime(t, 16)
			defer r.Close()
			ts := time.Unix(100, 0)
			arp := genericARP(t, ts)
			igmp := genericPacket(t, ts, genericEthernet(layers.EthernetTypeIPv4), &layers.IPv4{
				Version: 4, TTL: 1, Protocol: layers.IPProtocolIGMP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("224.0.0.1"),
			}, gopacket.Payload([]byte{0x11, 0, 0, 0, 0, 0, 0, 0}))
			udp := gopacket.NewPacket(udpPacket(t, 41000, 41001), layers.LinkTypeEthernet, gopacket.Default)
			udp.Metadata().Timestamp = ts
			inputs := []capture.PacketInfo{arp, tcpPacket(t, 42000, 42001, 1, true, nil, ts), igmp, {Packet: udp, LinkType: layers.LinkTypeEthernet}, arp}
			if local {
				for _, info := range inputs {
					observeGeneric(t, r, true, info)
				}
			} else {
				batch := make([]*data.CapturedPacket, 0, len(inputs))
				for _, info := range inputs {
					batch = append(batch, genericCaptured(info))
				}
				require.NoError(t, r.ObserveCaptured(Source{NodeID: "node", CaptureSource: "generic"}, batch))
			}
			r.EOF()
			require.NoError(t, d.Close(context.Background()))
			require.Zero(t, r.Stats().Invalid)
			require.Len(t, sink.events, 2, "only TCP and UDP should create connection events")
			protocols := []uint8{sink.events[0].Envelope().Flow.Protocol, sink.events[1].Envelope().Flow.Protocol}
			require.ElementsMatch(t, []uint8{flowid.ProtocolTCP, flowid.ProtocolUDP}, protocols)
		})
	}
}

func TestGenericCaptureICMPEchoIdentity(t *testing.T) {
	for _, local := range []bool{true, false} {
		for _, ipv6 := range []bool{false, true} {
			name := map[bool]string{true: "local", false: "transported"}[local] + "/" + map[bool]string{true: "IPv6", false: "IPv4"}[ipv6]
			t.Run(name, func(t *testing.T) {
				r, d, sink := testRuntime(t, 16)
				defer r.Close()
				var expected events.FlowTuple
				for _, reply := range []bool{false, true} {
					src, dst := "192.0.2.1", "192.0.2.2"
					if ipv6 {
						src, dst = "2001:db8::1", "2001:db8::2"
					}
					if reply {
						src, dst = dst, src
					}
					typeCode := uint8(8)
					if reply {
						typeCode = 0
					}
					protocol := uint8(flowid.ProtocolICMP)
					var info capture.PacketInfo
					if ipv6 {
						protocol, typeCode = flowid.ProtocolICMPv6, 128
						if reply {
							typeCode = 129
						}
						ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
						icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(typeCode, 0)}
						require.NoError(t, icmp.SetNetworkLayerForChecksum(ip))
						info = genericPacket(t, time.Unix(100, 0), genericEthernet(layers.EthernetTypeIPv6), ip, icmp, &layers.ICMPv6Echo{Identifier: 1, SeqNumber: 1}, gopacket.Payload("echo"))
					} else {
						ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: net.ParseIP(src), DstIP: net.ParseIP(dst)}
						info = genericPacket(t, time.Unix(100, 0), genericEthernet(layers.EthernetTypeIPv4), ip, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(typeCode, 0), Id: 1, Seq: 1}, gopacket.Payload("echo"))
					}
					if !reply {
						expected = events.FlowTuple{Protocol: protocol, SourceAddress: netip.MustParseAddr(src), DestinationAddress: netip.MustParseAddr(dst), SourcePort: uint16(typeCode)}
					}
					observeGeneric(t, r, local, info)
					// Flush connection summaries while retaining flow identities so
					// request and reply envelopes can be compared directly.
					r.EOF()
				}
				require.NoError(t, d.Close(context.Background()))
				require.Zero(t, r.Stats().Invalid)
				require.Len(t, sink.events, 2)
				first, second := sink.events[0].Envelope(), sink.events[1].Envelope()
				require.Equal(t, expected, first.Flow)
				require.NotEmpty(t, first.UID)
				require.Equal(t, first.UID, second.UID)
				communityID, err := flowid.CommunityID(expected, 0)
				require.NoError(t, err)
				require.Equal(t, communityID, first.CommunityID)
				require.Equal(t, first.CommunityID, second.CommunityID)
			})
		}
	}
}

func TestGenericCapturePreservesInvalidMetadataErrors(t *testing.T) {
	for _, field := range []string{"source", "transport"} {
		t.Run(field, func(t *testing.T) {
			r, d, _ := testRuntime(t, 16)
			defer r.Close()
			info := tcpPacket(t, 42000, 42001, 1, true, nil, time.Unix(100, 0))
			raw := genericCaptured(info)
			if field == "source" {
				raw.Metadata.SrcIp = ""
			} else {
				raw.Metadata.Transport = "invalid"
			}
			require.Error(t, r.ObserveCaptured(Source{NodeID: "node"}, []*data.CapturedPacket{raw}))
			require.Equal(t, uint64(1), r.Stats().Invalid)
			require.NoError(t, d.Close(context.Background()))
		})
	}
}

func TestGenericCaptureDoesNotSkipTruncatedFrames(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(map[bool]string{true: "local", false: "transported"}[local], func(t *testing.T) {
			r, d, _ := testRuntime(t, 16)
			defer r.Close()
			pkt := gopacket.NewPacket([]byte{0, 1, 2}, layers.LinkTypeEthernet, gopacket.Default)
			require.NotNil(t, pkt.ErrorLayer())
			info := capture.PacketInfo{Packet: pkt, LinkType: layers.LinkTypeEthernet}
			var err error
			if local {
				err = r.ObservePacket(Source{NodeID: "node"}, info)
			} else {
				err = r.ObserveCaptured(Source{NodeID: "node"}, []*data.CapturedPacket{genericCaptured(info)})
			}
			require.Error(t, err)
			require.Equal(t, uint64(1), r.Stats().Invalid)
			require.NoError(t, d.Close(context.Background()))
		})
	}
}

func TestGenericCaptureSkippedPacketAdvancesExpiry(t *testing.T) {
	for _, local := range []bool{true, false} {
		t.Run(map[bool]string{true: "local", false: "transported"}[local], func(t *testing.T) {
			r, d, sink := testRuntime(t, 16)
			defer r.Close()
			observeGeneric(t, r, local, tcpPacket(t, 42000, 42001, 1, true, nil, time.Unix(100, 0)))
			observeGeneric(t, r, local, genericARP(t, time.Unix(1000, 0)))
			// Close the dispatcher before runtime EOF: the ARP timestamp itself
			// must expire the earlier connection.
			require.NoError(t, d.Close(context.Background()))
			require.Len(t, sink.events, 1)
			require.Equal(t, events.KindConn, sink.events[0].Kind())
			require.Zero(t, r.Stats().Invalid)
		})
	}
}

// genericProtocolPacket allows a payload decoder to be absent or fail.
func genericProtocolPacket(t *testing.T, packetLayers ...gopacket.SerializableLayer) capture.PacketInfo {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, packetLayers...))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(100, 0), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
	return capture.PacketInfo{Packet: pkt, LinkType: layers.LinkTypeEthernet}
}

func TestGenericCaptureSkipsNonIPDecoderFailures(t *testing.T) {
	const unknown = layers.EthernetType(0x88b5)
	cases := []struct {
		name   string
		layers []gopacket.SerializableLayer
	}{
		{"unknown EtherType", []gopacket.SerializableLayer{genericEthernet(unknown), gopacket.Payload("unsupported protocol")}},
		{"VLAN unknown EtherType", []gopacket.SerializableLayer{genericEthernet(layers.EthernetTypeDot1Q), &layers.Dot1Q{VLANIdentifier: 7, Type: unknown}, gopacket.Payload("unsupported protocol")}},
		{"stacked VLAN unknown EtherType", []gopacket.SerializableLayer{genericEthernet(layers.EthernetTypeQinQ), &layers.Dot1Q{VLANIdentifier: 7, Type: layers.EthernetTypeDot1Q}, &layers.Dot1Q{VLANIdentifier: 8, Type: unknown}, gopacket.Payload("unsupported protocol")}},
		{"LLDP decoder failure", []gopacket.SerializableLayer{genericEthernet(layers.EthernetTypeLinkLayerDiscovery), gopacket.Payload([]byte{0x02, 0xff})}},
	}
	for _, tc := range cases {
		for _, local := range []bool{true, false} {
			t.Run(tc.name+"/"+map[bool]string{true: "local", false: "transported"}[local], func(t *testing.T) {
				r, d, sink := testRuntime(t, 16)
				defer r.Close()
				info := genericProtocolPacket(t, tc.layers...)
				if tc.name == "unknown EtherType" || tc.name == "LLDP decoder failure" {
					require.NotNil(t, info.Packet.ErrorLayer())
				}
				require.Nil(t, info.Packet.NetworkLayer())
				observeGeneric(t, r, local, info)
				observeGeneric(t, r, local, tcpPacket(t, 42000, 42001, 1, true, nil, time.Unix(100, 0)))
				r.EOF()
				require.NoError(t, d.Close(context.Background()))
				require.Zero(t, r.Stats().Invalid)
				require.Len(t, sink.events, 1, "unsupported link traffic must not prevent valid TCP analysis")
				require.Equal(t, uint8(flowid.ProtocolTCP), sink.events[0].Envelope().Flow.Protocol)
			})
		}
	}
}

func TestGenericCapturePreservesMalformedIPDecoderErrors(t *testing.T) {
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	icmp := genericProtocolPacket(t, genericEthernet(layers.EthernetTypeIPv4), ip, gopacket.Payload([]byte{8, 0}))
	truncatedIP := append([]byte(nil), icmp.Packet.Data()[:17]...)
	cases := []struct {
		name string
		data []byte
	}{
		{"truncated ICMP", icmp.Packet.Data()},
		{"truncated IP", truncatedIP},
	}
	for _, tc := range cases {
		for _, local := range []bool{true, false} {
			t.Run(tc.name+"/"+map[bool]string{true: "local", false: "transported"}[local], func(t *testing.T) {
				r, d, _ := testRuntime(t, 16)
				defer r.Close()
				pkt := gopacket.NewPacket(tc.data, layers.LinkTypeEthernet, gopacket.Default)
				require.NotNil(t, pkt.ErrorLayer())
				info := capture.PacketInfo{Packet: pkt, LinkType: layers.LinkTypeEthernet}
				var err error
				if local {
					err = r.ObservePacket(Source{NodeID: "node"}, info)
				} else {
					err = r.ObserveCaptured(Source{NodeID: "node"}, []*data.CapturedPacket{genericCaptured(info)})
				}
				require.Error(t, err)
				require.Equal(t, uint64(1), r.Stats().Invalid)
				require.NoError(t, d.Close(context.Background()))
			})
		}
	}
}

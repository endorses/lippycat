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
)

func inventoryTCPPacket(t *testing.T, client, server string, reverse bool, seq, ack uint32, flags string, payload string, at time.Time) capture.PacketInfo {
	t.Helper()
	src, dst := net.ParseIP(client), net.ParseIP(server)
	sp, dp := layers.TCPPort(42000), layers.TCPPort(80)
	if reverse {
		src, dst, sp, dp = dst, src, dp, sp
	}
	ether := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}}
	tcp := &layers.TCP{SrcPort: sp, DstPort: dp, Seq: seq, Ack: ack, Window: 65535}
	for _, flag := range flags {
		switch flag {
		case 'S':
			tcp.SYN = true
		case 'A':
			tcp.ACK = true
		case 'R':
			tcp.RST = true
		case 'P':
			tcp.PSH = true
		}
	}
	var network gopacket.SerializableLayer
	if src.To4() != nil {
		ether.EthernetType = layers.EthernetTypeIPv4
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		network = ip
	} else {
		ether.EthernetType = layers.EthernetTypeIPv6
		ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
		network = ip
	}
	buffer := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ether, network, tcp, gopacket.Payload(payload)))
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	require.Nil(t, packet.ErrorLayer())
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(buffer.Bytes()), Length: len(buffer.Bytes())}
	return capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet}
}

func TestInventoryTCPRequiresHandshakeAndParsedService(t *testing.T) {
	for _, network := range []struct{ name, client, server, cidr string }{
		{"ipv4", "192.0.2.20", "192.0.2.80", "192.0.2.0/24"},
		{"ipv6", "2001:db8::20", "2001:db8::80", "2001:db8::/32"},
		{"ipv6_linklocal", "fe80::20", "fe80::80", "fe80::/64"},
		{"ipv4_linklocal", "169.254.1.20", "169.254.1.80", "169.254.0.0/16"},
	} {
		for _, scenario := range []string{"http", "lone_syn", "refused", "midstream", "bad_ack", "cached_http"} {
			t.Run(network.name+"/"+scenario, func(t *testing.T) {
				r, dispatcher, sink := inventoryRuntime(t)
				r.cfg.Policy.Inventory.LocalCIDRs = []string{network.cidr}
				require.NoError(t, r.Reset())
				t.Cleanup(func() {
					r.Close()
					require.NoError(t, dispatcher.Close(context.Background()))
				})
				source := Source{NodeID: "tcp-sensor", CaptureSource: "tcp-fixture", CaptureScope: events.CaptureScopeFiltered, Partial: true}
				at := time.Unix(1800000000, 0)
				observe := func(reverse bool, seq, ack uint32, flags, payload string) {
					p := inventoryTCPPacket(t, network.client, network.server, reverse, seq, ack, flags, payload, at)
					at = at.Add(time.Millisecond)
					if scenario == "cached_http" {
						meta := protocolmeta.Enrich(p.Packet, nil, false)
						meta.Protocol = "HTTP"
						meta.Http = nil
						ci := p.Packet.Metadata().CaptureInfo
						require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{{Data: p.Packet.Data(), TimestampNs: ci.Timestamp.UnixNano(), LinkType: uint32(p.LinkType), Metadata: meta, CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length)}}))
					} else {
						require.NoError(t, r.ObservePacket(source, p))
					}
				}
				if scenario != "midstream" {
					observe(false, 100, 0, "S", "")
					if scenario == "refused" {
						observe(true, 500, 101, "RA", "")
					} else if scenario != "lone_syn" {
						observe(true, 500, 101, "SA", "")
						ack := uint32(501)
						if scenario == "bad_ack" {
							ack++
						}
						observe(false, 101, ack, "A", "")
					}
				}
				if scenario == "http" || scenario == "midstream" || scenario == "bad_ack" {
					request := "GET /inventory HTTP/1.1\r\nHost: example.test\r\n\r\n"
					ack := uint32(501)
					if scenario == "bad_ack" {
						ack++ // The data packet must not accidentally complete the handshake.
					}
					observe(false, 101, ack, "PA", request)
					observe(true, 501, 101+uint32(len(request)), "PA", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
				}
				r.Close()
				require.NoError(t, dispatcher.Close(context.Background()))
				parsedRequests := 0
				for _, event := range sink.events {
					if http, ok := event.(events.HTTPEvent); ok && http.Method == "GET" {
						require.Equal(t, "/inventory", http.URI)
						parsedRequests++
					}
				}
				if scenario == "http" || scenario == "midstream" || scenario == "bad_ack" {
					require.Equal(t, 1, parsedRequests)
				} else {
					require.Zero(t, parsedRequests)
				}
				got := inventoryEvents(sink)
				wantHosts, wantServices := 0, 0
				if scenario == "http" || scenario == "cached_http" {
					wantHosts = 2
				}
				if scenario == "http" {
					wantServices = 1
				}
				require.Len(t, got, wantHosts+wantServices)
				var hosts []netip.Addr
				services := 0
				for _, event := range got {
					require.Equal(t, events.CaptureScopeFiltered, event.Envelope().CaptureScope)
					require.True(t, event.Envelope().Partial)
					require.NotEmpty(t, event.Envelope().EventID)
					switch e := event.(type) {
					case events.KnownHostEvent:
						hosts = append(hosts, e.Host)
						require.Equal(t, events.EvidenceTCPHandshake, e.Evidence)
					case events.KnownServiceEvent:
						services++
						require.Equal(t, netip.MustParseAddr(network.server), e.Host)
						require.Equal(t, uint16(80), e.Port)
						require.Equal(t, uint8(flowid.ProtocolTCP), e.Transport)
						require.Equal(t, "http", e.Protocol)
						require.Equal(t, events.EvidenceTCPHandshake, e.Evidence)
					}
				}
				require.Len(t, hosts, wantHosts)
				require.Equal(t, wantServices, services)
				if wantHosts != 0 {
					require.ElementsMatch(t, []netip.Addr{netip.MustParseAddr(network.client), netip.MustParseAddr(network.server)}, hosts)
				}
			})
		}
	}
}

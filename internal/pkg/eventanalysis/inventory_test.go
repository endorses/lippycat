package eventanalysis

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func inventoryRuntime(t *testing.T) (*Runtime, *events.Dispatcher, *memorySink) {
	t.Helper()
	r, d, s := testRuntime(t, 256)
	policy := eventconfig.Default()
	policy.Inventory.Enabled = true
	policy.Inventory.LocalCIDRs = []string{"192.0.2.0/24"}
	r.cfg.Policy = &policy
	require.NoError(t, r.Reset())
	return r, d, s
}
func inventoryEvents(s *memorySink) []events.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []events.Event
	for _, ev := range s.events {
		if ev.Kind() == events.KindKnownHost || ev.Kind() == events.KindKnownService {
			out = append(out, ev)
		}
	}
	return out
}
func TestInventoryRuntimeLifecycle(t *testing.T) {
	packets, err := eventfixture.NetworkMessages()
	require.NoError(t, err)
	for _, boundary := range []string{"eof", "reset", "close", "expiry", "eviction"} {
		t.Run(boundary, func(t *testing.T) {
			r, d, s := inventoryRuntime(t)
			if boundary == "eviction" {
				r.cfg.Connections.MaxFlows = 1
				require.NoError(t, r.Reset())
			}
			source := Source{NodeID: "node", CaptureSource: "fixture", CaptureScope: events.CaptureScopeFiltered}
			for _, p := range packets[3:] {
				require.NoError(t, r.ObservePacket(source, p))
			}
			switch boundary {
			case "eof":
				r.EOF()
			case "reset":
				require.NoError(t, r.Reset())
			case "close":
				r.Close()
			case "expiry":
				r.Expire(packets[4].Packet.Metadata().Timestamp.Add(6 * time.Minute))
			case "eviction":
				other, err := eventfixture.NetworkDatagram("192.0.2.10", "192.0.2.11", 41000, 41001, []byte{1}, packets[4].Packet.Metadata().Timestamp.Add(time.Second))
				require.NoError(t, err)
				require.NoError(t, r.ObservePacket(source, other))
			}
			r.Close()
			require.NoError(t, d.Close(context.Background()))
			inventory := inventoryEvents(s)
			require.Len(t, inventory, 3)
			hosts := 0
			services := 0
			for _, ev := range inventory {
				require.Equal(t, events.CaptureScopeFiltered, ev.Envelope().CaptureScope)
				require.True(t, ev.Envelope().Partial)
				require.True(t, packets[3].Packet.Metadata().Timestamp.Equal(ev.Envelope().Timestamp))
				require.NotEmpty(t, ev.Envelope().EventID)
				switch e := ev.(type) {
				case events.KnownHostEvent:
					hosts++
					require.Equal(t, events.EvidenceUDPBidirectional, e.Evidence)
				case events.KnownServiceEvent:
					services++
					require.Equal(t, "ntp", e.Protocol)
					require.Equal(t, uint16(123), e.Port)
					require.Equal(t, "192.0.2.123", e.Host.String())
				}
			}
			require.Equal(t, 2, hosts)
			require.Equal(t, 1, services)
			for _, ev := range s.events {
				if conn, ok := ev.(events.ConnEvent); ok && conn.Envelope().Flow.SourcePort == 40000 {
					require.True(t, conn.LocalOrigin)
					require.True(t, conn.LocalResponse)
					require.Empty(t, conn.AnalysisScope)
					require.Empty(t, conn.Evidence)
				}
			}
		})
	}
}

func TestInventoryRuntimeRejectsUnprovenAndLateServices(t *testing.T) {
	packets, err := eventfixture.NetworkMessages()
	require.NoError(t, err)
	for _, mode := range []string{"disabled", "one_way", "different_epoch", "late", "spoofed_metadata", "fake_ntp"} {
		t.Run(mode, func(t *testing.T) {
			r, d, s := inventoryRuntime(t)
			if mode == "disabled" {
				r.cfg.Policy.Inventory.Enabled = false
				require.NoError(t, r.Reset())
			}
			source := Source{NodeID: "node", CaptureSource: "fixture", CaptureEpoch: "one"}
			if mode == "late" {
				r.Expire(packets[4].Packet.Metadata().Timestamp.Add(time.Hour))
			}
			for i, p := range packets[3:] {
				if mode == "one_way" && i == 1 {
					break
				}
				if mode == "different_epoch" && i == 1 {
					source.CaptureEpoch = "two"
				}
				if mode == "fake_ntp" {
					f := p.Packet.NetworkLayer().(*layers.IPv4)
					u := p.Packet.TransportLayer().(*layers.UDP)
					p, err = eventfixture.NetworkDatagram(f.SrcIP.String(), f.DstIP.String(), uint16(u.SrcPort), uint16(u.DstPort), []byte{1, 2, 3}, p.Packet.Metadata().Timestamp)
					require.NoError(t, err)
				}
				if mode == "spoofed_metadata" {
					meta := protocolmeta.Enrich(p.Packet, nil, false)
					meta.SrcIp = "192.0.2.200"
					ci := p.Packet.Metadata().CaptureInfo
					require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{{Data: p.Packet.Data(), TimestampNs: ci.Timestamp.UnixNano(), LinkType: uint32(p.LinkType), Metadata: meta, CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length)}}))
				} else {
					require.NoError(t, r.ObservePacket(source, p))
				}
			}
			r.Close()
			require.NoError(t, d.Close(context.Background()))
			got := inventoryEvents(s)
			require.Empty(t, got)
		})
	}
}

func dnsInventoryPacket(t *testing.T, at time.Time, response bool, id uint16, name string) capture.PacketInfo {
	t.Helper()
	m := &layers.DNS{ID: id, QR: response, Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}}
	b := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true}, m))
	src, dst, sp, dp := "192.0.2.20", "192.0.2.53", uint16(40000), uint16(53)
	if response {
		src, dst, sp, dp = dst, src, dp, sp
	}
	p, err := eventfixture.NetworkDatagram(src, dst, sp, dp, b.Bytes(), at)
	require.NoError(t, err)
	return p
}
func TestInventoryRuntimeDNSActualExchange(t *testing.T) {
	for _, name := range []string{"example.test", "different.test"} {
		t.Run(name, func(t *testing.T) {
			r, d, s := inventoryRuntime(t)
			source := Source{NodeID: "node"}
			at := time.Unix(1800000000, 0)
			require.NoError(t, r.ObservePacket(source, dnsInventoryPacket(t, at, false, 17, "example.test")))
			require.NoError(t, r.ObservePacket(source, dnsInventoryPacket(t, at.Add(time.Second), true, 17, name)))
			r.Close()
			require.NoError(t, d.Close(context.Background()))
			got := inventoryEvents(s)
			if name == "example.test" {
				require.Len(t, got, 3)
				require.Equal(t, "dns", got[2].(events.KnownServiceEvent).Protocol)
			} else {
				require.Len(t, got, 2)
			}
		})
	}
}

func TestInventoryRuntimeDHCPUnicastAndRelay(t *testing.T) {
	packets, err := eventfixture.NetworkMessages()
	require.NoError(t, err)
	for _, relay := range []bool{false, true} {
		t.Run(map[bool]string{false: "unicast", true: "relay"}[relay], func(t *testing.T) {
			r, d, s := inventoryRuntime(t)
			source := Source{NodeID: "node"}
			for i, p := range packets[:2] {
				payload := append([]byte(nil), p.Packet.TransportLayer().(*layers.UDP).Payload...)
				if relay {
					binary.BigEndian.PutUint32(payload[24:28], 0xc0000202)
				}
				src, dst, sp, dp := "192.0.2.20", "192.0.2.1", uint16(68), uint16(67)
				if i == 1 {
					src, dst, sp, dp = dst, src, dp, sp
				}
				p, err = eventfixture.NetworkDatagram(src, dst, sp, dp, payload, p.Packet.Metadata().Timestamp)
				require.NoError(t, err)
				require.NoError(t, r.ObservePacket(source, p))
			}
			r.Close()
			require.NoError(t, d.Close(context.Background()))
			got := inventoryEvents(s)
			if relay {
				require.Len(t, got, 2)
			} else {
				require.Len(t, got, 3)
				require.Equal(t, "dhcp", got[2].(events.KnownServiceEvent).Protocol)
			}
		})
	}
}

func TestNetworkDecodedTruncationIsPartialAndCannotProveInventory(t *testing.T) {
	messages, err := eventfixture.NetworkMessages()
	require.NoError(t, err)
	for _, protocol := range []string{"dhcp", "ntp"} {
		for _, transported := range []bool{false, true} {
			for _, declared := range []string{"ip", "udp"} {
				for _, broken := range []int{0, 1} {
					t.Run(fmt.Sprintf("%s/transported=%t/%s/message=%d", protocol, transported, declared, broken), func(t *testing.T) {
						r, d, s := inventoryRuntime(t)
						packets := messages[:2]
						kind := events.KindDHCP
						if protocol == "ntp" {
							packets = messages[3:]
							kind = events.KindNTP
						}
						for i, info := range packets {
							if i == broken {
								bytes := append([]byte(nil), info.Packet.Data()...)
								offset := 14 + 2
								if declared == "udp" {
									offset = 14 + 20 + 4
								}
								binary.BigEndian.PutUint16(bytes[offset:offset+2], binary.BigEndian.Uint16(bytes[offset:offset+2])+8)
								packet := gopacket.NewPacket(bytes, layers.LinkTypeEthernet, gopacket.Default)
								packet.Metadata().CaptureInfo = info.Packet.Metadata().CaptureInfo
								require.True(t, packet.Metadata().Truncated)
								require.Nil(t, packet.ErrorLayer())
								info.Packet = packet
							}
							source := Source{NodeID: "node", CaptureSource: "fixture"}
							if transported {
								ci := info.Packet.Metadata().CaptureInfo
								metadata := protocolmeta.Enrich(info.Packet, nil, false)
								require.NoError(t, r.ObserveCaptured(source, []*data.CapturedPacket{{Data: info.Packet.Data(), LinkType: uint32(info.LinkType), TimestampNs: ci.Timestamp.UnixNano(), CaptureLength: uint32(ci.CaptureLength), OriginalLength: uint32(ci.Length), Metadata: metadata}}))
							} else {
								require.NoError(t, r.ObservePacket(source, info))
							}
						}
						r.Close()
						require.NoError(t, d.Close(context.Background()))
						var observed []events.Event
						for _, event := range s.events {
							if event.Kind() == kind {
								observed = append(observed, event)
							}
						}
						require.Len(t, observed, 2)
						require.True(t, observed[broken].Envelope().Partial)
						switch event := observed[broken].(type) {
						case events.DHCPEvent:
							require.True(t, event.Truncated)
							require.NotEqual(t, events.AssociationUnique, event.Association)
						case events.NTPEvent:
							require.True(t, event.Truncated)
							require.NotEqual(t, events.AssociationUnique, event.Association)
						}
						switch response := observed[1].(type) {
						case events.DHCPEvent:
							require.NotEqual(t, events.AssociationUnique, response.Association)
						case events.NTPEvent:
							require.NotEqual(t, events.AssociationUnique, response.Association)
						}
						require.Empty(t, inventoryEvents(s))
					})
				}
			}
		}
	}
}

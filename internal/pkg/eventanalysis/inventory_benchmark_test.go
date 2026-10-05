package eventanalysis

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type benchmarkDiscardSink struct{}

func (benchmarkDiscardSink) HandleEvent(context.Context, events.Event) error { return nil }
func (benchmarkDiscardSink) Flush(context.Context) error                     { return nil }
func (benchmarkDiscardSink) Close(context.Context) error                     { return nil }

// BenchmarkInventoryAnalysis reconstructs a synthetic workload; it is not the
// unavailable original review harness. One operation is one observed packet.
func BenchmarkInventoryAnalysis(b *testing.B) {
	const flows = 2048
	packets := make([]capture.PacketInfo, 0, flows*2)
	for i := 0; i < flows; i++ {
		for direction := 0; direction < 2; direction++ {
			src, dst := net.IPv4(192, 0, 2, 1), net.IPv4(198, 51, 100, 2)
			sport, dport := layers.UDPPort(10000+i), layers.UDPPort(30000)
			if direction == 1 {
				src, dst = dst, src
				sport, dport = dport, sport
			}
			eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
			ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, SrcIP: src, DstIP: dst, Protocol: layers.IPProtocolUDP}
			udp := &layers.UDP{SrcPort: sport, DstPort: dport}
			if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
				b.Fatal(err)
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp, gopacket.Payload(make([]byte, 172))); err != nil {
				b.Fatal(err)
			}
			p := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
			p.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(1000, 0), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
			packets = append(packets, capture.PacketInfo{Packet: p, Interface: "fixture0", LinkType: layers.LinkTypeEthernet})
		}
	}
	source := Source{NodeID: "synthetic-node", CaptureSource: "pcap", CaptureEpoch: "synthetic-capture", InputFile: "synthetic.pcap"}
	for _, enabled := range []bool{false, true} {
		for _, mode := range []string{"discovery", "steady"} {
			b.Run(fmt.Sprintf("inventory=%t/%s", enabled, mode), func(b *testing.B) {
				policy := eventconfig.Default()
				policy.Inventory.Enabled = enabled
				d, err := events.NewDispatcher(events.Config{QueueSize: 8192, SinkQueueSize: 8192})
				if err != nil {
					b.Fatal(err)
				}
				if err = d.Register(benchmarkDiscardSink{}); err != nil {
					b.Fatal(err)
				}
				if err = d.Start(context.Background()); err != nil {
					b.Fatal(err)
				}
				r, err := New(Config{Policy: &policy, Dispatcher: d, AnalysisEpoch: "synthetic-analysis", LosslessDelivery: true})
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() {
					r.EOF()
					if err := d.Close(context.Background()); err != nil {
						b.Error(err)
					}
				})
				if mode == "steady" {
					for _, p := range packets {
						if err := r.ObservePacket(source, p); err != nil {
							b.Fatal(err)
						}
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if mode == "discovery" && i > 0 && i%len(packets) == 0 {
						b.StopTimer()
						if err := r.resetState(); err != nil {
							b.Fatal(err)
						}
						b.StartTimer()
					}
					if err := r.ObservePacket(source, packets[i%len(packets)]); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

package enrichment

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const enrichmentBenchmarkFlows = 4095

func BenchmarkEnricher_MixedHighCardinality(b *testing.B) {
	det := detector.New()
	b.Cleanup(det.Shutdown)
	det.RegisterSignature(application.NewDNSSignature())
	det.RegisterSignature(application.NewHTTPSignature())

	packets := make([]*data.CapturedPacket, 0, enrichmentBenchmarkFlows)
	for i := 0; i < enrichmentBenchmarkFlows; i++ {
		var payload []byte
		var protocol layers.IPProtocol
		var dstPort uint16
		switch i % 3 {
		case 0:
			payload = []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
			protocol, dstPort = layers.IPProtocolUDP, 53
		case 1:
			payload = []byte("GET /resource HTTP/1.1\r\nHost: example.test\r\n\r\n")
			protocol, dstPort = layers.IPProtocolTCP, 80
		default:
			payload = []byte("synthetic-unrecognized-payload")
			protocol, dstPort = layers.IPProtocolTCP, 9000
		}
		packets = append(packets, &data.CapturedPacket{
			Data:     serializeEnrichmentPacket(i, protocol, 20000+uint16(i%20000), dstPort, payload),
			LinkType: uint32(layers.LinkTypeEthernet),
		})
	}

	enricher := NewEnricher(det)
	assertEnrichmentBenchmarkFixtures(b, enricher, packets[:3])
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := packets[i%len(packets)]
		packet.Metadata = nil
		enricher.Enrich([]*data.CapturedPacket{packet})
	}
}

func assertEnrichmentBenchmarkFixtures(b *testing.B, enricher *Enricher, packets []*data.CapturedPacket) {
	b.Helper()
	for _, packet := range packets {
		packet.Metadata = nil
		enricher.Enrich([]*data.CapturedPacket{packet})
	}
	if packets[0].Metadata == nil || packets[0].Metadata.Protocol != "DNS" {
		b.Fatalf("DNS fixture detected as %#v", packets[0].Metadata)
	}
	if packets[1].Metadata == nil || packets[1].Metadata.Protocol != "HTTP" {
		b.Fatalf("HTTP fixture detected as %#v", packets[1].Metadata)
	}
	if packets[2].Metadata != nil {
		b.Fatalf("unknown fixture unexpectedly enriched as %#v", packets[2].Metadata)
	}
}

func serializeEnrichmentPacket(flow int, protocol layers.IPProtocol, srcPort, dstPort uint16, payload []byte) []byte {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ethernet := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: protocol,
		SrcIP:    benchmarkIPv4(0x0a000001 + uint32(flow)),
		DstIP:    benchmarkIPv4(0xc0000201 + uint32(flow%200)),
	}
	var err error
	if protocol == layers.IPProtocolUDP {
		udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
		_ = udp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(buffer, options, ethernet, ip, udp, gopacket.Payload(payload))
	} else {
		tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), ACK: true}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		err = gopacket.SerializeLayers(buffer, options, ethernet, ip, tcp, gopacket.Payload(payload))
	}
	if err != nil {
		panic(err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func benchmarkIPv4(value uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, value)
	return ip
}

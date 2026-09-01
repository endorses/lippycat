package detector_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/vpn"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const benchmarkFlowCardinality = 4096

func BenchmarkDetector_SingleSignature(b *testing.B) {
	det := detector.NewDetector()
	b.Cleanup(det.Shutdown)
	det.RegisterSignature(application.NewDNSSignature())
	packet := createDNSPacket(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

func BenchmarkDetector_MultipleSignatures(b *testing.B) {
	det := createBenchDetector(b)
	packets := []gopacket.Packet{createDNSPacket(0), createHTTPPacket(1), createRTPPacket(2)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, packet := range packets {
			_ = det.Detect(packet)
		}
	}
}

func BenchmarkDetector_BuildContext(b *testing.B) {
	det := detector.NewDetector()
	b.Cleanup(det.Shutdown)
	packet := createHTTPPacket(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.BuildContext(packet)
	}
}

func BenchmarkDetector_Cache(b *testing.B) {
	b.Run("hit", func(b *testing.B) {
		det := createBenchDetector(b)
		packet := createTLSPacket(0)
		_ = det.Detect(packet)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = det.Detect(packet)
		}
	})
	b.Run("high_cardinality_flows", func(b *testing.B) {
		det := createBenchDetector(b)
		packets := createFlowPackets(benchmarkFlowCardinality, createTLSPacket)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = det.Detect(packets[i%len(packets)])
		}
	})
}

func BenchmarkDetectionCache(b *testing.B) {
	result := &signatures.DetectionResult{Protocol: "TLS", CacheStrategy: signatures.CacheSession}
	b.Run("hit", func(b *testing.B) {
		cache := detector.NewDetectionCacheWithMaxEntries(time.Hour, 1024)
		b.Cleanup(cache.Close)
		cache.Set("flow-1", result)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = cache.Get("flow-1")
		}
	})
	b.Run("miss_churn", func(b *testing.B) {
		const capacity = 1024
		cache := detector.NewDetectionCacheWithMaxEntries(time.Hour, capacity)
		b.Cleanup(cache.Close)
		keys := make([]string, capacity+1)
		for i := range keys {
			keys[i] = "flow-" + strconv.Itoa(i)
		}
		// Keep one more key than the cache can retain. Seed all but the first,
		// then insert the first before timing so every timed lookup is a miss.
		for _, key := range keys[1:] {
			cache.Set(key, result)
		}
		cache.Set(keys[0], result)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			key := keys[(i+1)%len(keys)]
			_ = cache.Get(key)
			cache.Set(key, result)
		}
	})
}

func BenchmarkDetector_WithoutCache(b *testing.B) {
	det := createBenchDetector(b)
	packet := createDNSPacket(0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.DetectWithoutCache(packet)
	}
}

func BenchmarkDetector_MixedHighCardinality(b *testing.B) {
	det := createBenchDetector(b)
	constructors := []func(int) gopacket.Packet{createDNSPacket, createHTTPPacket, createRTPPacket, createTLSPacket, createUnknownTCPPacket, createUnknownUDPPacket}
	packets := make([]gopacket.Packet, 0, benchmarkFlowCardinality)
	for i := 0; i < benchmarkFlowCardinality; i++ {
		packets = append(packets, constructors[i%len(constructors)](i))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packets[i%len(packets)])
	}
}

func BenchmarkSignature_DNS(b *testing.B) {
	benchmarkSignature(b, application.NewDNSSignature(), createDNSPacket(0))
}

func BenchmarkSignature_HTTP(b *testing.B) {
	benchmarkSignature(b, application.NewHTTPSignature(), createHTTPPacket(0))
}

func BenchmarkSignature_RTP(b *testing.B) {
	benchmarkSignature(b, voip.NewRTPSignature(), createRTPPacket(0))
}

func BenchmarkSignature_TLS(b *testing.B) {
	benchmarkSignature(b, application.NewTLSSignature(), createTLSPacket(0))
}

func BenchmarkSignature_WireGuard(b *testing.B) {
	benchmarkSignature(b, vpn.NewWireGuardSignature(), createWireGuardPacket(0))
}

func benchmarkSignature(b *testing.B, sig signatures.Signature, packet gopacket.Packet) {
	det := detector.NewDetector()
	b.Cleanup(det.Shutdown)
	det.RegisterSignature(sig)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

func BenchmarkDetector_Parallel(b *testing.B) {
	det := createBenchDetector(b)
	packet := createDNSPacket(0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = det.Detect(packet)
		}
	})
}

func BenchmarkDetector_VariousPacketSizes(b *testing.B) {
	for _, size := range []int{64, 128, 256, 512, 1024, 1500} {
		b.Run(fmt.Sprintf("bytes_%d", size), func(b *testing.B) {
			det := createBenchDetector(b)
			packet := createPacketWithSize(size)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = det.Detect(packet)
			}
		})
	}
}

func createDNSPacket(flow int) gopacket.Packet {
	payload := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	return serializeUDP(flow, 40000+uint16(flow%20000), 53, payload)
}

func createHTTPPacket(flow int) gopacket.Packet {
	return serializeTCP(flow, 30000+uint16(flow%20000), 80, []byte("GET /resource HTTP/1.1\r\nHost: example.invalid\r\n\r\n"))
}

func createRTPPacket(flow int) gopacket.Packet {
	return serializeUDP(flow, 20000+uint16(flow%10000), 21000+uint16(flow%10000), []byte{0x80, 0, 0, 1, 0, 0, 0, 0x64, 0x12, 0x34, 0x56, 0x78, 0, 1, 2, 3})
}

func createTLSPacket(flow int) gopacket.Packet {
	return serializeTCP(flow, 30000+uint16(flow%20000), 443, []byte{0x16, 3, 1, 0, 0x10, 1, 0, 0, 0x0c, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0})
}

func createWireGuardPacket(flow int) gopacket.Packet {
	return serializeUDP(flow, 40000+uint16(flow%20000), 51820, []byte{1, 0, 0, 0, 0x12, 0x34, 0x56, 0x78})
}

func createUnknownTCPPacket(flow int) gopacket.Packet {
	return serializeTCP(flow, 10000+uint16(flow%10000), 9000, []byte("synthetic-payload"))
}

func createUnknownUDPPacket(flow int) gopacket.Packet {
	return serializeUDP(flow, 10000+uint16(flow%10000), 9001, []byte("synthetic-datagram"))
}

func createPacketWithSize(size int) gopacket.Packet {
	payload := make([]byte, size)
	copy(payload, []byte("GET /resource HTTP/1.1\r\nHost: example.invalid\r\n\r\n"))
	return serializeTCP(0, 32000, 80, payload)
}

func createFlowPackets(count int, constructor func(int) gopacket.Packet) []gopacket.Packet {
	packets := make([]gopacket.Packet, count)
	for i := range packets {
		packets[i] = constructor(i)
	}
	return packets
}

func serializeTCP(flow int, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	ip := benchmarkIPv4(flow)
	tcp := &layers.TCP{SrcPort: layers.TCPPort(srcPort), DstPort: layers.TCPPort(dstPort), Seq: uint32(flow + 1), ACK: true, Window: 65535}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	return serializePacket(ip, tcp, payload)
}

func serializeUDP(flow int, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	ip := benchmarkIPv4(flow)
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		panic(err)
	}
	return serializePacket(ip, udp, payload)
}

func benchmarkIPv4(flow int) *layers.IPv4 {
	src, dst := make(net.IP, net.IPv4len), make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(src, 0x0a000001+uint32(flow))
	binary.BigEndian.PutUint32(dst, 0xc0000201+uint32(flow%250))
	return &layers.IPv4{Version: 4, TTL: 64, SrcIP: src, DstIP: dst}
}

func serializePacket(ip *layers.IPv4, transport gopacket.SerializableLayer, payload []byte) gopacket.Packet {
	ethernet := &layers.Ethernet{SrcMAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, DstMAC: net.HardwareAddr{2, 0, 0, 0, 0, 2}, EthernetType: layers.EthernetTypeIPv4}
	switch transport.(type) {
	case *layers.TCP:
		ip.Protocol = layers.IPProtocolTCP
	case *layers.UDP:
		ip.Protocol = layers.IPProtocolUDP
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ethernet, ip, transport, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.DecodeOptions{NoCopy: true})
}

func createBenchDetector(b *testing.B) *detector.Detector {
	b.Helper()
	det := detector.NewDetector()
	b.Cleanup(det.Shutdown)
	det.RegisterSignature(application.NewDNSSignature())
	det.RegisterSignature(application.NewHTTPSignature())
	det.RegisterSignature(application.NewTLSSignature())
	det.RegisterSignature(application.NewSSHSignature())
	det.RegisterSignature(application.NewWebSocketSignature())
	det.RegisterSignature(application.NewGRPCSignature())
	det.RegisterSignature(voip.NewSIPSignature())
	det.RegisterSignature(voip.NewRTPSignature())
	det.RegisterSignature(vpn.NewWireGuardSignature())
	det.RegisterSignature(vpn.NewOpenVPNSignature())
	det.RegisterSignature(vpn.NewL2TPSignature())
	det.RegisterSignature(vpn.NewIKEv2Signature())
	return det
}

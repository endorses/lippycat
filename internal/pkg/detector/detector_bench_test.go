package detector_test

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/vpn"
)

// BenchmarkDetector_SingleSignature benchmarks detection with a single signature
func BenchmarkDetector_SingleSignature(b *testing.B) {
	det := detector.NewDetector()
	det.RegisterSignature(application.NewDNSSignature())

	// Create a sample DNS packet
	packet := createDNSPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

// BenchmarkDetector_MultipleSignatures benchmarks with all signatures
func BenchmarkDetector_MultipleSignatures(b *testing.B) {
	det := createBenchDetector()

	// Create various test packets
	packets := []gopacket.Packet{
		createDNSPacket(),
		createHTTPPacket(),
		createRTPPacket(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, packet := range packets {
			_ = det.Detect(packet)
		}
	}
}

// BenchmarkDetector_WithCache benchmarks cache performance
func BenchmarkDetector_WithCache(b *testing.B) {
	det := createBenchDetector()
	packet := createDNSPacket()

	// Prime the cache
	_ = det.Detect(packet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

// BenchmarkDetector_WithoutCache benchmarks without cache
func BenchmarkDetector_WithoutCache(b *testing.B) {
	det := createBenchDetector()
	packet := createDNSPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.DetectWithoutCache(packet)
	}
}

// BenchmarkSignature_DNS benchmarks DNS signature specifically
func BenchmarkSignature_DNS(b *testing.B) {
	det := detector.NewDetector()
	sig := application.NewDNSSignature()
	det.RegisterSignature(sig)

	packet := createDNSPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

// BenchmarkSignature_HTTP benchmarks HTTP signature
func BenchmarkSignature_HTTP(b *testing.B) {
	det := detector.NewDetector()
	sig := application.NewHTTPSignature()
	det.RegisterSignature(sig)

	packet := createHTTPPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

// BenchmarkSignature_RTP benchmarks RTP signature
func BenchmarkSignature_RTP(b *testing.B) {
	det := detector.NewDetector()
	sig := voip.NewRTPSignature()
	det.RegisterSignature(sig)

	packet := createRTPPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

// BenchmarkSignature_TLS benchmarks TLS signature
func BenchmarkSignature_TLS(b *testing.B) {
	det := detector.NewDetector()
	sig := application.NewTLSSignature()
	det.RegisterSignature(sig)

	packet := createTLSPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

// BenchmarkSignature_WireGuard benchmarks WireGuard signature
func BenchmarkSignature_WireGuard(b *testing.B) {
	det := detector.NewDetector()
	sig := vpn.NewWireGuardSignature()
	det.RegisterSignature(sig)

	packet := createWireGuardPacket()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(packet)
	}
}

// BenchmarkDetector_Parallel benchmarks parallel detection
func BenchmarkDetector_Parallel(b *testing.B) {
	det := createBenchDetector()
	packet := createDNSPacket()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = det.Detect(packet)
		}
	})
}

// BenchmarkDetector_VariousPacketSizes benchmarks with different packet sizes
func BenchmarkDetector_VariousPacketSizes(b *testing.B) {
	det := createBenchDetector()

	sizes := []int{64, 128, 256, 512, 1024, 1500}

	for _, size := range sizes {
		b.Run(string(rune(size)), func(b *testing.B) {
			packet := createPacketWithSize(size)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = det.Detect(packet)
			}
		})
	}
}

// Helper functions to create test packets

func createDNSPacket() gopacket.Packet {
	// DNS query packet
	payload := []byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags (standard query)
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		// Query: example.com
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	return gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.NoCopy)
}

func createHTTPPacket() gopacket.Packet {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	return gopacket.NewPacket(payload, layers.LayerTypeTCP, gopacket.NoCopy)
}

func createRTPPacket() gopacket.Packet {
	payload := []byte{
		0x80,       // V=2, P=0, X=0, CC=0
		0x00,       // M=0, PT=0
		0x00, 0x01, // Sequence number
		0x00, 0x00, 0x00, 0x64, // Timestamp
		0x12, 0x34, 0x56, 0x78, // SSRC
		// Payload
		0x00, 0x01, 0x02, 0x03,
	}

	return gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.NoCopy)
}

func createTLSPacket() gopacket.Packet {
	// TLS ClientHello
	payload := []byte{
		0x16,       // Content Type: Handshake
		0x03, 0x01, // Version: TLS 1.0
		0x00, 0x10, // Length
		0x01,             // Handshake Type: ClientHello
		0x00, 0x00, 0x0C, // Length
		0x03, 0x03, // Version: TLS 1.2
		0x00, 0x00, 0x00, 0x00, // Timestamp
		0x00, 0x00, 0x00, 0x00, // Random (partial)
	}

	return gopacket.NewPacket(payload, layers.LayerTypeTCP, gopacket.NoCopy)
}

func createWireGuardPacket() gopacket.Packet {
	// WireGuard handshake initiation
	payload := []byte{
		0x01, 0x00, 0x00, 0x00, // Message type: Handshake Initiation
		0x12, 0x34, 0x56, 0x78, // Sender index (partial)
		// ... rest would be crypto data
	}

	return gopacket.NewPacket(payload, layers.LayerTypeUDP, gopacket.NoCopy)
}

func createPacketWithSize(size int) gopacket.Packet {
	payload := make([]byte, size)
	// Add HTTP-like header to make it realistic
	copy(payload, []byte("GET / HTTP/1.1\r\n"))
	return gopacket.NewPacket(payload, layers.LayerTypeTCP, gopacket.NoCopy)
}

func createBenchDetector() *detector.Detector {
	det := detector.NewDetector()

	// Register all signatures
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

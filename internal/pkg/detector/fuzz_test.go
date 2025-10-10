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

// FuzzDetector_DNS fuzzes DNS signature
func FuzzDetector_DNS(f *testing.F) {
	// Add seed corpus
	f.Add([]byte{
		0x00, 0x01, // Transaction ID
		0x01, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	})

	det := detector.NewDetector()
	det.RegisterSignature(application.NewDNSSignature())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		// Create packet from fuzz input
		packet := gopacket.NewPacket(data, layers.LayerTypeUDP, gopacket.NoCopy)

		// Should not crash
		_ = det.Detect(packet)
	})
}

// FuzzDetector_HTTP fuzzes HTTP signature
func FuzzDetector_HTTP(f *testing.F) {
	// Add seed corpus
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("POST /api HTTP/1.1\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"))

	det := detector.NewDetector()
	det.RegisterSignature(application.NewHTTPSignature())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeTCP, gopacket.NoCopy)
		_ = det.Detect(packet)
	})
}

// FuzzDetector_TLS fuzzes TLS signature
func FuzzDetector_TLS(f *testing.F) {
	// Add TLS ClientHello seed
	f.Add([]byte{
		0x16, 0x03, 0x01, 0x00, 0x10,
		0x01, 0x00, 0x00, 0x0C,
		0x03, 0x03,
		0x00, 0x00, 0x00, 0x00,
	})

	det := detector.NewDetector()
	det.RegisterSignature(application.NewTLSSignature())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeTCP, gopacket.NoCopy)
		_ = det.Detect(packet)
	})
}

// FuzzDetector_SIP fuzzes SIP signature
func FuzzDetector_SIP(f *testing.F) {
	// Add SIP INVITE seed
	f.Add([]byte("INVITE sip:user@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1\r\n\r\n"))
	f.Add([]byte("REGISTER sip:example.com SIP/2.0\r\n\r\n"))

	det := detector.NewDetector()
	det.RegisterSignature(voip.NewSIPSignature())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeUDP, gopacket.NoCopy)
		_ = det.Detect(packet)
	})
}

// FuzzDetector_RTP fuzzes RTP signature
func FuzzDetector_RTP(f *testing.F) {
	// Add RTP packet seed
	f.Add([]byte{
		0x80, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x64,
		0x12, 0x34, 0x56, 0x78,
		0x00, 0x01, 0x02, 0x03,
	})

	det := detector.NewDetector()
	det.RegisterSignature(voip.NewRTPSignature())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeUDP, gopacket.NoCopy)
		_ = det.Detect(packet)
	})
}

// FuzzDetector_SSH fuzzes SSH signature
func FuzzDetector_SSH(f *testing.F) {
	// Add SSH banner seeds
	f.Add([]byte("SSH-2.0-OpenSSH_8.0\r\n"))
	f.Add([]byte("SSH-1.99-Cisco-1.25\r\n"))

	det := detector.NewDetector()
	det.RegisterSignature(application.NewSSHSignature())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeTCP, gopacket.NoCopy)
		_ = det.Detect(packet)
	})
}

// FuzzDetector_WireGuard fuzzes WireGuard signature
func FuzzDetector_WireGuard(f *testing.F) {
	// Add WireGuard handshake initiation seed
	f.Add([]byte{
		0x01, 0x00, 0x00, 0x00,
		0x12, 0x34, 0x56, 0x78,
	})

	det := detector.NewDetector()
	det.RegisterSignature(vpn.NewWireGuardSignature())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeUDP, gopacket.NoCopy)
		_ = det.Detect(packet)
	})
}

// FuzzDetector_AllSignatures fuzzes with all signatures registered
func FuzzDetector_AllSignatures(f *testing.F) {
	// Add various seeds
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01})
	f.Add([]byte("SSH-2.0-OpenSSH\r\n"))

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

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}

		// Test with different layer types
		layerTypes := []gopacket.LayerType{
			layers.LayerTypeUDP,
			layers.LayerTypeTCP,
		}

		for _, layerType := range layerTypes {
			packet := gopacket.NewPacket(data, layerType, gopacket.NoCopy)
			_ = det.Detect(packet)
		}
	})
}

// FuzzDetector_EdgeCases fuzzes edge cases
func FuzzDetector_EdgeCases(f *testing.F) {
	// Add edge case seeds
	f.Add([]byte{})           // Empty
	f.Add([]byte{0x00})       // Single byte
	f.Add([]byte{0xFF, 0xFF}) // Two 0xFF bytes
	f.Add(make([]byte, 1500)) // Max Ethernet frame
	f.Add(make([]byte, 9000)) // Jumbo frame

	det := detector.NewDetector()
	det.RegisterSignature(application.NewDNSSignature())
	det.RegisterSignature(application.NewHTTPSignature())

	f.Fuzz(func(t *testing.T, data []byte) {
		packet := gopacket.NewPacket(data, layers.LayerTypeUDP, gopacket.NoCopy)
		_ = det.Detect(packet)
	})
}

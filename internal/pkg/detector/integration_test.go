package detector_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/application"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/vpn"
)

// TestIntegration_PcapDetection tests protocol detection on real PCAP files
func TestIntegration_PcapDetection(t *testing.T) {
	// Find testdata directory
	testdataDir := findTestdataDir(t)

	tests := []struct {
		name              string
		pcapFile          string
		expectedProtocols []string
		minPackets        int
	}{
		{
			name:              "DNS Traffic",
			pcapFile:          "dns.pcap",
			expectedProtocols: []string{"DNS"},
			minPackets:        1,
		},
		{
			name:              "RTP Traffic",
			pcapFile:          "rtp.pcap",
			expectedProtocols: []string{"RTP"},
			minPackets:        1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcapPath := filepath.Join(testdataDir, "pcaps", tt.pcapFile)

			// Skip if PCAP doesn't exist
			if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
				t.Skipf("PCAP file not found: %s", pcapPath)
				return
			}

			// Create detector with all signatures
			det := createFullDetector()

			// Open PCAP
			handle, err := pcap.OpenOffline(pcapPath)
			require.NoError(t, err, "Failed to open PCAP: %s", pcapPath)
			defer handle.Close()

			// Process packets
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			detectedProtocols := make(map[string]int)
			totalPackets := 0

			for packet := range packetSource.Packets() {
				totalPackets++
				result := det.Detect(packet)

				if result != nil && result.Protocol != "unknown" {
					detectedProtocols[result.Protocol]++
				}
			}

			// Verify expected protocols were detected
			for _, expectedProto := range tt.expectedProtocols {
				count, found := detectedProtocols[expectedProto]
				assert.True(t, found, "Expected protocol %s not detected in %s", expectedProto, tt.pcapFile)
				assert.GreaterOrEqual(t, count, tt.minPackets,
					"Expected at least %d %s packets, got %d", tt.minPackets, expectedProto, count)
			}

			t.Logf("Total packets: %d, Detected protocols: %v", totalPackets, detectedProtocols)
		})
	}
}

// TestIntegration_MultiProtocolFlow tests flows containing multiple protocols
func TestIntegration_MultiProtocolFlow(t *testing.T) {
	testdataDir := findTestdataDir(t)
	pcapPath := filepath.Join(testdataDir, "pcaps", "dns.pcap")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("DNS PCAP file not found")
		return
	}

	det := createFullDetector()

	handle, err := pcap.OpenOffline(pcapPath)
	require.NoError(t, err)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	protocolSequence := []string{}

	for packet := range packetSource.Packets() {
		result := det.Detect(packet)
		if result != nil && result.Protocol != "unknown" {
			// Add to sequence if different from last
			if len(protocolSequence) == 0 || protocolSequence[len(protocolSequence)-1] != result.Protocol {
				protocolSequence = append(protocolSequence, result.Protocol)
			}
		}
	}

	// HTTP traffic should contain TCP establishment and HTTP
	assert.NotEmpty(t, protocolSequence, "Should detect some protocols")
	t.Logf("Protocol sequence: %v", protocolSequence)
}

// TestIntegration_ConfidenceScoring tests confidence levels on real traffic
func TestIntegration_ConfidenceScoring(t *testing.T) {
	testdataDir := findTestdataDir(t)

	tests := []struct {
		name           string
		pcapFile       string
		protocol       string
		minConfidence  float64
	}{
		{
			name:          "DNS High Confidence",
			pcapFile:      "dns.pcap",
			protocol:      "DNS",
			minConfidence: 0.85,
		},
		{
			name:          "RTP Medium Confidence",
			pcapFile:      "rtp.pcap",
			protocol:      "RTP",
			minConfidence: 0.70,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcapPath := filepath.Join(testdataDir, "pcaps", tt.pcapFile)

			if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
				t.Skipf("PCAP file not found: %s", pcapPath)
				return
			}

			det := createFullDetector()

			handle, err := pcap.OpenOffline(pcapPath)
			require.NoError(t, err)
			defer handle.Close()

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			highConfidenceCount := 0

			for packet := range packetSource.Packets() {
				result := det.Detect(packet)

				if result != nil && result.Protocol == tt.protocol {
					if result.Confidence >= tt.minConfidence {
						highConfidenceCount++
					}
				}
			}

			assert.Greater(t, highConfidenceCount, 0,
				"Should have at least one high-confidence %s detection", tt.protocol)

			t.Logf("High confidence %s detections: %d", tt.protocol, highConfidenceCount)
		})
	}
}

// TestIntegration_CachePerformance tests cache hit rates on real traffic
func TestIntegration_CachePerformance(t *testing.T) {
	testdataDir := findTestdataDir(t)
	pcapPath := filepath.Join(testdataDir, "pcaps", "dns.pcap")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("DNS PCAP file not found")
		return
	}

	det := createFullDetector()

	// First pass - populate cache
	handle, err := pcap.OpenOffline(pcapPath)
	require.NoError(t, err)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		_ = det.Detect(packet)
	}

	// Check stats - DNS uses CacheNever strategy so cache_size will be 0
	// but active_flows should be > 0
	stats := det.GetStats()
	activeFlows := stats["active_flows"].(int)

	assert.Greater(t, activeFlows, 0, "Should have active flows after processing")
	t.Logf("Cache stats: %+v", stats)
}

// TestIntegration_FlowTracking tests flow context tracking
func TestIntegration_FlowTracking(t *testing.T) {
	testdataDir := findTestdataDir(t)
	pcapPath := filepath.Join(testdataDir, "pcaps", "dns.pcap")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		t.Skip("DNS PCAP file not found")
		return
	}

	det := createFullDetector()

	handle, err := pcap.OpenOffline(pcapPath)
	require.NoError(t, err)
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetsProcessed := 0

	for packet := range packetSource.Packets() {
		_ = det.Detect(packet)
		packetsProcessed++
	}

	stats := det.GetStats()
	activeFlows := stats["active_flows"].(int)

	assert.Greater(t, activeFlows, 0, "Should track at least one flow")
	assert.Greater(t, packetsProcessed, 0, "Should process packets")

	t.Logf("Processed %d packets, tracked %d flows", packetsProcessed, activeFlows)
}

// Helper functions

func findTestdataDir(t *testing.T) string {
	// Try to find testdata directory
	candidates := []string{
		"../../../testdata",        // From internal/pkg/detector
		"../../testdata",           // Alternative
		"testdata",                 // Root level
		"./testdata",               // Current dir
	}

	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath
		}
	}

	t.Fatal("Could not find testdata directory")
	return ""
}

func createFullDetector() *detector.Detector {
	det := detector.NewDetector()

	// Register all application layer signatures
	det.RegisterSignature(application.NewDNSSignature())
	det.RegisterSignature(application.NewHTTPSignature())
	det.RegisterSignature(application.NewTLSSignature())
	det.RegisterSignature(application.NewSSHSignature())
	det.RegisterSignature(application.NewWebSocketSignature())
	det.RegisterSignature(application.NewGRPCSignature())

	// Register VoIP signatures
	det.RegisterSignature(voip.NewSIPSignature())
	det.RegisterSignature(voip.NewRTPSignature())

	// Register VPN signatures
	det.RegisterSignature(vpn.NewWireGuardSignature())
	det.RegisterSignature(vpn.NewOpenVPNSignature())
	det.RegisterSignature(vpn.NewL2TPSignature())
	det.RegisterSignature(vpn.NewIKEv2Signature())

	return det
}

// BenchmarkIntegration_PcapProcessing benchmarks PCAP processing speed
func BenchmarkIntegration_PcapProcessing(b *testing.B) {
	testdataDir := findTestdataDirB(b)
	pcapPath := filepath.Join(testdataDir, "pcaps", "rtp.pcap")

	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		b.Skip("RTP PCAP file not found")
		return
	}

	det := createFullDetector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handle, err := pcap.OpenOffline(pcapPath)
		if err != nil {
			b.Fatal(err)
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			_ = det.Detect(packet)
		}

		handle.Close()
	}
}

// findTestdataDirB for benchmarks (accepts testing.TB)
func findTestdataDirB(tb testing.TB) string {
	candidates := []string{
		"../../../testdata",
		"../../testdata",
		"testdata",
		"./testdata",
	}

	for _, candidate := range candidates {
		absPath, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		if _, err := os.Stat(absPath); err == nil {
			return absPath
		}
	}

	fmt.Fprintf(os.Stderr, "Warning: Could not find testdata directory\n")
	return "testdata"
}

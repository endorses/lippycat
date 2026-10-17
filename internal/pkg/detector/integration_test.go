package detector_test

import (
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

// TestIntegration_PcapDetection tests protocol detection through generated PCAP files
func TestIntegration_PcapDetection(t *testing.T) {
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
			pcapPath := writeDetectorPCAP(t, tt.pcapFile)

			// Create detector with all signatures
			det := createFullDetector(t)

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
	pcapPath := writeDetectorPCAP(t, "mixed.pcap")

	det := createFullDetector(t)

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

	assert.Equal(t, []string{"DNS", "HTTP", "RTP"}, protocolSequence)
	t.Logf("Protocol sequence: %v", protocolSequence)
}

// TestIntegration_ConfidenceScoring tests confidence levels on known protocol traffic
func TestIntegration_ConfidenceScoring(t *testing.T) {
	tests := []struct {
		name          string
		pcapFile      string
		protocol      string
		minConfidence float64
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
			pcapPath := writeDetectorPCAP(t, tt.pcapFile)

			det := createFullDetector(t)

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

// TestIntegration_CachePerformance tests cache accounting after reading a capture
func TestIntegration_CachePerformance(t *testing.T) {
	pcapPath := writeDetectorPCAP(t, "dns.pcap")

	det := createFullDetector(t)

	// Process the capture and inspect flow accounting
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
	pcapPath := writeDetectorPCAP(t, "dns.pcap")

	det := createFullDetector(t)

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

func createFullDetector(tb testing.TB) *detector.Detector {
	tb.Helper()
	det := detector.NewDetector()
	tb.Cleanup(det.Shutdown)

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
	pcapPath := writeDetectorPCAP(b, "rtp.pcap")
	det := createFullDetector(b)

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

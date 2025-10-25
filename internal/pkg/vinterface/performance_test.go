package vinterface

import (
	"runtime"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// BenchmarkConvertToEthernet_IPv4_TCP benchmarks IPv4 TCP packet conversion
func BenchmarkConvertToEthernet_IPv4_TCP(b *testing.B) {
	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		SrcPort:  "5060",
		DstPort:  "5061",
		Protocol: "TCP",
		Info:     "SIP INVITE",
		LinkType: layers.LinkTypeEthernet,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertToEthernet(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConvertToEthernet_IPv4_UDP benchmarks IPv4 UDP packet conversion
func BenchmarkConvertToEthernet_IPv4_UDP(b *testing.B) {
	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		SrcPort:  "5060",
		DstPort:  "5060",
		Protocol: "UDP",
		Info:     "RTP",
		LinkType: layers.LinkTypeEthernet,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertToEthernet(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConvertToEthernet_IPv6_TCP benchmarks IPv6 TCP packet conversion
func BenchmarkConvertToEthernet_IPv6_TCP(b *testing.B) {
	pkt := &types.PacketDisplay{
		SrcIP:    "2001:db8::1",
		DstIP:    "2001:db8::2",
		SrcPort:  "5060",
		DstPort:  "5061",
		Protocol: "TCP",
		Info:     "SIP INVITE",
		LinkType: layers.LinkTypeEthernet,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertToEthernet(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConvertToEthernet_WithRawData benchmarks conversion with raw data
func BenchmarkConvertToEthernet_WithRawData(b *testing.B) {
	// Pre-build raw IP packet
	rawData := []byte{
		0x45, 0x00, 0x00, 0x28, // IPv4 header
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		192, 168, 1, 100,
		192, 168, 1, 200,
		0x13, 0xc4, 0x13, 0xc5, // TCP header (partial)
	}

	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		Protocol: "TCP",
		RawData:  rawData,
		LinkType: layers.LinkTypeRaw,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertToEthernet(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConvertToIP_IPv4_UDP benchmarks TUN (Layer 3) conversion
func BenchmarkConvertToIP_IPv4_UDP(b *testing.B) {
	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		SrcPort:  "5060",
		DstPort:  "5060",
		Protocol: "UDP",
		Info:     "RTP",
		LinkType: layers.LinkTypeRaw,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertToIP(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConvertToIP_StripEthernet benchmarks stripping Ethernet headers
func BenchmarkConvertToIP_StripEthernet(b *testing.B) {
	// Raw data with Ethernet header
	rawData := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Dst MAC
		0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // Src MAC
		0x08, 0x00, // EtherType
		0x45, 0x00, 0x00, 0x28, // IPv4 header
	}

	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		Protocol: "TCP",
		RawData:  rawData,
		LinkType: layers.LinkTypeEthernet,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ConvertToIP(pkt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParsePorts benchmarks port parsing
func BenchmarkParsePorts(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := parsePorts("5060", "5061")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// generateTestPacketsPerf creates test packets for performance testing
func generateTestPacketsPerf(count int) []types.PacketDisplay {
	packets := make([]types.PacketDisplay, count)
	for i := 0; i < count; i++ {
		packets[i] = types.PacketDisplay{
			SrcIP:    "192.168.1.100",
			DstIP:    "192.168.1.200",
			SrcPort:  "5060",
			DstPort:  "5060",
			Protocol: "UDP",
			Info:     "Test packet",
			LinkType: layers.LinkTypeEthernet,
		}
	}
	return packets
}

// TestPerformance_InjectionThroughput measures actual injection throughput
// This is a performance test, not a benchmark
func TestPerformance_InjectionThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// This test measures realistic throughput
	// It's informational only - not a pass/fail test

	// Generate test packets
	packets := generateTestPacketsPerf(10000)

	// Measure conversion time
	start := time.Now()
	for i := range packets {
		_, err := ConvertToEthernet(&packets[i])
		if err != nil {
			t.Fatalf("Conversion error: %v", err)
		}
	}
	elapsed := time.Since(start)

	// Calculate throughput
	pps := float64(len(packets)) / elapsed.Seconds()

	t.Logf("Conversion performance:")
	t.Logf("  Packets: %d", len(packets))
	t.Logf("  Time: %v", elapsed)
	t.Logf("  Throughput: %.0f packets/sec", pps)
	t.Logf("  Latency (avg): %v per packet", elapsed/time.Duration(len(packets)))

	// Target: 100k pps conversion rate
	// On modern hardware, we should easily exceed this
	if pps < 100000 {
		t.Logf("WARNING: Conversion rate below 100k pps target (got %.0f pps)", pps)
	}
}

// TestPerformance_BatchConversion measures batch conversion performance
func TestPerformance_BatchConversion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	batchSizes := []int{1, 10, 100, 1000}

	for _, batchSize := range batchSizes {
		t.Run(string(rune('0'+batchSize)), func(t *testing.T) {
			packets := generateTestPacketsPerf(batchSize)

			start := time.Now()
			for i := range packets {
				_, err := ConvertToEthernet(&packets[i])
				if err != nil {
					t.Fatalf("Conversion error: %v", err)
				}
			}
			elapsed := time.Since(start)

			pps := float64(len(packets)) / elapsed.Seconds()
			t.Logf("Batch size %d: %.0f pps, %v total", batchSize, pps, elapsed)
		})
	}
}

// TestPerformance_MemoryAllocation measures memory allocations
func TestPerformance_MemoryAllocation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	pkt := &types.PacketDisplay{
		SrcIP:    "192.168.1.100",
		DstIP:    "192.168.1.200",
		SrcPort:  "5060",
		DstPort:  "5060",
		Protocol: "UDP",
		Info:     "RTP",
		LinkType: layers.LinkTypeEthernet,
	}

	// Warmup
	for i := 0; i < 1000; i++ {
		ConvertToEthernet(pkt)
	}

	// Measure
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	iterations := 10000
	for i := 0; i < iterations; i++ {
		_, err := ConvertToEthernet(pkt)
		if err != nil {
			t.Fatal(err)
		}
	}

	runtime.ReadMemStats(&m2)

	allocPerPacket := (m2.TotalAlloc - m1.TotalAlloc) / uint64(iterations)
	t.Logf("Memory allocation per packet: %d bytes", allocPerPacket)

	// Target: < 2KB per packet (reasonable for packet processing)
	if allocPerPacket > 2048 {
		t.Logf("WARNING: High memory allocation per packet: %d bytes", allocPerPacket)
	}
}

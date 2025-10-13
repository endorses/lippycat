//go:build cli || all
// +build cli all

package voip

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
)

// PerformanceBenchmark represents a performance benchmark result
type PerformanceBenchmark struct {
	Name        string    `json:"name"`
	NsPerOp     float64   `json:"ns_per_op"`
	BytesPerOp  int64     `json:"bytes_per_op"`
	AllocsPerOp int64     `json:"allocs_per_op"`
	Timestamp   time.Time `json:"timestamp"`
	GitCommit   string    `json:"git_commit,omitempty"`
	BuildInfo   string    `json:"build_info,omitempty"`
}

// PerformanceBaseline stores baseline performance metrics
type PerformanceBaseline struct {
	Benchmarks []PerformanceBenchmark `json:"benchmarks"`
	Updated    time.Time              `json:"updated"`
}

// Expected performance targets (these should be updated as optimizations improve)
var performanceTargets = map[string]PerformanceBenchmark{
	"CallIDDetection": {
		Name:        "CallIDDetection",
		NsPerOp:     250.0, // Target: under 250ns per operation (increased for proper whitespace trimming)
		BytesPerOp:  0,     // Target: zero allocations
		AllocsPerOp: 0,     // Target: zero allocations
	},
	"ContentLengthParsing": {
		Name:        "ContentLengthParsing",
		NsPerOp:     50.0, // Target: under 50ns per operation
		BytesPerOp:  32,   // Target: minimal allocations
		AllocsPerOp: 1,    // Target: at most 1 allocation
	},
	"SIPMessageProcessing": {
		Name:        "SIPMessageProcessing",
		NsPerOp:     1000.0, // Target: under 1μs per operation
		BytesPerOp:  256,    // Target: reasonable memory usage
		AllocsPerOp: 5,      // Target: minimal allocations
	},
	"AsyncWriting": {
		Name:        "AsyncWriting",
		NsPerOp:     100.0, // Target: under 100ns for queueing
		BytesPerOp:  0,     // Target: zero allocations in fast path
		AllocsPerOp: 0,     // Target: zero allocations in fast path
	},
}

// TestPerformanceRegression runs performance regression tests
func TestPerformanceRegression(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance regression tests in short mode")
	}

	// Skip performance tests when race detector is enabled
	// Race detector adds 10-100x overhead, making performance measurements meaningless
	if raceDetectorEnabled {
		t.Skip("Skipping performance regression tests with race detector enabled")
	}

	results := runPerformanceBenchmarks(t)

	// Load baseline if it exists
	baseline, err := loadPerformanceBaseline()
	if err != nil {
		t.Logf("No performance baseline found, creating new one: %v", err)
		savePerformanceBaseline(results)
		return
	}

	// Compare against baseline and targets
	regressions := []string{}
	improvements := []string{}

	for _, result := range results {
		// Check against performance targets
		if target, exists := performanceTargets[result.Name]; exists {
			if result.NsPerOp > target.NsPerOp*1.1 { // 10% tolerance
				regressions = append(regressions,
					fmt.Sprintf("%s: %0.2f ns/op > target %0.2f ns/op",
						result.Name, result.NsPerOp, target.NsPerOp))
			}
			if result.AllocsPerOp > target.AllocsPerOp {
				regressions = append(regressions,
					fmt.Sprintf("%s: %d allocs/op > target %d allocs/op",
						result.Name, result.AllocsPerOp, target.AllocsPerOp))
			}
		}

		// Check against baseline
		if baselineResult := findBenchmarkInBaseline(baseline, result.Name); baselineResult != nil {
			perfChange := (result.NsPerOp - baselineResult.NsPerOp) / baselineResult.NsPerOp * 100

			if perfChange > 15.0 { // 15% regression threshold
				regressions = append(regressions,
					fmt.Sprintf("%s: %0.1f%% performance regression (%0.2f -> %0.2f ns/op)",
						result.Name, perfChange, baselineResult.NsPerOp, result.NsPerOp))
			} else if perfChange < -10.0 { // 10% improvement threshold
				improvements = append(improvements,
					fmt.Sprintf("%s: %0.1f%% performance improvement (%0.2f -> %0.2f ns/op)",
						result.Name, -perfChange, baselineResult.NsPerOp, result.NsPerOp))
			}
		}
	}

	// Report results
	if len(improvements) > 0 {
		t.Logf("Performance improvements detected:")
		for _, improvement := range improvements {
			t.Logf("  ✅ %s", improvement)
		}
	}

	if len(regressions) > 0 {
		t.Errorf("Performance regressions detected:")
		for _, regression := range regressions {
			t.Errorf("  ❌ %s", regression)
		}
	}

	// Update baseline with current results
	savePerformanceBaseline(results)
}

// runPerformanceBenchmarks executes key performance benchmarks and returns results
func runPerformanceBenchmarks(t *testing.T) []PerformanceBenchmark {
	results := []PerformanceBenchmark{}

	// Test Call-ID detection performance
	t.Run("CallIDDetection", func(t *testing.T) {
		result := testing.Benchmark(func(b *testing.B) {
			testLine := "Call-ID: 1234567890@example.com"
			var callID string

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				detectCallIDHeader(testLine, &callID)
			}
		})

		results = append(results, PerformanceBenchmark{
			Name:        "CallIDDetection",
			NsPerOp:     float64(result.NsPerOp()),
			BytesPerOp:  result.AllocedBytesPerOp(),
			AllocsPerOp: result.AllocsPerOp(),
			Timestamp:   time.Now(),
		})
	})

	// Test content length parsing performance
	t.Run("ContentLengthParsing", func(t *testing.T) {
		result := testing.Benchmark(func(b *testing.B) {
			testValue := "1234"

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				parseContentLength(testValue)
			}
		})

		results = append(results, PerformanceBenchmark{
			Name:        "ContentLengthParsing",
			NsPerOp:     float64(result.NsPerOp()),
			BytesPerOp:  result.AllocedBytesPerOp(),
			AllocsPerOp: result.AllocsPerOp(),
			Timestamp:   time.Now(),
		})
	})

	// Test async writer queueing performance
	t.Run("AsyncWriting", func(t *testing.T) {
		pool := NewAsyncWriterPool(0, 1000) // No workers to test pure queueing speed
		defer pool.Stop()

		// Setup test call
		setupTestCall(t, "test-call-perf")
		defer cleanupTestCall("test-call-perf")

		packet := createTestPacketForAsyncRegression(t)

		result := testing.Benchmark(func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				pool.WritePacketAsync("test-call-perf", packet, PacketTypeSIP)
			}
		})

		results = append(results, PerformanceBenchmark{
			Name:        "AsyncWriting",
			NsPerOp:     float64(result.NsPerOp()),
			BytesPerOp:  result.AllocedBytesPerOp(),
			AllocsPerOp: result.AllocsPerOp(),
			Timestamp:   time.Now(),
		})
	})

	return results
}

// loadPerformanceBaseline loads the performance baseline from disk
func loadPerformanceBaseline() (*PerformanceBaseline, error) {
	filename := "performance_baseline.json"
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("baseline file does not exist: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var baseline PerformanceBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file: %w", err)
	}

	return &baseline, nil
}

// savePerformanceBaseline saves the performance baseline to disk
func savePerformanceBaseline(benchmarks []PerformanceBenchmark) error {
	baseline := PerformanceBaseline{
		Benchmarks: benchmarks,
		Updated:    time.Now(),
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	filename := "performance_baseline.json"
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write baseline file: %w", err)
	}

	return nil
}

// findBenchmarkInBaseline finds a specific benchmark in the baseline
func findBenchmarkInBaseline(baseline *PerformanceBaseline, name string) *PerformanceBenchmark {
	for _, benchmark := range baseline.Benchmarks {
		if benchmark.Name == name {
			return &benchmark
		}
	}
	return nil
}

// createTestPacketForAsyncRegression creates a test packet for async benchmarks
func createTestPacketForAsyncRegression(t *testing.T) gopacket.Packet {
	// This would normally create a proper test packet
	// For benchmarking, we just need something that implements the interface
	return &testPacket{
		data: []byte("test packet data"),
		ci: gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: 16,
			Length:        16,
		},
	}
}

// testPacket implements gopacket.Packet for testing
type testPacket struct {
	data []byte
	ci   gopacket.CaptureInfo
}

func (p *testPacket) Data() []byte { return p.data }
func (p *testPacket) Metadata() *gopacket.PacketMetadata {
	return &gopacket.PacketMetadata{CaptureInfo: p.ci}
}
func (p *testPacket) Layers() []gopacket.Layer                      { return nil }
func (p *testPacket) Layer(gopacket.LayerType) gopacket.Layer       { return nil }
func (p *testPacket) LayerClass(gopacket.LayerClass) gopacket.Layer { return nil }
func (p *testPacket) LinkLayer() gopacket.LinkLayer                 { return nil }
func (p *testPacket) NetworkLayer() gopacket.NetworkLayer           { return nil }
func (p *testPacket) TransportLayer() gopacket.TransportLayer       { return nil }
func (p *testPacket) ApplicationLayer() gopacket.ApplicationLayer   { return nil }
func (p *testPacket) ErrorLayer() gopacket.ErrorLayer               { return nil }
func (p *testPacket) String() string                                { return "test packet" }
func (p *testPacket) Dump() string                                  { return "test packet dump" }

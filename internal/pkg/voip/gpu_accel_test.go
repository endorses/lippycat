package voip

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultGPUConfig(t *testing.T) {
	config := DefaultGPUConfig()

	assert.True(t, config.Enabled) // Enabled by default for pattern matching
	assert.Equal(t, 0, config.DeviceID)
	assert.Equal(t, "auto", config.Backend)
	assert.Equal(t, 1024, config.MaxBatchSize)
	assert.True(t, config.PinnedMemory)
	assert.Equal(t, 4, config.StreamCount)
}

func TestNewGPUAccelerator(t *testing.T) {
	config := DefaultGPUConfig()
	config.Enabled = true // Enable for testing

	ga, err := NewGPUAccelerator(config)
	require.NoError(t, err)
	defer ga.Close()

	// Should fall back to SIMD backend
	assert.NotNil(t, ga)
	assert.Equal(t, "cpu-simd-avx2", ga.GetBackendName())
}

func TestGPUAccelerator_Disabled(t *testing.T) {
	config := DefaultGPUConfig()
	config.Enabled = false

	ga, err := NewGPUAccelerator(config)
	require.NoError(t, err)
	defer ga.Close()

	assert.False(t, ga.IsEnabled())
	assert.Equal(t, "none", ga.GetBackendName())
}

func TestGPUAccelerator_ProcessBatch(t *testing.T) {
	config := DefaultGPUConfig()
	config.Enabled = true

	ga, err := NewGPUAccelerator(config)
	require.NoError(t, err)
	defer ga.Close()

	// Create test packets
	packets := [][]byte{
		[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123\r\n"),
		[]byte("200 OK\r\nCall-ID: test456\r\n"),
		[]byte("No SIP data here"),
	}

	// Define patterns
	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("Call-ID:"),
			PatternLen: 8,
			Type:       PatternTypeContains,
		},
		{
			ID:         1,
			Pattern:    []byte("INVITE"),
			PatternLen: 6,
			Type:       PatternTypePrefix,
		},
	}

	// Process batch
	results, err := ga.ProcessBatch(packets, patterns)
	require.NoError(t, err)

	// Check results
	assert.Greater(t, len(results), 0)

	// Should find Call-ID in first two packets
	foundCallID := 0
	foundInvite := 0

	for _, result := range results {
		if result.Matched {
			if result.PatternID == 0 {
				foundCallID++
			} else if result.PatternID == 1 {
				foundInvite++
			}
		}
	}

	assert.Equal(t, 2, foundCallID)
	assert.Equal(t, 1, foundInvite)
}

func TestGPUAccelerator_ExtractCallIDsGPU(t *testing.T) {
	config := DefaultGPUConfig()
	config.Enabled = true

	ga, err := NewGPUAccelerator(config)
	require.NoError(t, err)
	defer ga.Close()

	packets := [][]byte{
		[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc123@host\r\n"),
		[]byte("200 OK\r\nCall-ID: xyz789@server\r\n"),
		[]byte("REGISTER sip:proxy SIP/2.0\r\ni: short123\r\n"),
	}

	callIDs, err := ga.ExtractCallIDsGPU(packets)
	require.NoError(t, err)

	assert.Equal(t, 3, len(callIDs))
	assert.Contains(t, callIDs, "abc123@host")
	assert.Contains(t, callIDs, "xyz789@server")
	assert.Contains(t, callIDs, "short123")
}

func TestGPUAccelerator_CPUFallback(t *testing.T) {
	config := DefaultGPUConfig()
	config.Enabled = false // Force CPU fallback

	ga, err := NewGPUAccelerator(config)
	require.NoError(t, err)
	defer ga.Close()

	packets := [][]byte{
		[]byte("Test packet with Call-ID: test123\r\n"),
	}

	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("Call-ID:"),
			PatternLen: 8,
			Type:       PatternTypeContains,
		},
	}

	results, err := ga.ProcessBatch(packets, patterns)
	require.NoError(t, err)
	assert.Greater(t, len(results), 0)

	// Check stats show CPU fallback
	stats := ga.GetStats()
	assert.Greater(t, stats.FallbackToCPU.Get(), uint64(0))
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		pattern  GPUPattern
		expected bool
		offset   int
	}{
		{
			name: "literal match",
			data: []byte("exact"),
			pattern: GPUPattern{
				Pattern:    []byte("exact"),
				PatternLen: 5,
				Type:       PatternTypeLiteral,
			},
			expected: true,
			offset:   0,
		},
		{
			name: "prefix match",
			data: []byte("INVITE sip:user"),
			pattern: GPUPattern{
				Pattern:    []byte("INVITE"),
				PatternLen: 6,
				Type:       PatternTypePrefix,
			},
			expected: true,
			offset:   0,
		},
		{
			name: "contains match",
			data: []byte("Header: Call-ID: value"),
			pattern: GPUPattern{
				Pattern:    []byte("Call-ID:"),
				PatternLen: 8,
				Type:       PatternTypeContains,
			},
			expected: true,
			offset:   8,
		},
		{
			name: "no match",
			data: []byte("no pattern here"),
			pattern: GPUPattern{
				Pattern:    []byte("missing"),
				PatternLen: 7,
				Type:       PatternTypeContains,
			},
			expected: false,
			offset:   -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, offset := matchPattern(tt.data, tt.pattern)
			assert.Equal(t, tt.expected, matched)
			if matched {
				assert.Equal(t, tt.offset, offset)
			}
		})
	}
}

func TestGPUStats(t *testing.T) {
	config := DefaultGPUConfig()
	config.Enabled = true

	ga, err := NewGPUAccelerator(config)
	require.NoError(t, err)
	defer ga.Close()

	packets := [][]byte{
		[]byte("packet1"),
		[]byte("packet2"),
	}

	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("packet"),
			PatternLen: 6,
			Type:       PatternTypeContains,
		},
	}

	_, err = ga.ProcessBatch(packets, patterns)
	require.NoError(t, err)

	stats := ga.GetStats()
	assert.Greater(t, stats.BatchesProcessed.Get(), uint64(0))
	assert.Greater(t, stats.PacketsProcessed.Get(), uint64(0))
}

func TestPatternTypes(t *testing.T) {
	assert.Equal(t, PatternTypeLiteral, PatternType(0))
	assert.Equal(t, PatternTypePrefix, PatternType(1))
	assert.Equal(t, PatternTypeContains, PatternType(2))
	assert.Equal(t, PatternTypeSuffix, PatternType(3))
	assert.Equal(t, PatternTypeRegex, PatternType(4))
}

func TestGPUPattern_String(t *testing.T) {
	pattern := GPUPattern{
		ID:         1,
		Pattern:    []byte("test"),
		PatternLen: 4,
		Type:       PatternTypeContains,
	}

	str := pattern.String()
	assert.Contains(t, str, "ID:1")
	assert.Contains(t, str, "test")
}

// Integration test with batch processor
func TestGPUAccelerator_WithBatchProcessor(t *testing.T) {
	// Create GPU accelerator
	gpuConfig := DefaultGPUConfig()
	gpuConfig.Enabled = true

	ga, err := NewGPUAccelerator(gpuConfig)
	require.NoError(t, err)
	defer ga.Close()

	// Create batch processor
	batchConfig := DefaultBatchConfig()
	batchConfig.BatchSize = 4
	batchConfig.WorkerAffinity = false

	bp := NewBatchProcessor(batchConfig)
	defer bp.Stop()

	// Consume results
	go func() {
		for range bp.GetResults() {
			// Discard
		}
	}()

	// Create batch collector
	bc := NewBatchCollector(batchConfig, bp)

	// Add packets
	sipPackets := []string{
		"INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: call1\r\n",
		"200 OK\r\nCall-ID: call2\r\n",
		"ACK sip:bob@example.com SIP/2.0\r\nCall-ID: call3\r\n",
		"BYE sip:bob@example.com SIP/2.0\r\nCall-ID: call4\r\n",
	}

	for i, sipData := range sipPackets {
		pkt := GetPacketPool().Get()
		pkt.Data = []byte(sipData)

		ci := gopacket.CaptureInfo{
			CaptureLength: len(pkt.Data),
			Length:        len(pkt.Data),
		}

		bc.Add(pkt, ci, uint32(i))
	}

	// Extract Call-IDs using GPU
	packets := make([][]byte, len(sipPackets))
	for i, data := range sipPackets {
		packets[i] = []byte(data)
	}

	callIDs, err := ga.ExtractCallIDsGPU(packets)
	require.NoError(t, err)

	assert.Equal(t, 4, len(callIDs))
	assert.Contains(t, callIDs, "call1")
	assert.Contains(t, callIDs, "call2")
	assert.Contains(t, callIDs, "call3")
	assert.Contains(t, callIDs, "call4")
}

// Benchmarks

func BenchmarkGPUAccelerator_ProcessBatch(b *testing.B) {
	config := DefaultGPUConfig()
	config.Enabled = true

	ga, err := NewGPUAccelerator(config)
	require.NoError(b, err)
	defer ga.Close()

	// Create test packets
	packets := make([][]byte, 64)
	for i := 0; i < 64; i++ {
		packets[i] = []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123@host\r\n")
	}

	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("Call-ID:"),
			PatternLen: 8,
			Type:       PatternTypeContains,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = ga.ProcessBatch(packets, patterns)
	}
}

func BenchmarkGPUAccelerator_ExtractCallIDs(b *testing.B) {
	config := DefaultGPUConfig()
	config.Enabled = true

	ga, err := NewGPUAccelerator(config)
	require.NoError(b, err)
	defer ga.Close()

	packets := make([][]byte, 64)
	for i := 0; i < 64; i++ {
		packets[i] = []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123@host\r\n")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = ga.ExtractCallIDsGPU(packets)
	}
}

func BenchmarkMatchPattern_Literal(b *testing.B) {
	data := []byte("exact")
	pattern := GPUPattern{
		Pattern:    []byte("exact"),
		PatternLen: 5,
		Type:       PatternTypeLiteral,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = matchPattern(data, pattern)
	}
}

func BenchmarkMatchPattern_Contains(b *testing.B) {
	data := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123\r\n")
	pattern := GPUPattern{
		Pattern:    []byte("Call-ID:"),
		PatternLen: 8,
		Type:       PatternTypeContains,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = matchPattern(data, pattern)
	}
}

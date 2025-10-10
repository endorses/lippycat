package voip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSIMDBackend(t *testing.T) {
	backend := NewSIMDBackend()

	assert.NotNil(t, backend)
	assert.True(t, backend.IsAvailable())
	assert.Contains(t, backend.Name(), "cpu-simd")
}

func TestSIMDBackend_Initialize(t *testing.T) {
	backend := NewSIMDBackend()
	config := DefaultGPUConfig()

	err := backend.Initialize(config)
	require.NoError(t, err)
}

func TestSIMDBackend_TransferPackets(t *testing.T) {
	backend := NewSIMDBackend().(*SIMDBackend)
	config := DefaultGPUConfig()
	_ = backend.Initialize(config)

	packets := [][]byte{
		[]byte("packet1"),
		[]byte("packet2"),
		[]byte("packet3"),
	}

	err := backend.TransferPacketsToGPU(packets)
	require.NoError(t, err)

	assert.Equal(t, 3, len(backend.packets))
}

func TestSIMDBackend_PatternMatching(t *testing.T) {
	backend := NewSIMDBackend().(*SIMDBackend)
	config := DefaultGPUConfig()
	_ = backend.Initialize(config)

	packets := [][]byte{
		[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test1\r\n"),
		[]byte("200 OK\r\nCall-ID: test2\r\n"),
		[]byte("No pattern here"),
	}

	err := backend.TransferPacketsToGPU(packets)
	require.NoError(t, err)

	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("Call-ID:"),
			PatternLen: 8,
			Type:       PatternTypeContains,
		},
	}

	err = backend.ExecutePatternMatching(patterns)
	require.NoError(t, err)

	results, err := backend.TransferResultsFromGPU()
	require.NoError(t, err)

	// Should find Call-ID in first two packets
	assert.Equal(t, 2, len(results))

	// Check both packets were matched (order may vary)
	indices := make(map[int]bool)
	for _, result := range results {
		indices[result.PacketIndex] = true
	}
	assert.True(t, indices[0], "Packet 0 should be matched")
	assert.True(t, indices[1], "Packet 1 should be matched")
}

func TestSIMDBackend_MultiplePatterns(t *testing.T) {
	backend := NewSIMDBackend().(*SIMDBackend)
	config := DefaultGPUConfig()
	_ = backend.Initialize(config)

	packets := [][]byte{
		[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc\r\n"),
	}

	err := backend.TransferPacketsToGPU(packets)
	require.NoError(t, err)

	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("INVITE"),
			PatternLen: 6,
			Type:       PatternTypePrefix,
		},
		{
			ID:         1,
			Pattern:    []byte("Call-ID:"),
			PatternLen: 8,
			Type:       PatternTypeContains,
		},
		{
			ID:         2,
			Pattern:    []byte("missing"),
			PatternLen: 7,
			Type:       PatternTypeContains,
		},
	}

	err = backend.ExecutePatternMatching(patterns)
	require.NoError(t, err)

	results, err := backend.TransferResultsFromGPU()
	require.NoError(t, err)

	// Should match INVITE and Call-ID
	assert.Equal(t, 2, len(results))

	foundInvite := false
	foundCallID := false

	for _, result := range results {
		if result.PatternID == 0 {
			foundInvite = true
		}
		if result.PatternID == 1 {
			foundCallID = true
		}
	}

	assert.True(t, foundInvite)
	assert.True(t, foundCallID)
}

func TestSIMDBackend_MatchTypes(t *testing.T) {
	backend := NewSIMDBackend().(*SIMDBackend)
	config := DefaultGPUConfig()
	_ = backend.Initialize(config)

	tests := []struct {
		name     string
		packet   []byte
		pattern  GPUPattern
		expected bool
	}{
		{
			name:   "prefix match",
			packet: []byte("INVITE sip:user"),
			pattern: GPUPattern{
				ID:         0,
				Pattern:    []byte("INVITE"),
				PatternLen: 6,
				Type:       PatternTypePrefix,
			},
			expected: true,
		},
		{
			name:   "prefix no match",
			packet: []byte("200 OK"),
			pattern: GPUPattern{
				ID:         0,
				Pattern:    []byte("INVITE"),
				PatternLen: 6,
				Type:       PatternTypePrefix,
			},
			expected: false,
		},
		{
			name:   "contains match",
			packet: []byte("Header: Call-ID: value"),
			pattern: GPUPattern{
				ID:         0,
				Pattern:    []byte("Call-ID:"),
				PatternLen: 8,
				Type:       PatternTypeContains,
			},
			expected: true,
		},
		{
			name:   "literal match",
			packet: []byte("exact"),
			pattern: GPUPattern{
				ID:         0,
				Pattern:    []byte("exact"),
				PatternLen: 5,
				Type:       PatternTypeLiteral,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = backend.TransferPacketsToGPU([][]byte{tt.packet})
			_ = backend.ExecutePatternMatching([]GPUPattern{tt.pattern})
			results, _ := backend.TransferResultsFromGPU()

			if tt.expected {
				assert.Greater(t, len(results), 0)
				assert.True(t, results[0].Matched)
			} else {
				assert.Equal(t, 0, len(results))
			}
		})
	}
}

func TestSIMDBackend_Cleanup(t *testing.T) {
	backend := NewSIMDBackend()
	config := DefaultGPUConfig()
	_ = backend.Initialize(config)

	err := backend.Cleanup()
	require.NoError(t, err)
}

func TestSIMDCallIDExtractor(t *testing.T) {
	extractor := NewSIMDCallIDExtractor()

	packets := [][]byte{
		[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc123\r\n"),
		[]byte("200 OK\r\nCall-ID: xyz789\r\n"),
		[]byte("REGISTER sip:proxy SIP/2.0\r\ni: short123\r\n"),
		[]byte("No Call-ID here"),
	}

	callIDs, err := extractor.ExtractCallIDs(packets)
	require.NoError(t, err)

	assert.Equal(t, 3, len(callIDs))
	assert.Contains(t, callIDs, "abc123")
	assert.Contains(t, callIDs, "xyz789")
	assert.Contains(t, callIDs, "short123")
}

func TestSIMDPatternMatcher(t *testing.T) {
	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("test"),
			PatternLen: 4,
			Type:       PatternTypeContains,
		},
	}

	matcher := NewSIMDPatternMatcher(patterns)

	packets := [][]byte{
		[]byte("this is a test packet"),
		[]byte("no match here"),
		[]byte("another test"),
	}

	results := matcher.MatchBatch(packets)

	// Should match packets 0 and 2
	assert.Equal(t, 2, len(results))
	assert.Equal(t, 0, results[0].PacketIndex)
	assert.Equal(t, 2, results[1].PacketIndex)
}

func TestMultiPatternSearch(t *testing.T) {
	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("pattern1"),
			PatternLen: 8,
			Type:       PatternTypeContains,
		},
		{
			ID:         1,
			Pattern:    []byte("pattern2"),
			PatternLen: 8,
			Type:       PatternTypeContains,
		},
	}

	searcher := NewMultiPatternSearch(patterns)

	data := []byte("text with pattern1 and pattern2 inside")
	results := searcher.Search(data)

	assert.Equal(t, 2, len(results))
}

func TestSIMDBackend_Stats(t *testing.T) {
	backend := NewSIMDBackend().(*SIMDBackend)
	config := DefaultGPUConfig()
	_ = backend.Initialize(config)

	packets := [][]byte{
		[]byte("packet1"),
		[]byte("packet2"),
	}

	_ = backend.TransferPacketsToGPU(packets)

	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("packet"),
			PatternLen: 6,
			Type:       PatternTypeContains,
		},
	}

	_ = backend.ExecutePatternMatching(patterns)

	stats := backend.GetStats()
	assert.Greater(t, stats.ProcessingTimeNS.Get(), uint64(0))
	assert.Equal(t, uint64(2), stats.PacketsProcessed.Get())
}

// Benchmarks

func BenchmarkSIMDBackend_PatternMatching(b *testing.B) {
	backend := NewSIMDBackend().(*SIMDBackend)
	config := DefaultGPUConfig()
	_ = backend.Initialize(config)

	packets := make([][]byte, 64)
	for i := 0; i < 64; i++ {
		packets[i] = []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123\r\n")
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
		_ = backend.TransferPacketsToGPU(packets)
		_ = backend.ExecutePatternMatching(patterns)
		_, _ = backend.TransferResultsFromGPU()
	}
}

func BenchmarkSIMDCallIDExtractor(b *testing.B) {
	extractor := NewSIMDCallIDExtractor()

	packets := make([][]byte, 64)
	for i := 0; i < 64; i++ {
		packets[i] = []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123@host\r\n")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = extractor.ExtractCallIDs(packets)
	}
}

func BenchmarkSIMDPatternMatcher(b *testing.B) {
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

	matcher := NewSIMDPatternMatcher(patterns)

	packets := make([][]byte, 64)
	for i := 0; i < 64; i++ {
		packets[i] = []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test\r\n")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = matcher.MatchBatch(packets)
	}
}

func BenchmarkFindPatternOffset(b *testing.B) {
	backend := NewSIMDBackend().(*SIMDBackend)

	data := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123@host\r\nFrom: alice\r\n")
	pattern := []byte("Call-ID:")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = backend.findPatternOffset(data, pattern)
	}
}
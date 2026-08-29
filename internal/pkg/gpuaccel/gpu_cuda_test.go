//go:build cuda

package gpuaccel

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCUDABackend(t *testing.T, maxBatchSize int) *CUDABackendImpl {
	t.Helper()
	backend := NewCUDABackendImpl()
	if !backend.IsAvailable() {
		t.Skip("CUDA not available")
	}
	config := DefaultGPUConfig()
	config.MaxBatchSize = maxBatchSize
	require.NoError(t, backend.Initialize(config))
	t.Cleanup(func() { require.NoError(t, backend.Cleanup()) })
	return backend
}

func TestCUDABackend_AhoCorasickSemantics(t *testing.T) {
	backend := newTestCUDABackend(t, 16)
	patterns := []ahocorasick.Pattern{
		{ID: 101, Text: "alice", Type: filtering.PatternTypeContains},
		{ID: 205, Text: "+49", Type: filtering.PatternTypePrefix},
		{ID: 307, Text: "example.com", Type: filtering.PatternTypeSuffix},
		{ID: 409, Text: "he", Type: filtering.PatternTypeContains},
		{ID: 503, Text: "she", Type: filtering.PatternTypeContains},
		{ID: 601, Text: "alice", Type: filtering.PatternTypeContains},
	}
	require.NoError(t, backend.BuildAutomaton(patterns))

	inputs := [][]byte{
		[]byte("ALICE-alice@example.com"), // case fold, repeated match, suffix
		[]byte("x+49-middle"),             // prefix false positive
		[]byte("+49123"),                  // valid prefix
		[]byte("example.com.invalid"),     // suffix false positive
		[]byte("she"),                     // failure-link output: she and he
		{},
	}
	results, err := backend.MatchWithAutomaton("default", inputs)
	require.NoError(t, err)
	require.Len(t, results, len(inputs))
	assert.ElementsMatch(t, []int{101, 601, 307}, results[0])
	assert.Empty(t, results[1])
	assert.Equal(t, []int{205}, results[2])
	assert.Empty(t, results[3])
	assert.ElementsMatch(t, []int{503, 409}, results[4])
	assert.Empty(t, results[5])
}

func TestCUDABackend_AhoCorasickDistinctMatchLimit(t *testing.T) {
	backend := newTestCUDABackend(t, 2)
	patterns := make([]ahocorasick.Pattern, 20)
	input := make([]byte, 0, 100)
	for i := range patterns {
		text := fmt.Sprintf("p%02d", i)
		patterns[i] = ahocorasick.Pattern{ID: 1000 + i, Text: text, Type: filtering.PatternTypeContains}
		input = append(input, text...)
	}
	require.NoError(t, backend.BuildAutomaton(patterns))

	results, err := backend.MatchWithAutomaton("default", [][]byte{input, make([]byte, 200)})
	require.NoError(t, err)
	require.Len(t, results[0], 16)
	for i := range 16 {
		assert.Contains(t, results[0], 1000+i)
	}
	assert.Empty(t, results[1])
	assert.GreaterOrEqual(t, backend.usernameBufferCapacity, len(input)+200)
}

func TestCUDABackend_Available(t *testing.T) {
	backend := NewCUDABackendImpl()

	// Check if CUDA is available
	available := backend.IsAvailable()

	if !available {
		t.Skip("CUDA not available on this system")
	}

	assert.True(t, available)
}

func TestCUDABackend_Initialize(t *testing.T) {
	backend := NewCUDABackendImpl()

	if !backend.IsAvailable() {
		t.Skip("CUDA not available")
	}

	config := DefaultGPUConfig()
	config.DeviceID = 0

	err := backend.Initialize(config)
	require.NoError(t, err)

	assert.True(t, backend.initialized)

	// Cleanup
	backend.Cleanup()
}

func TestCUDABackend_AllocateBuffers(t *testing.T) {
	backend := NewCUDABackendImpl()

	if !backend.IsAvailable() {
		t.Skip("CUDA not available")
	}

	config := DefaultGPUConfig()
	err := backend.Initialize(config)
	require.NoError(t, err)
	defer backend.Cleanup()

	err = backend.AllocatePacketBuffers(1024, 2048)
	require.NoError(t, err)

	assert.NotNil(t, backend.packetBuffer)
	assert.NotNil(t, backend.offsetBuffer)
	assert.NotNil(t, backend.patternBuffer)
	assert.NotNil(t, backend.resultBuffer)
}

func TestCUDABackend_TransferPackets(t *testing.T) {
	backend := NewCUDABackendImpl()

	if !backend.IsAvailable() {
		t.Skip("CUDA not available")
	}

	config := DefaultGPUConfig()
	err := backend.Initialize(config)
	require.NoError(t, err)
	defer backend.Cleanup()

	packets := [][]byte{
		[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123\r\n"),
		[]byte("200 OK\r\nCall-ID: test456\r\n"),
	}

	err = backend.TransferPacketsToGPU(packets)
	require.NoError(t, err)
}

func TestCUDABackend_PatternMatching(t *testing.T) {
	backend := NewCUDABackendImpl()

	if !backend.IsAvailable() {
		t.Skip("CUDA not available")
	}

	config := DefaultGPUConfig()
	err := backend.Initialize(config)
	require.NoError(t, err)
	defer backend.Cleanup()

	packets := [][]byte{
		[]byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123\r\n"),
		[]byte("200 OK\r\nCall-ID: test456\r\n"),
		[]byte("No SIP data here"),
	}

	err = backend.TransferPacketsToGPU(packets)
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
	assert.GreaterOrEqual(t, len(results), 2)
}

func TestCUDABackend_LinearPatternSemantics(t *testing.T) {
	backend := newTestCUDABackend(t, 8)
	packets := [][]byte{
		[]byte("prefix-middle-suffix"),
		[]byte("xprefix-middle-suffixx"),
	}
	require.NoError(t, backend.TransferPacketsToGPU(packets))
	require.NoError(t, backend.ExecutePatternMatching([]GPUPattern{
		{ID: 101, Pattern: []byte("prefix"), PatternLen: 6, Type: PatternTypePrefix},
		{ID: 205, Pattern: []byte("suffix"), PatternLen: 6, Type: PatternTypeSuffix},
		{ID: 307, Pattern: packets[0], PatternLen: len(packets[0]), Type: PatternTypeLiteral},
	}))

	results, err := backend.TransferResultsFromGPU()
	require.NoError(t, err)
	assert.ElementsMatch(t, []GPUResult{
		{PacketIndex: 0, PatternID: 101, Offset: 0, Length: 6, Matched: true},
		{PacketIndex: 0, PatternID: 205, Offset: 14, Length: 6, Matched: true},
		{PacketIndex: 0, PatternID: 307, Offset: 0, Length: 20, Matched: true},
	}, results)
}

func TestCUDABackend_Name(t *testing.T) {
	backend := NewCUDABackendImpl()

	if !backend.IsAvailable() {
		t.Skip("CUDA not available")
	}

	config := DefaultGPUConfig()
	err := backend.Initialize(config)
	require.NoError(t, err)
	defer backend.Cleanup()

	name := backend.Name()
	assert.Contains(t, name, "cuda")
	// Should contain device name like "cuda-NVIDIA GeForce RTX 4090"
}

func TestCUDABackend_EndToEnd(t *testing.T) {
	backend := NewCUDABackendImpl()

	if !backend.IsAvailable() {
		t.Skip("CUDA not available")
	}

	config := DefaultGPUConfig()
	config.MaxBatchSize = 64

	err := backend.Initialize(config)
	require.NoError(t, err)
	defer backend.Cleanup()

	// Create test packets
	packets := make([][]byte, 64)
	for i := 0; i < 64; i++ {
		packets[i] = []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test123\r\n")
	}

	// Transfer to GPU
	err = backend.TransferPacketsToGPU(packets)
	require.NoError(t, err)

	// Define patterns
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
	}

	// Execute pattern matching
	err = backend.ExecutePatternMatching(patterns)
	require.NoError(t, err)

	// Get results
	results, err := backend.TransferResultsFromGPU()
	require.NoError(t, err)

	// Should find both patterns in all packets
	assert.Greater(t, len(results), 0)

	t.Logf("Found %d matches across %d packets", len(results), len(packets))
}

// Benchmark CUDA backend
func BenchmarkCUDABackend_PatternMatching(b *testing.B) {
	backend := NewCUDABackendImpl()

	if !backend.IsAvailable() {
		b.Skip("CUDA not available")
	}

	config := DefaultGPUConfig()
	config.MaxBatchSize = 64

	if err := backend.Initialize(config); err != nil {
		b.Fatal(err)
	}
	defer backend.Cleanup()

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
		backend.TransferPacketsToGPU(packets)
		backend.ExecutePatternMatching(patterns)
		backend.TransferResultsFromGPU()
	}
}

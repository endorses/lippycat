//go:build cuda

package voip

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

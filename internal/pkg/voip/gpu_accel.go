package voip

import (
	"errors"
	"fmt"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/logger"
)

// GPUAccelerator provides GPU-accelerated pattern matching and parsing
type GPUAccelerator struct {
	backend       GPUBackend
	config        *GPUConfig
	packetBuffers *GPUPacketBuffers
	resultBuffers *GPUResultBuffers
	stats         GPUStats
	mu            sync.RWMutex
}

// GPUConfig configures GPU acceleration
type GPUConfig struct {
	Enabled           bool
	DeviceID          int
	Backend           string // "cuda", "opencl", "cpu-simd"
	MaxBatchSize      int
	PinnedMemory      bool
	StreamCount       int
	PatternBufferSize int
}

// GPUBackend defines the interface for GPU compute backends
type GPUBackend interface {
	// Initialize the GPU backend
	Initialize(config *GPUConfig) error

	// Allocate GPU memory for packet buffers
	AllocatePacketBuffers(maxPackets int, maxPacketSize int) error

	// Copy packets from CPU to GPU
	TransferPacketsToGPU(packets [][]byte) error

	// Execute pattern matching kernel
	ExecutePatternMatching(patterns []GPUPattern) error

	// Copy results from GPU to CPU
	TransferResultsFromGPU() ([]GPUResult, error)

	// Free GPU resources
	Cleanup() error

	// Get backend name
	Name() string

	// Check if backend is available
	IsAvailable() bool
}

// GPUPattern represents a pattern to match on GPU
type GPUPattern struct {
	ID          int
	Pattern     []byte
	PatternLen  int
	Type        PatternType
	CaseSensitive bool
}

// PatternType defines the type of pattern matching
type PatternType int

const (
	PatternTypeLiteral PatternType = iota // Exact string match
	PatternTypePrefix                     // Prefix match
	PatternTypeContains                   // Contains substring
	PatternTypeRegex                      // Regular expression (complex)
)

// GPUResult represents a pattern match result from GPU
type GPUResult struct {
	PacketIndex int
	PatternID   int
	Offset      int
	Length      int
	Matched     bool
}

// GPUPacketBuffers manages packet buffers on GPU
type GPUPacketBuffers struct {
	devicePtr     uintptr
	hostPtr       []byte
	capacity      int
	packetCount   int
	packetOffsets []int
	pinnedMemory  bool
}

// GPUResultBuffers manages result buffers
type GPUResultBuffers struct {
	devicePtr    uintptr
	hostPtr      []byte
	capacity     int
	resultCount  int
	pinnedMemory bool
}

// GPUStats holds GPU acceleration statistics
type GPUStats struct {
	_                   CachePadding
	BatchesProcessed    PaddedCounter
	PacketsProcessed    PaddedCounter
	PatternsMatched     PaddedCounter
	TransferToGPUNS     PaddedCounter
	KernelExecutionNS   PaddedCounter
	TransferFromGPUNS   PaddedCounter
	TotalProcessingNS   PaddedCounter
	GPUMemoryUsed       PaddedCounter
	FallbackToCPU       PaddedCounter
	_                   CachePadding
}

// DefaultGPUConfig returns default GPU configuration
func DefaultGPUConfig() *GPUConfig {
	return &GPUConfig{
		Enabled:           false, // Disabled by default
		DeviceID:          0,
		Backend:           "auto", // Auto-detect best backend
		MaxBatchSize:      1024,
		PinnedMemory:      true,
		StreamCount:       4,
		PatternBufferSize: 1024 * 1024, // 1MB for patterns
	}
}

// NewGPUAccelerator creates a new GPU accelerator
func NewGPUAccelerator(config *GPUConfig) (*GPUAccelerator, error) {
	if config == nil {
		config = DefaultGPUConfig()
	}

	ga := &GPUAccelerator{
		config: config,
	}

	// Select and initialize backend
	if err := ga.initializeBackend(); err != nil {
		logger.Warn("Failed to initialize GPU backend, falling back to CPU", "error", err)
		config.Enabled = false
		return ga, nil
	}

	logger.Info("GPU accelerator initialized",
		"backend", ga.backend.Name(),
		"device", config.DeviceID,
		"batch_size", config.MaxBatchSize)

	return ga, nil
}

// initializeBackend selects and initializes the best available backend
func (ga *GPUAccelerator) initializeBackend() error {
	if !ga.config.Enabled {
		return errors.New("GPU acceleration disabled")
	}

	// Try backends in order of preference
	backends := []string{}

	if ga.config.Backend == "auto" {
		backends = []string{"cuda", "opencl", "cpu-simd"}
	} else {
		backends = []string{ga.config.Backend}
	}

	for _, backendName := range backends {
		backend, err := createBackend(backendName)
		if err != nil {
			logger.Debug("Backend not available", "backend", backendName, "error", err)
			continue
		}

		if !backend.IsAvailable() {
			logger.Debug("Backend not available on this system", "backend", backendName)
			continue
		}

		if err := backend.Initialize(ga.config); err != nil {
			logger.Debug("Failed to initialize backend", "backend", backendName, "error", err)
			continue
		}

		ga.backend = backend
		logger.Info("Selected GPU backend", "backend", backendName)
		return nil
	}

	return errors.New("no suitable GPU backend available")
}

// createBackend creates a backend instance by name
func createBackend(name string) (GPUBackend, error) {
	switch name {
	case "cuda":
		return NewCUDABackend(), nil
	case "opencl":
		return NewOpenCLBackend(), nil
	case "cpu-simd":
		return NewSIMDBackend(), nil
	default:
		return nil, fmt.Errorf("unknown backend: %s", name)
	}
}

// ProcessBatch processes a batch of packets with GPU acceleration
func (ga *GPUAccelerator) ProcessBatch(packets [][]byte, patterns []GPUPattern) ([]GPUResult, error) {
	if !ga.config.Enabled || ga.backend == nil {
		// Fallback to CPU processing
		ga.stats.FallbackToCPU.Inc()
		return ga.processBatchCPU(packets, patterns)
	}

	ga.mu.Lock()
	defer ga.mu.Unlock()

	// Transfer packets to GPU
	if err := ga.backend.TransferPacketsToGPU(packets); err != nil {
		ga.stats.FallbackToCPU.Inc()
		return ga.processBatchCPU(packets, patterns)
	}

	// Execute pattern matching on GPU
	if err := ga.backend.ExecutePatternMatching(patterns); err != nil {
		ga.stats.FallbackToCPU.Inc()
		return ga.processBatchCPU(packets, patterns)
	}

	// Transfer results back from GPU
	results, err := ga.backend.TransferResultsFromGPU()
	if err != nil {
		ga.stats.FallbackToCPU.Inc()
		return ga.processBatchCPU(packets, patterns)
	}

	ga.stats.BatchesProcessed.Inc()
	ga.stats.PacketsProcessed.Add(uint64(len(packets)))
	ga.stats.PatternsMatched.Add(uint64(len(results)))

	return results, nil
}

// processBatchCPU is the CPU fallback implementation
func (ga *GPUAccelerator) processBatchCPU(packets [][]byte, patterns []GPUPattern) ([]GPUResult, error) {
	results := make([]GPUResult, 0)

	for packetIdx, packet := range packets {
		for _, pattern := range patterns {
			if matched, offset := matchPattern(packet, pattern); matched {
				results = append(results, GPUResult{
					PacketIndex: packetIdx,
					PatternID:   pattern.ID,
					Offset:      offset,
					Length:      pattern.PatternLen,
					Matched:     true,
				})
			}
		}
	}

	return results, nil
}

// matchPattern performs CPU-based pattern matching
func matchPattern(data []byte, pattern GPUPattern) (bool, int) {
	switch pattern.Type {
	case PatternTypeLiteral:
		return matchLiteral(data, pattern.Pattern)
	case PatternTypePrefix:
		return matchPrefix(data, pattern.Pattern)
	case PatternTypeContains:
		return matchContains(data, pattern.Pattern)
	default:
		return false, -1
	}
}

// matchLiteral checks for exact match
func matchLiteral(data, pattern []byte) (bool, int) {
	if len(data) != len(pattern) {
		return false, -1
	}
	if BytesEqual(data, pattern) {
		return true, 0
	}
	return false, -1
}

// matchPrefix checks for prefix match
func matchPrefix(data, pattern []byte) (bool, int) {
	if len(data) < len(pattern) {
		return false, -1
	}
	if BytesEqual(data[:len(pattern)], pattern) {
		return true, 0
	}
	return false, -1
}

// matchContains checks if pattern is contained in data
func matchContains(data, pattern []byte) (bool, int) {
	if len(pattern) == 0 {
		return true, 0
	}

	// Use SIMD-optimized BytesContains
	if BytesContains(data, pattern) {
		// Find offset (simple linear search for now)
		for i := 0; i <= len(data)-len(pattern); i++ {
			if BytesEqual(data[i:i+len(pattern)], pattern) {
				return true, i
			}
		}
	}

	return false, -1
}

// ExtractCallIDsGPU extracts Call-IDs using GPU acceleration
func (ga *GPUAccelerator) ExtractCallIDsGPU(packets [][]byte) ([]string, error) {
	// Define Call-ID patterns
	patterns := []GPUPattern{
		{
			ID:            0,
			Pattern:       []byte("Call-ID:"),
			PatternLen:    8,
			Type:          PatternTypeContains,
			CaseSensitive: false,
		},
		{
			ID:            1,
			Pattern:       []byte("\ni:"),
			PatternLen:    3,
			Type:          PatternTypeContains,
			CaseSensitive: true,
		},
	}

	results, err := ga.ProcessBatch(packets, patterns)
	if err != nil {
		return nil, err
	}

	// Extract Call-IDs from matched packets
	callIDs := make([]string, 0)
	for _, result := range results {
		if result.Matched && result.PacketIndex < len(packets) {
			packet := packets[result.PacketIndex]
			// Use existing fast extraction
			if callID := extractCallIDFast(packet); callID != "" {
				callIDs = append(callIDs, callID)
			}
		}
	}

	return callIDs, nil
}

// GetStats returns GPU acceleration statistics
func (ga *GPUAccelerator) GetStats() GPUStats {
	ga.mu.RLock()
	defer ga.mu.RUnlock()
	return ga.stats
}

// IsEnabled returns whether GPU acceleration is enabled
func (ga *GPUAccelerator) IsEnabled() bool {
	return ga.config.Enabled && ga.backend != nil
}

// GetBackendName returns the current backend name
func (ga *GPUAccelerator) GetBackendName() string {
	if ga.backend == nil {
		return "none"
	}
	return ga.backend.Name()
}

// Close releases GPU resources
func (ga *GPUAccelerator) Close() error {
	if ga.backend != nil {
		return ga.backend.Cleanup()
	}
	return nil
}

// Common errors
var (
	ErrGPUNotAvailable    = errors.New("GPU not available")
	ErrGPUOutOfMemory     = errors.New("GPU out of memory")
	ErrGPUTransferFailed  = errors.New("GPU transfer failed")
	ErrGPUKernelFailed    = errors.New("GPU kernel execution failed")
	ErrInvalidBackend     = errors.New("invalid GPU backend")
)
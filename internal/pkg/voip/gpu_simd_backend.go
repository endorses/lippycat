package voip

import (
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// SIMDBackend implements GPU backend interface using CPU SIMD instructions
type SIMDBackend struct {
	config     *GPUConfig
	packets    [][]byte
	results    []GPUResult
	patterns   []GPUPattern
	numWorkers int
	mu         sync.Mutex
	stats      SIMDBackendStats

	// acMatcher is the Aho-Corasick automaton for efficient pattern matching.
	// Uses DenseAhoCorasick for O(1) state transitions and SIMD-optimized matching.
	acMatcher *ahocorasick.DenseAhoCorasick
}

// SIMDBackendStats holds SIMD backend statistics
type SIMDBackendStats struct {
	ProcessingTimeNS PaddedCounter
	PacketsProcessed PaddedCounter
	PatternsMatched  PaddedCounter
}

// NewSIMDBackend creates a new SIMD-optimized CPU backend
func NewSIMDBackend() GPUBackend {
	return &SIMDBackend{
		numWorkers: runtime.NumCPU(),
	}
}

// Initialize initializes the SIMD backend
func (sb *SIMDBackend) Initialize(config *GPUConfig) error {
	sb.config = config
	sb.numWorkers = runtime.NumCPU()

	logger.Info("SIMD backend initialized",
		"workers", sb.numWorkers,
		"avx2", cpuFeatures.HasAVX2,
		"sse4.2", cpuFeatures.HasSSE42)

	return nil
}

// AllocatePacketBuffers allocates memory for packet buffers (no-op for SIMD)
func (sb *SIMDBackend) AllocatePacketBuffers(maxPackets int, maxPacketSize int) error {
	// SIMD backend uses regular Go memory
	return nil
}

// TransferPacketsToGPU stores packets in CPU memory
func (sb *SIMDBackend) TransferPacketsToGPU(packets [][]byte) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Store packets for processing
	sb.packets = packets
	return nil
}

// ExecutePatternMatching executes pattern matching using SIMD instructions
func (sb *SIMDBackend) ExecutePatternMatching(patterns []GPUPattern) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	startTime := time.Now()
	sb.patterns = patterns
	sb.results = make([]GPUResult, 0)

	// Parallel processing using goroutines
	numPackets := len(sb.packets)
	packetsPerWorker := (numPackets + sb.numWorkers - 1) / sb.numWorkers

	var wg sync.WaitGroup
	resultsChan := make(chan []GPUResult, sb.numWorkers)

	for workerID := range sb.numWorkers {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()

			start := wid * packetsPerWorker
			end := start + packetsPerWorker
			if end > numPackets {
				end = numPackets
			}

			localResults := sb.processPacketRange(start, end)
			resultsChan <- localResults
		}(workerID)
	}

	// Wait for all workers
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for workerResults := range resultsChan {
		sb.results = append(sb.results, workerResults...)
	}

	// Stats updates (safe: durations and counts won't overflow uint64)
	processingTime := time.Since(startTime)
	sb.stats.ProcessingTimeNS.Add(uint64(processingTime.Nanoseconds())) // #nosec G115
	sb.stats.PacketsProcessed.Add(uint64(numPackets))                   // #nosec G115
	sb.stats.PatternsMatched.Add(uint64(len(sb.results)))               // #nosec G115

	return nil
}

// processPacketRange processes a range of packets
func (sb *SIMDBackend) processPacketRange(start, end int) []GPUResult {
	results := make([]GPUResult, 0)

	for packetIdx := start; packetIdx < end; packetIdx++ {
		packet := sb.packets[packetIdx]

		for _, pattern := range sb.patterns {
			if matched, offset := sb.matchPatternSIMD(packet, pattern); matched {
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

	return results
}

// matchPatternSIMD performs SIMD-optimized pattern matching
func (sb *SIMDBackend) matchPatternSIMD(data []byte, pattern GPUPattern) (bool, int) {
	switch pattern.Type {
	case PatternTypeLiteral:
		return sb.matchLiteralSIMD(data, pattern)
	case PatternTypePrefix:
		return sb.matchPrefixSIMD(data, pattern)
	case PatternTypeContains:
		return sb.matchContainsSIMD(data, pattern)
	case PatternTypeSuffix:
		return sb.matchSuffixSIMD(data, pattern)
	default:
		return false, -1
	}
}

// matchLiteralSIMD checks for exact match using SIMD
func (sb *SIMDBackend) matchLiteralSIMD(data []byte, pattern GPUPattern) (bool, int) {
	if len(data) != pattern.PatternLen {
		return false, -1
	}

	// Use SIMD-optimized BytesEqual
	if BytesEqual(data, pattern.Pattern) {
		return true, 0
	}

	return false, -1
}

// matchPrefixSIMD checks for prefix match using SIMD
func (sb *SIMDBackend) matchPrefixSIMD(data []byte, pattern GPUPattern) (bool, int) {
	if len(data) < pattern.PatternLen {
		return false, -1
	}

	// Use SIMD-optimized comparison
	if BytesEqual(data[:pattern.PatternLen], pattern.Pattern) {
		return true, 0
	}

	return false, -1
}

// matchSuffixSIMD checks for suffix match using SIMD
func (sb *SIMDBackend) matchSuffixSIMD(data []byte, pattern GPUPattern) (bool, int) {
	if len(data) < pattern.PatternLen {
		return false, -1
	}

	// Calculate offset to start of suffix
	offset := len(data) - pattern.PatternLen

	// Use SIMD-optimized comparison on last N bytes
	if BytesEqual(data[offset:], pattern.Pattern) {
		return true, offset
	}

	return false, -1
}

// matchContainsSIMD checks if pattern is contained using SIMD
func (sb *SIMDBackend) matchContainsSIMD(data []byte, pattern GPUPattern) (bool, int) {
	if pattern.PatternLen == 0 {
		return true, 0
	}

	// Use SIMD-optimized BytesContains for quick check
	if !BytesContains(data, pattern.Pattern) {
		return false, -1
	}

	// Find exact offset using SIMD where possible
	return sb.findPatternOffset(data, pattern.Pattern)
}

// findPatternOffset finds the offset of pattern in data
func (sb *SIMDBackend) findPatternOffset(data, pattern []byte) (bool, int) {
	if len(pattern) == 0 {
		return true, 0
	}

	dataLen := len(data)
	patternLen := len(pattern)

	if patternLen > dataLen {
		return false, -1
	}

	// For short patterns, use SIMD byte-by-byte comparison
	if cpuFeatures.HasAVX2 && patternLen >= 16 {
		// Use AVX2 for longer patterns
		return sb.findOffsetAVX2(data, pattern)
	}

	// Fallback to optimized scalar search
	return sb.findOffsetScalar(data, pattern)
}

// findOffsetAVX2 uses AVX2 instructions for pattern search
func (sb *SIMDBackend) findOffsetAVX2(data, pattern []byte) (bool, int) {
	// For now, use optimized scalar version
	// Real AVX2 implementation would use assembly or intrinsics
	return sb.findOffsetScalar(data, pattern)
}

// findOffsetScalar uses optimized scalar search
func (sb *SIMDBackend) findOffsetScalar(data, pattern []byte) (bool, int) {
	dataLen := len(data)
	patternLen := len(pattern)
	firstByte := pattern[0]

	// Boyer-Moore-Horspool style search
	for i := 0; i <= dataLen-patternLen; i++ {
		// Quick check for first byte
		if data[i] != firstByte {
			continue
		}

		// Full comparison using SIMD-optimized BytesEqual
		if BytesEqual(data[i:i+patternLen], pattern) {
			return true, i
		}
	}

	return false, -1
}

// TransferResultsFromGPU returns results from CPU memory
func (sb *SIMDBackend) TransferResultsFromGPU() ([]GPUResult, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	return sb.results, nil
}

// Cleanup releases resources (no-op for SIMD)
func (sb *SIMDBackend) Cleanup() error {
	sb.packets = nil
	sb.results = nil
	sb.patterns = nil
	return nil
}

// Name returns the backend name
func (sb *SIMDBackend) Name() string {
	if cpuFeatures.HasAVX2 {
		return "cpu-simd-avx2"
	} else if cpuFeatures.HasSSE42 {
		return "cpu-simd-sse4.2"
	}
	return "cpu-simd"
}

// IsAvailable checks if SIMD backend is available (always true)
func (sb *SIMDBackend) IsAvailable() bool {
	return true
}

// BuildAutomaton builds an Aho-Corasick automaton from patterns.
// This enables O(n+m+z) matching using the DenseAhoCorasick implementation
// which provides O(1) state transitions and SIMD-optimized lowercase conversion.
func (sb *SIMDBackend) BuildAutomaton(patterns []ahocorasick.Pattern) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(patterns) == 0 {
		sb.acMatcher = nil
		return nil
	}

	startTime := time.Now()
	ac := ahocorasick.NewDenseAhoCorasick()
	if err := ac.Build(patterns); err != nil {
		return fmt.Errorf("failed to build AC automaton: %w", err)
	}
	sb.acMatcher = ac

	logger.Info("SIMD backend AC automaton built",
		"pattern_count", len(patterns),
		"build_duration", time.Since(startTime))

	return nil
}

// MatchUsernames matches usernames against the built Aho-Corasick automaton.
// Returns matched pattern IDs for each input username.
// If no automaton is built, returns empty results for all inputs.
func (sb *SIMDBackend) MatchUsernames(usernames [][]byte) ([][]int, error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	results := make([][]int, len(usernames))

	if sb.acMatcher == nil {
		// No automaton built, return empty results
		return results, nil
	}

	startTime := time.Now()

	// Use parallel processing for large batches
	numUsernames := len(usernames)
	if numUsernames > sb.numWorkers*10 {
		// Parallel processing
		usernamesPerWorker := (numUsernames + sb.numWorkers - 1) / sb.numWorkers

		var wg sync.WaitGroup
		for workerID := range sb.numWorkers {
			wg.Add(1)
			go func(wid int) {
				defer wg.Done()

				start := wid * usernamesPerWorker
				end := start + usernamesPerWorker
				if end > numUsernames {
					end = numUsernames
				}

				for i := start; i < end; i++ {
					matchResults := sb.acMatcher.Match(usernames[i])
					if len(matchResults) > 0 {
						patternIDs := make([]int, len(matchResults))
						for j, mr := range matchResults {
							patternIDs[j] = mr.PatternID
						}
						results[i] = patternIDs
					}
				}
			}(workerID)
		}
		wg.Wait()
	} else {
		// Sequential processing for small batches
		for i, username := range usernames {
			matchResults := sb.acMatcher.Match(username)
			if len(matchResults) > 0 {
				patternIDs := make([]int, len(matchResults))
				for j, mr := range matchResults {
					patternIDs[j] = mr.PatternID
				}
				results[i] = patternIDs
			}
		}
	}

	processingTime := time.Since(startTime)
	sb.stats.ProcessingTimeNS.Add(uint64(processingTime.Nanoseconds())) // #nosec G115
	sb.stats.PacketsProcessed.Add(uint64(numUsernames))                 // #nosec G115

	return results, nil
}

// GetStats returns SIMD backend statistics
func (sb *SIMDBackend) GetStats() *SIMDBackendStats {
	return &sb.stats
}

// SIMDPatternMatcher provides vectorized pattern matching
type SIMDPatternMatcher struct {
	patterns []GPUPattern
	numLanes int
	useAVX2  bool
}

// NewSIMDPatternMatcher creates a new SIMD pattern matcher
func NewSIMDPatternMatcher(patterns []GPUPattern) *SIMDPatternMatcher {
	return &SIMDPatternMatcher{
		patterns: patterns,
		numLanes: 8, // Process 8 patterns in parallel
		useAVX2:  cpuFeatures.HasAVX2,
	}
}

// MatchBatch matches patterns across a batch of packets
func (spm *SIMDPatternMatcher) MatchBatch(packets [][]byte) []GPUResult {
	results := make([]GPUResult, 0)

	// Vectorized processing
	for packetIdx, packet := range packets {
		for _, pattern := range spm.patterns {
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

	return results
}

// MultiPatternSearch performs multi-pattern search using Aho-Corasick style algorithm
type MultiPatternSearch struct {
	patterns []GPUPattern
	// Simplified - real implementation would use trie structure
}

// NewMultiPatternSearch creates a multi-pattern searcher
func NewMultiPatternSearch(patterns []GPUPattern) *MultiPatternSearch {
	return &MultiPatternSearch{
		patterns: patterns,
	}
}

// Search searches for all patterns in data
func (mps *MultiPatternSearch) Search(data []byte) []GPUResult {
	results := make([]GPUResult, 0)

	// Simple multi-pattern matching
	// Real implementation would use Aho-Corasick automaton
	for _, pattern := range mps.patterns {
		if matched, offset := matchPattern(data, pattern); matched {
			results = append(results, GPUResult{
				PacketIndex: 0,
				PatternID:   pattern.ID,
				Offset:      offset,
				Length:      pattern.PatternLen,
				Matched:     true,
			})
		}
	}

	return results
}

// SIMDCallIDExtractor extracts Call-IDs using SIMD acceleration
type SIMDCallIDExtractor struct {
	backend  *SIMDBackend
	patterns []GPUPattern
}

// NewSIMDCallIDExtractor creates a SIMD-accelerated Call-ID extractor
func NewSIMDCallIDExtractor() *SIMDCallIDExtractor {
	backend := NewSIMDBackend().(*SIMDBackend)
	_ = backend.Initialize(DefaultGPUConfig())

	patterns := []GPUPattern{
		{
			ID:         0,
			Pattern:    []byte("Call-ID:"),
			PatternLen: 8,
			Type:       PatternTypeContains,
		},
		{
			ID:         1,
			Pattern:    []byte("\ni:"),
			PatternLen: 3,
			Type:       PatternTypeContains,
		},
	}

	return &SIMDCallIDExtractor{
		backend:  backend,
		patterns: patterns,
	}
}

// ExtractCallIDs extracts Call-IDs from packet batch
func (sce *SIMDCallIDExtractor) ExtractCallIDs(packets [][]byte) ([]string, error) {
	// Transfer packets
	if err := sce.backend.TransferPacketsToGPU(packets); err != nil {
		return nil, err
	}

	// Execute pattern matching
	if err := sce.backend.ExecutePatternMatching(sce.patterns); err != nil {
		return nil, err
	}

	// Get results
	results, err := sce.backend.TransferResultsFromGPU()
	if err != nil {
		return nil, err
	}

	// Extract Call-IDs from matched packets
	callIDs := make([]string, 0)
	seen := make(map[int]bool)

	for _, result := range results {
		if !result.Matched || seen[result.PacketIndex] {
			continue
		}

		seen[result.PacketIndex] = true
		packet := packets[result.PacketIndex]

		// Use fast extraction
		if callID := extractCallIDFast(packet); callID != "" {
			callIDs = append(callIDs, callID)
		}
	}

	return callIDs, nil
}

// String returns a string representation of the pattern
func (p GPUPattern) String() string {
	return fmt.Sprintf("Pattern{ID:%d, Type:%d, Len:%d, Pattern:%s}",
		p.ID, p.Type, p.PatternLen, string(p.Pattern))
}

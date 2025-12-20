# GPU Pattern Matching Architecture Research

**Date:** 2025-12-20
**Status:** Research Complete (Revised)
**Author:** Claude (with human review)

## Executive Summary

The current GPU/SIMD pattern matching architecture has two significant inefficiencies:

1. **Patterns are re-transferred to GPU on every batch** despite rarely changing
2. **GPU path matches against raw payload** instead of extracted usernames like CPU path does

These issues negate much of the performance benefit GPU acceleration is meant to provide.

## Target Use Case: Lawful Intercept

This architecture must support lawful intercept (LI) on high-traffic networks:

| Parameter | Scale |
|-----------|-------|
| Target patterns | 1,000 - 100,000 phone numbers |
| SIP traffic | 10,000+ messages/second |
| Usernames to match | 30,000+/second (From + To + PAI per message) |
| Filter changes | Very rare (add/delete individual patterns) |

**Critical requirements:**
- No false positives (intercepting wrong calls = legal liability)
- No false negatives (missing target calls = operational failure)
- Must handle scale without linear scan becoming bottleneck

## Current Architecture Analysis

### Filter Storage

When filters are updated via `UpdateFilters()` in `application_filter.go`:

```go
type ApplicationFilter struct {
    sipUsers     []parsedFilter     // Parsed patterns in CPU memory
    phoneNumbers []parsedFilter     // Parsed patterns in CPU memory
    patterns     []voip.GPUPattern  // GPU-ready patterns (still in CPU memory)
    // ...
}
```

Filters are stored in CPU memory. No VRAM allocation occurs at filter update time.

### Pattern Flow per Batch

```
┌─────────────────────────────────────────────────────────────────────┐
│ ProcessBatch() - Called for EVERY packet batch                      │
├─────────────────────────────────────────────────────────────────────┤
│ 1. TransferPacketsToGPU(packets)     ← Packets copied to GPU        │
│ 2. ExecutePatternMatching(patterns)  ← Patterns copied to GPU AGAIN │
│ 3. TransferResultsFromGPU()          ← Results copied back          │
└─────────────────────────────────────────────────────────────────────┘
```

**Key observation:** `patterns` parameter is passed fresh on every call, forcing re-transfer.

### CUDA Implementation (gpu_cuda_backend_impl.go:241-273)

```go
func (cb *CUDABackendImpl) ExecutePatternMatching(patterns []GPUPattern) error {
    // ... flatten patterns into buffer ...

    // Copy patterns to GPU - THIS HAPPENS EVERY CALL
    if cerr := C.copyHostToDevice(cb.patternBuffer,
        unsafe.Pointer(&flatPatterns[0]), C.size_t(totalPatternSize)); cerr != 0 {
        return fmt.Errorf("failed to copy patterns to GPU: %d", cerr)
    }
    // ...
}
```

### SIMD Implementation (gpu_simd_backend.go:66-116)

```go
func (sb *SIMDBackend) ExecutePatternMatching(patterns []GPUPattern) error {
    sb.patterns = patterns  // Stored temporarily for this batch only
    // ... matching logic ...
}
```

The SIMD backend stores patterns in a struct field, but this is overwritten every call anyway.

### CPU vs GPU Matching Logic

#### CPU Path (application_filter.go:307-363)

```go
func (af *ApplicationFilter) matchWithCPU(payload string) bool {
    // 1. Extract SIP headers
    sipHeaders := extractSIPHeaders(payloadBytes)

    // 2. Extract usernames from each header
    fromUser := voip.ExtractUserFromHeaderBytes(sipHeaders.from)
    toUser := voip.ExtractUserFromHeaderBytes(sipHeaders.to)
    paiUser := voip.ExtractUserFromHeaderBytes(sipHeaders.pAssertedIdentity)

    // 3. Match extracted usernames against patterns
    for _, filter := range af.sipUsers {
        if filtering.Match(fromUser, filter.pattern, filter.patternType) {
            return true
        }
        // ... similar for toUser, paiUser ...
    }
}
```

#### GPU Path (application_filter.go:283-303)

```go
func (af *ApplicationFilter) matchWithGPU(payload []byte) bool {
    // Directly search for pattern in raw payload - NO username extraction
    results, err := af.gpuAccel.ProcessBatch([][]byte{payload}, af.patterns)
    // ...
}
```

**Critical difference:** The GPU path searches for pattern bytes anywhere in the raw SIP message, while the CPU path properly extracts usernames from From/To/P-Asserted-Identity headers and matches against those.

## Identified Issues

### Issue 1: Pattern Re-Transfer Overhead

**Frequency analysis:**
- Filter changes: Rare (minutes to hours between changes)
- Packet batches: Frequent (100s per second at high traffic)

**Current behavior:**
- Patterns copied to GPU/stored in SIMD on every batch
- For CUDA: `cudaMemcpy()` called every batch
- Typical overhead: 10-50μs per transfer for small pattern sets

**Impact:**
- At 1000 batches/second with 10μs transfer: 10ms/second wasted (1% CPU)
- Negates latency benefits of GPU acceleration

### Issue 2: Semantic Mismatch Between CPU and GPU Paths

**Example scenario:**

Filter: `*456789` (suffix match for phone number ending in 456789)

SIP Message:
```
INVITE sip:+49123456789@example.com SIP/2.0
From: <sip:alice@example.com>;tag=abc123
To: <sip:+49123456789@example.com>
```

| Path | What Happens | Result |
|------|--------------|--------|
| **CPU** | Extracts `+49123456789` from To header, suffix-matches `456789` | ✓ Match |
| **GPU** | Searches raw payload for bytes `456789` | ✓ Match (but for wrong reason) |

**Problem case - From header matching:**

Filter: `alice*` (prefix match)

| Path | What Happens | Result |
|------|--------------|--------|
| **CPU** | Extracts `alice` from From header, prefix-matches | ✓ Match |
| **GPU** | Finds `alice` in `From: <sip:alice@...>` | ✓ Match (includes `From:` context) |

**False positive case:**

Filter: `error` (contains match)

SIP Message with SDP:
```
INVITE sip:bob@example.com SIP/2.0
...
a=rtpmap:0 PCMU/8000
a=fmtp:101 0-15
v=error-correction-disabled
```

| Path | What Happens | Result |
|------|--------------|--------|
| **CPU** | Extracts usernames, none contain "error" | ✗ No match |
| **GPU** | Finds "error" in SDP body | ✓ False positive! |

### Issue 3: Build Tag Complexity

The CUDA implementation requires:
1. `make build-cuda` with `-tags cuda`
2. CUDA toolkit installed at `/opt/cuda`
3. Compiled CUDA kernels (`libcuda_kernels.so`)

Most users will get the stub, falling back to SIMD automatically. This is fine, but the stub's `IsAvailable()` always returns `false`, which could be confusing.

### Issue 4: Incomplete CUDA Kernel

The CUDA kernel wrapper is declared but not implemented:

```c
// gpu_cuda_backend_impl.go:59-70
extern void launchPatternMatchKernel(...);
```

The `ExecutePatternMatching` function logs but doesn't actually launch the kernel:
```go
// Line 270
logger.Debug("CUDA pattern matching kernel would execute here")
```

## Performance Characteristics

### Current Overhead per Batch

| Operation | CUDA | SIMD | Notes |
|-----------|------|------|-------|
| Pattern transfer | 10-50μs | ~0 (pointer assign) | Happens every batch |
| Packet transfer | 50-200μs | ~0 | Depends on batch size |
| Pattern matching | GPU: parallel | CPU: sequential | Core operation |
| Result transfer | 10-30μs | ~0 | Depends on matches |

### Ideal Overhead per Batch

| Operation | CUDA | SIMD | Notes |
|-----------|------|------|-------|
| Pattern transfer | 0 | 0 | Pre-cached in VRAM/RAM |
| Username extraction | 5-10μs | 5-10μs | New step needed |
| Username transfer | 5-20μs | ~0 | Small data (just usernames) |
| Pattern matching | GPU: parallel | CPU: sequential | Against cached patterns |
| Result transfer | 5-10μs | ~0 | Simple bool per username |

## Recommended Strategy: Aho-Corasick with Double-Buffering

### Why Aho-Corasick is Mandatory

**Linear scan complexity:** O(U × P × L)
- U = usernames per second (30,000)
- P = patterns (10,000)
- L = average length (~15 chars)
- = **4.5 billion character comparisons/second**

**Aho-Corasick complexity:** O(U × L + M)
- U = usernames (30,000)
- L = average length (15)
- M = total matches (typically small)
- = **450,000 character comparisons/second**

**Result: 10,000x reduction in comparison operations.**

At LI scale, linear scan is simply not viable. Aho-Corasick (AC) must be the default algorithm.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│ On filter change (rare - seconds acceptable):                       │
│   1. Build new Aho-Corasick automaton from all patterns             │
│   2. For CUDA: Serialize automaton, upload to VRAM                  │
│   3. For SIMD/CPU: Store automaton in RAM                           │
│   4. Atomic swap: Replace old automaton with new one                │
│   (Building AC for 100K patterns takes ~100-500ms - acceptable)     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│ On each SIP packet batch (frequent - microseconds required):        │
│   1. [CPU] Extract usernames from From/To/PAI headers               │
│   2. [CPU/GPU] Run each username through cached automaton           │
│   3. Return: matched pattern IDs per username                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Handling Automaton Rebuilds

**Problem:** AC automaton must be rebuilt from scratch when patterns change. During rebuild, matching must continue uninterrupted.

**Solution: Double-Buffering**

```go
type PatternMatcher struct {
    // Double-buffered automata
    automaton       atomic.Pointer[AhoCorasick]  // Currently active
    buildingNew     atomic.Bool                   // Build in progress flag

    // For linear scan fallback during first build
    patterns        []GPUPattern

    mu              sync.RWMutex
}

func (pm *PatternMatcher) UpdatePatterns(patterns []GPUPattern) {
    pm.buildingNew.Store(true)

    go func() {
        // Build new automaton in background
        newAC := buildAhoCorasick(patterns)

        // Atomic swap - no locking needed for readers
        pm.automaton.Store(newAC)
        pm.buildingNew.Store(false)

        // Old automaton garbage collected after all readers done
    }()
}

func (pm *PatternMatcher) Match(username []byte) []int {
    ac := pm.automaton.Load()
    if ac != nil {
        return ac.Match(username)
    }
    // Fallback to linear scan during initial build
    return pm.linearScanMatch(username)
}
```

**Behavior:**
- First filter update: Linear scan until AC build completes (~100-500ms)
- Subsequent updates: Old AC continues serving while new AC builds
- Atomic pointer swap: Zero-downtime transition
- Memory: Briefly holds two automata during transition (~20MB for 100K patterns)

### Backend-Agnostic Implementation

**Critical requirement:** AC algorithm must work identically on CPU (SIMD) and GPU (CUDA).

```go
// Shared interface for both backends
type AhoCorasickMatcher interface {
    // Build automaton from patterns (called on filter update)
    Build(patterns []Pattern) error

    // Match username against automaton (called per packet)
    Match(input []byte) []MatchResult

    // Match batch of usernames (for GPU efficiency)
    MatchBatch(inputs [][]byte) [][]MatchResult
}

// CPU/SIMD implementation
type CPUAhoCorasick struct {
    states      []State           // Automaton states in RAM
    // Uses SIMD for state transition table lookups
}

// CUDA implementation
type CUDAAhoCorasick struct {
    deviceStates unsafe.Pointer   // Automaton states in VRAM
    // Each GPU thread processes one username
}
```

**Key insight:** The AC algorithm is the same; only the memory location (RAM vs VRAM) and parallelization differ.

### Handling Suffix/Prefix/Contains Patterns

AC naturally matches prefixes. For other pattern types:

| Pattern Type | Example | AC Strategy |
|--------------|---------|-------------|
| Contains | `alice` | Standard AC match |
| Prefix | `alice*` | AC match, verify at string start |
| Suffix | `*456789` | **Reverse** both pattern and input, then AC match |

**Implementation:**

```go
type MultiModeAC struct {
    containsAC  *AhoCorasick  // Standard patterns
    prefixAC    *AhoCorasick  // Prefix patterns (match, check offset=0)
    suffixAC    *AhoCorasick  // Reversed suffix patterns
}

func (m *MultiModeAC) Match(username []byte) []MatchResult {
    results := m.containsAC.Match(username)

    // Prefix matches must start at position 0
    for _, match := range m.prefixAC.Match(username) {
        if match.Offset == 0 {
            results = append(results, match)
        }
    }

    // Suffix matches: reverse username, match against reversed patterns
    reversed := reverseBytes(username)
    for _, match := range m.suffixAC.Match(reversed) {
        if match.Offset == 0 {  // Suffix = prefix of reversed
            results = append(results, match)
        }
    }

    return results
}
```

### Configuration Options

#### Auto-Selection Based on Pattern Count

```go
const (
    ACThreshold = 50  // Use AC when pattern count exceeds this
)

func (pm *PatternMatcher) selectAlgorithm(patternCount int) Algorithm {
    if patternCount > ACThreshold {
        return AlgorithmAhoCorasick
    }
    return AlgorithmLinearScan
}
```

**Rationale:**
- For <50 patterns, linear scan overhead is lower than AC automaton traversal
- For >50 patterns, AC's O(n) vs O(n×m) advantage dominates
- Threshold of 50 is approximate; benchmarks may refine this

#### User Override Flag

```
--pattern-algorithm=auto|linear|aho-corasick

auto (default):  Select based on pattern count
linear:          Force linear scan (for debugging/testing)
aho-corasick:    Force AC even for small pattern sets
```

**When to use linear:**
- Debugging pattern matching issues
- Benchmarking to compare algorithms
- Very small pattern sets where AC overhead isn't worth it

**Recommendation:** Default to `auto`. Log which algorithm is selected:
```
INFO Pattern matcher initialized algorithm=aho-corasick patterns=10523 automaton_build_time=342ms
```

### Memory Requirements

| Patterns | Raw Size | AC Automaton | VRAM/RAM Required |
|----------|----------|--------------|-------------------|
| 1,000 | 20 KB | ~200 KB | 400 KB (double-buffer) |
| 10,000 | 200 KB | ~2 MB | 4 MB (double-buffer) |
| 100,000 | 2 MB | ~20 MB | 40 MB (double-buffer) |

**Recommendation:**
- Default buffer: 64 MB (sufficient for 300K+ patterns)
- Configurable via `--pattern-buffer-mb`
- Log warning at 50% utilization

### Revised Interface

```go
type GPUBackend interface {
    // Existing methods (keep for compatibility)
    Initialize(config *GPUConfig) error
    AllocatePacketBuffers(maxPackets int, maxPacketSize int) error
    Cleanup() error
    Name() string
    IsAvailable() bool

    // NEW: Aho-Corasick automaton management
    BuildAutomaton(patterns []Pattern) error

    // NEW: Match extracted usernames against cached automaton
    // Returns slice of match results (pattern IDs) per input
    MatchUsernames(usernames [][]byte) ([][]int, error)

    // DEPRECATED: Old interface (remove after migration)
    TransferPacketsToGPU(packets [][]byte) error
    ExecutePatternMatching(patterns []GPUPattern) error
    TransferResultsFromGPU() ([]GPUResult, error)
}
```

## Resolved Questions

### Q1: Batch Size Optimization

**Answer:** With AC, batch size matters less since matching is O(input_length) not O(patterns).

**Recommendation:**
- SIMD/CPU: Process usernames as they're extracted (no batching needed)
- CUDA: Batch 64-256 usernames to amortize kernel launch overhead
- Benchmark to optimize, but expect diminishing returns past 128

### Q2: CUDA Kernel Priority

**Answer:** CUDA becomes essential at LI scale, but must implement AC traversal, not linear scan.

**Recommendation:**
1. Implement AC algorithm first (shared code, CPU-only)
2. Add SIMD optimizations for state transitions
3. Port to CUDA kernel (state table in VRAM, parallel username processing)

### Q3: Backward Compatibility (Raw Payload Search)

**Answer:** Remove as default. Raw payload search causes false positives/negatives that are unacceptable for LI.

**Recommendation:**
- Remove raw payload search entirely
- If needed for legacy: `--legacy-payload-search` flag with prominent warning
- Log deprecation warning if used

### Q4: Memory Limits

**Answer:** Current 1MB is insufficient for LI scale.

**Recommendation:**
- Increase default to 64 MB
- Configurable via `--pattern-buffer-mb`
- Log warning at 50% utilization
- Modern GPUs have 8-24GB VRAM; 64MB is negligible

### Q5: Multi-Pattern Optimization (Aho-Corasick)

**Answer:** Yes, AC is mandatory for LI scale. Must work on both CPU and GPU.

**Recommendation:**
- Implement `AhoCorasickMatcher` interface
- CPU implementation with SIMD-optimized state transitions
- CUDA implementation with automaton in VRAM
- Double-buffering for zero-downtime updates
- Auto-select based on pattern count (threshold ~50)

## Related Files

| File | Purpose |
|------|---------|
| `internal/pkg/voip/gpu_accel.go` | GPUAccelerator main interface |
| `internal/pkg/voip/gpu_cuda_backend.go` | CUDA stub (no cuda tag) |
| `internal/pkg/voip/gpu_cuda_backend_impl.go` | Real CUDA implementation |
| `internal/pkg/voip/gpu_simd_backend.go` | SIMD/CPU backend |
| `internal/pkg/hunter/application_filter.go` | Filter management, matching entry point |
| `internal/pkg/filtering/pattern.go` | Wildcard pattern parsing |
| `internal/pkg/voip/sip.go` | SIP header/username extraction |

## References

### Aho-Corasick Algorithm
- [Aho-Corasick Algorithm (Wikipedia)](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) - algorithm overview
- [Efficient String Matching: An Aid to Bibliographic Search](https://dl.acm.org/doi/10.1145/360825.360855) - original 1975 paper
- [cloudflare/ahocorasick](https://github.com/cloudflare/ahocorasick) - Go implementation (potential dependency)
- [petar-dambovaliev/aho-corasick](https://github.com/petar-dambovaliev/aho-corasick) - another Go implementation

### GPU Pattern Matching
- [CUDA Programming Guide](https://docs.nvidia.com/cuda/cuda-c-programming-guide/)
- [Parallel Aho-Corasick on GPU](https://ieeexplore.ieee.org/document/6114493) - GPU AC implementation paper
- [High-Performance Pattern Matching on GPU](https://dl.acm.org/doi/10.1145/2935764.2935800) - relevant research

### SIMD Optimization
- [SIMD Pattern Matching](https://www.strchr.com/strcmp_and_strlen_using_sse_4.2) - SSE4.2 string operations
- [Hyperscan](https://github.com/intel/hyperscan) - Intel's high-performance regex library (AC + SIMD)

### Lock-Free Data Structures
- [atomic.Pointer in Go](https://pkg.go.dev/sync/atomic#Pointer) - for double-buffering implementation

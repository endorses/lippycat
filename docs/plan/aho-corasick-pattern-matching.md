# Aho-Corasick Pattern Matching Implementation

**Date:** 2025-12-20
**Status:** Phase 1 Complete
**Research:** `docs/research/gpu-pattern-matching-architecture.md`

## Goal

Replace linear scan pattern matching with Aho-Corasick algorithm to support LI-scale workloads (10K-100K patterns, 30K+ usernames/second).

## Phase 1: Core AC Implementation

- [x] Create `internal/pkg/ahocorasick/` package
  - [x] `ahocorasick.go` - Core AC automaton (trie + failure links)
  - [x] `builder.go` - Automaton builder from patterns
  - [x] `matcher.go` - Match interface and Pattern/MatchResult types
  - [x] `ahocorasick_test.go` - Unit tests

- [x] Implement `Matcher` interface:
  ```go
  type Matcher interface {
      Build(patterns []Pattern) error
      Match(input []byte) []MatchResult
      MatchBatch(inputs [][]byte) [][]MatchResult
      PatternCount() int
  }
  ```

- [x] Add benchmarks comparing AC vs linear scan at various pattern counts
  - Benchmark results show AC is ~265x faster at 10K patterns

## Phase 2: Multi-Mode Support (Prefix/Suffix/Contains)

**Note:** Basic multi-mode support already implemented in Phase 1. The current implementation handles all pattern types in a single automaton by validating match positions during the match phase (prefix must start at offset 0, suffix must end at input length). The `MultiModeAC` wrapper with separate automata can be added later for optimization if needed.

- [x] Handle prefix/suffix/contains patterns in core AC
  - [x] Prefix handling: verify match offset == 0
  - [x] Suffix handling: verify match ends at input length
  - [x] Contains: matches anywhere

- [x] `PatternType` already exists in `internal/pkg/filtering/pattern.go`

- [x] Tests for all pattern types added in Phase 1

- [ ] (Optional) Create `MultiModeAC` wrapper for optimized suffix matching
  - [ ] Separate automata for contains, prefix, suffix patterns
  - [ ] Suffix handling: reverse patterns and inputs (for potential performance boost)

## Phase 3: Double-Buffering & Integration

- [ ] Create `internal/pkg/ahocorasick/buffered.go`
  - [ ] `atomic.Pointer[MultiModeAC]` for lock-free reads
  - [ ] Background rebuild on pattern update
  - [ ] Linear scan fallback during initial build

- [ ] Update `internal/pkg/hunter/application_filter.go`
  - [ ] Replace linear scan with `MultiModeAC`
  - [ ] Call `RebuildAutomaton()` in `UpdateFilters()`
  - [ ] Use `MatchUsernames()` in `matchWithCPU()`

- [ ] Add integration tests

## Phase 4: SIMD Optimization

- [ ] Optimize state transitions in `internal/pkg/ahocorasick/`
  - [ ] SIMD-accelerated state table lookups (AVX2/SSE4.2)
  - [ ] Cache-friendly state layout

- [ ] Add SIMD build tag variants
  - [ ] `ahocorasick_amd64.go` - SIMD-optimized
  - [ ] `ahocorasick_generic.go` - Portable fallback

- [ ] Benchmark SIMD vs generic

## Phase 5: GPU Backend Update

- [ ] Update `GPUBackend` interface in `internal/pkg/voip/gpu_accel.go`
  - [ ] Add `BuildAutomaton(patterns []Pattern) error`
  - [ ] Add `MatchUsernames(usernames [][]byte) ([][]int, error)`
  - [ ] Deprecate `ExecutePatternMatching()`

- [ ] Update `SIMDBackend` in `internal/pkg/voip/gpu_simd_backend.go`
  - [ ] Embed `MultiModeAC` for pattern matching
  - [ ] Implement new interface methods

- [ ] Update `CUDABackend` in `internal/pkg/voip/gpu_cuda_backend_impl.go`
  - [ ] Serialize AC automaton to VRAM
  - [ ] Implement CUDA kernel for automaton traversal
  - [ ] Each thread processes one username

## Phase 6: Configuration & Flags

- [ ] Add CLI flags to `cmd/hunt/hunt.go` and `cmd/sniff/voip.go`
  - [ ] `--pattern-algorithm=auto|linear|aho-corasick`
  - [ ] `--pattern-buffer-mb=64` (default)

- [ ] Add config file support in Viper
  ```yaml
  voip:
    pattern_algorithm: auto
    pattern_buffer_mb: 64
  ```

- [ ] Add logging for algorithm selection and build times

## Phase 7: Cleanup & Documentation

- [ ] Remove raw payload search from GPU path
  - [ ] Add `--legacy-payload-search` flag if needed
  - [ ] Log deprecation warning

- [ ] Update documentation
  - [ ] `cmd/hunt/README.md` - new flags
  - [ ] `cmd/sniff/README.md` - new flags
  - [ ] `docs/PERFORMANCE.md` - AC algorithm section

- [ ] Remove deprecated interface methods after migration

## File Changes Summary

### New Files
| Path | Purpose |
|------|---------|
| `internal/pkg/ahocorasick/ahocorasick.go` | Core AC implementation |
| `internal/pkg/ahocorasick/builder.go` | Automaton builder |
| `internal/pkg/ahocorasick/matcher.go` | Match interface |
| `internal/pkg/ahocorasick/multimode.go` | Prefix/suffix/contains handling |
| `internal/pkg/ahocorasick/buffered.go` | Double-buffered wrapper |
| `internal/pkg/ahocorasick/ahocorasick_test.go` | Tests |
| `internal/pkg/ahocorasick/benchmark_test.go` | Benchmarks |

### Modified Files
| Path | Changes |
|------|---------|
| `internal/pkg/voip/gpu_accel.go` | Add new interface methods |
| `internal/pkg/voip/gpu_simd_backend.go` | Integrate AC matcher |
| `internal/pkg/voip/gpu_cuda_backend_impl.go` | CUDA AC kernel |
| `internal/pkg/hunter/application_filter.go` | Use AC instead of linear |
| `cmd/hunt/hunt.go` | Add flags |
| `cmd/sniff/voip.go` | Add flags |

## Success Criteria

- [ ] AC matching 10,000x faster than linear scan at 10K patterns
- [ ] Zero-downtime pattern updates (double-buffering works)
- [ ] All pattern types (prefix/suffix/contains) work correctly
- [ ] GPU and CPU paths produce identical results
- [ ] Memory usage <100MB for 100K patterns

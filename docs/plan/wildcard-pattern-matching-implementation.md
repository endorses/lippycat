# Wildcard Pattern Matching Implementation

**Date:** 2025-12-20
**Status:** Implementation Complete (Phases 1-5)
**Research:** `docs/research/wildcard-pattern-matching.md`

## Overview

Add wildcard pattern matching for SIP user and phone number filters to handle international number format variations (E.164, 00-prefix, tech prefixes, etc.).

## Pattern Syntax

| Input | Type | Description |
|-------|------|-------------|
| `alice` | Contains | Substring match (backward compatible) |
| `*456789` | Suffix | Matches any prefix + `456789` |
| `alice*` | Prefix | Matches `alice` + any suffix |
| `*alice*` | Contains | Explicit contains (same as no wildcards) |
| `\*alice` | Literal | Escaped `*` treated as literal character |

## Implementation Tasks

### Phase 1: Pattern Parsing Package

- [x] Create `internal/pkg/filtering/pattern.go`
  - `ParsePattern(input string) (pattern string, patternType PatternType)`
  - Handle `\*` escape sequences (unescape to literal `*`)
  - Return stripped pattern and detected type
  - Added `Match()` helper function for case-insensitive matching

- [x] Create `internal/pkg/filtering/pattern_test.go`
  - Test all pattern types: suffix, prefix, contains, escaped

### Phase 2: SIMD Suffix Matching

- [x] Add `PatternTypeSuffix` constant in `internal/pkg/voip/gpu_accel.go`

- [x] Implement `matchSuffixSIMD()` in `internal/pkg/voip/gpu_simd_backend.go`
  - Compare last N bytes of data against pattern
  - Add case to `matchPatternSIMD()` switch
  - Also added `matchSuffix()` CPU fallback in `gpu_accel.go`

- [x] Add suffix tests in `internal/pkg/voip/gpu_simd_backend_test.go`
  - Added suffix test cases to `TestSIMDBackend_MatchTypes`
  - Added dedicated `TestSIMDBackend_SuffixMatching` for phone number variations

### Phase 3: Username Extraction for Matching

- [x] Extract P-Asserted-Identity username in `internal/pkg/voip/sip.go`
  - Added `ExtractUserFromHeader()` and `ExtractUserFromHeaderBytes()` exported functions
  - Reuses existing `extractUserFromSIPURI()` logic for all headers

- [x] Update `internal/pkg/hunter/application_filter.go`
  - Import `internal/pkg/filtering` package
  - Added `parsedFilter` struct to store parsed patterns with their types
  - Use `ParsePattern()` when adding filters in `UpdateFilters()`
  - In `matchWithCPU()`: extract username from From/To/P-Asserted-Identity before matching
  - Match against extracted usernames using `filtering.Match()` with pattern type

### Phase 4: Update sipusers Package

- [x] Update `internal/pkg/voip/sipusers/sipusers.go`
  - Use pattern parsing for stored patterns
  - Match against extracted username, not full header
  - Support P-Asserted-Identity matching (via containsUserInHeaders in shared.go)

### Phase 5: Documentation

- [x] Update CLI help text for `--sipuser` flag
- [x] Add examples to `cmd/sniff/README.md`, `cmd/hunt/README.md`, and `cmd/process/README.md`

## File Changes

### New Files

| Path | Purpose |
|------|---------|
| `internal/pkg/filtering/pattern.go` | Pattern syntax parsing |
| `internal/pkg/filtering/pattern_test.go` | Pattern parsing tests |

### Modified Files

| Path | Changes |
|------|---------|
| `internal/pkg/voip/gpu_accel.go` | Add `PatternTypeSuffix` |
| `internal/pkg/voip/gpu_simd_backend.go` | Add `matchSuffixSIMD()` |
| `internal/pkg/voip/gpu_simd_backend_test.go` | Add suffix tests |
| `internal/pkg/voip/sip.go` | Add P-Asserted-Identity extraction |
| `internal/pkg/hunter/application_filter.go` | Use pattern parsing, match extracted usernames |
| `internal/pkg/voip/sipusers/sipusers.go` | Add wildcard support |

## Key Design Decisions

1. **Backward compatible**: Patterns without `*` continue as substring matches
2. **Case insensitive**: Matches remain case-insensitive (irrelevant for digits)
3. **P-Asserted-Identity**: Extracted and matched alongside From/To
4. **Escape syntax**: `\*` for literal asterisk (rare use case)

## Testing Checklist

- [x] Pattern parsing: all types including escaped `\*`
- [x] Suffix SIMD: phone number variations (+49..., 0049..., *31#+49...)
- [x] Prefix SIMD: username prefix matching
- [x] P-Asserted-Identity: extraction and matching
- [ ] Integration: end-to-end with `lc sniff voip --sipuser '*456789'`

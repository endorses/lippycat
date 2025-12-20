# Wildcard Pattern Matching Implementation

**Date:** 2025-12-20
**Status:** Ready for Implementation
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

- [ ] Create `internal/pkg/filtering/pattern.go`
  - `ParsePattern(input string) (pattern string, patternType PatternType)`
  - Handle `\*` escape sequences (unescape to literal `*`)
  - Return stripped pattern and detected type

- [ ] Create `internal/pkg/filtering/pattern_test.go`
  - Test all pattern types: suffix, prefix, contains, escaped

### Phase 2: SIMD Suffix Matching

- [ ] Add `PatternTypeSuffix` constant in `internal/pkg/voip/gpu_accel.go`

- [ ] Implement `matchSuffixSIMD()` in `internal/pkg/voip/gpu_simd_backend.go`
  - Compare last N bytes of data against pattern
  - Add case to `matchPatternSIMD()` switch

- [ ] Add suffix tests in `internal/pkg/voip/gpu_simd_backend_test.go`

### Phase 3: Username Extraction for Matching

- [ ] Extract P-Asserted-Identity username in `internal/pkg/voip/sip.go`
  - Add `extractPAssertedIdentityUser()` function
  - Extract from `P-Asserted-Identity` header using same logic as From/To

- [ ] Update `internal/pkg/hunter/application_filter.go`
  - Import `internal/pkg/filtering` package
  - Use `ParsePattern()` when adding filters in `UpdateFilters()`
  - In `matchWithCPU()`: extract username from From/To/P-Asserted-Identity before matching
  - Match against extracted usernames instead of full header values

### Phase 4: Update sipusers Package

- [ ] Update `internal/pkg/voip/sipusers/sipusers.go`
  - Use pattern parsing for stored patterns
  - Match against extracted username, not full header
  - Support P-Asserted-Identity matching

### Phase 5: Documentation

- [ ] Update CLI help text for `--sipuser` and `--phone` flags
- [ ] Add examples to `cmd/sniff/README.md` and `cmd/hunt/README.md`

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

- [ ] Pattern parsing: all types including escaped `\*`
- [ ] Suffix SIMD: phone number variations (+49..., 0049..., *31#+49...)
- [ ] Prefix SIMD: username prefix matching
- [ ] P-Asserted-Identity: extraction and matching
- [ ] Integration: end-to-end with `lc sniff voip --sipuser '*456789'`

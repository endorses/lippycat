# Wildcard Pattern Matching Research

**Date:** 2025-12-19
**Status:** Research Complete
**Related:** `docs/research/cli-filter-management.md`

## Overview

This document captures research for implementing wildcard pattern matching in SIP user and phone number filters, inspired by OpenLI's implementation.

## Problem Statement

Phone numbers appear in SIP URIs with varying formats:

| Format | Example | Description |
|--------|---------|-------------|
| E.164 with + | `+49123456789@example.com` | Standard international |
| 00 prefix | `0049123456789@example.com` | ITU international prefix |
| No prefix | `49123456789@example.com` | Some systems strip + |
| National | `0123456789@example.com` | No country code |
| Tech prefix | `*31#+49123456789@...` | Hide caller ID, etc. |
| Extension | `+49123456789;ext=100@...` | SIP extensions |

A user wanting to match `+49123456789` needs to catch all these variations.

## OpenLI's Solution

**Source:** OpenLI project, `src/collector/sip_update_state.c`

OpenLI uses **simple suffix matching**:

```c
// sipid_matches_target() - sip_update_state.c:49-96
// Target starting with * does suffix matching
// e.g., *2345 matches +12345, 002345, 492345, etc.
```

**Why suffix matching works:**
- The **subscriber number** (local digits) is constant
- The **prefix** (country code, tech prefix, `+`, `00`) varies
- Matching the tail catches all variations

| Pattern | Matches |
|---------|---------|
| `*123456789` | `+49123456789`, `0049123456789`, `0123456789`, `*31#+49123456789` |

## Current lippycat State

### Username Extraction Already Exists

**File:** `internal/pkg/voip/sip.go:14`

```go
// extractUserFromSIPURI extracts the username from a SIP URI
// Example: "Alicent <sip:alicent@domain.com>" -> "alicent"
// Example: "sip:+49123456789@domain.com" -> "+49123456789"
func extractUserFromSIPURI(uri string) string
```

**Protobuf metadata (hunter → processor):**

```protobuf
// api/proto/data.proto
message SIPMetadata {
    string from_user = 3;    // Extracted username (no domain)
    string to_user = 4;      // Extracted username (no domain)
    string from_uri = 9;     // Full URI
    string to_uri = 10;      // Full URI
}
```

### Current Filtering Does NOT Use Extracted Username

**File:** `internal/pkg/hunter/application_filter.go`

The `matchWithCPU()` function extracts full header values and does substring matching:

```go
sipHeaders := extractSIPHeaders(payloadBytes)  // Gets full header value
// ...
if simd.BytesContains(fromLower, userBytes) {  // Substring match on full value
    return true
}
```

**File:** `internal/pkg/voip/sipusers/sipusers.go:73`

```go
// Substring match on full header - doesn't extract username
if strings.Contains(normalizedHeader, normalizedUsername) {
    return true
}
```

### GPU Pattern Types Already Support Prefix

**File:** `internal/pkg/voip/gpu_accel.go:69-76`

```go
type PatternType int

const (
    PatternTypeLiteral  PatternType = iota // Exact string match
    PatternTypePrefix                      // Prefix match (already implemented)
    PatternTypeContains                    // Contains substring (current default)
    PatternTypeRegex                       // Regular expression
)
```

**Missing:** `PatternTypeSuffix` - not yet implemented

**File:** `internal/pkg/voip/gpu_simd_backend.go:142-150`

```go
func (sb *SIMDBackend) matchPatternSIMD(data []byte, pattern GPUPattern) (bool, int) {
    switch pattern.Type {
    case PatternTypeLiteral:
        return sb.matchLiteralSIMD(data, pattern)
    case PatternTypePrefix:
        return sb.matchPrefixSIMD(data, pattern)
    case PatternTypeContains:
        return sb.matchContainsSIMD(data, pattern)
    // PatternTypeSuffix - NOT IMPLEMENTED
    }
}
```

## Recommended Implementation

### 1. Add PatternTypeSuffix

**File:** `internal/pkg/voip/gpu_accel.go`

```go
const (
    PatternTypeLiteral  PatternType = iota
    PatternTypePrefix
    PatternTypeSuffix   // NEW
    PatternTypeContains
    PatternTypeRegex
)
```

### 2. Implement SIMD Suffix Matching

**File:** `internal/pkg/voip/gpu_simd_backend.go`

```go
// matchSuffixSIMD checks for suffix match using SIMD
func (sb *SIMDBackend) matchSuffixSIMD(data []byte, pattern GPUPattern) (bool, int) {
    if len(data) < pattern.PatternLen {
        return false, -1
    }

    // Compare last N bytes
    offset := len(data) - pattern.PatternLen
    if simd.BytesEqual(data[offset:], pattern.Pattern) {
        return true, offset
    }
    return false, -1
}
```

Add to switch in `matchPatternSIMD()`:

```go
case PatternTypeSuffix:
    return sb.matchSuffixSIMD(data, pattern)
```

### 3. Pattern Syntax Detection

**File:** `internal/pkg/filtering/pattern.go` (new shared package)

```go
// ParsePattern determines pattern type from syntax
// *pattern = suffix match
// pattern* = prefix match
// pattern  = contains match (backward compatible)
func ParsePattern(input string) (pattern string, patternType PatternType) {
    if strings.HasPrefix(input, "*") && !strings.HasSuffix(input, "*") {
        // *456789 → suffix match on "456789"
        return input[1:], PatternTypeSuffix
    }
    if strings.HasSuffix(input, "*") && !strings.HasPrefix(input, "*") {
        // alice* → prefix match on "alice"
        return input[:len(input)-1], PatternTypePrefix
    }
    if strings.HasPrefix(input, "*") && strings.HasSuffix(input, "*") {
        // *pattern* → contains (strip both)
        return input[1:len(input)-1], PatternTypeContains
    }
    // No wildcards → contains (backward compatible)
    return input, PatternTypeContains
}
```

### 4. Match Against Extracted Username

**File:** `internal/pkg/hunter/application_filter.go`

Update `UpdateFilters()` to parse pattern syntax:

```go
case management.FilterType_FILTER_SIP_USER, management.FilterType_FILTER_PHONE_NUMBER:
    pattern, patternType := filtering.ParsePattern(filter.Pattern)
    af.patterns = append(af.patterns, voip.GPUPattern{
        ID:            len(af.patterns),
        Pattern:       []byte(pattern),
        PatternLen:    len(pattern),
        Type:          patternType,  // Now uses detected type
        CaseSensitive: false,
    })
```

Update `matchWithCPU()` to extract username before matching:

```go
// Extract username from SIP URI before matching
fromUser := extractUserFromSIPURI(string(sipHeaders.from))
toUser := extractUserFromSIPURI(string(sipHeaders.to))

for _, pattern := range af.patterns {
    if matchPattern(fromUser, pattern) || matchPattern(toUser, pattern) {
        return true
    }
}
```

### 5. Update sipusers Package (Optional)

If `sipusers` package is still used, update `IsSurveiled()` to support wildcards:

```go
func IsSurveiled(sipHeader string) bool {
    // Extract username from SIP URI
    username := extractUserFromSIPURI(sipHeader)

    for pattern, _ := range sipUserMap {
        if matchPattern(username, pattern) {
            return true
        }
    }
    return false
}
```

## GPU Compatibility

**Suffix matching is fully GPU-compatible:**

| Operation | Complexity | GPU-friendly? |
|-----------|------------|---------------|
| Prefix match | Compare first N bytes | Yes |
| Suffix match | Compare last N bytes | Yes |
| Contains match | Scan for substring | Yes |

Suffix matching is the **same complexity as prefix** - just offset calculation differs.

**CUDA kernel pseudocode:**

```c
__global__ void suffix_match(char* data, int data_len, char* pattern, int pattern_len, bool* result) {
    if (data_len < pattern_len) {
        *result = false;
        return;
    }
    int offset = data_len - pattern_len;
    *result = memcmp(data + offset, pattern, pattern_len) == 0;
}
```

## File Changes Summary

### New Files

| Path | Purpose |
|------|---------|
| `internal/pkg/filtering/pattern.go` | Pattern syntax parsing and type detection |
| `internal/pkg/filtering/pattern_test.go` | Pattern parsing tests |

### Modified Files

| Path | Changes |
|------|---------|
| `internal/pkg/voip/gpu_accel.go` | Add `PatternTypeSuffix` constant |
| `internal/pkg/voip/gpu_simd_backend.go` | Add `matchSuffixSIMD()` method |
| `internal/pkg/voip/gpu_cuda_backend.go` | Add suffix support to CUDA kernel |
| `internal/pkg/hunter/application_filter.go` | Use pattern parsing, match against extracted username |
| `internal/pkg/voip/sipusers/sipusers.go` | Optional: add wildcard support |

## Pattern Matching Examples

| User Input | Parsed Pattern | Type | Matches |
|------------|----------------|------|---------|
| `alice` | `alice` | Contains | `alice`, `alice@example.com`, `bigalice` |
| `*456789` | `456789` | Suffix | `+49123456789`, `0049123456789`, `0123456789` |
| `alice*` | `alice` | Prefix | `alice`, `alice123`, `alice_smith` |
| `*alice*` | `alice` | Contains | Same as no wildcards |

## Migration Path

1. **Phase 1:** Add `PatternTypeSuffix` and SIMD implementation (no behavior change)
2. **Phase 2:** Add pattern syntax parsing in `internal/pkg/filtering/`
3. **Phase 3:** Update `application_filter.go` to use parsed patterns
4. **Phase 4:** Update `sipusers` package if still needed
5. **Phase 5:** Update documentation and CLI help text

## Backward Compatibility

- Patterns without `*` continue to work as substring (contains) matches
- Existing filters are unaffected
- New suffix/prefix syntax is opt-in

## Testing Strategy

```go
func TestPatternParsing(t *testing.T) {
    tests := []struct {
        input       string
        wantPattern string
        wantType    PatternType
    }{
        {"alice", "alice", PatternTypeContains},
        {"*456789", "456789", PatternTypeSuffix},
        {"alice*", "alice", PatternTypePrefix},
        {"*alice*", "alice", PatternTypeContains},
    }
    // ...
}

func TestSuffixMatching(t *testing.T) {
    tests := []struct {
        pattern string
        input   string
        want    bool
    }{
        {"456789", "+49123456789", true},
        {"456789", "0049123456789", true},
        {"456789", "0123456789", true},
        {"456789", "*31#+49123456789", true},
        {"456789", "123456780", false},  // Wrong suffix
    }
    // ...
}
```

## Open Questions

1. **Should we extract P-Asserted-Identity username too?**
   - Currently only From/To are matched
   - OpenLI matches P-Asserted-Identity with lower trust

2. **Case sensitivity for phone numbers?**
   - Currently case-insensitive (good for SIP users)
   - Phone numbers are digits, case doesn't apply

3. **Escape syntax for literal `*`?**
   - If someone wants to match literal `*`, use `\*` or `**`?
   - Low priority - rare use case

## References

- OpenLI: `src/collector/sip_update_state.c` - `sipid_matches_target()`
- Current extraction: `internal/pkg/voip/sip.go` - `extractUserFromSIPURI()`
- GPU patterns: `internal/pkg/voip/gpu_accel.go` - `PatternType`
- SIMD backend: `internal/pkg/voip/gpu_simd_backend.go` - `matchPatternSIMD()`

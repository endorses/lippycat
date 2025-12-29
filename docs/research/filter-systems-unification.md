# Filter Systems Unification Research

**Date:** 2025-12-24
**Status:** Archived - Validated by LI Implementation
**Updated:** 2025-12-29 (Post-LI Analysis)
**Author:** Claude Code

---

## Post-Implementation Analysis (2025-12-29)

> **Context:** This research was conducted during ETSI LI (X1/X2/X3) implementation. LI is now complete (v0.5.0). This section documents what we learned.

### What the Research Got Right

1. **"Do NOT block on unification"** - Correct. LI shipped successfully without touching sipusers.
2. **ApplicationFilter for LI ID tracking** - Worked as predicted. Filter IDs map to XIDs for X2/X3 correlation.
3. **Separate systems serving different purposes** - Validated. LI made ApplicationFilter *more* enterprise-focused.

### What Changed During LI Implementation

The gap between systems widened significantly:

| Metric | sipusers | ApplicationFilter (post-LI) |
|--------|----------|----------------------------|
| LOC | ~132 | ~1,500+ (was 1,123) |
| Filter types | 1 (SIP user) | 4 + LI targets |
| New dependencies | none | PhoneNumberMatcher, LI Manager, enhanced GPU backends |

LI added:
- `PhoneNumberMatcher` package (`internal/pkg/phonematcher/`) with bloom filter + suffix matching
- SIPURI filter type with GPU-accelerated Aho-Corasick
- IP optimizations (O(1) hash maps for exact, O(prefix) radix tries for CIDR)
- LI filter ID tracking integrated throughout pipeline

### Updated Recommendations

| Original | Status | Notes |
|----------|--------|-------|
| Short-term: Add FilterMatcher interface | **Optional** | Lower priority now that LI validates current design |
| Short-term: Document relationship | **Done** | LI docs cover this |
| Medium-term: Extract core matching | **Partially done** | PhoneNumberMatcher, Aho-Corasick already extracted |
| Long-term: Modular ApplicationFilter | **Reconsidered** | Cost increased to 10-15 days; benefit unclear |

### Final Recommendation

**Keep systems separate.** The LI implementation reinforced the original design choice:

- **sipusers**: Simple CLI debugging (works well for its purpose)
- **ApplicationFilter**: Enterprise LI-capable filtering engine

Unifying now would drag LI complexity into `lc sniff`, violating the "avoid over-engineering" principle. If sniff needs phone/IP/URI filtering in the future:
1. Add specific capabilities to sipusers incrementally, OR
2. Use `lc tap voip` which has full ApplicationFilter support

**This research is archived.** The two systems should remain separate unless a concrete requirement emerges.

---

## Executive Summary

lippycat has two separate filtering systems that evolved independently:

1. **sipusers** (132 LOC) - Simple map-based filtering for `lc sniff voip`
2. **ApplicationFilter** (1,123 LOC) - Enterprise-grade filtering for hunters/processors with GPU, LI support, and hot-reload

This document analyzes what would be required to unify them and the trade-offs involved.

## Current Architecture

### System A: sipusers Package

**Location:** `internal/pkg/voip/sipusers/`
**Used by:** `lc sniff voip` command only

```
cmd/sniff/voip.go
    ↓ sipusers.AddSipUser() [via --sipuser flag]
internal/pkg/voip/sipusers/ (global state)
    ↓ sipusers.IsSurveiled()
internal/pkg/voip/shared.go::containsUserInHeaders()
    ↓ returns bool
internal/pkg/voip/*.go (UDP/TCP packet handlers)
```

**Characteristics:**
- Global mutex-protected maps
- Stores `SipUser` structs with `ExpirationDate` metadata
- Uses `filtering.ParsePattern()` for wildcard support
- Single integration point: `IsSurveiled(sipHeader string)`
- **Only supports SIP users** (no phone numbers, IPs, or URIs)

### System B: ApplicationFilter

**Location:** `internal/pkg/hunter/application_filter.go`
**Used by:** `lc hunt`, `lc tap`, `lc process`

```
processor (gRPC server)
    ↓ management.Filter messages
hunter/filtering/manager.go::Subscribe()
    ↓ UpdateFilters() → ApplicationFilter::UpdateFilters()
hunter/application_filter.go (instance per hunter)
    ↓ MatchPacket() or MatchPacketWithIDs()
processor/source/local.go or hunter/forwarding/manager.go
```

**Characteristics:**
- Per-instance state (each hunter has its own)
- Four filter types: SIP User, Phone Number, IP Address, SIP URI
- GPU acceleration via Aho-Corasick automatons
- PhoneNumberMatcher with bloom filter for fast rejection
- IP matching via hash maps (exact) and radix trees (CIDR)
- Hot-reload via gRPC without restart
- LI filter ID tracking for XID correlation

### Shared Component: filtering Package

**Location:** `internal/pkg/filtering/`

Both systems share:
- `ParsePattern()` - Wildcard detection (prefix/suffix/contains)
- `FilterConfig` types for persistence
- BPF filter parsing utilities

## Feature Comparison

| Feature | sipusers | ApplicationFilter |
|---------|----------|-------------------|
| **Scope** | CLI only | Distributed |
| **Pattern Count** | 1-10 typical | Hundreds to thousands |
| **SIP Users** | Yes (wildcards) | Yes (Aho-Corasick) |
| **Phone Numbers** | No | Yes (bloom + hash) |
| **IP Addresses** | No | Yes (hash + radix) |
| **SIP URIs** | No | Yes (Aho-Corasick) |
| **GPU Acceleration** | No | Yes |
| **Hot-reload** | No | Yes |
| **LI ID Tracking** | No | Yes |
| **Batch Processing** | No | Yes |
| **State Model** | Global singleton | Per-instance |
| **Thread Safety** | Mutex | RWMutex per instance |

## Why Two Systems Exist

1. **Historical Evolution:** sipusers was built first for simple CLI debugging. ApplicationFilter was built later for production distributed capture.

2. **Different Design Goals:**
   - sniff: Low-latency, single-threaded, developer-focused
   - hunter: High-throughput, batched, enterprise-focused

3. **LI Requirements:** ApplicationFilter tracks filter IDs for ETSI XID correlation. sipusers has no such requirement.

## Integration Challenges

### Challenge 1: Global vs Per-Instance State

sipusers uses global singleton maps. ApplicationFilter uses per-instance state. If sniff and hunter were ever used together (e.g., sniff debugging while hunter runs), global state could cause conflicts.

### Challenge 2: Protocol Detection Order

- **sipusers:** Assumes SIP headers already extracted by voip package
- **ApplicationFilter:** Uses centralized protocol detector first, then extracts headers

Different assumptions about packet processing order.

### Challenge 3: Filter ID Tracking

ApplicationFilter tracks filter IDs for LI correlation. sipusers has no concept of IDs. Unifying would add overhead to sniff that provides no benefit.

### Challenge 4: GPU Integration

ApplicationFilter has complex GPU state management. Adding this to sniff would significantly increase complexity for minimal benefit (sniff typically processes 1-10 patterns).

### Challenge 5: Dependency Direction

```
Current safe direction:
  cmd/sniff → voip → sipusers ✓

Would cause circular import:
  voip → hunter/application_filter ✗
```

ApplicationFilter is in `internal/pkg/hunter`. Moving it or creating a shared interface requires careful dependency management.

## Unification Approaches

### Approach 1: Replace sipusers with ApplicationFilter

**Effort:** 2-3 days
**Risk:** Medium

Convert sniff to use ApplicationFilter directly:
- Remove global sipusers state
- Convert `--sipuser` flags to Filter objects
- Disable GPU/ID tracking for sniff mode

**Pros:**
- True unification
- sniff gains phone/IP/URI filtering
- Single codebase to maintain

**Cons:**
- ApplicationFilter is 9x larger than sipusers
- GPU initialization overhead (even if disabled)
- More complex debugging for simple CLI tool

### Approach 2: Lightweight Facade (Interface)

**Effort:** 1-2 days
**Risk:** Low

Define shared interface, keep separate implementations:

```go
// internal/pkg/filtering/matcher.go
type FilterMatcher interface {
    Match(value string) bool
    MatchWithIDs(value string) (bool, []string)
    UpdateFilters(filters []*management.Filter)
}
```

**Pros:**
- sniff stays simple and fast
- Shared contract for both systems
- Low risk migration path
- Documents the relationship

**Cons:**
- Still two implementations
- Doesn't reduce code duplication

### Approach 3: Modular ApplicationFilter

**Effort:** 5-10 days
**Risk:** Medium

Refactor ApplicationFilter into composable layers:

```
Core Matching Engine (shared by all)
├── Pattern Parser (filtering.ParsePattern)
├── Aho-Corasick Matcher
├── PhoneNumberMatcher
└── IP Radix Trees

Optional Plugins (loaded as needed)
├── GPU Backend (hunter only)
├── ID Tracker (processor + LI only)
├── Hot-reload Manager (distributed only)
└── Batch Processor (hunter only)
```

**Pros:**
- True unification with zero duplication
- Each component is testable
- sniff gets lightweight core
- hunter/processor get full capabilities

**Cons:**
- Significant refactoring effort
- Risk of performance regressions
- Upfront design work required

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| sniff performance degrades | Medium | High | Benchmark before/after |
| Circular imports | Low | High | Clear layering in design |
| Breaking hunter filters | Low | High | Integration tests |
| ETSI work delayed | Medium | Medium | Decouple from ETSI |

## Recommendations

### For ETSI LI Integration (Current Work)

**Do NOT block on unification.** ApplicationFilter already has ID tracking. Continue enhancing it independently.

### Short-term (1-2 weeks)

1. Add `FilterMatcher` interface to document the contract
2. Add comment in sipusers explaining the relationship
3. Document in CLAUDE.md when to use each system

### Medium-term (1-2 months)

1. Extract core matching functions to `filtering/matcher.go`
2. Share SIP header extraction utilities
3. Reduce code duplication without changing architecture

### Long-term (3+ months)

1. Implement Approach 3 (Modular ApplicationFilter)
2. Migrate sniff to use lightweight core
3. Remove sipusers package entirely

## What sniff Would Gain from Unification

If unified, `lc sniff voip` would support:
- `--phone-number` filtering (new capability)
- `--ip-address` filtering (new capability)
- `--sip-uri` filtering (new capability)
- Same filter syntax as hunters
- Consistent behavior across all modes

## What sniff Would Lose

- Simplicity (132 LOC → ~400 LOC dependency)
- Fast startup (no GPU initialization check)
- Easy debugging (simpler code paths)

## Conclusion

The two filtering systems serve different purposes and were designed with different constraints. Unification is possible but requires careful consideration of trade-offs.

**Recommended path:** Start with Approach 2 (Lightweight Facade) to document the relationship, then evaluate Approach 3 (Modular ApplicationFilter) as a separate project after ETSI LI integration is complete.

The current separation is not a bug - it's a design choice that optimizes each system for its intended use case. Unification should be driven by concrete requirements (e.g., "sniff needs phone number filtering") rather than abstract desire for code unification.

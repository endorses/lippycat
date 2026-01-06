# Hunt/Tap VoIP Filtering and RTP Handling Issues

**Date:** 2026-01-06
**Status:** Analysis Complete

## Overview

Two related issues affect VoIP filtering and packet handling:

1. `lc hunt voip` matches all calls when using `phone_number` filters (while `lc tap voip` works correctly)
2. `lc tap voip` doesn't create RTP PCAP files or forward RTP packets to TUI clients (while processors receiving from hunters work correctly)

---

## Issue 1: Hunt VoIP Phone Number Filtering

### Symptom

When a processor sends `phone_number` filters to a hunter, the hunter matches ALL calls instead of only calls involving the specified phone numbers.

### Root Cause

The filter synchronization in `internal/pkg/hunter/filtering/manager.go:302-322` only handles `FILTER_SIP_USER` filters:

```go
func (m *Manager) syncSIPUserFilters(filters []*management.Filter) {
    sipUsers := make(map[string]*sipusers.SipUser)
    for _, filter := range filters {
        if filter.Type == management.FilterType_FILTER_SIP_USER {  // ← Only SIP_USER
            sipUsers[filter.Pattern] = &sipusers.SipUser{
                ExpirationDate: time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC),
            }
        }
    }
    sipusers.ClearAll()
    sipusers.AddMultipleSipUsers(sipUsers)
}
```

### Data Flow Analysis

```
Filter arrives at hunter:
  ├── filterManager.handleUpdate()
  │     ├── appFilter.UpdateFilters(filters)     ✓ Phone numbers stored correctly
  │     │     └── af.phoneMatcher.Add(pattern)   ✓ Pattern added to Bloom filter
  │     └── syncSIPUserFilters(filters)          ✗ Only syncs FILTER_SIP_USER
  │           └── sipusers.AddMultipleSipUsers() ✗ Phone numbers NOT added
  │
Packet arrives:
  └── VoIPPacketProcessor.HandleUDPPacket()
        └── sipusers.IsSurveiled(from, to)       ✗ No phone numbers to match
              └── Returns false → packet dropped
```

### Why Tap Works

Tap mode uses the `ApplicationFilter` directly for matching decisions, which properly contains phone_number patterns. It doesn't rely on the legacy `sipusers` package for surveillance decisions.

### Required Changes

#### Recommended: Refactor to use ApplicationFilter directly

Refactor the VoIP packet processor to use `ApplicationFilter.MatchPacket()` instead of `sipusers.IsSurveiled()`.

**Why this is the better architectural choice:**

1. **Single source of truth** - All filter logic lives in ApplicationFilter
2. **Automatic support for all filter types** - No need to update sync functions for new filter types
3. **GPU-accelerated matching** - ApplicationFilter supports CUDA/OpenCL backends
4. **Eliminates technical debt** - Removes the legacy sipusers synchronization entirely
5. **Consistency** - Same filtering approach used by tap mode

**Current architecture (problematic):**

```
Filters → ApplicationFilter (complete)
       ↘ syncSIPUserFilters() → sipusers (partial) ← VoIP buffering uses this
```

**Target architecture:**

```
Filters → ApplicationFilter ← VoIP buffering uses this directly
          (sipusers eliminated from hunter flow)
```

**Implementation approach:**

1. Add `ApplicationFilter` reference to `UDPPacketHandler`
2. Replace `sipusers.IsSurveiled()` calls with `appFilter.MatchPacket()`
3. Remove `syncSIPUserFilters()` from filter manager
4. Keep `sipusers` package only for backward compatibility with non-hunter modes (if needed)

**Affected files:**
- `internal/pkg/voip/udp_handler_hunter.go` - Use ApplicationFilter for matching
- `internal/pkg/hunter/filtering/manager.go` - Remove `syncSIPUserFilters()`
- `cmd/hunt/voip.go` - Wire ApplicationFilter to UDPPacketHandler

#### Quick Fix Alternative (Not Recommended)

Extending `syncSIPUserFilters()` to handle phone numbers would work but perpetuates technical debt:

- Maintains two parallel filter systems
- Requires updating sync function for each new filter type
- Misses GPU acceleration opportunity

---

## Issue 2: Tap VoIP Missing RTP Handling

### Symptom

When running `lc tap voip`:
- Per-call PCAP files don't contain RTP packets (only SIP)
- TUI clients connected to tap don't see RTP packets
- The same configuration works when using hunter → processor

### Root Cause

The `LocalSource` in tap mode converts raw packets without VoIP protocol analysis:

**File:** `internal/pkg/processor/source/local.go:390-425`

```go
func convertPacketInfo(pktInfo capture.PacketInfo) *data.CapturedPacket {
    // ... extracts raw packet data ...

    return &data.CapturedPacket{
        Data:           packetData,
        TimestampNs:    timestampNs,
        CaptureLength:  uint32(captureLen),
        OriginalLength: uint32(originalLen),
        InterfaceIndex: 0,
        LinkType:       uint32(pktInfo.LinkType),
        InterfaceName:  pktInfo.Interface,
        // Metadata: nil  ← NOT POPULATED
    }
}
```

The processor pipeline checks for metadata before writing:

**File:** `internal/pkg/processor/processor_packet_pipeline.go:112-153`

```go
if p.perCallPcapWriter != nil {
    for _, packet := range batch.Packets {
        if packet.Metadata != nil && packet.Metadata.Sip != nil {  // ← Always false for tap
            // ... write SIP/RTP to per-call PCAP ...
        }
    }
}
```

### Architecture Comparison

```
HUNTER → PROCESSOR (works):
  Hunter captures packet
    └── UDPPacketHandler.HandleUDPPacket()
          ├── Detects SIP: parseSIPPacket() → populates SIP metadata
          ├── Tracks calls: extractCallInfo()
          ├── Detects RTP: port matching from SDP
          └── Forwards with populated Metadata

  Processor receives packet
    └── packet.Metadata.Sip != nil → writes to PCAP ✓


TAP (broken):
  LocalSource captures packet
    └── convertPacketInfo()
          └── Returns packet with Metadata = nil

  Processor pipeline
    └── packet.Metadata == nil → skips PCAP writing ✗
```

### Required Changes

#### Recommended: Extract shared VoIP processor (Option B)

Extract the VoIP processing from `internal/pkg/voip/udp_handler_hunter.go` into a reusable component that both hunters and tap can use.

**Why this is the better architectural choice:**

1. **DRY principle** - Single implementation to maintain
2. **Bug fixes apply everywhere** - Fix once, both hunters and tap benefit
3. **Consistent behavior** - Identical VoIP detection across all modes
4. **Cleaner separation of concerns** - VoIP processing decoupled from transport
5. **Easier testing** - Test VoIP logic independently

**Current architecture (duplicated):**

```
Hunter:
  UDPPacketHandler → SIP parsing, call tracking, RTP detection (embedded)

Tap:
  LocalSource → No VoIP processing (broken)
```

**Target architecture (shared):**

```
internal/pkg/voip/processor/
├── processor.go      # VoIPProcessor interface + implementation
├── sip_detector.go   # SIP message detection and parsing
├── call_tracker.go   # Call state management (call-id → ports)
└── rtp_detector.go   # RTP detection via learned ports

Hunter:
  UDPPacketHandler → VoIPProcessor.Process(packet)

Tap:
  LocalSource → VoIPProcessor.Process(packet)
```

**VoIPProcessor interface:**

```go
// internal/pkg/voip/processor/processor.go
type VoIPProcessor interface {
    // Process analyzes a packet and returns VoIP metadata if detected
    Process(packet gopacket.Packet) *data.PacketMetadata

    // ActiveCalls returns current call state (for debugging/metrics)
    ActiveCalls() []CallInfo
}

type CallInfo struct {
    CallID    string
    FromUser  string
    ToUser    string
    RTPPorts  []uint16
    StartTime time.Time
}
```

**Implementation steps:**

1. Create `internal/pkg/voip/processor/` package
2. Extract SIP parsing from `udp_handler_hunter.go` into `sip_detector.go`
3. Extract call tracking logic into `call_tracker.go`
4. Extract RTP port mapping into `rtp_detector.go`
5. Create `VoIPProcessor` that composes these components
6. Refactor `UDPPacketHandler` to use `VoIPProcessor`
7. Wire `VoIPProcessor` into `LocalSource` for tap mode

**Affected files:**
- `internal/pkg/voip/processor/` - New package (extracted logic)
- `internal/pkg/voip/udp_handler_hunter.go` - Use VoIPProcessor
- `internal/pkg/processor/source/local.go` - Add VoIPProcessor option
- `cmd/tap/tap_voip.go` - Wire VoIPProcessor to LocalSource

#### Alternative A: Duplicate VoIP processing in tap (Not Recommended)

Creating a separate `LocalVoIPSource` with duplicated SIP/RTP detection:

- Violates DRY principle
- Two implementations to maintain
- Risk of behavior divergence
- Bug fixes needed in two places

#### Alternative C: Process in processor pipeline (Not Recommended)

Adding VoIP detection in the processor after packets arrive:

- CPU overhead at processor (parsing happens twice for hunter path)
- Requires call state tracking at processor level
- Works but architecturally awkward

---

## Implementation Recommendation

Both issues require refactoring for a clean architectural solution. The work can be done in two phases:

### Phase 1: Extract shared VoIP processor

This addresses Issue 2 and prepares for Issue 1.

**Steps:**

1. Create `internal/pkg/voip/processor/` package
2. Extract SIP detection from `udp_handler_hunter.go` → `sip_detector.go`
3. Extract call tracking → `call_tracker.go`
4. Extract RTP port mapping → `rtp_detector.go`
5. Create `VoIPProcessor` interface and implementation
6. Refactor `UDPPacketHandler` to use `VoIPProcessor`
7. Wire `VoIPProcessor` into `LocalSource` for tap mode
8. Add comprehensive unit tests for the new package

**Outcome:** Tap VoIP now handles RTP correctly, identical to hunter→processor path.

### Phase 2: Refactor hunter filtering to use ApplicationFilter

This addresses Issue 1.

**Steps:**

1. Add `ApplicationFilter` reference to `UDPPacketHandler` (or `VoIPProcessor`)
2. Replace `sipusers.IsSurveiled()` calls with `appFilter.MatchPacket()`
3. Remove `syncSIPUserFilters()` from filter manager
4. Update `cmd/hunt/voip.go` to wire ApplicationFilter
5. Add tests for phone_number filter matching
6. Evaluate if `sipusers` package can be deprecated for hunters

**Outcome:** Hunter respects all filter types (phone_number, sip_user, IP, etc.) with GPU acceleration support.

### Why this order?

Phase 1 first because:
- The VoIPProcessor refactoring is prerequisite for cleanly integrating ApplicationFilter
- Tap VoIP RTP is completely broken (higher priority)
- Hunter phone_number filtering has a workaround (use sip_user pattern instead)

### Dependency graph

```
Phase 1: VoIPProcessor extraction
    │
    ├── Fixes: Tap VoIP RTP handling (Issue 2)
    │
    └── Enables: Clean ApplicationFilter integration
            │
            └── Phase 2: Hunter filtering refactor
                    │
                    └── Fixes: Hunt phone_number filtering (Issue 1)
```

---

## Test Plan

### Phase 1: VoIPProcessor Tests

- [ ] Unit test: `SIPDetector` parses SIP INVITE correctly
- [ ] Unit test: `SIPDetector` extracts Call-ID, From, To headers
- [ ] Unit test: `CallTracker` maintains call state
- [ ] Unit test: `CallTracker` expires stale calls
- [ ] Unit test: `RTPDetector` extracts ports from SDP
- [ ] Unit test: `RTPDetector` identifies RTP on learned ports
- [ ] Unit test: `VoIPProcessor.Process()` returns correct metadata
- [ ] Integration test: Hunter with VoIPProcessor matches behavior of old implementation
- [ ] Integration test: Tap writes RTP to per-call PCAP
- [ ] Integration test: TUI receives RTP packets from tap
- [ ] Regression test: Hunter → Processor RTP handling unchanged

### Phase 2: ApplicationFilter Integration Tests

- [ ] Unit test: `UDPPacketHandler` uses ApplicationFilter for matching
- [ ] Unit test: Phone number filter matches correctly
- [ ] Unit test: SIP user filter still works correctly
- [ ] Unit test: IP address filter works correctly
- [ ] Integration test: Hunter with phone_number filter only matches specified numbers
- [ ] Integration test: Hunter with mixed filter types (phone + sip_user)
- [ ] Regression test: Existing sip_user filter behavior unchanged

---

## Files Summary

### Phase 1: VoIPProcessor Extraction

| File | Change |
|------|--------|
| `internal/pkg/voip/processor/processor.go` | New: VoIPProcessor interface and implementation |
| `internal/pkg/voip/processor/sip_detector.go` | New: SIP message detection (extracted) |
| `internal/pkg/voip/processor/call_tracker.go` | New: Call state management (extracted) |
| `internal/pkg/voip/processor/rtp_detector.go` | New: RTP port tracking (extracted) |
| `internal/pkg/voip/processor/processor_test.go` | New: Unit tests |
| `internal/pkg/voip/udp_handler_hunter.go` | Refactor to use VoIPProcessor |
| `internal/pkg/processor/source/local.go` | Add VoIPProcessor option |
| `cmd/tap/tap_voip.go` | Wire VoIPProcessor to LocalSource |

### Phase 2: ApplicationFilter Integration

| File | Change |
|------|--------|
| `internal/pkg/voip/udp_handler_hunter.go` | Add ApplicationFilter, replace sipusers.IsSurveiled() |
| `internal/pkg/hunter/filtering/manager.go` | Remove syncSIPUserFilters() |
| `cmd/hunt/voip.go` | Wire ApplicationFilter to UDPPacketHandler |
| `internal/pkg/voip/sipusers/sipusers.go` | Evaluate for deprecation (hunter mode) |

# VoIP Processor Refactor Implementation Plan

**Issue:** [docs/research/hunt-tap-voip-filtering-issues.md](../research/hunt-tap-voip-filtering-issues.md)
**Branch:** `feature/voip-processor-refactor`

## Goals

1. Fix tap VoIP missing RTP in PCAP files and TUI forwarding
2. Fix hunt VoIP phone_number filters matching all calls

---

## Phase 1: Extract Shared VoIPProcessor

Extract VoIP processing from `udp_handler_hunter.go` into reusable package.

### 1.1 Create VoIPProcessor Package

- [x] Create `internal/pkg/voip/processor/` directory
- [x] Create `processor.go` with interface:
  ```go
  type VoIPProcessor interface {
      Process(packet gopacket.Packet) *ProcessResult
      ActiveCalls() []CallInfo
      Close()
  }
  ```
- [x] Create `sip_detector.go` - SIP parsing and header extraction
- [x] Create `rtp_detector.go` - RTP port tracking from SDP
- [x] Create `adapter.go` - SourceAdapter for LocalSource integration

### 1.2 Refactor Hunter to Use VoIPProcessor

- [ ] Update `udp_handler_hunter.go` to use `VoIPProcessor` (deferred - hunter has different buffering needs)
- [x] Verify hunter behavior unchanged (run existing tests)

### 1.3 Wire VoIPProcessor into Tap

- [x] Add `VoIPProcessor` option to `internal/pkg/processor/source/local.go`
- [x] Update `cmd/tap/tap_voip.go` to create and wire VoIPProcessor
- [x] Ensure `convertPacketInfo()` populates `Metadata` field

### 1.4 Tests

- [x] Unit tests for `sip_detector.go`
- [x] Unit tests for `rtp_detector.go`
- [x] Unit tests for `processor.go`
- [x] Integration test: tap writes RTP to per-call PCAP
- [x] Integration test: TUI receives RTP from tap

---

## Phase 2: Refactor Hunter Filtering

Replace `sipusers.IsSurveiled()` with `ApplicationFilter.MatchPacket()`.

### 2.1 Integrate ApplicationFilter into VoIPProcessor

- [x] Add optional `ApplicationFilter` to `VoIPProcessor` config
- [x] Add `MatchesFilter(packet) bool` method using ApplicationFilter
- [x] Update `UDPPacketHandler` to use filter matching

### 2.2 Remove Legacy sipusers Synchronization

- [x] Remove `syncSIPUserFilters()` from `internal/pkg/hunter/filtering/manager.go`
- [x] Update `cmd/hunt/voip.go` to wire ApplicationFilter to VoIPProcessor
- [x] Verify sipusers package no longer needed for hunters

### 2.3 Tests

- [x] Unit test: phone_number filter matches correctly (existing tests in application_filter_test.go)
- [x] Unit test: sip_user filter still works (existing tests in application_filter_test.go)
- [x] Integration test: hunter with phone_number filter only matches specified numbers

---

## File Changes Summary

### Phase 1 (New Files)

| File | Description | Status |
|------|-------------|--------|
| `internal/pkg/voip/processor/processor.go` | Interface + implementation | ✅ |
| `internal/pkg/voip/processor/sip_detector.go` | SIP parsing | ✅ |
| `internal/pkg/voip/processor/rtp_detector.go` | RTP detection + SDP port extraction | ✅ |
| `internal/pkg/voip/processor/adapter.go` | SourceAdapter for LocalSource | ✅ |
| `internal/pkg/voip/processor/processor_test.go` | Unit tests | ✅ |
| `internal/pkg/voip/processor/sip_detector_test.go` | SIP parsing tests | ✅ |
| `internal/pkg/voip/processor/rtp_detector_test.go` | RTP detection tests | ✅ |

### Phase 1 (Modified Files)

| File | Change | Status |
|------|--------|--------|
| `internal/pkg/processor/source/local.go` | Add VoIPProcessor type alias + SetVoIPProcessor() | ✅ |
| `cmd/tap/tap_voip.go` | Create and wire VoIPProcessor | ✅ |

### Phase 2 (Modified Files)

| File | Change | Status |
|------|--------|--------|
| `internal/pkg/voip/udp_handler_hunter.go` | Add ApplicationFilter interface and matchesFilter() | ✅ |
| `internal/pkg/voip/tcp_handler_hunter.go` | Add ApplicationFilter support and matchesFilter() | ✅ |
| `internal/pkg/voip/voip_packet_processor.go` | Add SetTCPHandler() and SetApplicationFilter() | ✅ |
| `internal/pkg/hunter/filtering/manager.go` | Remove `syncSIPUserFilters()` | ✅ |
| `internal/pkg/hunter/forwarding/manager.go` | Add `ApplicationFilterReceiver` interface | ✅ |
| `internal/pkg/hunter/hunter.go` | Wire ApplicationFilter to packet processor | ✅ |
| `cmd/hunt/voip.go` | Wire TCP handler to processor for filter propagation | ✅ |
| `internal/pkg/voip/sipusers/sipusers.go` | Legacy (kept for backward compatibility) | ⚠️ |

---

## Verification

After each phase:

```bash
make test
make build

# Phase 1 verification
sudo ./bin/lc tap voip -i eth0 --per-call-pcap --per-call-pcap-dir /tmp/calls
# Verify RTP files created alongside SIP files

# Phase 2 verification
# Start processor with phone_number filter, connect hunter
# Verify only matching calls are captured
```

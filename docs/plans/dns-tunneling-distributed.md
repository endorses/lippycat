# DNS Tunneling Detection for Distributed Mode

## Overview

Add DNS tunneling detection support to tap, hunt, and process modes. Currently only works in `lc sniff dns` CLI mode.

## Architecture Decision

**Hunter + Processor detection**: Hunter parses DNS and detects tunneling at the edge, then forwards enriched metadata. Processor aggregates statistics across all hunters.

Benefits:
- Early detection at the edge
- Reduced duplicate parsing at processor
- Hunter-level alerting capability
- Processor sees aggregated view across all hunters

## Current State

- **Working**: `lc sniff dns` has `--detect-tunneling` flag and displays tunneling scores
- **Missing**: tap/hunt/process modes don't enable tunneling detection
- **Missing**: gRPC proto doesn't have DNS metadata fields
- **Ready**: TUI already has code to display tunneling scores (just needs data)

## Implementation Plan

### Phase 1: Add DNSMetadata to gRPC Proto

**File:** `api/proto/data.proto`

- [x] Add `DNSMetadata` message with fields:
  - transaction_id, is_response, query_name, query_type, query_class
  - response_code, opcode, header flags (authoritative, truncated, etc.)
  - record counts (question, answer, authority, additional)
  - tunneling_score, entropy_score (key fields)
  - query_response_time_ms, correlated_query

- [x] Add `dns` field to `PacketMetadata` message (field 12)

- [x] Regenerate gRPC code: `make proto`

### Phase 2: Add Tunneling Detection to Commands

**File:** `cmd/tap/tap_dns.go`

- [x] Add `--detect-tunneling` flag (default: true)
- [x] Bind to viper: `viper.BindPFlag("dns.detect_tunneling", ...)`
- [x] Set viper value in runDNSTap()

**File:** `cmd/hunt/dns.go`

- [x] Add `--detect-tunneling` flag (default: true)
- [x] Bind to viper: `viper.BindPFlag("dns.detect_tunneling", ...)`
- [x] Set viper value in runDNSHunt()

### Phase 3: Hunter-Side DNS Detection

**File:** `internal/pkg/hunter/dns_processor.go` (new file)

- [x] Create `DNSProcessor` struct with:
  - `parser *dns.Parser`
  - `tunneling *dns.TunnelingDetector`

- [x] Implement `ProcessPacket(packet) → *data.DNSMetadata`:
  1. Parse DNS packet
  2. Run tunneling analysis
  3. Return proto-ready metadata

**File:** `internal/pkg/hunter/hunter.go`

- [x] Add `dnsProcessor *DNSProcessor` field
- [x] Initialize when DNS mode + tunneling detection enabled
- [x] In capture loop, call `dnsProcessor.ProcessPacket()` for DNS packets
- [x] Populate `CapturedPacket.Metadata.Dns` before batching

### Phase 4: Tap-Side DNS Detection (LocalSource)

**File:** `internal/pkg/processor/source/local.go`

- [x] Add `dnsProcessor` field (same interface as hunter)
- [x] Initialize when DNS tunneling detection enabled
- [x] Process DNS packets before batching
- [x] Populate metadata in CapturedPacket

### Phase 5: Processor-Side Aggregation

**File:** `internal/pkg/processor/processor.go`

- [x] Add `dnsTunneling *dns.TunnelingDetector` for cross-hunter aggregation
- [x] In `processBatch()`, update aggregated stats from hunter-provided metadata
- [x] Provide `GetSuspiciousDomains()` API for management/alerting

### Phase 6: Proto-to-Types Conversion (TUI)

**File:** `internal/pkg/remotecapture/client_conversion.go`

- [x] Add DNS metadata conversion in `convertToPacketDisplay()`:
  - Check if `pkt.Metadata.Dns != nil`
  - Create `types.DNSMetadata` from proto fields
  - Set `display.DNSData`

## Key Files to Modify

| File | Changes |
|------|---------|
| `api/proto/data.proto` | Add DNSMetadata message |
| `cmd/tap/tap_dns.go` | Add --detect-tunneling flag, wire DNS processor |
| `cmd/hunt/dns.go` | Add --detect-tunneling flag |
| `internal/pkg/hunter/dns_processor.go` | New: DNS parsing + tunneling at hunter |
| `internal/pkg/hunter/hunter.go` | Wire DNS processor |
| `internal/pkg/processor/source/source.go` | DNSProcessor interface |
| `internal/pkg/processor/source/dns_processor.go` | New: DNS processor impl for tap mode |
| `internal/pkg/processor/source/local.go` | DNS processing for tap mode |
| `internal/pkg/processor/processor.go` | Aggregated tunneling stats |
| `internal/pkg/remotecapture/client_conversion.go` | Proto to types conversion |

## Data Flow After Implementation

```
Tap Mode:
  Network → LocalSource.dnsProcessor
                    ↓
              DNS Parser + Tunneling Detector
                    ↓
              CapturedPacket.Metadata.Dns populated
                    ↓
              Processor.processBatch() (aggregates stats)
                    ↓
              Broadcast to TUI subscribers
                    ↓
              TUI displays tunneling column

Hunt Mode:
  Network → Hunter.dnsProcessor
                    ↓
              DNS Parser + Tunneling Detector (edge)
                    ↓
              CapturedPacket.Metadata.Dns populated
                    ↓
              gRPC → Processor (receives enriched metadata)
                    ↓
              Processor aggregates cross-hunter stats
                    ↓
              TUI displays tunneling column
```

## Verification

1. Build project: `make build`
2. Start tap dns: `sudo lc tap dns -i lo --insecure`
3. Connect TUI: `lc watch remote --node localhost:55555 --insecure`
4. Run test script: `./scripts/test-dns-tunneling.sh --all -n 100`
5. Verify TUI shows tunneling scores in "Tunnel" column
6. Verify details panel shows tunneling warning for high-score packets

## Notes

- TUI already has rendering code for tunneling (dnsqueriesview.go, detailspanel.go)
- Tunneling detector is stateful (tracks domain stats over time)
- Each hunter maintains its own tunneling statistics
- Processor aggregates statistics across all hunters for global view
- Hunter-side detection enables early alerting at the edge

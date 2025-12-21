# lc tap Implementation Plan

**Date:** 2025-12-21
**Status:** Planned
**Research:** `docs/research/lc-tap-standalone-mode.md`
**Branch:** `feature/lc-tap-standalone`

## Overview

Implement `lc tap` - standalone capture mode combining local packet capture with full processor capabilities. Reuses hunter code for capture and processor code for pipeline.

**Commands:**
- `lc tap` - Generic standalone capture
- `lc tap voip` - VoIP-optimized capture

## Phase 1: PacketSource Interface

Define abstraction for packet origin.

### Step 1.1: Create interface

- [x] Create `internal/pkg/processor/source/source.go`:
  ```go
  type PacketSource interface {
      Start(ctx context.Context) error
      Batches() <-chan *PacketBatch
      Stats() Stats
      SourceID() string
  }

  type PacketBatch struct {
      SourceID    string
      Packets     []*data.CapturedPacket
      Sequence    uint64
      TimestampNs int64
  }
  ```

### Step 1.2: Create FilterTarget interface

- [x] Create `internal/pkg/processor/filtering/target.go`:
  ```go
  type FilterTarget interface {
      ApplyFilter(filter *management.Filter) error
      RemoveFilter(filterID string) error
      GetActiveFilters() []*management.Filter
      SupportsFilterType(filterType management.FilterType) bool
  }
  ```

## Phase 2: Refactor Processor

Extract current gRPC handling to implement interfaces.

### Step 2.1: Extract GRPCSource

- [x] Create `internal/pkg/processor/source/grpc.go`
- [x] Move gRPC server setup and hunter connection handling
- [x] Implement PacketSource interface
- [x] Add `HunterManager()` accessor for distributed mode

### Step 2.2: Extract HunterTarget

- [x] Create `internal/pkg/processor/filtering/target_hunter.go`
- [x] Move filter distribution logic from Manager
- [x] Implement FilterTarget interface

### Step 2.3: Update Processor

- [x] Add `packetSource PacketSource` field to Processor
- [x] Add `filterTarget FilterTarget` field to Processor
- [x] Modify `New()` to accept source/target based on config
- [x] Update `processBatch()` to use `source.PacketBatch`
- [x] Run all existing tests

## Phase 3: Implement LocalSource

Wrap hunter capture code for local mode.

### Step 3.1: Create LocalSource

- [x] Create `internal/pkg/processor/source/local.go`
- [x] Import `capture` package directly (reuse, not reimplement)
- [x] Reuse `convertPacketInfo()` logic from forwarding
- [x] Support `ApplicationFilter` interface for GPU and CPU filtering
- [x] Add batching logic
- [x] Implement PacketSource interface
- [x] Add `SetBPFFilter()` for filter integration

### Step 3.2: Unit tests

- [x] Test config defaults and custom config
- [x] Test state management (Start/Stop/IsStarted)
- [x] Test BPF filter updates
- [x] Test graceful shutdown

## Phase 4: Implement LocalTarget

BPF-based filtering for local mode.

### Step 4.1: Create LocalTarget

- [x] Create `internal/pkg/processor/filtering/target_local.go`
- [x] Implement filter-to-BPF conversion (reuse `internal/pkg/filtering`)
- [x] Implement dynamic BPF recompilation
- [x] Integrate `hunter.ApplicationFilter` for VoIP filters
- [x] Implement FilterTarget interface

### Step 4.2: Unit tests

- [x] Test BPF generation from filters
- [x] Test filter add/remove/update

## Phase 5: Command Implementation

Create `lc tap` command with build tags.

### Step 5.1: Create tap command

- [ ] Create `cmd/tap/tap.go` with build tag `//go:build tap || all`
- [ ] Add capture flags (`-i`, `--bpf`, `--promiscuous`, `--snaplen`)
- [ ] Add management flags (`--listen`, `--max-subscribers`)
- [ ] Add PCAP flags (`-w`, `--per-call-pcap`, `--auto-rotate-pcap`)
- [ ] Add processor feature flags (`--detect`, `--virtual-interface`)
- [ ] Add TLS flags for management interface
- [ ] Add `--upstream` flag for hierarchical forwarding

### Step 5.2: Create tap voip subcommand

- [ ] Create `cmd/tap/tap_voip.go`
- [ ] Add VoIP flags (`--sipuser`, `--sip-port`, `--udp-only`)
- [ ] Enable TCP reassembly and ApplicationFilter by default

### Step 5.3: Build system

- [ ] Add `tap` build tag to Makefile
- [ ] Update `make binaries` to include tap variant
- [ ] Update `cmd/root_all.go` to include tap command

### Step 5.4: Integration tests

- [ ] Test basic capture flow
- [ ] Test per-call PCAP writing
- [ ] Test TUI connection to tap node
- [ ] Test upstream forwarding

## Phase 6: Documentation

- [ ] Create `cmd/tap/README.md`
- [ ] Create `cmd/tap/CLAUDE.md`
- [ ] Update main `CLAUDE.md` with tap command
- [ ] Update architecture diagrams

## Validation Criteria

1. `lc tap voip -i eth0` captures and processes VoIP traffic
2. `lc watch remote --addr localhost:50051` connects to tap node
3. Per-call PCAP files are written correctly
4. `lc tap --upstream processor:50051` forwards to upstream
5. All existing processor and hunter tests pass
6. No code duplication - only reuse

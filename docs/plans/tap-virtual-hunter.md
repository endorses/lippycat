# Plan: TAP Node Virtual Hunter for Capture Statistics

## Overview

Display TAP node capture statistics in the TUI by synthesizing a "virtual hunter" from `LocalSource` stats. The virtual hunter appears in the existing hunter table, reusing all hunter rendering logic.

## Current State

- TAP nodes show `[TAP] eth0` badge but no capture statistics
- Hunters display: Captured, Forwarded, Dropped, Filters, Uptime, Mode
- `LocalSource` already tracks stats (`PacketsReceived`, `PacketsDropped`, etc.)
- Stats exist but aren't exposed to TUI

## Design Decision

**Approach:** Response-level injection (not manager-level)

Synthesize virtual hunter only in gRPC response methods. This avoids:
- Heartbeat timeout cleanup (manager marks non-heartbeating hunters as ERROR)
- Filter distribution complications (filters apply locally via LocalTarget)
- Manager state complexity

## Implementation

### 1. Add ProcessorID to LocalSource

**File:** `internal/pkg/processor/source/source.go`

```go
type LocalSourceConfig struct {
    // ... existing fields ...
    ProcessorID string  // For virtual hunter ID generation
}
```

**File:** `internal/pkg/processor/source/local.go`

```go
func (s *LocalSource) SourceID() string {
    if s.config.ProcessorID != "" {
        return s.config.ProcessorID + "-local"
    }
    return "local"
}
```

### 2. Add Virtual Hunter Synthesis

**File:** `internal/pkg/processor/processor.go`

```go
func (p *Processor) synthesizeVirtualHunter() *management.ConnectedHunter {
    if !p.IsLocalMode() {
        return nil
    }

    localSource, ok := p.packetSource.(*source.LocalSource)
    if !ok {
        return nil
    }

    stats := localSource.Stats()

    return &management.ConnectedHunter{
        HunterId:         p.config.ProcessorID + "-local",
        Hostname:         p.getLocalHostname(),
        Status:           management.HunterStatus_HUNTER_STATUS_HEALTHY,
        ConnectedAt:      stats.StartTime.UnixNano(),
        LastHeartbeat:    time.Now().UnixNano(),
        PacketsCaptured:  stats.PacketsReceived,
        PacketsForwarded: stats.PacketsReceived,
        PacketsDropped:   stats.PacketsDropped,
        Interfaces:       localSource.Interfaces(),
        Capabilities:     p.getLocalCapabilities(),
    }
}

func (p *Processor) getLocalCapabilities() *management.HunterCapabilities {
    caps := &management.HunterCapabilities{}
    if p.hasVoIPProcessor() {
        caps.FilterTypes = []string{"sip_user", "phone_number"}
    }
    return caps
}
```

### 3. Inject in GetTopology Response

**File:** `internal/pkg/processor/processor_grpc_handlers.go`

In `GetTopology()` (around line 466), after building `connectedHunters`:

```go
// Inject virtual hunter for TAP nodes
if virtualHunter := p.synthesizeVirtualHunter(); virtualHunter != nil {
    connectedHunters = append([]*management.ConnectedHunter{virtualHunter}, connectedHunters...)
}
```

### 4. Inject in GetHunterStatus Response

**File:** `internal/pkg/processor/processor_grpc_handlers.go`

In `GetHunterStatus()` (around line 305), same injection:

```go
// Inject virtual hunter for TAP nodes
if virtualHunter := p.synthesizeVirtualHunter(); virtualHunter != nil {
    connectedHunters = append([]*management.ConnectedHunter{virtualHunter}, connectedHunters...)
}
```

### 5. Inject in ListAvailableHunters Response

**File:** `internal/pkg/processor/processor_grpc_handlers.go`

In `ListAvailableHunters()` (around line 335), inject as `AvailableHunter`:

```go
// Inject virtual hunter for TAP nodes
if p.IsLocalMode() {
    virtualHunter := p.synthesizeVirtualHunter()
    if virtualHunter != nil {
        availableHunters = append([]*management.AvailableHunter{{
            HunterId:     virtualHunter.HunterId,
            Hostname:     virtualHunter.Hostname,
            Interfaces:   virtualHunter.Interfaces,
            Capabilities: virtualHunter.Capabilities,
        }}, availableHunters...)
    }
}
```

### 6. Pass ProcessorID to LocalSource

**File:** `cmd/tap/tap.go` (or wherever LocalSource is created)

```go
localSourceConfig := source.LocalSourceConfig{
    // ... existing fields ...
    ProcessorID: processorID,
}
```

## Files Modified

- [x] `internal/pkg/processor/source/local.go` - Add ProcessorID to LocalSourceConfig, update SourceID() method
- [x] `internal/pkg/processor/processor.go` - Add SynthesizeVirtualHunter()
- [x] `internal/pkg/processor/processor_grpc_handlers.go` - Inject in GetTopology, GetHunterStatus, ListAvailableHunters
- [x] `cmd/tap/tap.go` - Pass ProcessorID to LocalSource config
- [x] `cmd/tap/tap_voip.go` - Pass ProcessorID to LocalSource config
- [x] `cmd/tap/tap_dns.go` - Pass ProcessorID to LocalSource config
- [x] `cmd/tap/tap_tls.go` - Pass ProcessorID to LocalSource config
- [x] `cmd/tap/tap_email.go` - Pass ProcessorID to LocalSource config
- [x] `cmd/tap/tap_http.go` - Pass ProcessorID to LocalSource config

## Files NOT Modified

- Proto definitions (no new fields)
- TUI components (existing hunter rendering works)
- Hunter manager (virtual hunter not added)
- Filter distribution (skipped for virtual)

## Verification

1. `make test` - Ensure no regressions
2. `make build` - Verify compilation
3. Manual testing:
   ```bash
   # Start TAP in VoIP mode
   sudo lc tap voip -i eth0 --insecure

   # Connect TUI
   lc watch remote --nodes localhost:50051 --insecure

   # Verify:
   # - Virtual hunter appears as "{processor-id}-local"
   # - Mode shows "VoIP"
   # - Stats update in real-time (Captured, Forwarded, etc.)
   ```

4. Test generic mode:
   ```bash
   sudo lc tap -i eth0 --insecure
   # Mode should show "Generic"
   ```

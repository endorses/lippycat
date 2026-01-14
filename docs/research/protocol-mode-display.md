# Protocol Mode Display for Hunter and Tap Nodes

## Overview

This document researches what changes are needed to display protocol modes (DNS, Email, HTTP, TLS) in the TUI for both hunter and tap nodes, similar to how VoIP mode is currently distinguished from generic mode.

## Current State

### Protocol Mode Commands Already Exist

Both `hunt` and `tap` commands already have protocol-specific subcommands:

| Protocol | Hunt Command | Tap Command |
|----------|--------------|-------------|
| Generic | `lc hunt` | `lc tap` |
| VoIP | `lc hunt voip` | `lc tap voip` |
| DNS | `lc hunt dns` | `lc tap dns` |
| Email | `lc hunt email` | `lc tap email` |
| HTTP | `lc hunt http` | `lc tap http` |
| TLS | `lc hunt tls` | `lc tap tls` |

### Architecture: Tap Nodes as Virtual Hunters

Tap nodes appear in the TUI as "virtual hunters". The processor synthesizes a hunter entry for local capture:

**File:** `internal/pkg/processor/processor.go:525-579`

```go
func (p *Processor) SynthesizeVirtualHunter() *management.ConnectedHunter {
    // ...
    // Build capabilities based on VoIP mode
    caps := &management.HunterCapabilities{}
    if localSource.GetVoIPProcessor() != nil {
        caps.FilterTypes = []string{"sip_user", "phone_number"}
    }
    // ...
}
```

This virtual hunter is injected into hunter status responses:

**File:** `internal/pkg/processor/processor_grpc_handlers.go:307-312`

```go
// Inject virtual hunter for TAP nodes (local capture)
if virtualHunter := p.SynthesizeVirtualHunter(); virtualHunter != nil {
    connectedHunters = append([]*management.ConnectedHunter{virtualHunter}, connectedHunters...)
}
```

### How Hunter Modes Are Advertised

Hunters register with processors and advertise capabilities via `HunterCapabilities.filter_types`:

**File:** `internal/pkg/hunter/connection/manager.go:428-451`

Each protocol mode sets `SupportedFilterTypes` in its command:

| Mode | Filter Types |
|------|--------------|
| Generic | `["bpf", "ip_address"]` |
| VoIP | `["bpf", "ip_address", "sip_user", "phone_number", "call_id", "codec", "sip_uri"]` |
| DNS | `["bpf", "ip_address", "dns_domain"]` |
| Email | `["bpf", "ip_address", "email_address", "email_subject"]` |
| HTTP | `["bpf", "ip_address", "http_host", "http_path"]` |
| TLS | `["bpf", "ip_address", "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4"]` |

### How TUI Currently Detects Mode

**File:** `internal/pkg/tui/components/nodesview/rendering.go:68-90`

```go
func IsVoIPHunter(capabilities *management.HunterCapabilities) bool {
    if capabilities == nil || len(capabilities.FilterTypes) == 0 {
        return false  // Assume generic
    }
    for _, ft := range capabilities.FilterTypes {
        if ft == "sip_user" {
            return true
        }
    }
    return false
}

func GetHunterModeBadge(capabilities *management.HunterCapabilities, theme themes.Theme) string {
    if IsVoIPHunter(capabilities) {
        return "VoIP"
    }
    return "Generic"
}
```

**Problem:** Only VoIP vs Generic is detected. DNS, Email, HTTP, TLS all show as "Generic".

## Required Changes

### 1. Update Virtual Hunter Capabilities (Tap Nodes)

**File:** `internal/pkg/processor/processor.go` - `SynthesizeVirtualHunter()`

Currently only checks for VoIP processor. Need to check for all protocol processors and set appropriate filter types:

```go
func (p *Processor) SynthesizeVirtualHunter() *management.ConnectedHunter {
    // ...

    // Build capabilities based on protocol mode
    caps := &management.HunterCapabilities{}

    // Check which protocol processor is active
    if localSource.GetVoIPProcessor() != nil {
        caps.FilterTypes = []string{"bpf", "ip_address", "sip_user", "phone_number", "call_id", "codec", "sip_uri"}
    } else if localSource.GetDNSProcessor() != nil {
        caps.FilterTypes = []string{"bpf", "ip_address", "dns_domain"}
    } else if localSource.GetEmailProcessor() != nil {
        caps.FilterTypes = []string{"bpf", "ip_address", "email_address", "email_subject"}
    } else if localSource.GetHTTPProcessor() != nil {
        caps.FilterTypes = []string{"bpf", "ip_address", "http_host", "http_path"}
    } else if localSource.GetTLSProcessor() != nil {
        caps.FilterTypes = []string{"bpf", "ip_address", "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4"}
    } else {
        caps.FilterTypes = []string{"bpf", "ip_address"}
    }

    // ...
}
```

**Alternative:** Add a `ProtocolMode` field to `LocalSource` config that stores the mode directly, avoiding multiple processor checks.

### 2. Add Protocol Processor Getters to LocalSource

**File:** `internal/pkg/processor/source/local.go`

Need to add getter methods for each protocol processor (similar to existing `GetVoIPProcessor()`):

```go
func (s *LocalSource) GetDNSProcessor() *dns.Processor { ... }
func (s *LocalSource) GetEmailProcessor() *email.Processor { ... }
func (s *LocalSource) GetHTTPProcessor() *http.Processor { ... }
func (s *LocalSource) GetTLSProcessor() *tls.Processor { ... }
```

Or simpler - add a `GetProtocolMode()` method:

```go
func (s *LocalSource) GetProtocolMode() string {
    return s.config.ProtocolMode  // "generic", "voip", "dns", "email", "http", "tls"
}
```

### 3. Update Tap Commands to Set Protocol Mode

**Files:** `cmd/tap/tap_*.go`

Each tap command should set the protocol mode in LocalSource config:

```go
// cmd/tap/tap_dns.go
localSourceConfig := source.LocalSourceConfig{
    // ... existing fields ...
    ProtocolMode: "dns",
}

// cmd/tap/tap_email.go
ProtocolMode: "email",

// etc.
```

### 4. Update TUI Mode Detection

**File:** `internal/pkg/tui/components/nodesview/rendering.go`

Extend mode detection to recognize all protocol modes:

```go
// GetProtocolMode determines protocol mode from filter types
func GetProtocolMode(capabilities *management.HunterCapabilities) string {
    if capabilities == nil || len(capabilities.FilterTypes) == 0 {
        return "Generic"
    }

    for _, ft := range capabilities.FilterTypes {
        switch ft {
        case "sip_user", "phone_number", "call_id", "codec", "sip_uri":
            return "VoIP"
        case "dns_domain":
            return "DNS"
        case "email_address", "email_subject":
            return "Email"
        case "http_host", "http_path":
            return "HTTP"
        case "tls_sni", "tls_ja3", "tls_ja3s", "tls_ja4":
            return "TLS"
        }
    }
    return "Generic"
}

// GetHunterModeBadge returns display text for hunter mode
func GetHunterModeBadge(capabilities *management.HunterCapabilities, theme themes.Theme) string {
    return GetProtocolMode(capabilities)
}
```

### 5. Update Table and Graph Views

**Files:**
- `internal/pkg/tui/components/nodesview/table_view.go`
- `internal/pkg/tui/components/nodesview/graph_view.go`

These already call `GetHunterModeBadge()` - no changes needed once rendering.go is updated.

### 6. Update Filter Validation

**File:** `internal/pkg/tui/components/filtermanager/validation.go`

Add helper functions for each protocol type:

```go
func IsDNSFilterType(filterType management.FilterType) bool {
    return filterType == management.FilterType_FILTER_DNS_DOMAIN
}

func IsEmailFilterType(filterType management.FilterType) bool {
    return filterType == management.FilterType_FILTER_EMAIL_ADDRESS ||
        filterType == management.FilterType_FILTER_EMAIL_SUBJECT
}

func IsHTTPFilterType(filterType management.FilterType) bool {
    return filterType == management.FilterType_FILTER_HTTP_HOST ||
        filterType == management.FilterType_FILTER_HTTP_URL
}

func IsTLSFilterType(filterType management.FilterType) bool {
    return filterType == management.FilterType_FILTER_TLS_SNI ||
        filterType == management.FilterType_FILTER_TLS_JA3 ||
        filterType == management.FilterType_FILTER_TLS_JA3S ||
        filterType == management.FilterType_FILTER_TLS_JA4
}
```

Update validation to check protocol-specific filters:

```go
func ValidateFilter(params ValidateFilterParams) ValidateFilterResult {
    // Check if protocol-specific filter type is used without matching hunters
    mode := GetProtocolMode(params.SelectedHunter.Capabilities)

    if IsVoIPFilterType(params.Type) && mode != "VoIP" {
        return ValidateFilterResult{
            Valid: false,
            ErrorMessage: "VoIP filter requires a VoIP-mode hunter",
        }
    }
    if IsDNSFilterType(params.Type) && mode != "DNS" {
        return ValidateFilterResult{
            Valid: false,
            ErrorMessage: "DNS filter requires a DNS-mode hunter",
        }
    }
    // ... similar for Email, HTTP, TLS
}
```

## Implementation Order

- [ ] 1. Add `ProtocolMode` field to `LocalSourceConfig` (`internal/pkg/processor/source/local.go`)
- [ ] 2. Add `GetProtocolMode()` method to `LocalSource`
- [ ] 3. Update tap commands to set protocol mode (`cmd/tap/tap_*.go`)
- [ ] 4. Update `SynthesizeVirtualHunter()` to use protocol mode for filter types (`internal/pkg/processor/processor.go`)
- [ ] 5. Update TUI mode detection (`internal/pkg/tui/components/nodesview/rendering.go`)
- [ ] 6. Add protocol type helper functions (`internal/pkg/tui/components/filtermanager/`)
- [ ] 7. Update filter validation for all protocol modes

## Files to Modify

| File | Changes |
|------|---------|
| `internal/pkg/processor/source/local.go` | Add `ProtocolMode` to config, add getter |
| `internal/pkg/processor/processor.go` | Update `SynthesizeVirtualHunter()` |
| `cmd/tap/tap.go` | Set `ProtocolMode: "generic"` |
| `cmd/tap/tap_voip.go` | Set `ProtocolMode: "voip"` |
| `cmd/tap/tap_dns.go` | Set `ProtocolMode: "dns"` |
| `cmd/tap/tap_email.go` | Set `ProtocolMode: "email"` |
| `cmd/tap/tap_http.go` | Set `ProtocolMode: "http"` |
| `cmd/tap/tap_tls.go` | Set `ProtocolMode: "tls"` |
| `internal/pkg/tui/components/nodesview/rendering.go` | Multi-mode detection from filter_types |
| `internal/pkg/tui/components/filtermanager/editor.go` | Protocol type helpers |
| `internal/pkg/tui/components/filtermanager/validation.go` | Validate filters per mode |

## No Changes Required

- **Proto definitions** - Filter types already defined for all protocols
- **Hunter registration** - Already sets `SupportedFilterTypes` per mode
- **Table/graph views** - Already call `GetHunterModeBadge()`

## Key Insight

The architecture is simpler than initially thought:
1. Hunters already advertise their protocol mode via `filter_types`
2. Tap nodes just need to set `filter_types` correctly in virtual hunter
3. TUI just needs to detect mode from `filter_types` (not just VoIP)

No protobuf changes required - the existing `filter_types` mechanism is sufficient.

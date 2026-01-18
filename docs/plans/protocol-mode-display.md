# Protocol Mode Display Implementation Plan

Display DNS, Email, HTTP, and TLS modes in TUI for hunter and tap nodes.

## Phase 1: LocalSource Protocol Mode

- [x] Add `ProtocolMode string` field to `LocalSourceConfig` in `internal/pkg/processor/source/local.go`
- [x] Add `GetProtocolMode() string` method to `LocalSource`
- [x] Update tap commands to set protocol mode:
  - [x] `cmd/tap/tap.go` → `"generic"`
  - [x] `cmd/tap/tap_voip.go` → `"voip"`
  - [x] `cmd/tap/tap_dns.go` → `"dns"`
  - [x] `cmd/tap/tap_email.go` → `"email"`
  - [x] `cmd/tap/tap_http.go` → `"http"`
  - [x] `cmd/tap/tap_tls.go` → `"tls"`

## Phase 2: Virtual Hunter Capabilities

- [x] Update `SynthesizeVirtualHunter()` in `internal/pkg/processor/processor.go`:
  - [x] Use `localSource.GetProtocolMode()` to set `FilterTypes` based on mode
  - [x] Map each mode to its corresponding filter types array

## Phase 3: TUI Mode Detection

- [x] Update `internal/pkg/tui/components/nodesview/rendering.go`:
  - [x] Add `GetProtocolMode(capabilities)` function that checks filter types for protocol indicators
  - [x] Update `GetHunterModeBadge()` to return DNS/Email/HTTP/TLS (not just VoIP/Generic)
- [x] Update `internal/pkg/tui/components/nodesview/table_view.go`:
  - [x] Fix tree view to use `GetHunterModeBadge()` instead of hardcoded VoIP/Generic check

## Phase 4: Filter Validation

- [x] Add helper functions to `internal/pkg/tui/components/filtermanager/`:
  - [x] `IsDNSFilterType()` (already existed)
  - [x] `IsEmailFilterType()` (already existed)
  - [x] `IsHTTPFilterType()` (already existed)
  - [x] `IsTLSFilterType()` (already existed)
  - [x] `GetHunterProtocolMode()` - get protocol mode from hunter capabilities
  - [x] `GetRequiredProtocolMode()` - get required protocol mode for filter type
  - [x] `HasDNSHunters()`, `HasEmailHunters()`, `HasHTTPHunters()`, `HasTLSHunters()`
- [x] Update filter validation to check protocol-specific filters against hunter mode:
  - [x] `HunterSupportsFilterType()` - uses protocol mode checking
  - [x] `FilterHuntersByCapability()` - filters hunters by protocol mode
  - [x] `ValidateFilter()` - validates all protocol-specific filters
  - [x] `CycleFormFilterType()` - skips filter types without compatible hunters

## Filter Type Mappings

| Mode | Filter Types | Indicator |
|------|--------------|-----------|
| Generic | `bpf`, `ip_address` | (default) |
| VoIP | `sip_user`, `phone_number`, `call_id`, `codec`, `sip_uri` | `sip_user` |
| DNS | `dns_domain` | `dns_domain` |
| Email | `email_address`, `email_subject` | `email_address` |
| HTTP | `http_host`, `http_path` | `http_host` |
| TLS | `tls_sni`, `tls_ja3`, `tls_ja3s`, `tls_ja4` | `tls_sni` |

## Testing

- [ ] Verify `lc tap dns` shows "DNS" mode in TUI nodes view
- [ ] Verify `lc tap email` shows "Email" mode in TUI nodes view
- [ ] Verify `lc tap http` shows "HTTP" mode in TUI nodes view
- [ ] Verify `lc tap tls` shows "TLS" mode in TUI nodes view
- [ ] Verify `lc hunt dns/email/http/tls` shows correct mode
- [ ] Verify protocol-specific filters only apply to matching hunters

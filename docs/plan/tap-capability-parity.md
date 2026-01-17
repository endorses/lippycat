# Plan: TAP Command Capability Parity

## Overview

Bring `lc tap` to parity with its architectural contract: `tap = process + hunt - gRPC`. Based on gap analysis in `docs/research/tap-capability-gap-analysis.md`.

## Code Reuse Strategy

### Extract to Shared Packages

**1. Helper functions → `internal/pkg/cmdutil/config.go`**

Currently duplicated in hunt.go, process.go, tap.go (identical implementations):
- `getStringConfig(key, flagValue string) string`
- `getIntConfig(key string, flagValue int) int`
- `getBoolConfig(key string, flagValue bool) bool`
- `getStringSliceConfig(key string, flagValue []string) []string`
- `getFloat64Config(key string, flagValue float64) float64`
- `parseSizeString(s string) (int64, error)`

**2. BPF port utilities → `internal/pkg/bpfutil/port.go`**

Currently in `internal/pkg/hunter/capture/manager.go` (hunter build tag):
- `extractPortFromAddr(addr string) string`

### Copy Pattern (Cannot Share Directly)

Flag registration must stay command-specific because:
- Package-level variables for flag values
- Command-specific Viper key prefixes (`hunter.*`, `processor.*`, `tap.*`)
- Different build tags (`cuda` for GPU, `li` for LI)

**GPU flags:** Copy from `cmd/hunt/flags_gpu.go`, change `hunter.voip_filter.*` → `tap.voip_filter.*`
**LI flags:** Copy from `cmd/process/flags_li.go`, change `processor.li.*` → `tap.li.*`

## Implementation Phases

### Phase 0: Extract Shared Code

- [x] Create `internal/pkg/cmdutil/config.go` with helper functions
- [x] Create `internal/pkg/bpfutil/port.go` with `ExtractPortFromAddr()`
- [x] Update `cmd/hunt/hunt.go` to use `cmdutil.*`
- [x] Update `cmd/process/process.go` to use `cmdutil.*`
- [x] Update `cmd/tap/tap.go` to use `cmdutil.*`
- [x] Update `internal/pkg/hunter/capture/manager.go` to use `bpfutil.*`
- [x] Run `make test` to verify

### Phase 1: Own-Traffic BPF Exclusion (High)

Prevent tap from capturing its own gRPC traffic.

- [x] Add `buildOwnTrafficExclusionFilter()` in `cmd/tap/tap.go`:
  ```go
  func buildOwnTrafficExclusionFilter(listenAddr, upstreamAddr string) string {
      var exclusions []string
      if port := bpfutil.ExtractPortFromAddr(listenAddr); port != "" {
          exclusions = append(exclusions, fmt.Sprintf("not port %s", port))
      }
      if port := bpfutil.ExtractPortFromAddr(upstreamAddr); port != "" {
          exclusions = append(exclusions, fmt.Sprintf("not port %s", port))
      }
      if len(exclusions) == 0 {
          return ""
      }
      return strings.Join(exclusions, " and ")
  }
  ```
- [x] Apply in all tap subcommands before passing filter to capture

### Phase 2: GPU Acceleration (High)

- [x] Create `cmd/tap/flags_gpu.go` (build tag: `cuda`)
- [x] Create `cmd/tap/flags_gpu_stub.go` (build tag: `!cuda`)
- [x] Call `RegisterGPUFlags(TapCmd)` in init
- [x] Call `BindGPUViperFlags(TapCmd)` in init
- [x] Wire `GetGPUConfig()` to capture config in `tap_voip.go`

**Viper keys:** `tap.voip_filter.enabled`, `tap.voip_filter.gpu_backend`, `tap.voip_filter.gpu_batch_size`

### Phase 3: LI Support (Critical)

- [x] Create `cmd/tap/flags_li.go` (build tag: `li`)
- [x] Create `cmd/tap/flags_li_stub.go` (build tag: `!li`)
- [x] Call `RegisterLIFlags(TapCmd)` in init
- [x] Call `BindLIViperFlags(TapCmd)` in init
- [x] Wire `GetLIConfig()` to `processor.Config{}` in runTap
- [x] LI examples in `tap.go` docstring are now accurate (no removal needed)

**Viper keys:** `tap.li.enabled`, `tap.li.x1_listen_addr`, etc.

### Phase 4: TLS Keylog (Medium)

- [x] Add `--tls-keylog-dir` flag in `cmd/tap/tap.go`
- [x] Bind to `tap.tls_keylog.output_dir`
- [x] Wire to `processor.Config.TLSKeylogConfig` in runTap

### Phase 5: DNS Tunneling (Medium)

- [x] Add flags in `cmd/tap/tap_dns.go`:
  - `--tunneling-command`
  - `--tunneling-threshold`
  - `--tunneling-debounce`
- [x] Wire to `processor.Config` and `CommandExecutorConfig`

### Phase 6: Production mTLS (Medium)

- [x] Add mTLS enforcement in `cmd/tap/tap.go` and all subcommands:
  - tap.go, tap_dns.go, tap_email.go, tap_http.go, tap_tls.go, tap_voip.go
  - Checks `!tlsClientAuth && !viper.GetBool("tap.tls.client_auth")`
  - Error: `LIPPYCAT_PRODUCTION=true requires mutual TLS (--tls-client-auth)`

### Phase 7: Minor Gaps (Low)

- [x] Add `--voip-command` to CommandExecutorConfig in `tap.go`
- [x] Add `--stats` flag (replace hardcoded `DisplayStats: true`)
- [x] Add `--pattern-algorithm`, `--pattern-buffer-mb` to `tap_voip.go` (already implemented)

## File Summary

### New Files
| File | Build Tag | Lines (est) |
|------|-----------|-------------|
| `internal/pkg/cmdutil/config.go` | none | ~60 |
| `internal/pkg/bpfutil/port.go` | none | ~30 |
| `cmd/tap/flags_gpu.go` | `cuda` | ~45 |
| `cmd/tap/flags_gpu_stub.go` | `!cuda` | ~20 |
| `cmd/tap/flags_li.go` | `li` | ~110 |
| `cmd/tap/flags_li_stub.go` | `!li` | ~25 |

### Modified Files
| File | Changes |
|------|---------|
| `cmd/hunt/hunt.go` | Import cmdutil, remove helper functions |
| `cmd/process/process.go` | Import cmdutil, remove helper functions |
| `cmd/tap/tap.go` | Import cmdutil/bpfutil, add BPF exclusion, add flags |
| `cmd/tap/tap_*.go` | Apply BPF exclusion, wire new configs |
| `internal/pkg/hunter/capture/manager.go` | Import bpfutil |

## Verification

```bash
# Phase 0: Shared code extraction
make test

# All phases
make build
make tap
make tap-li
make tap-li-cuda

# Test BPF exclusion
sudo lc tap -i eth0 --listen :50051 --filter "port 5060" -v
# Log should show: "(port 5060) and (not port 50051)"

# Test GPU
sudo lc tap voip -i eth0 --gpu-backend cuda --enable-voip-filter

# Test LI
sudo lc tap -i eth0 --li-enabled --li-x1-listen :8443

make test
```

## Dependencies

- Phase 0 must complete first (shared code)
- Phases 1-7 can proceed in parallel after Phase 0
- Phase 3 (LI) depends on Phase 0 for helper functions

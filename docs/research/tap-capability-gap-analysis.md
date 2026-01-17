# Research: Tap Command Capability Gap Analysis

## Overview

The `lc tap` command is architecturally defined as:

```
tap = process + hunt - gRPC
```

This means tap should have **all** capabilities of both processor and hunter nodes, running locally without gRPC overhead. However, an audit reveals significant capability gaps where tap is missing features from both process and hunt commands.

## Methodology

This analysis compared:
- `cmd/process/process.go` and associated flag files against `cmd/tap/tap.go`
- `cmd/hunt/hunt.go`, `cmd/hunt/voip.go` and associated flag files against `cmd/tap/tap.go`
- How each command builds and passes configuration to underlying packages

## Missing Processor Capabilities

### 1. Lawful Interception (LI)

**Severity: Critical**

Tap has zero LI support despite process having complete ETSI X1/X2/X3 implementation.

**Missing flags (14 total):**
| Flag | Default | Description |
|------|---------|-------------|
| `--li-enabled` | `false` | Enable ETSI LI support |
| `--li-x1-listen` | `:8443` | X1 administration interface listen address |
| `--li-x1-tls-cert` | `""` | Path to X1 server TLS certificate |
| `--li-x1-tls-key` | `""` | Path to X1 server TLS key |
| `--li-x1-tls-ca` | `""` | Path to CA certificate for X1 client verification |
| `--li-admf-endpoint` | `""` | ADMF endpoint for X1 notifications |
| `--li-admf-tls-cert` | `""` | Client TLS certificate for ADMF notifications |
| `--li-admf-tls-key` | `""` | Client TLS key for ADMF notifications |
| `--li-admf-tls-ca` | `""` | CA certificate for verifying ADMF server |
| `--li-admf-keepalive` | `30s` | Keepalive interval for ADMF notifications |
| `--li-delivery-tls-cert` | `""` | Client TLS certificate for X2/X3 delivery |
| `--li-delivery-tls-key` | `""` | Client TLS key for X2/X3 delivery |
| `--li-delivery-tls-ca` | `""` | CA certificate for verifying MDF servers |
| `--li-delivery-tls-pinned-cert` | `nil` | Pinned certificate fingerprints for MDF servers |

**Missing config wiring:**
- `processor.Config.LIEnabled` - never set
- `processor.Config.LIX1ListenAddr` - never set
- `processor.Config.LIX1TLSCertFile` - never set
- `processor.Config.LIX1TLSKeyFile` - never set
- `processor.Config.LIX1TLSCAFile` - never set
- `processor.Config.LIADMFEndpoint` - never set
- `processor.Config.LIADMFTLSCertFile` - never set
- `processor.Config.LIADMFTLSKeyFile` - never set
- `processor.Config.LIADMFTLSCAFile` - never set
- `processor.Config.LIADMFKeepalive` - never set
- `processor.Config.LIDeliveryTLSCertFile` - never set
- `processor.Config.LIDeliveryTLSKeyFile` - never set
- `processor.Config.LIDeliveryTLSCAFile` - never set
- `processor.Config.LIDeliveryTLSPinnedCert` - never set

**Missing infrastructure:**
- No `cmd/tap/flags_li.go` file
- No `cmd/tap/flags_li_stub.go` file
- No calls to `RegisterLIFlags()` or `BindLIViperFlags()`
- No `GetLIConfig()` retrieval or assignment to processor.Config

**Note:** The `internal/pkg/processor/` package has full LI support. The processor struct can handle LI when configured. Tap simply never passes LI configuration to it.

**Misleading documentation:** `cmd/tap/tap.go` lines 59-64 show an LI usage example that doesn't work:
```
# Lawful Interception (requires -tags li build)
lc tap -i eth0 --tls-cert server.crt --tls-key server.key \
  --li-enabled \
  --li-x1-listen :8443 ...
```
These flags do not exist in tap.

### 2. TLS Session Key Logging

**Severity: Medium**

Process can export TLS session keys in NSS keylog format for Wireshark decryption. Tap cannot.

**Missing flag:**
| Flag | Default | Description |
|------|---------|-------------|
| `--tls-keylog-dir` | `""` | Directory to write TLS session keys |

**Missing config wiring:**
- `processor.Config.TLSKeylogConfig` - never set (always nil)

**How process.go handles it (lines 357-368):**
```go
var tlsKeylogConfig *processor.TLSKeylogWriterConfig
keylogDir := getStringConfig("processor.tls_keylog.output_dir", tlsKeylogDir)
if keylogDir != "" {
    tlsKeylogConfig = &processor.TLSKeylogWriterConfig{
        OutputDir:   keylogDir,
        FilePattern: "session_{timestamp}.keys",
        MaxEntries:  10000,
        SessionTTL:  time.Hour,
    }
}
```

### 3. DNS Tunneling Detection

**Severity: Medium**

Process can detect DNS tunneling and execute alert commands. Tap cannot.

**Missing flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--tunneling-command` | `""` | Command to execute when DNS tunneling detected |
| `--tunneling-threshold` | `0.7` | DNS tunneling score threshold (0.0-1.0) |
| `--tunneling-debounce` | `5m` | Minimum time between alerts per domain |

**Missing config wiring:**
- `processor.Config.TunnelingThreshold` - defaults to 0 (disabled)
- `processor.Config.TunnelingDebounce` - defaults to 0 (no debounce)
- `processor.CommandExecutorConfig.TunnelingCommand` - never set

### 4. VoIP Command Hook

**Severity: Low**

Process can execute commands when VoIP calls complete. Tap's base command cannot (though `tap voip` may have separate handling).

**Missing flag:**
| Flag | Default | Description |
|------|---------|-------------|
| `--voip-command` | `""` | Command to execute when VoIP call completes |

**Missing config wiring:**
- `processor.CommandExecutorConfig.VoipCommand` - never set

**Note:** `tap.go` builds CommandExecutorConfig but only includes `PcapCommand`, omitting `VoipCommand` and `TunnelingCommand`:
```go
// tap.go lines 345-360
commandExecutorConfig = &processor.CommandExecutorConfig{
    PcapCommand: pcapCmd,
    Timeout:     timeout,
    Concurrency: getIntConfig("tap.command_concurrency", commandConcurrency),
}
```

### 5. Statistics Display Control

**Severity: Low**

Process allows disabling statistics display via flag. Tap hardcodes it.

**Missing flag:**
| Flag | Default | Description |
|------|---------|-------------|
| `--stats` / `-s` | `true` | Display statistics |

**Current tap behavior:**
```go
// tap.go line 400
DisplayStats: true,  // Hardcoded
```

### 6. Production Mode mTLS Enforcement

**Severity: Medium**

When `LIPPYCAT_PRODUCTION=true`, process enforces mutual TLS. Tap only checks for `--insecure`.

**process.go enforcement (lines 246-255):**
```go
if productionMode {
    if getBoolConfig("insecure", insecureAllowed) {
        return fmt.Errorf("LIPPYCAT_PRODUCTION=true does not allow --insecure flag")
    }
    if !tlsClientAuth && !viper.GetBool("processor.tls.client_auth") {
        return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires mutual TLS (--tls-client-auth)")
    }
}
```

**tap.go enforcement (lines 308-315):**
```go
if productionMode {
    if getBoolConfig("insecure", insecureAllowed) {
        return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (do not use --insecure)")
    }
}
// Missing: mTLS check
```

## Missing Hunter Capabilities

### 1. Automatic Own-Traffic BPF Exclusion

**Severity: High**

Hunter automatically excludes its processor communication port from packet capture at the kernel BPF level. Tap has no such filtering for its own gRPC traffic.

**Hunter implementation:** `internal/pkg/hunter/capture/manager.go` lines 172-187
```go
// buildProcessorPortExclusionFilter builds a BPF filter to exclude the processor communication port.
// This prevents the hunter from capturing its own gRPC traffic to the processor.
func (m *Manager) buildProcessorPortExclusionFilter() string {
    port := m.extractPortFromAddr(m.processorAddr)
    if port == "" {
        return ""
    }
    return fmt.Sprintf("not port %s", port)
}
```

**What tap needs to exclude:**
| Traffic Type | Flag | Purpose |
|-------------|------|---------|
| TUI subscriber connections | `--listen` (default `:50051`) | Inbound gRPC from TUI clients |
| Upstream processor traffic | `--processor` | Outbound gRPC to upstream processor |

**Missing infrastructure:**
- No `buildOwnTrafficExclusionFilter()` or equivalent in tap's capture setup
- Tap uses `internal/pkg/capture/` directly without the hunter's filter composition logic
- No exclusion for `ListenAddr` port (TUI connections)
- No exclusion for `UpstreamAddr` port (processor forwarding)

**Impact:**
Without this exclusion, tap will:
1. Capture its own gRPC traffic to TUI subscribers, creating noise
2. Capture its own gRPC traffic to upstream processors, creating feedback loops
3. Waste CPU cycles processing and displaying its own management traffic

**Note:** This is particularly problematic in hierarchical deployments where tap forwards to a processor on the same network segment.

### 2. GPU Acceleration

**Severity: High**

Hunt has GPU-accelerated filtering via CUDA/OpenCL. Tap has no GPU support.

**Missing flags (3 total):**
| Flag | Default | Description |
|------|---------|-------------|
| `--gpu-backend` / `-g` | `"auto"` | GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd' |
| `--gpu-batch-size` | `100` | Batch size for GPU processing |
| `--enable-voip-filter` | `false` | Enable GPU-accelerated VoIP filtering |

**Missing infrastructure:**
- No `cmd/tap/flags_gpu.go` file
- No `cmd/tap/flags_gpu_stub.go` file
- No calls to `RegisterGPUFlags()` or `BindGPUViperFlags()`
- No GPU configuration passed to filtering pipeline

**Viper bindings that would be needed:**
- `hunter.voip_filter.enabled`
- `hunter.voip_filter.gpu_backend`
- `hunter.voip_filter.gpu_batch_size`

### 3. Advanced Pattern Matching Configuration

**Severity: Low**

Hunt's voip subcommand has pattern matching algorithm selection. Tap voip does not.

**Missing flags:**
| Flag | Default | Description |
|------|---------|-------------|
| `--pattern-algorithm` | `"auto"` | Pattern matching: 'auto', 'linear', 'aho-corasick' |
| `--pattern-buffer-mb` | `64` | Memory budget for pattern buffer in MB |

**Location in hunt:** `cmd/hunt/voip.go` lines 20-29, 61-67

## Summary

### By Severity

| Severity | Category | Missing Flags |
|----------|----------|---------------|
| Critical | LI (Lawful Interception) | 14 |
| High | Own-Traffic BPF Exclusion | 0 (logic gap) |
| High | GPU Acceleration | 3 |
| Medium | TLS Keylog | 1 |
| Medium | DNS Tunneling | 3 |
| Medium | Production mTLS | 0 (logic gap) |
| Low | VoIP Command | 1 |
| Low | Stats Display | 1 |
| Low | Pattern Matching | 2 |

**Total missing flags: 25** (plus 2 logic gaps requiring implementation)

### By Source

| Source | Missing Flags | Missing Logic/Config |
|--------|---------------|----------------------|
| Process | 20 | 18+ config fields, 1 logic gap (mTLS) |
| Hunt | 5 | 3+ config fields, 1 logic gap (BPF exclusion) |

### Infrastructure Gaps

Files that need to be created for tap:
- `cmd/tap/flags_li.go` - LI flag implementation (build tag: `li`)
- `cmd/tap/flags_li_stub.go` - LI stubs (build tag: `!li`)
- `cmd/tap/flags_gpu.go` - GPU flag implementation (build tag: `cuda`)
- `cmd/tap/flags_gpu_stub.go` - GPU stubs (build tag: `!cuda`)

### Config Wiring Gaps

`tap.go` builds `processor.Config{}` but leaves these field groups at zero values:
1. All 14 LI configuration fields
2. TLSKeylogConfig (always nil)
3. TunnelingThreshold, TunnelingDebounce
4. VoipCommand in CommandExecutorConfig
5. TunnelingCommand in CommandExecutorConfig

### Documentation Issues

`cmd/tap/tap.go` contains misleading examples showing LI flags that don't exist. This documentation should either be removed or the functionality implemented.

## Conclusion

The `lc tap` command significantly violates its architectural contract of `tap = process + hunt - gRPC`. It is missing:

- **100% of LI capabilities** from process
- **100% of own-traffic BPF exclusion** from hunt (will capture its own gRPC traffic)
- **100% of GPU acceleration** from hunt
- **100% of TLS keylog** from process
- **100% of DNS tunneling detection** from process
- **Weaker production security enforcement** than process

To fulfill its architectural role, tap requires substantial work to bring it to parity with process and hunt capabilities.

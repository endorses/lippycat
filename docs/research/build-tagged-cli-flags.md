# Research: Build-Tagged CLI Flags

## Problem Statement

Certain CLI flags are only relevant when building with specific build tags:

- **GPU flags** (`--gpu-*`) - Only meaningful in CUDA/OpenCL builds
- **LI flags** (`--li-*`) - Only meaningful in builds with `-tags li`

Currently, these flags are registered unconditionally, meaning:
1. Users see irrelevant flags in `--help` output
2. Binary size includes flag definitions, help text, and validation code
3. Users may attempt to use flags that have no effect in their build

## Scope

### GPU Flags to Conditionally Include

| Command | Flags | Current Location |
|---------|-------|------------------|
| `lc sniff voip` | `--gpu-enable`, `--gpu-backend`, `--gpu-batch-size`, `--gpu-max-memory` | `cmd/sniff/voip.go:45-49, 242-271` |
| `lc hunt` | `--enable-voip-filter`, `--gpu-backend`, `--gpu-batch-size` | `cmd/hunt/hunt.go:60-62, 100-102, 134-135` |
| `lc tap` | (none currently - tap uses processor which doesn't have GPU flags) | N/A |

**Note:** The `lc tap` command doesn't currently have GPU flags. If GPU support is added to tap in the future, it should follow this pattern.

### LI Flags to Conditionally Include

| Command | Flags | Current Location |
|---------|-------|------------------|
| `lc process` | 17 flags (`--li-enabled`, `--li-x1-*`, `--li-admf-*`, `--li-delivery-*`) | `cmd/process/process.go:120-136, 205-221, 269-284` |
| `lc tap` | (not yet implemented - shown in help examples but no actual flags) | N/A |

**Note:** The `lc tap` command's help text mentions LI flags (lines 59-64), but the flags are not yet implemented. When added, they should use the build-tagged pattern from the start.

## Recommended Approach: Build-Tagged Registration Functions

### Pattern Overview

Create paired files per command package that define the same functions but with different implementations based on build tags:

```
cmd/sniff/
├── voip.go                    # Main command, calls RegisterGPUFlags()
├── flags_gpu.go               # //go:build cuda - actual flag registration
└── flags_gpu_stub.go          # //go:build !cuda - empty functions

cmd/hunt/
├── hunt.go                    # Main command, calls RegisterGPUFlags()
├── flags_gpu.go               # //go:build cuda
└── flags_gpu_stub.go          # //go:build !cuda

cmd/process/
├── process.go                 # Main command, calls RegisterLIFlags()
├── flags_li.go                # //go:build li
└── flags_li_stub.go           # //go:build !li

cmd/tap/
├── tap.go                     # Main command
├── flags_li.go                # //go:build li (future)
└── flags_li_stub.go           # //go:build !li (future)
```

### Implementation Pattern

#### GPU Flags Example (sniff)

**File: `cmd/sniff/flags_gpu.go`**
```go
//go:build cuda

package sniff

import (
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

var (
    gpuBackend   string
    gpuBatchSize int
    gpuMaxMemory int64
    gpuEnable    bool
)

// RegisterGPUFlags adds GPU-related flags to the command.
func RegisterGPUFlags(cmd *cobra.Command) {
    cmd.Flags().BoolVar(&gpuEnable, "gpu-enable", true, "Enable GPU acceleration for pattern matching")
    cmd.Flags().StringVarP(&gpuBackend, "gpu-backend", "g", "auto", "GPU backend: 'auto', 'cuda', 'opencl', 'cpu-simd', 'disabled'")
    cmd.Flags().IntVar(&gpuBatchSize, "gpu-batch-size", 1024, "Batch size for GPU processing")
    cmd.Flags().Int64Var(&gpuMaxMemory, "gpu-max-memory", 0, "Maximum GPU memory in bytes (0 = auto)")
}

// BindGPUViperFlags binds GPU flags to viper for config file support.
func BindGPUViperFlags(cmd *cobra.Command) {
    _ = viper.BindPFlag("voip.gpu_enable", cmd.Flags().Lookup("gpu-enable"))
    _ = viper.BindPFlag("voip.gpu_backend", cmd.Flags().Lookup("gpu-backend"))
    _ = viper.BindPFlag("voip.gpu_batch_size", cmd.Flags().Lookup("gpu-batch-size"))
    _ = viper.BindPFlag("voip.gpu_max_memory", cmd.Flags().Lookup("gpu-max-memory"))
}

// ApplyGPUConfig sets GPU configuration in viper if flags were changed.
func ApplyGPUConfig(cmd *cobra.Command) {
    if cmd.Flags().Changed("gpu-enable") {
        viper.Set("voip.gpu_enable", gpuEnable)
    }
    if cmd.Flags().Changed("gpu-backend") {
        viper.Set("voip.gpu_backend", gpuBackend)
    }
    if cmd.Flags().Changed("gpu-batch-size") {
        viper.Set("voip.gpu_batch_size", gpuBatchSize)
    }
    if cmd.Flags().Changed("gpu-max-memory") {
        viper.Set("voip.gpu_max_memory", gpuMaxMemory)
    }
}

// GPUEnabled returns whether GPU is enabled (for logging/info purposes).
func GPUEnabled() bool {
    return viper.GetBool("voip.gpu_enable")
}

// GPUBackend returns the configured GPU backend.
func GPUBackend() string {
    return viper.GetString("voip.gpu_backend")
}
```

**File: `cmd/sniff/flags_gpu_stub.go`**
```go
//go:build !cuda

package sniff

import "github.com/spf13/cobra"

// RegisterGPUFlags is a no-op in non-CUDA builds.
func RegisterGPUFlags(cmd *cobra.Command) {}

// BindGPUViperFlags is a no-op in non-CUDA builds.
func BindGPUViperFlags(cmd *cobra.Command) {}

// ApplyGPUConfig is a no-op in non-CUDA builds.
func ApplyGPUConfig(cmd *cobra.Command) {}

// GPUEnabled always returns false in non-CUDA builds.
func GPUEnabled() bool { return false }

// GPUBackend returns empty string in non-CUDA builds.
func GPUBackend() string { return "" }
```

**Modification to `cmd/sniff/voip.go`**
```go
func init() {
    // ... existing flags ...

    // GPU flags (only registered in CUDA builds)
    RegisterGPUFlags(voipCmd)
    BindGPUViperFlags(voipCmd)
}

func voipHandler(cmd *cobra.Command, args []string) {
    // ... existing logic ...

    // Apply GPU config (no-op in non-CUDA builds)
    ApplyGPUConfig(cmd)

    // Logging (shows false/empty in non-CUDA builds)
    logger.Info("Starting VoIP sniffing",
        "gpu_enable", GPUEnabled(),
        "gpu_backend", GPUBackend(),
        // ...
    )
}
```

#### LI Flags Example (process)

**File: `cmd/process/flags_li.go`**
```go
//go:build li

package process

import (
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

var (
    liEnabled               bool
    liX1ListenAddr          string
    liX1TLSCertFile         string
    liX1TLSKeyFile          string
    liX1TLSCAFile           string
    liADMFEndpoint          string
    liADMFTLSCertFile       string
    liADMFTLSKeyFile        string
    liADMFTLSCAFile         string
    liADMFKeepalive         string
    liDeliveryTLSCertFile   string
    liDeliveryTLSKeyFile    string
    liDeliveryTLSCAFile     string
    liDeliveryTLSPinnedCert []string
)

// RegisterLIFlags adds LI-related flags to the command.
func RegisterLIFlags(cmd *cobra.Command) {
    cmd.Flags().BoolVar(&liEnabled, "li-enabled", false, "Enable ETSI LI (Lawful Interception) support")
    cmd.Flags().StringVar(&liX1ListenAddr, "li-x1-listen", ":8443", "X1 administration interface listen address")
    cmd.Flags().StringVar(&liX1TLSCertFile, "li-x1-tls-cert", "", "Path to X1 server TLS certificate")
    cmd.Flags().StringVar(&liX1TLSKeyFile, "li-x1-tls-key", "", "Path to X1 server TLS key")
    cmd.Flags().StringVar(&liX1TLSCAFile, "li-x1-tls-ca", "", "Path to CA certificate for X1 client verification")
    cmd.Flags().StringVar(&liADMFEndpoint, "li-admf-endpoint", "", "ADMF endpoint for X1 notifications")
    cmd.Flags().StringVar(&liADMFTLSCertFile, "li-admf-tls-cert", "", "Path to client TLS certificate for ADMF")
    cmd.Flags().StringVar(&liADMFTLSKeyFile, "li-admf-tls-key", "", "Path to client TLS key for ADMF")
    cmd.Flags().StringVar(&liADMFTLSCAFile, "li-admf-tls-ca", "", "Path to CA certificate for ADMF server")
    cmd.Flags().StringVar(&liADMFKeepalive, "li-admf-keepalive", "30s", "Keepalive interval for ADMF notifications")
    cmd.Flags().StringVar(&liDeliveryTLSCertFile, "li-delivery-tls-cert", "", "Path to client TLS certificate for X2/X3")
    cmd.Flags().StringVar(&liDeliveryTLSKeyFile, "li-delivery-tls-key", "", "Path to client TLS key for X2/X3")
    cmd.Flags().StringVar(&liDeliveryTLSCAFile, "li-delivery-tls-ca", "", "Path to CA certificate for MDF servers")
    cmd.Flags().StringSliceVar(&liDeliveryTLSPinnedCert, "li-delivery-tls-pinned-cert", nil, "Pinned certificate fingerprints for MDF servers")
}

// BindLIViperFlags binds LI flags to viper.
func BindLIViperFlags(cmd *cobra.Command) {
    _ = viper.BindPFlag("processor.li.enabled", cmd.Flags().Lookup("li-enabled"))
    _ = viper.BindPFlag("processor.li.x1_listen_addr", cmd.Flags().Lookup("li-x1-listen"))
    // ... remaining bindings ...
}

// LIEnabled returns whether LI is enabled.
func LIEnabled() bool {
    return liEnabled || viper.GetBool("processor.li.enabled")
}

// GetLIConfig returns LI configuration for processor.Config.
// Returns nil if LI is not enabled.
func GetLIConfig() *LIConfig {
    if !LIEnabled() {
        return nil
    }
    return &LIConfig{
        Enabled:       true,
        X1ListenAddr:  getStringConfig("processor.li.x1_listen_addr", liX1ListenAddr),
        // ... remaining fields ...
    }
}
```

**File: `cmd/process/flags_li_stub.go`**
```go
//go:build !li

package process

import "github.com/spf13/cobra"

// RegisterLIFlags is a no-op in non-LI builds.
func RegisterLIFlags(cmd *cobra.Command) {}

// BindLIViperFlags is a no-op in non-LI builds.
func BindLIViperFlags(cmd *cobra.Command) {}

// LIEnabled always returns false in non-LI builds.
func LIEnabled() bool { return false }

// GetLIConfig always returns nil in non-LI builds.
func GetLIConfig() *LIConfig { return nil }
```

## Alternative Approaches Considered

### 1. Runtime Feature Detection

```go
if gpu.IsAvailable() {
    cmd.Flags().StringVar(&gpuBackend, "gpu-backend", ...)
}
```

**Pros:**
- Single binary, no build variants needed

**Cons:**
- Flags still compiled into binary (code bloat)
- Runtime detection adds complexity
- Help text still shows flags even if feature unavailable
- Doesn't match existing `cuda` build tag pattern

**Verdict:** Not recommended - doesn't address the core issues

### 2. Flag Groups with Visibility Control

Cobra doesn't natively support conditional flag visibility. Would require custom help template.

**Pros:**
- Single binary

**Cons:**
- Complex custom templates
- Flags still in binary
- Non-standard Cobra usage

**Verdict:** Not recommended - too hacky

### 3. Subcommand Approach

Create `lc sniff voip-gpu` as a separate command only in GPU builds.

**Pros:**
- Clear separation

**Cons:**
- Confusing UX (why two commands?)
- Breaks existing workflows
- Doesn't work for LI (processor needs LI, not a subcommand)

**Verdict:** Not recommended - poor UX

## Recommended Implementation Order

### Phase 1: GPU Flags (Lower Risk)

1. **`cmd/sniff/`** - Create `flags_gpu.go` and `flags_gpu_stub.go`
   - Extract GPU flags from `voip.go`
   - Update `voip.go` to call registration functions
   - Test: `make build` (non-CUDA) should not show GPU flags

2. **`cmd/hunt/`** - Create `flags_gpu.go` and `flags_gpu_stub.go`
   - Extract GPU flags from `hunt.go`
   - Update `hunt.go` to call registration functions

3. **`cmd/tap/`** - No changes needed (no GPU flags currently)

### Phase 2: LI Flags (Higher Complexity)

1. **`cmd/process/`** - Create `flags_li.go` and `flags_li_stub.go`
   - Extract 17 LI flags and variables from `process.go`
   - Create `LIConfig` struct for type-safe configuration
   - Update `process.go` to call registration functions
   - Test: `make processor` (non-LI) should not show LI flags

2. **`cmd/tap/`** - Create `flags_li.go` and `flags_li_stub.go`
   - LI flags not yet implemented in tap
   - When implementing, use this pattern from the start
   - Remove LI examples from help text until LI is implemented

## Files to Modify

### GPU Flags

| File | Action | Lines Affected |
|------|--------|----------------|
| `cmd/sniff/voip.go` | Extract to new files | 45-49 (vars), 101-112 (apply), 242-271 (register) |
| `cmd/sniff/flags_gpu.go` | Create (cuda build) | New file |
| `cmd/sniff/flags_gpu_stub.go` | Create (!cuda build) | New file |
| `cmd/hunt/hunt.go` | Extract to new files | 60-62 (vars), 100-102, 134-135 (register) |
| `cmd/hunt/flags_gpu.go` | Create (cuda build) | New file |
| `cmd/hunt/flags_gpu_stub.go` | Create (!cuda build) | New file |

### LI Flags

| File | Action | Lines Affected |
|------|--------|----------------|
| `cmd/process/process.go` | Extract to new files | 120-139 (vars), 205-221, 269-284 (register) |
| `cmd/process/flags_li.go` | Create (li build) | New file |
| `cmd/process/flags_li_stub.go` | Create (!li build) | New file |
| `cmd/tap/tap.go` | Update help text | 59-64 (remove LI examples until implemented) |
| `cmd/tap/flags_li.go` | Create when implementing LI | Future |
| `cmd/tap/flags_li_stub.go` | Create when implementing LI | Future |

## Verification

### Build Verification

```bash
# Verify GPU flags excluded from non-CUDA builds
make build
./bin/lc sniff voip --help | grep -c "gpu"  # Should be 0

# Verify GPU flags included in CUDA builds
make build-cuda
./bin/lc sniff voip --help | grep -c "gpu"  # Should be 4

# Verify LI flags excluded from non-LI builds
make processor
./bin/lc-processor process --help | grep -c "li-"  # Should be 0

# Verify LI flags included in LI builds
make processor-li
./bin/lc-processor-li process --help | grep -c "li-"  # Should be 14
```

### Functional Verification

```bash
# Non-CUDA build should work without GPU flags
make build
./bin/lc sniff voip -i eth0  # Should work, no GPU acceleration

# Non-LI build should work without LI flags
make processor
./bin/lc-processor process --listen :50051 --insecure  # Should work, no LI
```

## Consistency with Existing Patterns

This approach matches the existing pattern used for CUDA backend implementations:

```
internal/pkg/voip/
├── gpu_cuda_backend_impl.go  # //go:build cuda - Full implementation
└── gpu_cuda_backend.go       # //go:build !cuda - Stub returning ErrGPUNotAvailable
```

The same pattern extends naturally to CLI flags.

## Open Questions

1. **Pattern matching flags** - Should `--pattern-algorithm` and `--pattern-buffer-mb` also be build-tagged? They're used by Aho-Corasick which is available in all builds but optimized differently with GPU.

2. **Help text updates** - Should we add notes like "(requires CUDA build)" to flag descriptions in the CUDA build, or is the absence of flags in non-CUDA builds sufficient?

3. **Config file validation** - If a user has `voip.gpu_backend: cuda` in their config file but uses a non-CUDA build, should we warn or silently ignore? Current stub pattern silently ignores.

## Summary

The recommended approach uses Go's build tag system to conditionally compile flag registration code, matching the existing patterns in the codebase. This provides:

- **Clean `--help` output** - Users only see relevant flags
- **Smaller binaries** - Flag definitions excluded from non-feature builds
- **Compile-time safety** - No runtime checks needed
- **Consistent patterns** - Matches existing `gpu_cuda_backend*.go` approach

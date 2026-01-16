# Implementation Plan: Build-Tagged CLI Flags

Based on [research](../research/build-tagged-cli-flags.md).

## Phase 1: GPU Flags

### 1.1 cmd/sniff - GPU Flags

- [ ] Create `cmd/sniff/flags_gpu.go` (`//go:build cuda`)
  - Move vars: `gpuBackend`, `gpuBatchSize`, `gpuMaxMemory`, `gpuEnable`
  - Implement: `RegisterGPUFlags()`, `BindGPUViperFlags()`, `ApplyGPUConfig()`
- [ ] Create `cmd/sniff/flags_gpu_stub.go` (`//go:build !cuda`)
  - No-op implementations of same functions
- [ ] Update `cmd/sniff/voip.go`
  - Remove GPU flag vars and registration (lines 45-49, 242-271)
  - Call `RegisterGPUFlags(voipCmd)` and `BindGPUViperFlags(voipCmd)` in `init()`
  - Call `ApplyGPUConfig(cmd)` in `voipHandler()`
- [ ] Verify: `make build && ./bin/lc sniff voip --help | grep -c gpu` → 0

### 1.2 cmd/hunt - GPU Flags

- [ ] Create `cmd/hunt/flags_gpu.go` (`//go:build cuda`)
  - Move vars: `gpuBackend`, `gpuBatchSize`, `enableVoIPFilter`
  - Implement: `RegisterGPUFlags()`, `BindGPUViperFlags()`, `GetGPUConfig()`
- [ ] Create `cmd/hunt/flags_gpu_stub.go` (`//go:build !cuda`)
  - No-op implementations
- [ ] Update `cmd/hunt/hunt.go`
  - Remove GPU flag vars and registration (lines 60-62, 100-102, 134-135)
  - Call registration functions in `init()`
  - Update `runHunt()` to use `GetGPUConfig()`
- [ ] Verify: `make hunter && ./bin/lc-hunter hunt --help | grep -c gpu` → 0

## Phase 2: LI Flags

### 2.1 cmd/process - LI Flags

- [ ] Create `cmd/process/flags_li.go` (`//go:build li`)
  - Move 14 LI vars (lines 121-136)
  - Implement: `RegisterLIFlags()`, `BindLIViperFlags()`, `GetLIConfig()`
- [ ] Create `cmd/process/flags_li_stub.go` (`//go:build !li`)
  - No-op implementations, `GetLIConfig()` returns `nil`
- [ ] Update `cmd/process/process.go`
  - Remove LI flag vars and registration (lines 120-139, 205-221, 269-284)
  - Call registration functions in `init()`
  - Update `runProcess()` to use `GetLIConfig()`
- [ ] Verify: `make processor && ./bin/lc-processor process --help | grep -c "li-"` → 0

### 2.2 cmd/tap - LI Flags (Prep)

- [ ] Update `cmd/tap/tap.go` help text
  - Remove LI example (lines 59-64) until LI is implemented
- [ ] Create `cmd/tap/flags_li.go` (`//go:build li`) - empty placeholder
- [ ] Create `cmd/tap/flags_li_stub.go` (`//go:build !li`) - empty placeholder

## Phase 3: Verification

- [ ] Run full test suite: `make test`
- [ ] Build all variants and verify flag visibility:
  ```bash
  make build        # non-CUDA, non-LI
  make build-cuda   # CUDA
  make build-li     # LI
  make binaries     # all variants
  ```
- [ ] Verify GPU flags appear only in CUDA builds
- [ ] Verify LI flags appear only in LI builds
- [ ] Update CLAUDE.md if needed to document the pattern

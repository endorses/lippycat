# CLI Flag Refactoring Plan

## Overview

Add uppercase short flags where lowercase is taken, add new lowercase short flags where available, and normalize inconsistent flag names with a deprecation period.

## Key Findings from Exploration

1. **Hunt already uses `--processor`** - Only `tap` and `process` need `--upstream` → `--processor` rename
2. **Two virtual interface flags exist**:
   - `--virtual-interface` - Enables the feature (BoolVar) → gets `-V`
   - `--vif-name` - Sets interface name (StringVar, default: lc0) → no short flag needed
3. **Hunt voip has no `--sipuser`** - By design (filters pushed from processor)
4. **No existing deprecation patterns** - Clean slate for introducing deprecation
5. **Strong test coverage** - Tests in `cmd/sniff/sniff_test.go`, `cmd/sniff/voip_test.go`

## Phase 1: Non-Breaking Additions (New Short Flags)

Add short flags to existing long flags. No deprecation needed.

### Lowercase Short Flags

| Short | Long Flag | File(s) | Line |
|-------|-----------|---------|------|
| `-c` | `--config` | `cmd/root_*.go` | ~61 |
| `-g` | `--gpu-backend` | `cmd/sniff/voip.go` | 228 |
| | | `cmd/hunt/hunt.go` | 85 |
| | | `cmd/watch/live.go` | 105 |
| `-n` | `--nodes-file` | `cmd/watch/remote.go` | 100 |

### Uppercase Short Flags (lowercase taken)

| Short | Long Flag | File(s) | Line |
|-------|-----------|---------|------|
| `-T` | `--tls` | `cmd/hunt/hunt.go` | 94 |
| | | `cmd/process/process.go` | 133 |
| | | `cmd/tap/tap.go` | 192 |
| | | `cmd/watch/remote.go` | 104 |
| | | `cmd/filter/filter.go` | 42 |
| `-S` | `--sip-port` | `cmd/sniff/voip.go` | 218 |
| | | `cmd/hunt/voip.go` | 63 |
| | | `cmd/tap/tap_voip.go` | 85 |
| `-M` | `--tcp-performance-mode` | `cmd/sniff/voip.go` | 246 |
| | | `cmd/tap/tap_voip.go` | 93 |
| `-V` | `--virtual-interface` | `cmd/sniff/sniff.go` | 95 |
| | | `cmd/tap/tap.go` | 165 |
| | | `cmd/process/process.go` | 156 |
| `-U` | `--udp-only` | `cmd/sniff/voip.go` | 217 |
| | | `cmd/tap/tap_voip.go` | 84 |
| | | `cmd/hunt/voip.go` | 62 |
| `-R` | `--rtp-port-range` | `cmd/sniff/voip.go` | 219 |
| | | `cmd/tap/tap_voip.go` | 86 |
| | | `cmd/hunt/voip.go` | 64 |

### Implementation Steps

- [x] Add `-c` to `--config` in all `root_*.go` files (6 files)
- [x] Add `-g` to `--gpu-backend` in sniff/voip.go, hunt/hunt.go, watch/live.go
- [x] Add `-n` to `--nodes-file` in watch/remote.go
- [x] Add `-T` to `--tls` in hunt, process, tap, watch/remote, filter (5 files)
- [x] Add `-S` to `--sip-port` in sniff/voip, hunt/voip, tap/tap_voip (3 files)
- [x] Add `-M` to `--tcp-performance-mode` in sniff/voip, tap/tap_voip (2 files)
- [x] Add `-V` to `--virtual-interface` in sniff, tap, process (3 files)
- [x] Add `-U` to `--udp-only` in sniff/voip, tap/tap_voip, hunt/voip (3 files)
- [x] Add `-R` to `--rtp-port-range` in sniff/voip, tap/tap_voip, hunt/voip (3 files)
- [x] Update documentation (README.md files in cmd/)

---

## Phase 2: Breaking Changes (With Deprecation)

### 2.1: Rename `--upstream` to `--processor` with `-P`

**Affected files:**
- `cmd/tap/tap.go:148` - `StringVarP(&upstreamAddr, "upstream", "u", ...)`
- `cmd/process/process.go:124` - `StringVarP(&upstreamAddr, "upstream", "u", ...)`

**Viper bindings to update:**
- `cmd/tap/tap.go:223` - `tap.upstream_addr` → `tap.processor_addr`
- `cmd/process/process.go:193` - `processor.upstream_addr` → `processor.processor_addr`

**Steps:**
- [x] Add `--processor` / `-P` as new flag (primary)
- [x] Mark `--upstream` as deprecated with message
- [x] Add PreRunE validation: warn if `--upstream` used, copy value to processor var
- [x] Support both old and new Viper keys during transition
- [x] Update tests
- [x] Update documentation

### 2.2: Change `-p` to `-P` for `--processor` in filter commands

**Affected file:**
- `cmd/filter/filter.go:41` - `StringVarP(&processorAddr, "processor", "p", ...)`

**Steps:**
- [x] Change short flag from `"p"` to `"P"`
- [x] Update documentation

### 2.3: Unify `--hunter-id`, `--processor-id`, `--tap-id` to `--id` with `-I`

**Affected files:**
- `cmd/hunt/hunt.go:71` - `StringVarP(&hunterID, "hunter-id", "", ...)`
- `cmd/process/process.go:123` - `StringVarP(&processorID, "processor-id", "", ...)`
- `cmd/tap/tap.go:144` - `StringVar(&tapID, "tap-id", ...)`

**Viper bindings:**
- `hunter.hunter_id` → `hunter.id`
- `processor.processor_id` → `processor.id`
- `tap.tap_id` → `tap.id`

**Steps:**
- [x] Add `--id` / `-I` as new flag in each command
- [x] Mark old flags (`--hunter-id`, etc.) as deprecated
- [x] Add PreRunE validation to copy old value to new var if used
- [x] Support both old and new Viper keys
- [x] Update tests
- [x] Update documentation

### 2.4: Normalize `--sipuser` to `--sip-user` (keep `-u`)

**Affected files:**
- `cmd/sniff/voip.go:213` - `StringVarP(&sipuser, "sipuser", "u", ...)`
- `cmd/tap/tap_voip.go:81` - `StringVar(&sipuser, "sipuser", ...)` (no short flag!)

**Steps:**
- [x] Rename `--sipuser` to `--sip-user` in sniff/voip.go (keep `-u`)
- [x] Add `--sip-user` with `-u` to tap/tap_voip.go
- [x] Mark old `--sipuser` as deprecated alias
- [x] Update Viper binding from `voip.sipuser` to `voip.sip_user`
- [x] Update tests
- [x] Update documentation

---

## Phase 3: Documentation Updates

### README.md files to update
- [x] `cmd/sniff/README.md`
- [x] `cmd/tap/README.md`
- [x] `cmd/hunt/README.md`
- [x] `cmd/process/README.md`
- [x] `cmd/watch/README.md`
- [x] `cmd/filter/README.md` (does not exist)
- [x] `cmd/list/README.md` (no relevant flags)
- [x] Root `README.md`

### CLAUDE.md files to update
- [x] `CLAUDE.md` (root - CLI usage section)
- [x] `cmd/sniff/CLAUDE.md`
- [x] `cmd/tap/CLAUDE.md`
- [x] `cmd/hunt/CLAUDE.md`
- [x] `cmd/process/CLAUDE.md`
- [x] `cmd/watch/CLAUDE.md` (no changes needed)

### CHANGELOG.md
- [x] Add breaking changes section
- [x] Document deprecation timeline

---

## Implementation Pattern

### Adding a short flag (non-breaking)

```go
// Before
cmd.Flags().StringVar(&val, "long-flag", "", "help")

// After
cmd.Flags().StringVarP(&val, "long-flag", "X", "", "help")
```

### Deprecating a flag (breaking)

```go
// 1. Add new flag as primary
cmd.Flags().StringVarP(&processorAddr, "processor", "P", "", "Processor address")

// 2. Add old flag as deprecated alias
cmd.Flags().StringVar(&upstreamAddrDeprecated, "upstream", "", "")
cmd.Flags().Lookup("upstream").Deprecated = "use --processor instead"
cmd.Flags().Lookup("upstream").Hidden = true

// 3. In PreRunE, migrate old value
if cmd.Flags().Changed("upstream") {
    if cmd.Flags().Changed("processor") {
        return fmt.Errorf("cannot use both --upstream (deprecated) and --processor")
    }
    processorAddr = upstreamAddrDeprecated
}
```

### Deprecating a shorthand only

```go
flag := cmd.Flags().Lookup("processor")
flag.ShorthandDeprecated = "use -P instead"
```

---

## Verification

### Unit Tests
```bash
make test
```

### Manual Testing
```bash
# Test new short flags work
lc sniff voip -g cuda -S 5060 -M balanced -U -R 8000-9000

# Test deprecated flags show warning
lc tap --upstream localhost:55555  # Should warn

# Test help shows new flags
lc hunt --help
lc process --help
```

### Documentation Review
- Verify all README.md examples use new flag names
- Verify CLAUDE.md architecture docs are updated

---

## Deprecation Timeline

**Single version approach**: Deprecated flags will show warnings but still work in v0.8.0. Users should migrate immediately.

Old Viper config keys (e.g., `tap.upstream_addr`) will be supported with fallback logic reading old key if new key is not set.

---

## Summary of All New Short Flags

### Lowercase (new)
| Short | Long Flag | Reason |
|-------|-----------|--------|
| `-c` | `--config` | Available |
| `-g` | `--gpu-backend` | Available |
| `-n` | `--nodes-file` | Available |

### Uppercase (lowercase taken)
| Short | Long Flag | Lowercase Used By |
|-------|-----------|-------------------|
| `-I` | `--id` | `-i` = `--interface` |
| `-M` | `--tcp-performance-mode` | `-m` = `--max-hunters` |
| `-P` | `--processor` | `-p` = `--promiscuous` |
| `-R` | `--rtp-port-range` | `-r` = `--read-file` |
| `-S` | `--sip-port` | `-s` = `--stats` |
| `-T` | `--tls` | `-t` = `--type` |
| `-U` | `--udp-only` | `-u` = `--sip-user` |
| `-V` | `--virtual-interface` | `-v` = `--version` |

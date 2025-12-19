# CLI Verb-Object Restructuring Plan

**Date:** 2025-12-18
**Task:** Restructure CLI to follow consistent `lc [verb] [object]` pattern
**Effort:** Medium (3 phases)
**Risk:** Low (breaking change, but clean cut)

---

## Executive Summary

Restructure the lippycat CLI to follow a consistent `[verb] [object]` grammar pattern for improved discoverability and usability. Old commands will be removed immediately (no deprecation period).

**Current State:** Mixed patterns (`lc tui`, `lc interfaces`, `lc debug health`)
**Target State:** Consistent verb-object (`lc watch live`, `lc list interfaces`, `lc show health`)

---

## Current vs Proposed Structure

| Current Command | Pattern | Proposed Command | Notes |
|-----------------|---------|------------------|-------|
| `lc sniff` | verb | `lc sniff` | Keep as-is (generic capture) |
| `lc sniff voip` | verb + object | `lc sniff voip` | ✓ Already correct |
| `lc hunt` | verb | `lc hunt` | Keep as-is (generic hunt) |
| `lc hunt voip` | verb + object | `lc hunt voip` | ✓ Already correct |
| `lc process` | verb | `lc process` | Keep as-is (flags only, no subcommands) |
| `lc tui` | noun | `lc watch` | New verb, defaults to `live` |
| `lc tui --remote` | noun + flag | `lc watch remote` | Object replaces flag |
| `lc interfaces` | noun | `lc list interfaces` | New verb |
| `lc debug health` | verb + object | `lc show health` | Change verb |
| `lc debug metrics` | verb + object | `lc show metrics` | Change verb |
| `lc debug alerts` | verb + object | `lc show alerts` | Change verb |
| `lc debug buffers` | verb + object | `lc show buffers` | Change verb |
| `lc debug streams` | verb + object | `lc show streams` | Change verb |
| `lc debug config` | verb + object | `lc show config` | Change verb |
| `lc debug summary` | verb + object | `lc show summary` | Change verb |

---

## Final Command Structure

```
lc [verb] [object] [flags]

VERBS:
  sniff     Capture packets from interface or file
  hunt      Distributed edge capture (hunter node)
  process   Central aggregation (processor node)
  watch     Monitor traffic (TUI)
  list      List resources
  show      Display information/diagnostics

OBJECTS BY VERB:

  lc sniff [object]
    (none)    Generic packet capture
    voip      VoIP traffic (SIP/RTP)
    dns       DNS traffic (future)
    http      HTTP traffic (future)

  lc hunt [object]
    (none)    Generic distributed capture
    voip      VoIP traffic with call buffering
    dns       DNS traffic (future)
    http      HTTP traffic (future)

  lc process [flags]
    (no subcommands - uses flags for configuration)

  lc watch [object]
    (none)    Live capture TUI (default)
    live      Live capture TUI (explicit)
    file      Analyze PCAP file in TUI
    remote    Remote node monitoring

  lc list [object]
    interfaces    Available network interfaces
    hunters       Connected hunter nodes (future)
    calls         Active VoIP calls (future)

  lc show [object]
    health        Health status
    metrics       System metrics
    alerts        Active alerts
    buffers       Buffer statistics
    streams       Stream metrics
    config        Configuration
    summary       System summary
    call <id>     VoIP call details (future)
```

---

## Implementation Steps

### Phase 1: Create New Commands

#### Step 1.1: Create `cmd/watch/` command structure
- [x] Create `cmd/watch/watch.go` — Base watch command (defaults to `live`)
- [x] Create `cmd/watch/live.go` — Live capture TUI (imports from `internal/pkg/tui/`)
- [x] Create `cmd/watch/file.go` — PCAP file analysis TUI
- [x] Create `cmd/watch/remote.go` — Remote node monitoring
- [x] Add build tag variants for watch command
- [x] Run tests: `go test -race ./cmd/watch/...`

**Note:** The watch commands are thin wrappers that import the TUI model from
`internal/pkg/tui/`. This follows the project's established pattern where `cmd/`
packages are CLI entry points and `internal/pkg/` contains the implementation.

#### Step 1.2: Create `cmd/list/` command structure
- [x] Create `cmd/list/list.go` — Base list command
- [x] Create `cmd/list/interfaces.go` — List interfaces (move from `cmd/interfaces.go`)
- [x] Add build tag variants for list command
- [x] Run tests: `go test -race ./cmd/list/...`

#### Step 1.3: Create `cmd/show/` command structure
- [ ] Create `cmd/show/show.go` — Base show command
- [ ] Create `cmd/show/health.go` — Health status (move from debug)
- [ ] Create `cmd/show/metrics.go` — Metrics (move from debug)
- [ ] Create `cmd/show/alerts.go` — Alerts (move from debug)
- [ ] Create `cmd/show/buffers.go` — Buffers (move from debug)
- [ ] Create `cmd/show/streams.go` — Streams (move from debug)
- [ ] Create `cmd/show/config.go` — Config (move from debug)
- [ ] Create `cmd/show/summary.go` — Summary (move from debug)
- [ ] Add build tag variants for show command
- [ ] Run tests: `go test -race ./cmd/show/...`

#### Step 1.4: Update root command registrations
- [ ] Update `cmd/root_all.go` — Register watch, list, show
- [ ] Update `cmd/root_tui.go` — Register watch
- [ ] Update `cmd/root_cli.go` — Register list, show
- [ ] Update other root variants as needed

---

### Phase 2: Remove Old Commands

#### Step 2.1: Refactor TUI package location
- [ ] Move `cmd/tui/` to `internal/pkg/tui/` (keeps TUI logic as internal package)
- [ ] Update `cmd/watch/` imports to use `internal/pkg/tui/`
- [ ] Remove `cmd/tui/tui.go` (old command entry point, replaced by watch commands)
- [ ] Run tests: `go test -race ./internal/pkg/tui/...`

**Rationale:** This follows the project's architectural pattern where `cmd/` contains
thin CLI wrappers and `internal/pkg/` contains implementation. Compare with how
`cmd/sniff/` imports from `internal/pkg/capture/` and `internal/pkg/voip/`.

#### Step 2.2: Remove other deprecated command files
- [ ] Remove `cmd/interfaces.go`
- [ ] Remove `cmd/debug/` directory

#### Step 2.3: Clean up root registrations
- [ ] Remove tui command registration from root files
- [ ] Remove interfaces command registration from root files
- [ ] Remove debug command registration from root files

---

### Phase 3: Documentation & Validation

#### Step 3.1: Create new command documentation
- [ ] Create `cmd/watch/README.md`
- [ ] Create `cmd/watch/CLAUDE.md`
- [ ] Create `cmd/list/README.md`
- [ ] Create `cmd/list/CLAUDE.md`
- [ ] Create `cmd/show/README.md`
- [ ] Create `cmd/show/CLAUDE.md`

#### Step 3.2: Update root documentation
- [ ] Update `README.md` with new command structure
- [ ] Update `CLAUDE.md` CLI usage section
- [ ] Update `CHANGELOG.md` with breaking changes

#### Step 3.3: Build & test verification
- [ ] Run `make binaries` — all variants build
- [ ] Run `make test` — all tests pass
- [ ] Run `golangci-lint run ./...`
- [ ] Manual testing of all new commands

---

## File Changes Summary

### New Files
| File | Description |
|------|-------------|
| `cmd/watch/watch.go` | Base watch command |
| `cmd/watch/live.go` | Live capture TUI mode |
| `cmd/watch/file.go` | PCAP file analysis TUI mode |
| `cmd/watch/remote.go` | Remote monitoring mode |
| `cmd/list/list.go` | Base list command |
| `cmd/list/interfaces.go` | List interfaces |
| `cmd/show/show.go` | Base show command |
| `cmd/show/health.go` | Health diagnostics |
| `cmd/show/metrics.go` | Metrics display |
| `cmd/show/alerts.go` | Alerts display |
| `cmd/show/buffers.go` | Buffer stats |
| `cmd/show/streams.go` | Stream metrics |
| `cmd/show/config.go` | Config display |
| `cmd/show/summary.go` | System summary |

### Modified Files
| File | Change |
|------|--------|
| `cmd/root_*.go` | Register new commands, remove old |
| `README.md` | Update command documentation |
| `CLAUDE.md` | Update CLI usage section |
| `CHANGELOG.md` | Document breaking changes |

### Moved Files
| From | To | Notes |
|------|-----|-------|
| `cmd/tui/` | `internal/pkg/tui/` | TUI model/components become internal package |
| `cmd/tui/tui.go` | (deleted) | Replaced by `cmd/watch/` commands |

### Deleted Files
| File | Replacement |
|------|-------------|
| `cmd/interfaces.go` | `cmd/list/interfaces.go` |
| `cmd/debug/` | `cmd/show/` |

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Breaking user scripts | Medium | Clear changelog, version bump |
| Build tag complexity | Medium | Careful testing of all variants |
| Missing functionality in migration | Low | Side-by-side comparison during dev |

---

## Success Criteria

- [ ] All new commands work correctly
- [ ] Old commands are fully removed
- [ ] All build variants compile
- [ ] All tests pass
- [ ] Documentation is complete and accurate
- [ ] `lc watch` defaults to `live` mode
- [ ] Future expansion paths are clear

---

## Future Expansion

The verb-object pattern allows clean extension:

**Near-term:**
- `lc list hunters` — List connected hunter nodes
- `lc list calls` — List active VoIP calls
- `lc show call <id>` — Show details of specific call

**Medium-term:**
- `lc sniff dns` — DNS-specific capture mode
- `lc sniff http` — HTTP-specific capture mode
- `lc hunt dns` — Distributed DNS capture

**Long-term:**
- `lc replay file` — Replay PCAP with timing
- `lc export calls` — Export call data
- `lc analyze pcap` — Offline analysis

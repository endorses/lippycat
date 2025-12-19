# PCAP Command Hooks Implementation Plan

**Date:** 2025-12-19
**Task:** Add `--pcap-command` and `--voip-command` flags to processor node
**Effort:** Medium (3 phases)
**Risk:** Medium (requires call lifecycle integration)
**Reference:** [Research Report](../research/pcap-command-hooks.md)

---

## Executive Summary

Implement command hooks that execute when PCAP files are written by the processor node:

1. **pcapcommand** — Executes when any PCAP file is closed (supports `%pcap%` placeholder)
2. **voipcommand** — Executes when a VoIP call completes (supports `%callid%`, `%dirname%`, `%caller%`, `%called%`, `%calldate%`)

**Architecture Decision:** Callback functions (Approach A from research) — simple, direct, testable.

---

## Implementation Steps

### Phase 1: CommandExecutor Component

#### Step 1.1: Create `internal/pkg/processor/command_executor.go` ✅

- [x] Create `CommandExecutor` struct with template strings and concurrency control
- [x] Implement `ExecutePcapCommand(filePath string)` with `%pcap%` substitution
- [x] Implement `ExecuteVoipCommand(meta CallMetadata)` with all placeholders
- [x] Add async execution with timeout (default: 30s) and semaphore (default: 10)
- [x] Add dry-run mode for testing commands
- [x] Format: `gofmt -w internal/pkg/processor/command_executor.go`

#### Step 1.2: Create `internal/pkg/processor/command_executor_test.go` ✅

- [x] Test placeholder substitution for all placeholders
- [x] Test concurrent execution respects semaphore limit
- [x] Test timeout kills long-running commands
- [x] Test dry-run mode logs without executing
- [x] Run tests: `go test -race ./internal/pkg/processor/...`

---

### Phase 2: PCAP Writer Integration ✅

#### Step 2.1: Add callbacks to `CallPcapWriter` ✅

- [x] Add `OnFileClose func(filePath string)` to config
- [x] Add `OnCallComplete func(meta CallMetadata)` to config
- [x] Call `OnFileClose` in `Close()`, `rotateSipFile()`, `rotateRtpFile()`
- [x] Create new `CloseCall()` method that closes both files and fires `OnCallComplete`
- [x] Run tests: `go test -race ./internal/pkg/processor/...`

#### Step 2.2: Add callback to `AutoRotatePcapWriter` ✅

- [x] Add `OnFileClose func(filePath string)` to `AutoRotateConfig`
- [x] Call `OnFileClose` in `Close()` and `rotateFile()`
- [x] Run tests: `go test -race ./internal/pkg/processor/...`

#### Step 2.3: Integrate with `PcapWriterManager` ✅

- [x] Wire `CommandExecutor` callbacks to writer configs
- [x] Ensure callbacks are async (don't block writers)
- [x] Run tests: `go test -race ./internal/pkg/processor/...`

---

### Phase 3: Call Completion Detection ✅

#### Step 3.1: Add call state monitoring ✅

- [x] Add method to detect ended calls from `CallAggregator` state
- [x] Implement grace period timer (default: 5s) after BYE/CANCEL
- [x] Trigger `PcapWriterManager.CloseWriter(callID)` after grace period
- [x] Run tests: `go test -race ./internal/pkg/processor/...`

#### Step 3.2: Configuration and CLI flags ✅

- [x] Add `--pcap-command` flag to `cmd/process/process.go`
- [x] Add `--voip-command` flag to `cmd/process/process.go`
- [x] Add `--command-timeout` flag (default: 30s)
- [x] Add `--command-concurrency` flag (default: 10)
- [x] Bind flags to Viper: `processor.pcap_command`, `processor.voip_command`, etc.
- [x] Format: `gofmt -w cmd/process/process.go`

---

### Phase 4: Validation & Documentation

#### Step 4.1: Manual Testing

- [ ] Test `--pcap-command 'echo %pcap%'` fires on PCAP close
- [ ] Test `--voip-command 'echo %callid% %dirname%'` fires on call complete
- [ ] Test command timeout kills long-running process
- [ ] Test concurrent commands respect semaphore
- [ ] Test YAML config file values work

#### Step 4.2: Documentation Updates

- [ ] Update `cmd/process/README.md` — Add new flags with examples
- [ ] Update `cmd/process/CLAUDE.md` — Document hook architecture
- [ ] Update root `CLAUDE.md` — Add flags to CLI usage section

#### Step 4.3: Final Validation

- [ ] Run full test suite: `make test`
- [ ] Run linter: `golangci-lint run ./...`
- [ ] Build all variants: `make binaries`
- [ ] Commit changes

---

## File Changes Summary

| File | Change |
|------|--------|
| `internal/pkg/processor/command_executor.go` | **New** — Command execution with templates ✅ |
| `internal/pkg/processor/command_executor_test.go` | **New** — Unit tests ✅ |
| `internal/pkg/processor/call_completion_monitor.go` | **New** — Call state monitoring with grace period ✅ |
| `internal/pkg/processor/call_completion_monitor_test.go` | **New** — Unit tests ✅ |
| `internal/pkg/processor/pcap_writer.go` | **Modify** — Add callbacks, `CloseCall()` ✅ |
| `internal/pkg/processor/auto_rotate_pcap.go` | **Modify** — Add callback ✅ |
| `internal/pkg/processor/processor.go` | **Modify** — Wire CallCompletionMonitor ✅ |
| `internal/pkg/processor/processor_lifecycle.go` | **Modify** — Start/stop CallCompletionMonitor ✅ |
| `cmd/process/process.go` | **Modify** — Add 4 flags ✅ |
| `cmd/process/README.md` | **Modify** — Document new flags |
| `cmd/process/CLAUDE.md` | **Modify** — Document architecture |
| `CLAUDE.md` | **Modify** — Add flags to usage section |

---

## CommandExecutor Design

```go
// internal/pkg/processor/command_executor.go

type CallMetadata struct {
    CallID   string
    DirName  string
    Caller   string
    Called   string
    CallDate time.Time
}

type CommandExecutor struct {
    pcapCommand string        // Template with %pcap%
    voipCommand string        // Template with placeholders
    timeout     time.Duration // Default: 30s
    sem         chan struct{} // Concurrency limit (default: 10)
    dryRun      bool
}

func (e *CommandExecutor) ExecutePcapCommand(filePath string)
func (e *CommandExecutor) ExecuteVoipCommand(meta CallMetadata)
```

**Placeholder Substitution:**

| Placeholder | Source |
|-------------|--------|
| `%pcap%` | File path passed to callback |
| `%callid%` | `CallMetadata.CallID` |
| `%dirname%` | `CallMetadata.DirName` |
| `%caller%` | `CallMetadata.Caller` |
| `%called%` | `CallMetadata.Called` |
| `%calldate%` | `CallMetadata.CallDate.Format(time.RFC3339)` |

---

## Configuration Reference

**CLI Flags:**
```bash
lc process --per-call-pcap \
  --pcap-command 'echo %pcap% >> /tmp/pcap-list.txt' \
  --voip-command 'notify.sh %callid% %dirname%' \
  --command-timeout 30s \
  --command-concurrency 10
```

**Config File:**
```yaml
processor:
  pcap_command: "echo %pcap% >> /tmp/pcap-list.txt"
  voip_command: "notify.sh %callid% %dirname% %caller% %called% %calldate%"
  command_timeout: "30s"
  command_concurrency: 10
```

---

## Success Criteria

- [ ] `CommandExecutor` correctly substitutes all placeholders
- [ ] `pcapcommand` fires on every PCAP file close (including rotations)
- [ ] `voipcommand` fires after both SIP and RTP files are closed
- [ ] Grace period prevents premature call closure
- [ ] Timeout and concurrency limits work correctly
- [ ] All tests pass with race detector
- [ ] Documentation covers all new flags with examples

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Commands block writers | Async execution in goroutines |
| Runaway commands exhaust resources | Timeout + concurrency semaphore |
| Command injection | Commands from config only, not user input; avoid shell where possible |
| Call files closed too early | Grace period after BYE/CANCEL |
| Missing call metadata | Validate metadata before executing voipcommand |

---

## Dependencies

1. **Existing call state tracking** — `CallAggregator` already tracks `CallStateEnded`
2. **Existing PCAP infrastructure** — Writers already have close methods

No external dependencies required.

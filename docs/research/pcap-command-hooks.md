# PCAP Command Hooks - Research

## Overview

This document researches the implementation of command hooks that execute when PCAP files are written by the processor node. Two hook types are proposed:

1. **pcapcommand** - Executes whenever any PCAP file is closed
2. **voipcommand** - Executes when a VoIP call completes (both SIP and RTP files written)

## Current Architecture

### PCAP Writers

The processor has two PCAP writing mechanisms:

| Writer | Purpose | Files Created | Closure Trigger |
|--------|---------|---------------|-----------------|
| `CallPcapWriter` | Per-call VoIP traffic | Separate `*_sip.pcap` and `*_rtp.pcap` per call | Manual `CloseWriter()` or shutdown |
| `AutoRotatePcapWriter` | Non-VoIP traffic | Rotating files by size/time/idle | Idle timeout, size limit, or shutdown |

**Key Files:**
- `internal/pkg/processor/pcap_writer.go` - Per-call PCAP writer
- `internal/pkg/processor/auto_rotate_pcap.go` - Auto-rotating PCAP writer
- `internal/pkg/processor/call_correlator.go` - Call state tracking

### Gap: No Automatic Call Completion

Currently, PCAP writers do **not** automatically close when calls end. The `CallAggregator` and `CallCorrelator` track call state (detecting BYE/CANCEL), but this state change does not trigger file closure. Files remain open until processor shutdown.

This gap must be addressed as a prerequisite for the voipcommand feature.

## Proposed Placeholders

### pcapcommand

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `%pcap%` | Full path to the PCAP file | `/var/pcaps/call_123_sip.pcap` |

**Example usage:**
```bash
--pcap-command 'echo %pcap% >> /tmp/pcap-list.txt'
```

### voipcommand

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `%callid%` | SIP Call-ID | `abc123@192.168.1.1` |
| `%dirname%` | Directory containing call files | `/var/pcaps/calls/20241218_143052` |
| `%caller%` | Caller (From header) | `alice@example.com` |
| `%called%` | Called party (To header) | `bob@example.com` |
| `%calldate%` | Call start timestamp (ISO 8601) | `2024-12-18T14:30:52Z` |

**Example usage:**
```bash
--voip-command 'process-call.sh %callid% %dirname% %caller% %called% %calldate%'
```

## Design Approaches

### Approach A: Callback Functions (Recommended)

Add callback functions to the writer configuration structs that fire on specific events.

```go
type PcapWriterConfig struct {
    // existing fields...
    OnFileClose    func(filePath string)
    OnCallComplete func(callID, dir, caller, called string, callDate time.Time)
}

type AutoRotateConfig struct {
    // existing fields...
    OnFileClose func(filePath string)
}
```

**Advantages:**
- Simple and direct - callbacks are invoked at the exact point of file closure
- No additional infrastructure (channels, goroutines) required for the hook mechanism itself
- Easy to test - callbacks can be mocked
- Low latency - command execution starts immediately after file close
- Follows existing patterns in the codebase (e.g., `EventHandler` interface)

**Disadvantages:**
- Callbacks execute in the writer's goroutine context (must be async internally)
- Tight coupling between writer and executor (mitigated by interface)

### Approach B: Channel-Based Event Bus

Writers emit events to a channel; a dedicated goroutine consumes events and executes commands.

```go
type PcapEvent struct {
    Type     EventType // FileClose, CallComplete
    FilePath string
    CallMeta *CallMetadata
}

type PcapEventBus struct {
    events chan PcapEvent
    done   chan struct{}
}
```

**Why Not Recommended:**
- **Over-engineering** - Adds complexity for a simple fire-and-forget use case
- **Ordering concerns** - Channel buffering can delay or reorder events
- **Resource overhead** - Requires dedicated goroutine always running
- **Backpressure risk** - Full channel blocks writers or drops events
- **Harder to test** - Requires waiting for async channel consumption

This approach is better suited for systems with multiple consumers or complex event routing, which is not the case here.

### Approach C: Interface-Based Hooks

Define a `PcapHook` interface that consumers implement.

```go
type PcapHook interface {
    OnFileClose(filePath string)
    OnCallComplete(meta CallMetadata)
}

type PcapWriterConfig struct {
    Hook PcapHook
}
```

**Why Not Recommended:**
- **Unnecessary abstraction** - Only one implementation exists (command executor)
- **Interface pollution** - Adds types that serve no polymorphism purpose
- **Harder to configure** - Can't easily set hooks from config file/flags
- **More boilerplate** - Requires struct implementing interface vs. simple function

Interfaces are valuable when multiple implementations are expected. For command execution, a simple callback is sufficient.

## Recommended Architecture

### Component: CommandExecutor

A new component handles command template substitution and async execution:

```go
// internal/pkg/processor/command_executor.go

type CommandExecutor struct {
    pcapCommand string // Template with %pcap%
    voipCommand string // Template with %callid%, %dirname%, etc.
    timeout     time.Duration
    sem         chan struct{} // Limits concurrent executions
}

func (e *CommandExecutor) ExecutePcapCommand(filePath string)
func (e *CommandExecutor) ExecuteVoipCommand(meta CallMetadata)
```

**Key Properties:**
- **Async execution** - Commands run in goroutines, don't block writers
- **Timeout** - Prevents runaway commands (default: 30s)
- **Concurrency limit** - Semaphore prevents resource exhaustion (default: 10)
- **Error logging** - Failures logged but don't crash processor

### Hook Points

#### pcapcommand

| Location | Trigger |
|----------|---------|
| `CallPcapWriter.Close()` | Called for each file (SIP, RTP) |
| `CallPcapWriter.rotateSipFile()` | File rotation |
| `CallPcapWriter.rotateRtpFile()` | File rotation |
| `AutoRotatePcapWriter.Close()` | Final file close |
| `AutoRotatePcapWriter.rotateFile()` | File rotation |

#### voipcommand

| Location | Trigger |
|----------|---------|
| New `CallPcapWriter.CloseCall()` | After both SIP and RTP files closed |

### Call Completion Detection

To enable voipcommand, automatic call completion detection is required:

1. **State monitoring** - Watch `CallAggregator` for `CallStateEnded` / `CallStateFailed`
2. **Grace period** - Wait configurable duration (default: 5s) after BYE for retransmissions
3. **Trigger closure** - Call `PcapWriterManager.CloseWriter(callID)`
4. **Execute hook** - voipcommand fires after both files closed

This can be implemented via:
- Periodic sweep of ended calls (simple, batched)
- Immediate callback from state change (responsive, more complex)

### Configuration

**CLI Flags:**
```bash
lc process --per-call-pcap \
  --pcap-command 'echo %pcap% >> /tmp/pcap-list.txt' \
  --voip-command 'notify.sh %callid% %dirname%'
```

**Config File:**
```yaml
processor:
  pcap_command: "echo %pcap% >> /tmp/pcap-list.txt"
  voip_command: "notify.sh %callid% %dirname% %caller% %called% %calldate%"
  command_timeout: "30s"
  command_concurrency: 10
```

**Viper Integration:**
```go
ProcessCmd.Flags().String("pcap-command", "", "Command to run when PCAP file is closed")
ProcessCmd.Flags().String("voip-command", "", "Command to run when VoIP call completes")
viper.BindPFlag("processor.pcap_command", ProcessCmd.Flags().Lookup("pcap-command"))
viper.BindPFlag("processor.voip_command", ProcessCmd.Flags().Lookup("voip-command"))
```

## Security Considerations

1. **Command injection** - Commands come from config, not user input; still, avoid shell interpretation where possible
2. **Resource exhaustion** - Limit concurrent command executions
3. **Timeouts** - Kill long-running commands
4. **Privilege** - Commands run with processor's privileges; document this clearly

## Dependencies

This feature requires:

1. **Call completion detection** - Integration between CallAggregator state and PCAP writer lifecycle
2. **Grace period handling** - Timer-based delay before closing files after call end

## Open Questions

1. Should pcapcommand fire for rotated files (mid-call) or only final files?
   - **Recommendation:** Fire for all closed files (consistent behavior)

2. Should voipcommand wait for a grace period after the last packet?
   - **Recommendation:** Yes, configurable (default 5s) to handle retransmissions

3. Should command failures affect processor operation?
   - **Recommendation:** No, log errors but continue operation

4. Should there be a dry-run mode for testing commands?
   - **Recommendation:** Yes, log what would be executed without running

# Sniff Command - Architecture & Implementation

This document describes the architecture and implementation patterns for the `sniff` command subsystem.

## Purpose

The `sniff` command provides **standalone local packet capture** - both general-purpose and VoIP-specific. This is the non-distributed mode where capture, analysis, and output happen on a single machine.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Sniff Command                           │
├─────────────────────────────────────────────────────────────┤
│  cmd/sniff/                                                 │
│    ├── sniff.go         - Base sniff command (general)      │
│    └── voip.go          - VoIP-specific subcommand          │
├─────────────────────────────────────────────────────────────┤
│  Uses internal/pkg/                                         │
│    ├── capture/         - gopacket integration              │
│    ├── voip/            - VoIP protocol analysis            │
│    │   ├── sip.go       - SIP parsing                       │
│    │   ├── rtp.go       - RTP stream handling               │
│    │   ├── tcp*.go      - TCP reassembly                    │
│    │   └── gpu*.go      - GPU acceleration                  │
│    └── logger/          - Structured logging                │
└─────────────────────────────────────────────────────────────┘
```

## Build Tags

**Build Tag:** `cli` or `all`

```go
//go:build cli || all
```

The sniff command is only included in:
- `cli` builds (CLI-only binary)
- `all` builds (complete suite)

NOT included in `hunter`, `processor`, or `tui` specialized builds.

## Command Structure

### Base Command: `sniff.go`

**File:** `cmd/sniff/sniff.go`

General packet capture without VoIP-specific logic. Minimal implementation.

**Key Components:**
- Interface selection
- BPF filter support
- PCAP file reading/writing
- Basic packet display

### VoIP Subcommand: `voip.go`

**File:** `cmd/sniff/voip.go`

VoIP-specific capture with SIP/RTP analysis, TCP reassembly, and GPU acceleration.

**Architecture Pattern:** Flag-heavy with Viper binding

```go
var (
    sipuser   string
    writeVoip bool

    // GPU acceleration flags
    gpuBackend   string
    gpuBatchSize int
    gpuMaxMemory int64
    gpuEnable    bool

    // TCP-specific configuration flags
    tcpMaxGoroutines      int
    tcpCleanupInterval    time.Duration
    tcpBufferMaxAge       time.Duration
    tcpStreamMaxQueueTime time.Duration
    maxTCPBuffers         int
    tcpStreamTimeout      time.Duration
    tcpAssemblerMaxPages  int
    tcpPerformanceMode    string
    tcpBufferStrategy     string
    enableBackpressure    bool
    memoryOptimization    bool
)
```

**Why so many flags?**
- Allows runtime tuning without recompilation
- Configuration file support via Viper bindings
- Performance profiles auto-configure these (user rarely sets manually)

## Data Flow

### General Sniff Flow

```
Network Interface → gopacket → Packet Display → Output (stdout/file)
```

### VoIP Sniff Flow

```
Network Interface → gopacket → Protocol Detection
                                      ↓
                              ┌───────┴────────┐
                              │                │
                         UDP Packets      TCP Packets
                              │                │
                         SIP Parser       TCP Reassembly
                         RTP Detector     (tcp_assembler.go)
                              │                │
                              └────────┬───────┘
                                       ↓
                              VoIP Packet Processor
                                       ↓
                              GPU Acceleration (optional)
                                       ↓
                              Filter & Display
```

## Key Implementation Patterns

### 1. Viper Integration Pattern

All flags bound to Viper for config file support:

```go
func init() {
    voipCmd.Flags().StringVar(&gpuBackend, "gpu-backend", "auto", "...")
    _ = viper.BindPFlag("voip.gpu_backend", voipCmd.Flags().Lookup("gpu-backend"))
}
```

**Changed Flags Only:** Only set Viper values if flag was explicitly provided:

```go
if cmd.Flags().Changed("gpu-enable") {
    viper.Set("voip.gpu_enable", gpuEnable)
}
```

This allows config file defaults to work while still allowing flag overrides.

### 2. Performance Profile Pattern

Instead of setting 17+ TCP parameters manually, users select a profile:

```go
--tcp-performance-mode balanced  # Auto-configures all TCP parameters
```

**Implementation:** `internal/pkg/voip/tcp_config_simplified.go`

Profiles (`minimal`, `balanced`, `high_performance`, `low_latency`) map to full `Config` structs with all parameters pre-tuned.

### 3. GPU Acceleration Pattern

**Backend Auto-Detection:**

```go
--gpu-backend auto  # CUDA > OpenCL > CPU SIMD > Pure Go
```

**Implementation:** `internal/pkg/voip/gpu_*.go`

Uses interface-based abstraction with runtime backend selection.

### 4. TCP Reassembly Pattern

**Challenge:** SIP over TCP requires stream reassembly.

**Solution:** gopacket's `tcpassembly` package

```go
streamFactory := voip.NewSipStreamFactory(ctx, handler)
assembler := tcpassembly.NewAssembler(streamPool)

// Feed packets to assembler
assembler.AssembleWithContext(ctx, tcp.NetworkFlow(), tcp)
```

**Key Files:**
- `internal/pkg/voip/tcp_assembler.go` - Main assembler logic
- `internal/pkg/voip/tcp_stream.go` - Per-stream handler
- `internal/pkg/voip/tcp_config.go` - Configuration
- `internal/pkg/voip/tcp_config_simplified.go` - Performance profiles

## Integration Points

### With internal/pkg/capture

```go
// Starts live capture
voip.StartLiveVoipSniffer(interfaces, filter)

// Reads from PCAP file
voip.StartOfflineVoipSniffer(readFile, filter)
```

These functions in `internal/pkg/voip` handle all the capture logic using `internal/pkg/capture`.

### With internal/pkg/voip

The voip package is the core VoIP analysis engine. The sniff command is just a thin CLI wrapper.

**Key voip package functions:**
- `StartLiveVoipSniffer()` - Live capture
- `StartOfflineVoipSniffer()` - PCAP file reading
- `NewSipStreamFactory()` - TCP reassembly factory
- `NewVoIPPacketProcessor()` - UDP packet processing

### With Viper Configuration

Configuration cascade:
1. Built-in defaults (in code)
2. Config file (`~/.config/lippycat/config.yaml`)
3. Command-line flags (highest priority)

## Performance Considerations

### Memory Management

**TCP Buffers:** Configurable limit on concurrent TCP packet buffers:

```go
--max-tcp-buffers 5000  # Balanced default
```

**Why it matters:** Each SIP call over TCP creates buffers until the call is identified. Unbounded growth can exhaust memory.

### CPU Optimization

**Batch Processing:** Process packets in batches for efficiency:

```go
--tcp-batch-size 32  # Process 32 packets at once
```

**Worker Threads:** Parallel stream processing:

```go
--tcp-max-goroutines <NumCPU>  # Default: number of CPUs
```

### GPU Acceleration

**When to use:**
- High packet rates (>10,000 pps)
- Many concurrent SIP calls
- Pattern matching becomes CPU bottleneck

**Batch size tuning:**
```go
--gpu-batch-size 1024  # Larger = better throughput, higher latency
```

## Error Handling Patterns

### Graceful Degradation

GPU acceleration failures fall back to CPU:

```go
if gpuAccelerator, err := initGPU(); err != nil {
    logger.Warn("GPU init failed, using CPU", "error", err)
    // Continue with CPU backend
}
```

### Context Cancellation

All long-running operations respect context cancellation:

```go
func StartLiveVoipSniffer(ctx context.Context, ...) {
    select {
    case packet := <-packetChan:
        // Process packet
    case <-ctx.Done():
        return ctx.Err()
    }
}
```

## Testing Considerations

### PCAP File Testing

All VoIP logic can be tested with PCAP files:

```bash
lc sniff voip --read-file testdata/sip-calls.pcap
```

**Test files location:** `testdata/pcaps/` (if present)

### Mock Configuration

Tests can inject config via Viper:

```go
viper.Set("voip.tcp_performance_mode", "minimal")
```

## Common Development Tasks

### Adding a New TCP Parameter

1. Add flag to `voip.go`:
```go
var newParam int
voipCmd.Flags().IntVar(&newParam, "new-param", 100, "...")
```

2. Bind to Viper:
```go
_ = viper.BindPFlag("voip.new_param", voipCmd.Flags().Lookup("new-param"))
```

3. Handle in voipHandler:
```go
if cmd.Flags().Changed("new-param") {
    viper.Set("voip.new_param", newParam)
}
```

4. Use in `internal/pkg/voip`:
```go
newParam := viper.GetInt("voip.new_param")
```

### Adding a Performance Profile

Edit `internal/pkg/voip/tcp_config_simplified.go`:

```go
"custom": {
    Name: "custom",
    TCPPerformanceMode: "custom",
    // ... configure all parameters
}
```

## Dependencies

**External:**
- `github.com/google/gopacket` - Packet capture and parsing
- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration management

**Internal:**
- `internal/pkg/capture` - Capture abstraction
- `internal/pkg/voip` - VoIP analysis engine
- `internal/pkg/logger` - Structured logging

## Related Documentation

- [README.md](README.md) - User-facing command documentation
- [../../docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) - Performance tuning guide
- [../../docs/tcp-troubleshooting.md](../../docs/tcp-troubleshooting.md) - TCP troubleshooting

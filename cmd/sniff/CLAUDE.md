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
- JSON output format (default)
- Text output format (legacy)
- Clean stdout/stderr separation
- Automatic exit on EOF for offline mode

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
Network Interface → gopacket → ConvertPacketToDisplay → JSON Encoder → stdout
                                                              ↓
                                                          (logs → stderr)
```

**Offline Mode:**
```
PCAP File → gopacket → Packet Buffer → processPacketSimple → stdout
     ↓
   EOF detected → Close buffer → Drain processor → Exit cleanly
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

### 1. Output Format Pattern

**JSON Format (Default):**
- Structured `types.PacketDisplay` representation
- One JSON object per line (JSON Lines format)
- Parseable with jq, Python, etc.
- Conversion via `ConvertPacketToDisplay()` in `converter.go`

**Implementation:**
```go
format := viper.GetString("sniff.format")

var jsonEncoder *json.Encoder
if format == "json" {
    jsonEncoder = json.NewEncoder(os.Stdout)
}

for p := range packetChan {
    if format == "json" {
        display := ConvertPacketToDisplay(p)
        jsonEncoder.Encode(display)
    } else {
        fmt.Printf("%s\n", p.Packet)  // Text format
    }
}
```

**Why JSON as default?**
- Machine-readable for automation
- Works with standard Unix tools (jq, etc.)
- Consistent with distributed mode output
- Structured fields are parseable without regex

### 2. stdout/stderr Separation Pattern

Following Unix conventions:
- **stdout**: Packet data only (clean, parseable)
- **stderr**: Structured logs (JSON format via slog)

**Implementation:**
- Logger always uses `os.Stderr` (`internal/pkg/logger/logger.go`)
- All packet output goes to `os.Stdout`
- User can redirect independently: `lc sniff -i eth0 2>logs.json | process.py`

**Benefits:**
- Pipeable output without log contamination
- Logs can be redirected to monitoring systems
- Follows 12-factor app principles

### 3. Offline Mode Exit Pattern

**Challenge:** PCAP files should exit when complete, not wait for signals.

**Solution:** Separate execution paths for live vs offline:

```go
func StartSniffer(devices []pcaptypes.PcapInterface, filter string) {
    processor := func(ch <-chan PacketInfo, asm *tcpassembly.Assembler) {
        processPacketSimple(ch)
    }

    // Detect offline mode (filename contains .pcap/.pcapng or /)
    isOffline := false
    for _, dev := range devices {
        name := dev.Name()
        if strings.Contains(name, ".pcap") || strings.Contains(name, ".pcapng") || strings.Contains(name, "/") {
            isOffline = true
            break
        }
    }

    if isOffline {
        RunOffline(devices, filter, processor, nil)  // Exits on EOF
    } else {
        RunWithSignalHandler(devices, filter, processor, nil)  // Waits for signal
    }
}
```

**RunOffline() implementation:**
1. Start capture goroutines with WaitGroup
2. Start processor goroutine
3. Wait for capture goroutines to finish (EOF detected)
4. Close packet buffer channel
5. Wait for processor to drain remaining packets
6. Return cleanly

**Why this matters:**
- Works with pipes: `lc sniff -r file.pcap | head -100`
- No hanging processes requiring Ctrl+C
- Proper resource cleanup
- Fast exit (milliseconds, not seconds)

### 4. Packet Conversion Pattern

**File:** `internal/pkg/capture/converter.go`

Converts `gopacket.Packet` to `types.PacketDisplay` for structured output:

```go
func ConvertPacketToDisplay(pktInfo PacketInfo) types.PacketDisplay {
    display := types.PacketDisplay{
        Timestamp: pkt.Metadata().Timestamp,
        SrcIP:     "unknown",
        DstIP:     "unknown",
        Protocol:  "unknown",
        // ... fields
    }

    // Extract network layer (IPv4, IPv6)
    if netLayer := pkt.NetworkLayer(); netLayer != nil {
        // ... extract IPs
    }

    // Extract transport layer (TCP, UDP)
    if transLayer := pkt.TransportLayer(); transLayer != nil {
        // ... extract ports and flags
    }

    // Handle special cases (ARP, ICMP, link-layer)
    // ...

    return display
}
```

**Handles:**
- IPv4/IPv6 network layer
- TCP/UDP transport layer (with flags/ports)
- ARP packets (MAC addresses)
- ICMP/ICMPv6
- Link-layer protocols (LLC, CDP, LLDP)
- Ethernet-only frames

### 5. Viper Integration Pattern

All flags bound to Viper for config file support:

```go
func init() {
    SniffCmd.PersistentFlags().StringVar(&format, "format", "json", "output format: json, text")
    _ = viper.BindPFlag("sniff.format", SniffCmd.PersistentFlags().Lookup("format"))
}

func sniff(cmd *cobra.Command, args []string) {
    viper.Set("sniff.quiet", quiet)
    viper.Set("sniff.format", format)
    // ...
}
```

**Changed Flags Only (VoIP mode):** Only set Viper values if flag was explicitly provided:

```go
if cmd.Flags().Changed("gpu-enable") {
    viper.Set("voip.gpu_enable", gpuEnable)
}
```

This allows config file defaults to work while still allowing flag overrides.

### 6. Performance Profile Pattern (VoIP)

Instead of setting 17+ TCP parameters manually, users select a profile:

```go
--tcp-performance-mode balanced  # Auto-configures all TCP parameters
```

**Implementation:** `internal/pkg/voip/tcp_config_simplified.go`

Profiles (`minimal`, `balanced`, `high_performance`, `low_latency`) map to full `Config` structs with all parameters pre-tuned.

### 7. GPU Acceleration Pattern (VoIP)

**Backend Auto-Detection:**

```go
--gpu-backend auto  # CUDA > OpenCL > CPU SIMD > Pure Go
```

**Implementation:** `internal/pkg/voip/gpu_*.go`

Uses interface-based abstraction with runtime backend selection.

### 8. TCP Reassembly Pattern (VoIP)

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

**General sniff mode:**
```go
// Live capture
capture.StartLiveSniffer(interfaces, filter, capture.StartSniffer)

// Offline capture (PCAP file)
capture.StartOfflineSniffer(readFile, filter, capture.StartSniffer)
```

**VoIP sniff mode:**
```go
// Starts live capture
voip.StartLiveVoipSniffer(interfaces, filter)

// Reads from PCAP file
voip.StartOfflineVoipSniffer(readFile, filter)
```

These functions in `internal/pkg/voip` handle all the VoIP capture logic using `internal/pkg/capture`.

**Key capture functions:**
- `StartLiveSniffer()` - Live network interface capture
- `StartOfflineSniffer()` - PCAP file reading with EOF detection
- `RunWithSignalHandler()` - Live mode with signal handling
- `RunOffline()` - Offline mode with automatic exit
- `processPacketSimple()` - Lightweight packet processor for general sniff mode

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

## File Structure

### Core Files

**cmd/sniff/sniff.go** - Base sniff command
- Defines CLI flags and command structure
- Routes to live or offline sniffer
- Binds flags to Viper for config file support

**cmd/sniff/voip.go** - VoIP subcommand
- VoIP-specific flags (GPU, TCP tuning, SIP filtering)
- Performance profile selection
- Routes to VoIP-specific sniffers

### Supporting Files

**internal/pkg/capture/snifferstarter.go** - Capture orchestration
- `StartSniffer()` - Entry point for general sniffing
- `StartLiveSniffer()` - Live network capture setup
- `StartOfflineSniffer()` - PCAP file reading setup
- `RunWithSignalHandler()` - Live mode with graceful shutdown
- `RunOffline()` - Offline mode with EOF detection (NEW in v0.2.9)
- `processPacketSimple()` - JSON/text packet output (NEW in v0.2.9)

**internal/pkg/capture/converter.go** - Packet conversion (NEW in v0.2.9)
- `ConvertPacketToDisplay()` - Converts gopacket.Packet to types.PacketDisplay
- Handles all protocol types (TCP, UDP, ARP, ICMP, link-layer)
- Extracts structured fields for JSON output

**internal/pkg/logger/logger.go** - Logging infrastructure
- Uses `os.Stderr` for all log output (fixed in v0.2.9)
- JSON format via slog
- Level-based filtering

**internal/pkg/types/packet.go** - Shared types
- `PacketDisplay` - Common packet representation
- Used by sniff, hunt, processor, and TUI

## Common Development Tasks

### Adding a New Packet Field to JSON Output

1. Add field to `types.PacketDisplay` struct in `internal/pkg/types/packet.go`
2. Extract field in `ConvertPacketToDisplay()` in `internal/pkg/capture/converter.go`
3. Field automatically appears in JSON output

Example:
```go
// types.PacketDisplay
type PacketDisplay struct {
    // ... existing fields
    VLAN int `json:"VLAN,omitempty"`  // New field
}

// converter.go
func ConvertPacketToDisplay(pktInfo PacketInfo) types.PacketDisplay {
    // ... existing logic

    // Extract VLAN tag if present
    if dot1q := pkt.Layer(layers.LayerTypeDot1Q); dot1q != nil {
        vlan, _ := dot1q.(*layers.Dot1Q)
        display.VLAN = int(vlan.VLANIdentifier)
    }

    return display
}
```

### Adding a New Output Format

1. Add format to flag choices in `cmd/sniff/sniff.go`
2. Add format handling in `processPacketSimple()` in `internal/pkg/capture/snifferstarter.go`

Example (adding CSV format):
```go
// cmd/sniff/sniff.go
SniffCmd.PersistentFlags().StringVar(&format, "format", "json", "output format: json, text, csv")

// snifferstarter.go
format := viper.GetString("sniff.format")
switch format {
case "json":
    // existing JSON handling
case "csv":
    // CSV header
    fmt.Println("Timestamp,SrcIP,DstIP,Protocol")
    for p := range packetChan {
        display := ConvertPacketToDisplay(p)
        fmt.Printf("%s,%s,%s,%s\n", display.Timestamp, display.SrcIP, display.DstIP, display.Protocol)
    }
default:
    // text format
}
```

### Adding a New TCP Parameter (VoIP)

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
- `internal/pkg/capture` - Capture abstraction and packet processing
  - `snifferstarter.go` - Live/offline sniffer orchestration
  - `converter.go` - Packet to JSON conversion (NEW in v0.2.9)
- `internal/pkg/voip` - VoIP analysis engine
- `internal/pkg/logger` - Structured logging (stderr output)
- `internal/pkg/types` - Shared domain types (PacketDisplay)

## Related Documentation

- [README.md](README.md) - User-facing command documentation
- [../../docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) - Performance tuning guide
- [../../docs/tcp-troubleshooting.md](../../docs/tcp-troubleshooting.md) - TCP troubleshooting

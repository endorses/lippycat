# Tap Command - Architecture & Implementation

This document describes the architecture and implementation patterns for the `tap` command (standalone capture mode) that combines local packet capture with full processor capabilities.

## Purpose

Tap mode provides **standalone capture with processor capabilities**:
1. Captures packets from local network interfaces (like hunters)
2. Processes packets locally (like processors)
3. Writes PCAP files (unified, per-call, auto-rotating)
4. Serves TUI connections via gRPC
5. Optionally forwards to upstream processors (hierarchical mode)

**Key Difference from Hunt/Process:**
- `hunt` captures and forwards to remote processor
- `process` receives from remote hunters
- `tap` captures AND processes locally (no network hop)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Tap Node                                 │
├─────────────────────────────────────────────────────────────────┤
│  cmd/tap/                                                       │
│    ├── tap.go           - Base tap command                      │
│    └── tap_voip.go      - VoIP-optimized tap                    │
├─────────────────────────────────────────────────────────────────┤
│  Uses internal/pkg/                                             │
│    ├── processor/       - Core processor logic                  │
│    │   ├── source/      - PacketSource abstraction              │
│    │   │   ├── source.go      - Interface definitions           │
│    │   │   ├── local.go       - LocalSource implementation      │
│    │   │   └── grpc.go        - GRPCSource (for process cmd)    │
│    │   └── filtering/   - FilterTarget abstraction              │
│    │       ├── target.go        - Interface definitions         │
│    │       ├── target_local.go  - LocalTarget (BPF-based)       │
│    │       └── target_hunter.go - HunterTarget (distributed)    │
│    ├── capture/         - Packet capture (gopacket)             │
│    └── voip/            - VoIP protocol analysis                │
├─────────────────────────────────────────────────────────────────┤
│  gRPC Protocol: api/proto/                                      │
│    └── monitoring.proto - TUI monitoring (same as processor)    │
└─────────────────────────────────────────────────────────────────┘
```

## Build Tags

**Build Tag:** `tap` or `all`

```go
//go:build tap || all
```

The tap command is only included in:
- `tap` builds (tap-only binary)
- `all` builds (complete suite ~22MB)

NOT included in `hunter`, `processor`, `cli`, or `tui` specialized builds.

## Command Structure

### Base Command: `tap.go`

**File:** `cmd/tap/tap.go`

General-purpose standalone capture. Reuses processor infrastructure with local packet source.

### VoIP Subcommand: `tap_voip.go`

**File:** `cmd/tap/tap_voip.go`

VoIP-optimized capture with:
- SIP user filtering
- Per-call PCAP writing (enabled by default)
- TCP reassembly configuration
- BPF filter optimization

## Data Flow

### Tap Mode Data Flow

```
Network Interface
       ↓
   LocalSource (internal/pkg/processor/source/local.go)
       ↓
   Packet Batching
       ↓
   Processor Pipeline (internal/pkg/processor/processor.go)
       ↓
   ┌──────────────────────────────────────────┐
   │                                          │
   ↓                ↓               ↓         ↓
Per-Call        Auto-Rotate     Virtual    Upstream
PCAP Writer     PCAP Writer    Interface  Forwarding
(VoIP)          (non-VoIP)                (optional)
                                              ↓
                                     TUI Subscribers
                                     (via gRPC)
```

### Comparison with Hunt/Process Flow

```
Hunt Mode:                    Process Mode:                 Tap Mode:
Network → Hunter             Hunters → Processor           Network → Tap
           ↓                          ↓                              ↓
        gRPC Stream                gRPC Receive              Local Capture
           ↓                          ↓                              ↓
        Processor                  Processing                   Processing
                                                                     ↓
                                                              (same outputs)
```

## Key Implementation Patterns

### 1. PacketSource Interface Pattern

**File:** `internal/pkg/processor/source/source.go`

Abstraction for packet origin, allowing processor to work with local capture OR remote hunters:

```go
type PacketSource interface {
    Start(ctx context.Context) error
    Batches() <-chan *PacketBatch
    Stats() Stats
    SourceID() string
}

type PacketBatch struct {
    SourceID    string
    Packets     []*data.CapturedPacket
    Sequence    uint64
    TimestampNs int64
}
```

**Implementations:**
- `LocalSource` - Local network capture (used by tap)
- `GRPCSource` - Remote hunter connections (used by process)

### 2. LocalSource Implementation

**File:** `internal/pkg/processor/source/local.go`

Wraps the capture package for local packet capture:

```go
type LocalSource struct {
    config      LocalSourceConfig
    capturer    *capture.MultiCapture
    batchChan   chan *PacketBatch
    started     bool
    mu          sync.RWMutex
}

type LocalSourceConfig struct {
    Interfaces   []string
    BPFFilter    string
    BatchSize    int
    BatchTimeout time.Duration
    BufferSize   int
    BatchBuffer  int
}
```

**Key Methods:**

```go
// Start begins packet capture on configured interfaces
func (s *LocalSource) Start(ctx context.Context) error

// Batches returns channel for receiving packet batches
func (s *LocalSource) Batches() <-chan *PacketBatch

// SetBPFFilter updates the BPF filter on all interfaces
func (s *LocalSource) SetBPFFilter(filter string) error
```

### 3. FilterTarget Interface Pattern

**File:** `internal/pkg/processor/filtering/target.go`

Abstraction for filter application, allowing different filtering mechanisms:

```go
type FilterTarget interface {
    ApplyFilter(filter *management.Filter) error
    RemoveFilter(filterID string) error
    GetActiveFilters() []*management.Filter
    SupportsFilterType(filterType management.FilterType) bool
}
```

**Implementations:**
- `LocalTarget` - BPF-based filtering for local capture (used by tap)
- `HunterTarget` - Distributes filters to remote hunters (used by process)

### 4. LocalTarget Implementation

**File:** `internal/pkg/processor/filtering/target_local.go`

Converts management filters to BPF expressions for local capture:

```go
type LocalTarget struct {
    config      LocalTargetConfig
    filters     map[string]*management.Filter
    bpfUpdater  BPFUpdater
    mu          sync.RWMutex
}

// BPFUpdater is implemented by LocalSource
type BPFUpdater interface {
    SetBPFFilter(filter string) error
}
```

**Filter to BPF Conversion:**

```go
// sipuser filter → BPF expression (limited to port-based filtering)
// Note: Full SIP header matching requires application-level filtering
func (t *LocalTarget) filterToBPF(f *management.Filter) string {
    switch f.Type {
    case management.FilterType_IP:
        return fmt.Sprintf("host %s", f.Pattern)
    case management.FilterType_SIPUSER:
        // Can only apply port-based pre-filter at BPF level
        return "" // Application-level filtering
    }
}
```

### 5. Tap Command Integration Pattern

**File:** `cmd/tap/tap.go:407-435`

Wiring LocalSource and LocalTarget to the processor:

```go
// Create LocalSource for local packet capture
localSourceConfig := source.LocalSourceConfig{
    Interfaces:   getStringSliceConfig("tap.interfaces", interfaces),
    BPFFilter:    getStringConfig("tap.bpf_filter", bpfFilter),
    BatchSize:    getIntConfig("tap.batch_size", batchSize),
    BatchTimeout: time.Duration(getIntConfig("tap.batch_timeout_ms", batchTimeout)) * time.Millisecond,
    BufferSize:   getIntConfig("tap.buffer_size", bufferSize),
    BatchBuffer:  1000,
}
localSource := source.NewLocalSource(localSourceConfig)

// Create LocalTarget for local BPF filtering
localTargetConfig := filtering.LocalTargetConfig{
    BaseBPF: localSourceConfig.BPFFilter,
}
localTarget := filtering.NewLocalTarget(localTargetConfig)

// Wire LocalTarget to LocalSource for BPF filter updates
localTarget.SetBPFUpdater(localSource)

// Set the local source and target on the processor
p.SetPacketSource(localSource)
p.SetFilterTarget(localTarget)
```

### 6. VoIP Tap BPF Optimization Pattern

**File:** `cmd/tap/tap_voip.go:122-157`

VoIP mode builds optimized BPF filters for high-traffic networks:

```go
// Build optimized BPF filter using VoIPFilterBuilder
baseBPFFilter := getStringConfig("tap.bpf_filter", bpfFilter)
effectiveBPFFilter := baseBPFFilter

if voipUDPOnly || voipSIPPorts != "" || voipRTPPortRanges != "" {
    builder := voip.NewVoIPFilterBuilder()
    filterConfig := voip.VoIPFilterConfig{
        SIPPorts:      parsedSIPPorts,
        RTPPortRanges: parsedRTPRanges,
        UDPOnly:       voipUDPOnly,
        BaseFilter:    baseBPFFilter,
    }
    effectiveBPFFilter = builder.Build(filterConfig)
}
```

**Generated Filters:**

| Input | Generated BPF Filter |
|-------|---------------------|
| `--udp-only` | `udp` |
| `--sip-port 5060` | `(port 5060) or (udp portrange 10000-32768)` |
| `--udp-only --sip-port 5060` | `udp and ((port 5060) or (portrange 10000-32768))` |

### 7. Per-Call PCAP Default Pattern

**File:** `cmd/tap/tap_voip.go:165-169`

VoIP tap mode enables per-call PCAP by default:

```go
// Default to enabling per-call PCAP for VoIP mode if not explicitly set
effectivePerCallPcap := getBoolConfig("tap.per_call_pcap.enabled", perCallPcapEnabled)
if !cmd.Flags().Changed("per-call-pcap") && !viper.IsSet("tap.per_call_pcap.enabled") {
    // VoIP mode should default to per-call PCAP enabled
    effectivePerCallPcap = true
}
```

### 8. Security Banner Pattern

**File:** `cmd/tap/tap.go:376-400`

Prominent security warnings for insecure mode:

```go
if !config.TLSEnabled {
    logger.Warn("═══════════════════════════════════════════════════════════")
    logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
    logger.Warn("  Management interface will accept UNENCRYPTED connections")
    logger.Warn("  This mode should ONLY be used in trusted networks")
    logger.Warn("═══════════════════════════════════════════════════════════")
} else {
    authMode := "Server TLS"
    if config.TLSClientAuth {
        authMode = "Mutual TLS (client certs required)"
    }
    logger.Info("═══════════════════════════════════════════════════════════")
    logger.Info("  Security: TLS ENABLED")
    logger.Info("  Authentication mode: " + authMode)
    logger.Info("═══════════════════════════════════════════════════════════")
}
```

### 9. Processor Reuse Pattern

Tap reuses the full processor infrastructure without modification:

**Reused Components:**
- `processor.New(config)` - Same processor constructor
- `processor.Config` - Same configuration struct
- Per-call PCAP writing
- Auto-rotate PCAP writing
- Command hooks
- TUI subscriber management
- Virtual interface injection
- Protocol detection

**What's Different:**
- `PacketSource`: LocalSource instead of GRPCSource
- `FilterTarget`: LocalTarget instead of HunterTarget
- No hunter connection management
- No filter distribution to hunters

## Hierarchical Mode

Tap nodes can forward to upstream processors:

```
┌─────────┐     ┌─────────┐     ┌───────────┐
│  Tap    │────→│   Tap   │────→│ Processor │
│  (Edge) │     │ (Region)│     │ (Central) │
└─────────┘     └─────────┘     └───────────┘
     ↑                               ↑
  Local              Aggregates    Receives
  Capture            from edges    from all
```

**Configuration:**

```bash
# Edge tap (captures locally, forwards to regional)
lc tap -i eth0 --processor regional:50051 --tls --tls-ca ca.crt

# Regional tap (captures locally, receives from edges, forwards to central)
lc tap -i eth0 --processor central:50051 --tls --tls-ca ca.crt

# Central processor (receives from all)
lc process --listen 0.0.0.0:50051 --tls --tls-cert server.crt --tls-key server.key
```

## Configuration Patterns

### Viper Integration

All flags bound to Viper for config file support:

```yaml
tap:
  interfaces:
    - eth0
  bpf_filter: ""
  buffer_size: 10000
  batch_size: 100
  batch_timeout_ms: 100
  listen_addr: ":50051"
  id: "edge-tap"
  processor_addr: ""

  per_call_pcap:
    enabled: true
    output_dir: "./pcaps"

  tls:
    enabled: true
    cert_file: "server.crt"
    key_file: "server.key"
```

### Helper Functions Pattern

Same pattern as hunt/process:

```go
func getStringConfig(key, flagValue string) string {
    if flagValue != "" {
        return flagValue
    }
    return viper.GetString(key)
}
```

## Performance Considerations

### Memory Management

**Per-Tap Memory:**
- LocalSource packet buffer: `--buffer-size` × ~1KB ≈ 10MB
- Batch queue: 1000 batches × 100 packets × ~1KB ≈ 100MB
- Per-subscriber channels: 100 × ~2MB = 200MB
- PCAP write queues: ~50MB

**Total:** ~300-400MB for typical configuration

### CPU Optimization

**Pipeline:**
1. Kernel → gopacket (zero-copy where possible)
2. BPF filter (kernel space)
3. LocalSource batching
4. Processor pipeline
5. Output (PCAP, TUI, upstream)

**Bottleneck:** Usually I/O (PCAP writing) or VoIP parsing (use TCP profiles).

### Latency Comparison

| Mode | Capture to TUI Latency |
|------|----------------------|
| `lc tap` | ~1-10ms (local) |
| `lc hunt` + `lc process` | ~10-100ms (network hop) |
| `lc sniff` | N/A (no TUI) |

## Error Handling Patterns

### Capture Failure

```go
if err := localSource.Start(ctx); err != nil {
    return fmt.Errorf("failed to start local capture: %w", err)
}
```

**Recovery:** Exit with error (capture is fundamental).

### TUI Subscriber Disconnection

Handled by processor's subscriber management (same as process command).

### Graceful Shutdown

```go
cleanup := signals.SetupHandler(ctx, cancel)
defer cleanup()

// Wait for shutdown signal or error
select {
case <-ctx.Done():
    time.Sleep(constants.GracefulShutdownTimeout)
case err := <-errChan:
    logger.Error("Tap node failed", "error", err)
    return err
}
```

## Testing Considerations

### Unit Testing

LocalSource and LocalTarget have dedicated unit tests:

```bash
go test ./internal/pkg/processor/source/...
go test ./internal/pkg/processor/filtering/...
```

### Integration Testing

Tap command is tested via build verification:

```bash
make tap           # Build tap-only binary
./bin/lc-tap --help  # Verify help output
```

### PCAP Testing

Use test PCAP files for VoIP functionality:

```bash
lc tap voip -r testdata/pcaps/sip-call.pcap --insecure
```

## Common Development Tasks

### Adding a New Capture Option

1. Add flag in `cmd/tap/tap.go`:
```go
TapCmd.Flags().IntVar(&newOption, "new-option", 100, "...")
_ = viper.BindPFlag("tap.new_option", TapCmd.Flags().Lookup("new-option"))
```

2. Pass to LocalSourceConfig:
```go
localSourceConfig := source.LocalSourceConfig{
    NewOption: getIntConfig("tap.new_option", newOption),
}
```

3. Handle in LocalSource:
```go
func NewLocalSource(config LocalSourceConfig) *LocalSource {
    // Use config.NewOption
}
```

### Adding a Filter Type to LocalTarget

1. Update `filterToBPF()` in `target_local.go`
2. Add BPF generation logic
3. Test with `SetBPFFilter()` integration

### Modifying VoIP Defaults

Edit `cmd/tap/tap_voip.go` default handling logic.

## Dependencies

**External:**
- `google.golang.org/grpc` - gRPC server (for TUI)
- `github.com/google/gopacket` - Packet capture
- `github.com/spf13/cobra` - CLI framework

**Internal:**
- `internal/pkg/processor` - Core processor logic
- `internal/pkg/processor/source` - PacketSource abstraction
- `internal/pkg/processor/filtering` - FilterTarget abstraction
- `internal/pkg/capture` - Capture abstraction
- `internal/pkg/voip` - VoIP analysis

## Related Documentation

- [README.md](README.md) - User-facing command documentation
- [../sniff/CLAUDE.md](../sniff/CLAUDE.md) - CLI-only capture architecture
- [../hunt/CLAUDE.md](../hunt/CLAUDE.md) - Hunter architecture
- [../process/CLAUDE.md](../process/CLAUDE.md) - Processor architecture
- [../../docs/DISTRIBUTED_MODE.md](../../docs/DISTRIBUTED_MODE.md) - Distributed system overview
- [../../docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) - Performance tuning

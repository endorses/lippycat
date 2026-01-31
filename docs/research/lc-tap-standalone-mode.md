# lc tap: Standalone Capture Mode

## Executive Summary

This document describes the design and implementation of `lc tap`, a standalone capture mode that combines local packet capture with full processor capabilities—without the gRPC overhead of the distributed hunter/processor architecture.

**Use Case**: Single-node deployments where distributed capture is unnecessary, such as:
- Development and testing environments
- Small-scale VoIP monitoring
- Edge deployments with limited resources

**Key Benefits**:
- No gRPC overhead for packet transport
- All processor features available (per-call PCAP, call aggregation, X1/X2/X3)
- Remote TUI monitoring still supported
- Simpler deployment (single binary, single process)

## Current Architecture Gap

| Command | Capture | Remote Admin | Per-call PCAP | Call Aggregation | X1/X2/X3 |
|---------|---------|--------------|---------------|------------------|----------|
| `lc sniff` | Local | No | No | No | No |
| `lc sniff voip` | Local | No | Yes | No | No |
| `lc hunt` + `lc process` | Distributed | Yes | Yes | Yes | (future) |
| **`lc tap`** (new) | Local | Yes | Yes | Yes | Yes |

The gap: `lc sniff voip` captures locally with per-call PCAP but lacks remote management and advanced features like call aggregation. Getting those features currently requires the full distributed stack, even for single-node deployments.

## Design Goals

1. **Reuse hunter code**: LocalSource wraps hunter's capture manager, TCP reassembly, and packet conversion
2. **Reuse processor code**: No duplication of PCAP writing, call aggregation, subscriber management
3. **Interface abstraction**: Clean separation between packet source and processing pipeline
4. **Build-tag compatible**: Fits existing `hunter`, `processor`, `cli`, `tui`, `all` pattern
5. **Future-proof**: X1/X2/X3 protocols work identically in tap and distributed modes

## Architecture Overview

`lc tap` combines hunter capture code with processor pipeline code:

```
┌──────────────────────────────────────────────────────────────────────┐
│                            lc tap                                    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ LocalSource (reuses hunter code)                                │ │
│  │  ┌───────────────────┐  ┌──────────────────┐  ┌───────────────┐ │ │
│  │  │ hunter/capture    │  │ hunter TCP       │  │ hunter        │ │ │
│  │  │ (capture.Manager) │  │ reassembly       │  │ AppFilter     │ │ │
│  │  └─────────┬─────────┘  └────────┬─────────┘  └───────┬───────┘ │ │
│  │            │                     │                    │         │ │
│  │            └──────────┬──────────┴────────────────────┘         │ │
│  │                       ▼                                         │ │
│  │             hunter/forwarding.convertPacket()                   │ │
│  │                       │                                         │ │
│  └───────────────────────┼─────────────────────────────────────────┘ │
│                          ▼                                           │
│                   PacketBatch                                        │
│                          │                                           │
│  ┌───────────────────────┼─────────────────────────────────────────┐ │
│  │ Processor pipeline (reused as-is)                               │ │
│  │  • Per-call PCAP writer                                         │ │
│  │  • Auto-rotate PCAP writer                                      │ │
│  │  • Call aggregator + correlator                                 │ │
│  │  • Subscriber manager (TUI)                                     │ │
│  │  • Upstream manager (optional)                                  │ │
│  │  • Virtual interface                                            │ │
│  │  • (Future) X1/X2/X3                                            │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

## Architecture

### PacketSource Interface

Abstract where packets come from:

```go
// internal/pkg/processor/source/source.go

package source

import (
    "context"

    "github.com/endorses/lippycat/api/gen/data"
)

// PacketSource abstracts the origin of packets for the processor pipeline.
// Implementations include GRPCSource (distributed hunters) and LocalSource (local capture).
type PacketSource interface {
    // Start begins packet production. Blocks until ctx is cancelled.
    Start(ctx context.Context) error

    // Batches returns channel of packet batches for processing.
    // Channel is closed when source stops.
    Batches() <-chan *PacketBatch

    // Stats returns current source statistics.
    Stats() Stats

    // SourceID returns identifier for this source (e.g., "local", hunter ID).
    SourceID() string
}

// PacketBatch represents a batch of packets from a source.
// This is the internal representation; GRPCSource converts from data.PacketBatch.
type PacketBatch struct {
    SourceID    string
    Packets     []*data.CapturedPacket
    Sequence    uint64
    TimestampNs int64
}

// Stats contains packet source statistics.
type Stats struct {
    PacketsReceived uint64
    PacketsDropped  uint64
    BatchesSent     uint64
    Uptime          time.Duration
}
```

### GRPCSource (Existing Behavior)

Wraps current hunter gRPC handling:

```go
// internal/pkg/processor/source/grpc.go

package source

import (
    "context"
    "sync"

    "github.com/endorses/lippycat/api/gen/data"
    "github.com/endorses/lippycat/internal/pkg/processor/hunter"
    "google.golang.org/grpc"
)

// GRPCSource receives packets from distributed hunters via gRPC.
type GRPCSource struct {
    grpcServer    *grpc.Server
    hunterManager *hunter.Manager
    batches       chan *PacketBatch

    packetsReceived uint64
    batchesReceived uint64

    mu sync.RWMutex
}

// GRPCSourceConfig configures the gRPC packet source.
type GRPCSourceConfig struct {
    ListenAddr    string
    MaxHunters    int
    TLSEnabled    bool
    TLSCertFile   string
    TLSKeyFile    string
    TLSCAFile     string
    TLSClientAuth bool
    AuthConfig    *auth.Config
}

func NewGRPCSource(config GRPCSourceConfig) (*GRPCSource, error) {
    // ... initialize gRPC server, hunter manager
}

func (s *GRPCSource) Start(ctx context.Context) error {
    // Start gRPC server
    // Accept hunter connections
    // Convert data.PacketBatch to source.PacketBatch
    // Send to s.batches channel
}

func (s *GRPCSource) Batches() <-chan *PacketBatch {
    return s.batches
}

func (s *GRPCSource) SourceID() string {
    return "grpc"
}

// HunterManager returns the hunter manager for status queries.
// Only available for GRPCSource.
func (s *GRPCSource) HunterManager() *hunter.Manager {
    return s.hunterManager
}
```

### LocalSource (New)

Local packet capture that **reuses existing hunter code** - no reimplementation:

```go
// internal/pkg/processor/source/local.go

package source

import (
    "context"
    "sync/atomic"
    "time"

    "github.com/endorses/lippycat/api/gen/data"
    huntercapture "github.com/endorses/lippycat/internal/pkg/hunter/capture"
    "github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
)

// LocalSource captures packets from local network interfaces.
// It reuses hunter's capture manager, TCP reassembly, packet conversion,
// and application-level filtering (GPU-accelerated).
type LocalSource struct {
    config            LocalSourceConfig
    captureManager    *huntercapture.Manager    // Reused from hunter package
    applicationFilter *hunter.ApplicationFilter // Reused from hunter package
    batches           chan *PacketBatch

    packetsReceived atomic.Uint64
    batchesSent     atomic.Uint64
    startTime       time.Time
}

// LocalSourceConfig configures local packet capture.
type LocalSourceConfig struct {
    Interfaces     []string      // Network interfaces to capture from
    BPFFilter      string        // Base BPF filter expression
    BufferSize     int           // Packet buffer size
    BatchSize      int           // Packets per batch
    BatchTimeout   time.Duration // Max time to wait for full batch
    EnableDetector bool          // Run protocol detection
    Promiscuous    bool          // Promiscuous mode
    SnapLen        int           // Snapshot length
    VoIPMode       bool          // Enable TCP reassembly for SIP

    // Application-level filtering (reused from hunter)
    EnableAppFilter bool   // Enable application-level filtering
    GPUBackend      string // GPU backend: "auto", "cuda", "opencl", "cpu-simd"
}

func NewLocalSource(config LocalSourceConfig) (*LocalSource, error) {
    // Reuse hunter's capture manager - same code path as lc hunt
    captureManager := huntercapture.New(huntercapture.Config{
        Interfaces: config.Interfaces,
        BaseFilter: config.BPFFilter,
        BufferSize: config.BufferSize,
        // ProcessorAddr not needed - we're not forwarding via gRPC
    }, context.Background())

    return &LocalSource{
        config:         config,
        captureManager: captureManager,
        batches:        make(chan *PacketBatch, 100),
    }, nil
}

func (s *LocalSource) Start(ctx context.Context) error {
    s.startTime = time.Now()

    // Start hunter's capture manager
    // This handles interface setup, BPF filters, and (if VoIP mode) TCP reassembly
    if err := s.captureManager.Start(ctx); err != nil {
        return err
    }

    // Batch packets from capture manager and send to processor pipeline
    return s.batchLoop(ctx)
}

func (s *LocalSource) batchLoop(ctx context.Context) error {
    batch := make([]*data.CapturedPacket, 0, s.config.BatchSize)
    ticker := time.NewTicker(s.config.BatchTimeout)
    defer ticker.Stop()

    var sequence uint64

    sendBatch := func() {
        if len(batch) == 0 {
            return
        }

        pb := &PacketBatch{
            SourceID:    "local",
            Packets:     batch,
            Sequence:    sequence,
            TimestampNs: time.Now().UnixNano(),
        }

        select {
        case s.batches <- pb:
            s.batchesSent.Add(1)
            sequence++
        case <-ctx.Done():
            return
        }

        batch = make([]*data.CapturedPacket, 0, s.config.BatchSize)
    }

    // Read from capture manager's packet channel (same as hunter does)
    packetCh := s.captureManager.Packets()

    for {
        select {
        case <-ctx.Done():
            sendBatch()
            close(s.batches)
            return ctx.Err()

        case <-ticker.C:
            sendBatch()

        case pktInfo, ok := <-packetCh:
            if !ok {
                sendBatch()
                close(s.batches)
                return nil
            }

            // Reuse hunter's packet conversion - exact same code path
            pkt := forwarding.ConvertPacket(pktInfo)
            s.packetsReceived.Add(1)

            batch = append(batch, pkt)

            if len(batch) >= s.config.BatchSize {
                sendBatch()
            }
        }
    }
}

func (s *LocalSource) Batches() <-chan *PacketBatch {
    return s.batches
}

func (s *LocalSource) SourceID() string {
    return "local"
}

func (s *LocalSource) Stats() Stats {
    return Stats{
        PacketsReceived: s.packetsReceived.Load(),
        PacketsDropped:  0, // Get from capture manager if needed
        BatchesSent:     s.batchesSent.Load(),
        Uptime:          time.Since(s.startTime),
    }
}

// SetBPFFilter updates the BPF filter dynamically (for FilterTarget integration)
func (s *LocalSource) SetBPFFilter(filter string) error {
    return s.captureManager.SetBPFFilter(filter)
}
```

**Key point**: LocalSource doesn't reimplement capture or packet conversion.
It imports and uses `hunter/capture.Manager` and `hunter/forwarding.ConvertPacket()` directly.

### FilterTarget Interface

Abstract where filters are applied:

```go
// internal/pkg/processor/filtering/target.go

package filtering

import (
    "github.com/endorses/lippycat/api/gen/management"
)

// FilterTarget abstracts where filters are applied.
// Implementations include HunterTarget (distributed) and LocalTarget (BPF).
type FilterTarget interface {
    // ApplyFilter applies a filter to the target.
    ApplyFilter(filter *management.Filter) error

    // RemoveFilter removes a filter from the target.
    RemoveFilter(filterID string) error

    // GetActiveFilters returns currently active filters.
    GetActiveFilters() []*management.Filter

    // SupportsFilterType returns whether the target supports a filter type.
    SupportsFilterType(filterType management.FilterType) bool
}
```

### HunterTarget (Existing Behavior)

Distributes filters to hunters:

```go
// internal/pkg/processor/filtering/target_hunter.go

package filtering

// HunterTarget distributes filters to connected hunters.
type HunterTarget struct {
    hunterManager *hunter.Manager
    channels      map[string]chan *management.FilterUpdate
}

func (t *HunterTarget) ApplyFilter(filter *management.Filter) error {
    // Existing logic: send filter to hunters based on capabilities
    // ...
}
```

### LocalTarget (New)

Applies filters to local BPF:

```go
// internal/pkg/processor/filtering/target_local.go

package filtering

import (
    "fmt"
    "sync"

    "github.com/endorses/lippycat/api/gen/management"
    "github.com/endorses/lippycat/internal/pkg/filtering"
)

// LocalTarget applies filters to local BPF capture.
type LocalTarget struct {
    mu            sync.RWMutex
    activeFilters map[string]*management.Filter
    bpfApplier    BPFApplier
}

// BPFApplier applies BPF filters to capture.
type BPFApplier interface {
    SetBPFFilter(filter string) error
    GetCurrentFilter() string
}

func NewLocalTarget(applier BPFApplier) *LocalTarget {
    return &LocalTarget{
        activeFilters: make(map[string]*management.Filter),
        bpfApplier:    applier,
    }
}

func (t *LocalTarget) ApplyFilter(filter *management.Filter) error {
    t.mu.Lock()
    defer t.mu.Unlock()

    // Store filter
    t.activeFilters[filter.Id] = filter

    // Rebuild combined BPF expression
    bpf, err := t.buildCombinedBPF()
    if err != nil {
        return fmt.Errorf("failed to build BPF: %w", err)
    }

    // Apply to capture
    return t.bpfApplier.SetBPFFilter(bpf)
}

func (t *LocalTarget) RemoveFilter(filterID string) error {
    t.mu.Lock()
    defer t.mu.Unlock()

    delete(t.activeFilters, filterID)

    bpf, err := t.buildCombinedBPF()
    if err != nil {
        return err
    }

    return t.bpfApplier.SetBPFFilter(bpf)
}

func (t *LocalTarget) buildCombinedBPF() (string, error) {
    // Convert active filters to BPF expression
    // Uses internal/pkg/filtering package for conversion
    return filtering.FiltersToBPF(t.activeFilters)
}

func (t *LocalTarget) SupportsFilterType(filterType management.FilterType) bool {
    // Local target only supports BPF-convertible filters
    switch filterType {
    case management.FilterType_FILTER_BPF,
         management.FilterType_FILTER_IP,
         management.FilterType_FILTER_PORT,
         management.FilterType_FILTER_PROTOCOL:
        return true
    case management.FilterType_FILTER_VOIP:
        // VoIP filters require application-level filtering
        // which is not yet supported in local mode
        return false
    default:
        return false
    }
}

func (t *LocalTarget) GetActiveFilters() []*management.Filter {
    t.mu.RLock()
    defer t.mu.RUnlock()

    filters := make([]*management.Filter, 0, len(t.activeFilters))
    for _, f := range t.activeFilters {
        filters = append(filters, f)
    }
    return filters
}
```

## Processor Modifications

### Config Changes

```go
// internal/pkg/processor/processor.go

type Config struct {
    // Existing fields...

    // Source mode (mutually exclusive)
    StandaloneMode   bool     // Use local capture instead of gRPC
    CaptureInterface []string // Interfaces for local capture
    CaptureBPFFilter string   // Base BPF filter for local capture
    CaptureSnapLen   int      // Snapshot length (0 = default 65535)
    CapturePromisc   bool     // Promiscuous mode

    // These become optional (only needed in distributed mode)
    ListenAddr string // gRPC listen address (distributed mode only)
    MaxHunters int    // Max hunters (distributed mode only)
}
```

### Processor Changes

```go
// internal/pkg/processor/processor.go

type Processor struct {
    // Existing fields...

    // Abstract packet source
    packetSource source.PacketSource

    // Abstract filter target
    filterTarget filtering.FilterTarget
}

func New(config Config) (*Processor, error) {
    p := &Processor{
        config:         config,
        callAggregator: voip.NewCallAggregator(),
        callCorrelator: NewCallCorrelator(),
    }

    // Initialize packet source based on mode
    if config.StandaloneMode {
        // Local capture mode
        localSource, err := source.NewLocalSource(source.LocalSourceConfig{
            Interfaces:     config.CaptureInterface,
            BPFFilter:      config.CaptureBPFFilter,
            BufferSize:     10000,
            BatchSize:      100,
            BatchTimeout:   100 * time.Millisecond,
            EnableDetector: config.EnableDetection,
            Promiscuous:    config.CapturePromisc,
            SnapLen:        config.CaptureSnapLen,
        })
        if err != nil {
            return nil, fmt.Errorf("failed to create local source: %w", err)
        }
        p.packetSource = localSource

        // Local filter target (BPF-based)
        p.filterTarget = filtering.NewLocalTarget(localSource)

        // No hunter manager in standalone mode
        p.hunterManager = nil

    } else {
        // Distributed mode (existing behavior)
        grpcSource, err := source.NewGRPCSource(source.GRPCSourceConfig{
            ListenAddr:    config.ListenAddr,
            MaxHunters:    config.MaxHunters,
            TLSEnabled:    config.TLSEnabled,
            TLSCertFile:   config.TLSCertFile,
            TLSKeyFile:    config.TLSKeyFile,
            TLSCAFile:     config.TLSCAFile,
            TLSClientAuth: config.TLSClientAuth,
            AuthConfig:    config.AuthConfig,
        })
        if err != nil {
            return nil, fmt.Errorf("failed to create gRPC source: %w", err)
        }
        p.packetSource = grpcSource
        p.hunterManager = grpcSource.HunterManager()

        // Hunter filter target (distributed)
        p.filterTarget = filtering.NewHunterTarget(p.hunterManager)
    }

    // Everything else stays the same:
    // - callAggregator
    // - perCallPcapWriter
    // - autoRotatePcapWriter
    // - statsCollector
    // - subscriberManager
    // - enricher
    // - vifManager

    return p, nil
}
```

### Packet Pipeline Changes

```go
// internal/pkg/processor/processor_packet_pipeline.go

// processBatch now takes source.PacketBatch instead of data.PacketBatch
func (p *Processor) processBatch(batch *source.PacketBatch) {
    sourceID := batch.SourceID

    // Update statistics
    if p.hunterManager != nil {
        // Distributed mode: update hunter stats
        p.hunterManager.UpdatePacketStats(sourceID, uint64(len(batch.Packets)), batch.TimestampNs)
    }
    // Standalone mode: stats handled by LocalSource

    // Rest of pipeline unchanged...
    // - PCAP writing
    // - Call aggregation
    // - Upstream forwarding
    // - Subscriber broadcast
    // - VIF injection
}
```

## Command Implementation

### Build Tags

```go
// cmd/tap/tap.go
//go:build tap || all

package tap

// cmd/tap/tap_voip.go
//go:build tap || all

package tap
```

### Command Structure

```go
// cmd/tap/tap.go

var tapCmd = &cobra.Command{
    Use:   "tap",
    Short: "Standalone capture with full processor capabilities",
    Long: `Tap mode combines local packet capture with all processor features:
- Per-call PCAP writing (VoIP)
- Auto-rotating PCAP writing (non-VoIP)
- Call aggregation and correlation
- Remote TUI monitoring
- Virtual interface injection
- (Future) X1/X2/X3 lawful interception interfaces

Unlike 'lc sniff', tap mode can be remotely administered and supports
all advanced features. Unlike 'lc hunt' + 'lc process', it runs as a
single process without gRPC overhead.`,
    RunE: runTap,
}

func init() {
    // Capture flags
    tapCmd.Flags().StringSliceP("interface", "i", nil, "Capture interface(s)")
    tapCmd.Flags().String("bpf", "", "BPF filter expression")
    tapCmd.Flags().Bool("promiscuous", true, "Promiscuous mode")
    tapCmd.Flags().Int("snaplen", 65535, "Snapshot length")

    // Management interface
    tapCmd.Flags().String("listen", ":55555", "Management/TUI listen address")
    tapCmd.Flags().Int("max-subscribers", 10, "Maximum TUI subscribers")

    // PCAP writing
    tapCmd.Flags().StringP("write", "w", "", "Write to unified PCAP file")
    tapCmd.Flags().Bool("per-call-pcap", false, "Enable per-call PCAP writing")
    tapCmd.Flags().String("per-call-pcap-dir", "", "Per-call PCAP output directory")
    tapCmd.Flags().String("per-call-pcap-pattern", "", "Per-call filename pattern")
    tapCmd.Flags().Bool("auto-rotate-pcap", false, "Enable auto-rotating PCAP")
    tapCmd.Flags().String("auto-rotate-pcap-dir", "", "Auto-rotate PCAP directory")

    // Protocol detection
    tapCmd.Flags().Bool("detect", true, "Enable protocol detection")

    // Virtual interface
    tapCmd.Flags().Bool("virtual-interface", false, "Enable virtual interface")
    tapCmd.Flags().String("vif-name", "lc0", "Virtual interface name")

    // TLS (for management interface)
    tapCmd.Flags().Bool("tls", false, "Enable TLS for management interface")
    tapCmd.Flags().String("tls-cert", "", "TLS certificate file")
    tapCmd.Flags().String("tls-key", "", "TLS key file")
    tapCmd.Flags().String("tls-ca", "", "TLS CA certificate file")

    // Command hooks
    tapCmd.Flags().String("pcap-command", "", "Command to run on PCAP file close")
    tapCmd.Flags().String("voip-command", "", "Command to run on call complete")

    // Future: X1/X2/X3 flags
    // tapCmd.Flags().Bool("x1-enabled", false, "Enable X1 interface")
    // tapCmd.Flags().String("x1-listen", ":8443", "X1 HTTPS listen address")
}

func runTap(cmd *cobra.Command, args []string) error {
    // Build processor config in standalone mode
    config := processor.Config{
        StandaloneMode:   true,
        CaptureInterface: viper.GetStringSlice("interface"),
        CaptureBPFFilter: viper.GetString("bpf"),
        CaptureSnapLen:   viper.GetInt("snaplen"),
        CapturePromisc:   viper.GetBool("promiscuous"),

        // Management interface (still uses gRPC for TUI)
        ListenAddr:     viper.GetString("listen"),
        MaxSubscribers: viper.GetInt("max-subscribers"),

        // All processor features available
        WriteFile:        viper.GetString("write"),
        EnableDetection:  viper.GetBool("detect"),
        VirtualInterface: viper.GetBool("virtual-interface"),
        // ... etc
    }

    // Create and start processor
    proc, err := processor.New(config)
    if err != nil {
        return err
    }

    return proc.Start(cmd.Context())
}
```

### VoIP Subcommand

```go
// cmd/tap/tap_voip.go

var tapVoipCmd = &cobra.Command{
    Use:   "voip",
    Short: "Tap mode optimized for VoIP traffic",
    Long:  `VoIP tap mode with SIP/RTP-specific features and filtering.`,
    RunE:  runTapVoip,
}

func init() {
    tapCmd.AddCommand(tapVoipCmd)

    // VoIP-specific flags
    tapVoipCmd.Flags().String("sipuser", "", "Filter by SIP user")
    tapVoipCmd.Flags().StringSlice("sip-port", []string{"5060"}, "SIP ports")
    tapVoipCmd.Flags().Bool("udp-only", false, "UDP-only mode (skip TCP)")
}
```

## Usage Examples

### Basic VoIP Tap

```bash
# Single interface, per-call PCAP
sudo lc tap voip -i eth0 \
    --per-call-pcap \
    --per-call-pcap-dir /var/capture/calls

# Monitor with TUI from remote machine
lc watch remote --addr tap-node:55555
```

### LIaaS Deployment

```bash
# CSP-A tap node with X1 enabled (future)
sudo lc tap voip -i eth0 \
    --per-call-pcap \
    --per-call-pcap-dir /var/li/csp-a/calls \
    --x1-enabled \
    --x1-listen :8443 \
    --x1-cert /etc/li/x1.crt \
    --x1-key /etc/li/x1.key \
    --tls \
    --tls-cert /etc/li/mgmt.crt \
    --tls-key /etc/li/mgmt.key
```

### Development/Testing

```bash
# Read from PCAP file (future: add file source)
lc tap -r capture.pcap --per-call-pcap --per-call-pcap-dir ./calls

# Virtual interface for Wireshark
sudo lc tap voip -i eth0 --virtual-interface --vif-name lc-tap0
```

## Implementation Roadmap

### Phase 1: Core Interfaces (Foundation)

- [ ] Define `PacketSource` interface in `internal/pkg/processor/source/`
- [ ] Define `FilterTarget` interface in `internal/pkg/processor/filtering/`
- [ ] Create interface documentation

### Phase 2: Refactor Processor

- [ ] Extract current gRPC handling to `GRPCSource`
- [ ] Extract current filter distribution to `HunterTarget`
- [ ] Modify `Processor.New()` to accept source/target
- [ ] Update `processBatch()` to use abstract batch type
- [ ] Ensure all tests pass

### Phase 3: Implement LocalSource

- [ ] Implement `LocalSource` wrapping `hunter/capture.Manager` (reuse, not reimplement)
- [ ] Wire up `hunter/forwarding.ConvertPacket()` for packet conversion
- [ ] Add batching logic (new, but simple)
- [ ] Expose `SetBPFFilter()` for FilterTarget integration
- [ ] Unit tests for LocalSource

### Phase 4: Implement LocalTarget + Application Filtering

- [ ] Implement `LocalTarget` for BPF-based filtering
- [ ] Add filter-to-BPF conversion (reuse `internal/pkg/filtering`)
- [ ] Add dynamic BPF recompilation
- [ ] Integrate `hunter.ApplicationFilter` for VoIP/protocol filters (reuse, not reimplement)
- [ ] Unit tests for LocalTarget

### Phase 5: Command Implementation

- [ ] Create `cmd/tap/` package
- [ ] Implement `tap` command
- [ ] Implement `tap voip` subcommand
- [ ] Add build tags
- [ ] Update Makefile for `tap` build variant
- [ ] Integration tests

### Phase 6: Documentation

- [ ] Update CLAUDE.md with tap command
- [ ] Create cmd/tap/README.md
- [ ] Create cmd/tap/CLAUDE.md
- [ ] Update architecture diagrams

## Comparison: tap vs sniff vs hunt+process

| Feature | `lc sniff` | `lc sniff voip` | `lc hunt` + `lc process` | `lc tap` |
|---------|-----------|-----------------|-------------------------|----------|
| Local capture | Yes | Yes | Yes (hunter) | Yes |
| Remote admin | No | No | Yes | Yes |
| Per-call PCAP | No | Yes | Yes | Yes |
| Auto-rotate PCAP | No | No | Yes | Yes |
| Call aggregation | No | No | Yes | Yes |
| Call correlation | No | No | Yes | Yes |
| TUI monitoring | CLI only | CLI only | Yes | Yes |
| Virtual interface | Yes | Yes | Yes | Yes |
| X1/X2/X3 (future) | No | No | Yes | Yes |
| Processes | 1 | 1 | 2+ | 1 |
| gRPC overhead | None | None | Yes | None |
| Distributed capture | No | No | Yes | No |
| Multi-interface | Yes | Yes | Yes (per hunter) | Yes |
| TCP SIP reassembly | No | Yes | Yes | Yes |

## Security Considerations

1. **Privilege Requirements**: Same as `lc sniff` - requires `CAP_NET_RAW` or root
2. **Management Interface**: TLS recommended for remote TUI access
3. **X1 Interface**: Mutual TLS required (same as processor mode)
4. **PCAP Files**: Same security as processor mode

## Testing Strategy

1. **Unit Tests**: PacketSource, FilterTarget interfaces
2. **Integration Tests**: End-to-end tap capture with PCAP verification
3. **Compatibility Tests**: Ensure `lc tap` produces identical output to `lc hunt` + `lc process` for same input
4. **Performance Tests**: Verify no regression vs distributed mode for single-node

## Out of Scope

1. **File Source (`-r` flag)**: Hunter nodes don't support this either. Use `lc sniff -r` for PCAP file analysis. Could be added later for testing purposes if needed.

## References

- [Processor architecture](../CLAUDE.md)
- [Hunter architecture](../../cmd/hunt/CLAUDE.md)
- [Capture package](../../internal/pkg/capture/)
- [ETSI X1/X2/X3 research](./etsi-x1-x2-x3-integration.md)

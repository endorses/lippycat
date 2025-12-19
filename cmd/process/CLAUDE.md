# Process Command - Architecture & Implementation

This document describes the architecture and implementation patterns for the `process` command (processor node) in the distributed capture system.

## Purpose

Processors are **central aggregation nodes** that:
1. Accept connections from multiple hunter nodes
2. Receive packet streams via gRPC
3. Perform centralized protocol detection
4. Distribute filters to hunters
5. Write packets to PCAP files (optional)
6. Provide monitoring APIs for TUI clients
7. Forward filtered traffic to upstream processors (hierarchical mode)

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│                      Processor Node                            │
├────────────────────────────────────────────────────────────────┤
│  cmd/process/                                                  │
│    └── process.go       - Processor command                    │
├────────────────────────────────────────────────────────────────┤
│  Uses internal/pkg/                                            │
│    ├── processor/       - Core processor logic                 │
│    │   ├── processor.go                - Core types & constructor │
│    │   ├── processor_lifecycle.go      - Server lifecycle     │
│    │   ├── processor_packet_pipeline.go - Packet processing   │
│    │   ├── processor_grpc_handlers.go  - gRPC services        │
│    │   ├── config.go                   - Configuration        │
│    │   ├── filters.go                  - Filter management    │
│    │   └── subscribers.go              - TUI subscriber mgmt  │
│    ├── detector/        - Protocol detection                   │
│    └── tlsutil/         - TLS configuration                    │
├────────────────────────────────────────────────────────────────┤
│  gRPC Protocol: api/proto/                                     │
│    ├── data.proto       - Packet streaming (hunter → proc)     │
│    ├── management.proto - Filter dist & heartbeat              │
│    └── monitoring.proto - TUI monitoring                       │
└────────────────────────────────────────────────────────────────┘
```

## Processor Package File Organization

The processor package has been refactored (v0.3.0+) from a single 1,921-line file into four focused files:

| File | Lines | Purpose | Key Contents |
|------|-------|---------|--------------|
| `processor.go` | ~270 | Core types & constructor | Config, Processor struct, New(), GetStats(), embedded gRPC interfaces |
| `processor_lifecycle.go` | ~250 | Server lifecycle | Start(), Shutdown(), TCP listener creation, gRPC server setup |
| `processor_packet_pipeline.go` | ~200 | Packet processing | processBatch(), PCAP coordination, call aggregation, protocol detection |
| `processor_grpc_handlers.go` | ~1,200 | gRPC service implementations | 21 gRPC methods (data service, management service), helper functions |

**Benefits:**
- **Easier navigation:** Methods grouped by purpose (lifecycle vs. processing vs. gRPC)
- **Faster file loading:** Average file size reduced from 1,921 to ~480 lines
- **Clearer separation:** Core types, lifecycle, processing pipeline, and API handlers in separate files
- **Maintained architecture:** No structural changes, all tests pass unchanged

**Design Principle:** File splitting only, no architectural changes. The Processor remains a single struct with all methods as receiver methods, preserving existing patterns and test compatibility.

## Build Tags

**Build Tag:** `processor` or `all`

```go
//go:build processor || all
```

The process command is only included in:
- `processor` builds (processor-only binary ~14MB)
- `all` builds (complete suite ~22MB)

NOT included in `hunter`, `cli`, or `tui` specialized builds.

## Command Structure

### Single Command: `process.go`

**File:** `cmd/process/process.go`

Unlike hunt/sniff, processor has no subcommands. Single command handles all functionality.

**Why no subcommands?**
- Processor role is well-defined
- Configuration handled via flags or config file
- Hierarchical mode enabled via `--upstream` flag (not a subcommand)

## Data Flow

### Packet Aggregation Flow

```
Hunter 1 ──┐
Hunter 2 ──┼──→ Processor ──→ PCAP Writer (optional)
Hunter 3 ──┘         │
                     ├──→ Protocol Detector
                     ├──→ TUI Subscribers (broadcast)
                     └──→ Upstream Processor (optional)
```

### Filter Distribution Flow

```
Filter File/API ──→ Processor ──→ Filter Update Stream ──→ All Hunters
                                                              ↓
                                                         Apply Filters
```

### Monitoring Flow

```
TUI Client 1 ──┐
TUI Client 2 ──┼──→ Processor ──→ Packet Broadcast ──→ Per-Client Channels
TUI Client 3 ──┘                  Hunter Status            ↓
                                                      Selective Drops
```

## Key Implementation Patterns

### 1. Multi-Tenant Server Pattern

**File:** `internal/pkg/processor/server.go`

Processor manages multiple concurrent connections:

```go
type Processor struct {
    hunters       map[string]*HunterConnection  // Connected hunters
    subscribers   map[string]*Subscriber        // TUI clients
    huntersMu     sync.RWMutex
    subscribersMu sync.RWMutex
}
```

**Thread Safety:** All connection maps protected by RW mutexes.

### 2. Packet Broadcasting Pattern

**File:** `internal/pkg/processor/subscribers.go`

Broadcast packets to all TUI subscribers without blocking:

```go
func (p *Processor) broadcastPackets(packets []types.PacketDisplay) {
    p.subscribersMu.RLock()
    defer p.subscribersMu.RUnlock()

    for _, sub := range p.subscribers {
        select {
        case sub.packetChan <- packets:
            // Sent successfully
        default:
            // Channel full, drop packet (don't block other subscribers)
            atomic.AddUint64(&sub.droppedPackets, 1)
        }
    }
}
```

**Key Decision:** Slow subscribers don't block hunters or other subscribers.

### 3. Filter Management Pattern

**File:** `internal/pkg/processor/filters.go`

Filters loaded from YAML file and distributed to hunters:

```yaml
filters:
  - id: "filter-001"
    type: "sipuser"
    pattern: "alicent@example.com"
    enabled: true
```

**Implementation:**

```go
// Load filters from file
filters, err := loadFilters(filterFile)

// Watch file for changes (optional)
watcher.Add(filterFile)

// On change: reload and redistribute
newFilters := loadFilters(filterFile)
p.broadcastFilterUpdate(newFilters)
```

**Pattern:** File-based with hot-reload (future: gRPC management API).

### 4. Per-Subscriber Buffering Pattern

**File:** `internal/pkg/processor/subscribers.go`

Each TUI subscriber has own buffered channel:

```go
type Subscriber struct {
    id           string
    packetChan   chan []types.PacketDisplay
    hunterFilter map[string]bool  // Selected hunters
    droppedPackets uint64
}

// Create with buffer
sub := &Subscriber{
    packetChan: make(chan []types.PacketDisplay, bufferSize),
}
```

**Buffer Size:** Configurable, default 100 batches.

**Benefit:** Absorbs temporary subscriber slowness without blocking.

### 5. Hunter Subscription Filtering Pattern

**File:** `internal/pkg/processor/subscribers.go`

TUI clients can subscribe to specific hunters:

```go
type SubscribeRequest struct {
    HunterIDs      []string
    HasHunterFilter bool  // Distinguish empty list from "all hunters"
}

// Before broadcasting
if sub.hasHunterFilter && !sub.hunterFilter[hunterID] {
    continue  // Skip this subscriber for this hunter's packets
}
```

**Proto3 Challenge:** Empty list vs. nil - solved with `has_hunter_filter` boolean.

### 6. Flow Control Pattern

**File:** `internal/pkg/processor/processor.go`

Processor determines flow control based on own state:

```go
func (p *Processor) determineFlowControl() FlowControl {
    // Check PCAP write queue utilization
    queueUtil := float64(len(pcapQueue)) / float64(cap(pcapQueue))

    if queueUtil > 0.90 {
        return PAUSE
    } else if queueUtil > 0.70 {
        return SLOW
    } else if queueUtil > 0.30 {
        return CONTINUE
    }
    return CONTINUE
}
```

**Critical:** TUI subscriber drops do NOT trigger flow control (see Architecture Patterns in main CLAUDE.md).

### 7. Hierarchical Processor Pattern

**File:** `internal/pkg/processor/processor.go`

Processor can act as hunter to upstream processor:

```go
if config.UpstreamAddr != "" {
    // Create hunter client to upstream
    upstreamHunter := hunter.New(hunter.Config{
        ProcessorAddr: config.UpstreamAddr,
        HunterID:      config.ProcessorID + "-upstream",
    })

    // Forward filtered packets to upstream
    p.upstreamHunter = upstreamHunter
}
```

**Use Case:** Regional aggregation before central.

### 8. Protocol Detection Pattern

**File:** `internal/pkg/detector/`

Centralized protocol detection on received packets:

```go
if p.config.EnableDetection {
    for _, packet := range packets {
        protocol := detector.Detect(packet.Data)
        packet.Metadata["protocol"] = protocol
    }
}
```

**Detectors:** HTTP, DNS, TLS, MySQL, PostgreSQL, SIP, VPN

**Why centralized?** Single detection point vs. detection at each hunter.

### 9. PCAP Writing Pattern

**File:** `internal/pkg/processor/processor.go`

Asynchronous PCAP writing with queue:

```go
pcapQueue := make(chan []types.PacketDisplay, queueSize)

// Writer goroutine
go func() {
    for packets := range pcapQueue {
        for _, pkt := range packets {
            pcapWriter.WritePacket(pkt.CaptureInfo, pkt.Data)
        }
    }
}()

// Main processing
select {
case pcapQueue <- packets:
    // Queued successfully
default:
    // Queue full - triggers flow control
}
```

**Non-blocking:** Main processing never blocks on I/O.

### 10. Per-Call PCAP Writing Pattern (VoIP)

**Files:** `internal/pkg/processor/pcap_writer.go`, `internal/pkg/processor/processor.go`

For VoIP traffic, processor can write separate SIP and RTP PCAP files per call:

**Architecture:**

```go
type CallPcapWriter struct {
    callID      string
    from        string
    to          string
    startTime   time.Time
    // SIP file
    sipFile        *os.File
    sipWriter      *pcapgo.Writer
    sipSize        int64
    sipFileIndex   int
    sipPacketCount int
    // RTP file
    rtpFile        *os.File
    rtpWriter      *pcapgo.Writer
    rtpSize        int64
    rtpFileIndex   int
    rtpPacketCount int
}
```

**Packet Routing Logic:**

```go
// In processor.go processBatch()
if p.perCallPcapWriter != nil {
    for _, packet := range batch.Packets {
        if packet.Metadata != nil && packet.Metadata.Sip != nil && packet.Metadata.Sip.CallId != "" {
            callID := packet.Metadata.Sip.CallId
            writer, _ := p.perCallPcapWriter.GetOrCreateWriter(callID, from, to)

            timestamp := time.Unix(0, packet.TimestampNs)

            // Route based on packet type
            if packet.Metadata.Rtp != nil {
                writer.WriteRTPPacket(timestamp, packet.Data)  // → RTP file
            } else {
                writer.WriteSIPPacket(timestamp, packet.Data)  // → SIP file
            }
        }
    }
}
```

**Key Features:**

1. **Separate Files:** Creates `{pattern}_sip.pcap` and `{pattern}_rtp.pcap` for each call
2. **Automatic Call Detection:** Uses `packet.Metadata.Sip.CallId` (hunter includes this for both SIP and RTP packets)
3. **File Rotation:** Each file rotates independently when reaching size limit (default: 100MB)
4. **Rotation Limit:** Maximum files per call per type (default: 10)
5. **Concurrent Writers:** Thread-safe management of multiple concurrent calls
6. **Async Syncing:** Periodic `fsync()` every 5 seconds
7. **Pattern Support:** Filename templates with `{callid}`, `{from}`, `{to}`, `{timestamp}` placeholders

**File Naming Example:**

```
20250123_143022_abc123_sip.pcap       # SIP signaling
20250123_143022_abc123_rtp.pcap       # RTP media
20250123_143022_abc123_sip_1.pcap     # After rotation
20250123_143022_abc123_rtp_1.pcap     # After rotation
```

**Configuration:**

```bash
# Enable per-call PCAP writing
lc process --per-call-pcap \
  --per-call-pcap-dir ./pcaps \
  --per-call-pcap-pattern "{timestamp}_{callid}.pcap"
```

```yaml
# In config file
processor:
  per_call_pcap:
    enabled: true
    output_dir: "./pcaps"
    file_pattern: "{timestamp}_{callid}.pcap"
```

**Why Separate Files?**

- **Analysis Tools:** Many VoIP analysis tools expect separate SIP/RTP files
- **Wireshark:** Better filtering and analysis with protocol-specific files
- **Call Recording:** Easy to extract just audio (RTP) or signaling (SIP)
- **Storage:** Can archive/compress SIP and RTP separately based on retention policies

**Critical Implementation Detail:**

Hunter nodes running in VoIP mode include call-id in `packet.Metadata.Sip.CallId` for BOTH SIP and RTP packets (see `internal/pkg/voip/udp_handler_hunter.go:243-253`), enabling the processor to correlate RTP packets to their calls without additional state tracking.

### 11. Auto-Rotating PCAP Writing Pattern (Non-VoIP)

**Files:** `internal/pkg/processor/auto_rotate_pcap.go`, `internal/pkg/processor/processor.go`

For non-VoIP traffic, processor can auto-rotate PCAP files based on activity:

**Architecture:**

```go
type AutoRotatePcapWriter struct {
    config         *AutoRotateConfig
    currentFile    *os.File
    currentWriter  *pcapgo.Writer
    lastPacketTime time.Time
    fileStartTime  time.Time
    currentSize    int64
    idleTimer      *time.Timer
}
```

**Rotation Logic:**

```go
// Rotation triggers (multiple conditions)
func (w *AutoRotatePcapWriter) shouldRotate() bool {
    // 1. File too large
    if w.currentSize >= w.config.MaxFileSize {
        return true
    }

    // 2. File too old
    if time.Since(w.fileStartTime) >= w.config.MaxDuration {
        return true
    }

    // 3. Idle timeout (handled by timer)
    return false
}

// Idle timer with minimum duration protection
func (w *AutoRotatePcapWriter) resetIdleTimer() {
    w.idleTimer = time.AfterFunc(w.config.MaxIdleTime, func() {
        // Only close if minimum duration elapsed
        if time.Since(w.fileStartTime) >= w.config.MinDuration {
            w.closeCurrentFile()
        }
    })
}
```

**Packet Routing:**

```go
// In processor.go processBatch()
if p.autoRotatePcapWriter != nil {
    for _, packet := range batch.Packets {
        // Skip VoIP packets (handled by per-call writer)
        isVoIP := packet.Metadata != nil && (packet.Metadata.Sip != nil || packet.Metadata.Rtp != nil)
        if isVoIP {
            continue
        }

        // Write non-VoIP packet
        timestamp := time.Unix(0, packet.TimestampNs)
        p.autoRotatePcapWriter.WritePacket(timestamp, packet.Data)
    }
}
```

**Key Features:**

1. **Auto-rotation on idle:** Closes file after N seconds without packets
2. **Size-based rotation:** Rotates when file reaches size limit
3. **Duration-based rotation:** Rotates after maximum duration (1 hour)
4. **Minimum duration:** Prevents tiny files from rapid start/stop traffic
5. **Async syncing:** Periodic fsync() every 5 seconds
6. **Independent of VoIP:** VoIP packets bypass auto-rotate writer

**File Naming:**

```
20250123_143022.pcap       # First burst
20250123_144530.pcap       # Next burst after idle period
```

**Configuration:**

```bash
lc process --auto-rotate-pcap \
  --auto-rotate-pcap-dir ./bursts \
  --auto-rotate-idle-timeout 30s \
  --auto-rotate-max-size 100M
```

**Default Values:**

- `MaxIdleTime`: 30 seconds
- `MaxFileSize`: 100MB
- `MaxDuration`: 1 hour
- `MinDuration`: 10 seconds
- `SyncInterval`: 5 seconds

### 12. Resilience Patterns (Network Interruption Survival)

**File:** `internal/pkg/processor/processor.go`

#### Lenient Keepalive Settings

To survive network interruptions like laptop standby:

```go
grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
    MinTime:             10 * time.Second, // Minimum time between client pings
    PermitWithoutStream: true,             // Allow pings without active streams
}),
grpc.KeepaliveParams(keepalive.ServerParameters{
    Time:    30 * time.Second, // Send ping if no activity for 30s
    Timeout: 20 * time.Second, // Wait 20s for ping ack before closing connection
}),
```

**Changed from:** 20s/3s → 30s/20s (more tolerant of delays)

**Rationale:** Survive temporary network disruptions without closing connections.

#### Stale Hunter Cleanup

**File:** `internal/pkg/processor/hunter/monitor.go`

Faster cleanup check with generous grace period:

```go
// Cleanup interval: check every 2 minutes (faster recovery)
ticker := time.NewTicker(2 * time.Minute)

// Grace period: 5 minutes since last heartbeat
const graceperiod = 5 * time.Minute
```

**Changed from:** 5min cleanup interval → 2min interval

**Benefit:** Faster detection and cleanup of truly dead hunters while maintaining 5min grace period for temporary disruptions.

### 13. Command Hooks Pattern

**Files:** `internal/pkg/processor/command_executor.go`, `internal/pkg/processor/call_completion_monitor.go`

Execute custom commands when PCAP files are written or VoIP calls complete:

**Architecture:**

```go
// CommandExecutor handles async command execution with placeholders
type CommandExecutor struct {
    config *CommandExecutorConfig
    sem    chan struct{} // Concurrency limiter
}

type CommandExecutorConfig struct {
    PcapCommand string        // Template: "gzip %pcap%"
    VoipCommand string        // Template: "notify.sh %callid% %dirname%"
    Timeout     time.Duration // Default: 30s
    Concurrency int           // Default: 10
}
```

**Callback Integration:**

```go
// PCAP writers call OnFileClose callback when files are closed
type CallPcapWriterConfig struct {
    OnFileClose    func(filePath string)     // Fires on every file close
    OnCallComplete func(meta CallMetadata)   // Fires when call ends
}

// CommandExecutor provides callback functions
executor := NewCommandExecutor(config)
pcapConfig.OnFileClose = executor.OnFileClose()
pcapConfig.OnCallComplete = executor.OnCallComplete()
```

**Call Completion Flow:**

```
BYE/CANCEL received
       ↓
CallAggregator.State = CallStateEnded
       ↓
CallCompletionMonitor detects ended call
       ↓
Grace period (5s) to capture late packets
       ↓
PcapWriterManager.CloseCallWriter(callID)
       ↓
OnFileClose(sipFile) + OnFileClose(rtpFile)
       ↓
OnCallComplete(CallMetadata)
       ↓
CommandExecutor.ExecuteVoipCommand(meta)
       ↓
Async shell execution with timeout
```

**Key Features:**

1. **Async Execution:** Commands run in goroutines, never block packet processing
2. **Concurrency Control:** Semaphore limits concurrent executions (default: 10)
3. **Timeout Protection:** Commands killed after timeout (default: 30s)
4. **Placeholder Substitution:** `%pcap%`, `%callid%`, `%dirname%`, `%caller%`, `%called%`, `%calldate%`
5. **Grace Period:** Waits 5s after BYE/CANCEL before closing files

**CLI Flags:**

```bash
--pcap-command 'gzip %pcap%'                    # Execute on file close
--voip-command 'notify.sh %callid% %dirname%'   # Execute on call complete
--command-timeout 30s                            # Execution timeout
--command-concurrency 10                         # Max concurrent commands
```

**Viper Configuration:**

```yaml
processor:
  pcap_command: "gzip %pcap%"
  voip_command: "notify.sh %callid% %dirname%"
  command_timeout: "30s"
  command_concurrency: 10
```

## gRPC Server Implementation

### Packet Reception Service

**Protocol:** `api/proto/data.proto`

```protobuf
service DataService {
    rpc StreamPackets(stream PacketBatch) returns (stream Ack);
}
```

**Implementation:**

```go
func (s *Server) StreamPackets(stream pb.DataService_StreamPacketsServer) error {
    for {
        batch, err := stream.Recv()
        if err != nil {
            return err
        }

        // Process packets
        s.processor.OnPacketBatch(batch)

        // Send acknowledgment
        stream.Send(&pb.Ack{
            SequenceNumber: batch.SequenceNumber,
            FlowControl:    s.processor.GetFlowControl(),
        })
    }
}
```

**Pattern:** Bidirectional streaming with flow control in acks.

### Filter Distribution Service

**Protocol:** `api/proto/management.proto`

```protobuf
service ManagementService {
    rpc SubscribeFilters(FilterSubscription) returns (stream FilterUpdate);
}
```

**Implementation:**

```go
func (s *Server) SubscribeFilters(req *pb.FilterSubscription, stream pb.ManagementService_SubscribeFiltersServer) error {
    // Send initial filters
    stream.Send(getCurrentFilters())

    // Stream updates
    for update := range s.filterUpdateChan {
        stream.Send(update)
    }
}
```

**Pattern:** Long-lived server-side stream.

### Monitoring Service

**Protocol:** `api/proto/monitoring.proto`

```protobuf
service MonitoringService {
    rpc SubscribePackets(SubscribeRequest) returns (stream PacketBatch);
    rpc GetHunterStatus(Empty) returns (stream HunterStatus);
}
```

Used by TUI clients for real-time monitoring.

## Security Patterns

### Production Mode Enforcement

**File:** `cmd/process/process.go:100-110`

```go
productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
if productionMode {
    if !tlsEnabled {
        return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
    }
    if !tlsClientAuth {
        return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires mutual TLS (--tls-client-auth)")
    }
}
```

**Enforcement:** Production requires BOTH TLS AND client cert authentication.

### TLS Server Configuration

**File:** `internal/pkg/processor/server.go`

```go
if config.TLSEnabled {
    creds, err := credentials.NewServerTLSFromFile(
        config.TLSCertFile,
        config.TLSKeyFile,
    )

    opts = append(opts, grpc.Creds(creds))

    if config.TLSClientAuth {
        // Mutual TLS - require client certificates
        tlsConfig := &tls.Config{
            ClientAuth: tls.RequireAndVerifyClientCert,
            ClientCAs:  loadCAPool(config.TLSCAFile),
        }
    }
}
```

## Configuration Patterns

### Viper Integration

All flags bound to Viper:

```yaml
processor:
  listen_addr: "0.0.0.0:50051"
  processor_id: "central-proc"
  upstream_addr: ""
  max_hunters: 100
  max_subscribers: 100
  write_file: "/var/capture/packets.pcap"
  enable_detection: true
  filter_file: "~/.config/lippycat/filters.yaml"
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/server.crt"
    key_file: "/etc/lippycat/certs/server.key"
    ca_file: "/etc/lippycat/certs/ca.crt"
    client_auth: true
```

### Helper Functions Pattern

Same pattern as hunter:

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

**Per-Hunter Memory:**
- Packet receive buffer: ~5-10MB
- Total with 100 hunters: ~500MB-1GB

**Per-Subscriber Memory:**
- Packet broadcast channel: ~2-5MB
- Total with 100 subscribers: ~200MB-500MB

**PCAP Writer Queue:** ~10-50MB depending on queue size

**Total:** ~1-2GB for 100 hunters + 100 subscribers

### CPU Optimization

**Packet Processing Pipeline:**
1. gRPC receive (async, goroutine per hunter)
2. Protocol detection (parallel, optional)
3. Broadcast to subscribers (non-blocking)
4. PCAP writing (async queue)
5. Upstream forwarding (async, optional)

**Bottleneck:** Usually gRPC overhead or PCAP I/O, not CPU.

### I/O Optimization

**PCAP Writing:**
- Buffered I/O
- Async queue prevents blocking
- SSD recommended for high packet rates

## Error Handling Patterns

### Hunter Disconnection

```go
func (p *Processor) OnHunterDisconnect(hunterID string) {
    p.huntersMu.Lock()
    delete(p.hunters, hunterID)
    p.huntersMu.Unlock()

    logger.Info("Hunter disconnected", "hunter_id", hunterID)
    p.notifySubscribers(HunterDisconnectedEvent{HunterID: hunterID})
}
```

**Graceful:** Remove from map, notify subscribers, continue operation.

### Subscriber Disconnection

```go
func (p *Processor) OnSubscriberDisconnect(subscriberID string) {
    p.subscribersMu.Lock()
    if sub, exists := p.subscribers[subscriberID]; exists {
        close(sub.packetChan)
        delete(p.subscribers, subscriberID)
    }
    p.subscribersMu.Unlock()
}
```

**Cleanup:** Close channel, remove from map.

## Testing Considerations

### Unit Testing

Mock hunter connections:

```go
type mockHunter struct {
    packets chan *pb.PacketBatch
}

func (m *mockHunter) Send(batch *pb.PacketBatch) {
    m.packets <- batch
}
```

### Integration Testing

**File:** `test/tls_integration_test.go`

Tests full hunter-processor flow with TLS.

## Common Development Tasks

### Adding a New Detection Protocol

1. Implement detector in `internal/pkg/detector/`:
```go
func DetectNewProtocol(data []byte) bool {
    // Signature matching
}
```

2. Register in `internal/pkg/detector/detector.go`:
```go
case DetectNewProtocol(data):
    return "newprotocol"
```

### Adding a Filter Type

See hunter/CLAUDE.md - filters defined in proto shared by both.

### Modifying Broadcast Logic

Edit `internal/pkg/processor/subscribers.go` broadcast functions.

## Dependencies

**External:**
- `google.golang.org/grpc` - gRPC server
- `github.com/spf13/cobra` - CLI framework

**Internal:**
- `internal/pkg/processor` - Core processor logic
- `internal/pkg/detector` - Protocol detection
- `internal/pkg/tlsutil` - TLS utilities
- `api/gen/go` - Generated gRPC stubs

## Virtual Interface Integration

**Status:** Production-ready (v0.2.10+)

The processor supports virtual interface creation for exposing aggregated packet streams from multiple hunters to third-party tools.

### Overview

When `--virtual-interface` is enabled, the processor creates a TAP/TUN interface (default: `lc0`) and injects packets received from all connected hunters.

**Use Case:** Centralized monitoring of distributed capture with tools like Wireshark or Snort.

### Integration Pattern

**Location:** `cmd/process/process.go`

```go
// Initialize virtual interface manager
if viper.GetBool("virtual_interface.enabled") {
    vifMgr, err := vinterface.NewManager(vinterface.Config{
        Name:       viper.GetString("virtual_interface.name"),
        Type:       vinterface.InterfaceType(viper.GetString("virtual_interface.type")),
        BufferSize: viper.GetInt("virtual_interface.buffer_size"),
    })
    if err != nil {
        logger.Error("Failed to create virtual interface", "error", err)
    } else {
        defer vifMgr.Shutdown()
        if err := vifMgr.Start(); err != nil {
            logger.Error("Failed to start virtual interface", "error", err)
        }

        // Inject packets in processBatch() pipeline
        if err := vifMgr.InjectPacketBatch(batch); err != nil {
            logger.Debug("Virtual interface injection failed", "error", err)
        }
    }
}
```

### Injection Point

Packets are injected in `processBatch()` (`internal/pkg/processor/processor.go`) after:
1. Receiving from hunter
2. Protocol detection (if enabled)
3. Filter application

**Parallel outputs:**
- Virtual interface injection
- PCAP file writing
- TUI subscriber broadcast
- Upstream forwarding (hierarchical mode)

### CLI Flags

```bash
--virtual-interface              # Enable virtual interface
--vif-name lc0                   # Interface name
--vif-type tap                   # Interface type: tap or tun
--vif-buffer-size 4096           # Injection queue size
```

### Configuration Support

```yaml
virtual_interface:
  enabled: true
  name: lc0
  type: tap
  buffer_size: 4096
```

### Error Handling

- **Permission denied:** Logged, continues without virtual interface
- **Injection failures:** Non-blocking (other outputs continue)
- **Hunter disconnects:** Virtual interface remains active, continues injecting from remaining hunters

**See:** [internal/pkg/vinterface/CLAUDE.md](../../internal/pkg/vinterface/CLAUDE.md) for implementation details

## Related Documentation

- [README.md](README.md) - User-facing command documentation
- [../hunt/CLAUDE.md](../hunt/CLAUDE.md) - Hunter architecture
- [../tui/CLAUDE.md](../tui/CLAUDE.md) - TUI client architecture
- [../../docs/DISTRIBUTED_MODE.md](../../docs/DISTRIBUTED_MODE.md) - Distributed system overview
- [../../docs/VIRTUAL_INTERFACE.md](../../docs/VIRTUAL_INTERFACE.md) - Virtual interface guide
- [../../internal/pkg/vinterface/CLAUDE.md](../../internal/pkg/vinterface/CLAUDE.md) - Virtual interface architecture

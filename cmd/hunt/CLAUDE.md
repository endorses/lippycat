# Hunt Command - Architecture & Implementation

This document describes the architecture and implementation patterns for the `hunt` command (hunter node) in the distributed capture system.

## Purpose

Hunters are **edge capture agents** that:
1. Capture packets from network interfaces
2. Apply local filtering (BPF, VoIP call matching)
3. Batch packets for efficiency
4. Forward to processor nodes via gRPC
5. Respond to flow control signals

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                      Hunter Node                             │
├──────────────────────────────────────────────────────────────┤
│  cmd/hunt/                                                   │
│    ├── hunt.go          - Base hunter command                │
│    └── voip.go          - VoIP hunter with call buffering    │
├──────────────────────────────────────────────────────────────┤
│  Uses internal/pkg/                                          │
│    ├── hunter/          - Core hunter logic                  │
│    │   ├── hunter.go    - Main hunter implementation         │
│    │   ├── config.go    - Configuration                      │
│    │   └── client.go    - gRPC client                        │
│    ├── capture/         - Packet capture                     │
│    ├── voip/            - VoIP filtering & buffering         │
│    │   ├── buffer_manager.go  - Call buffering               │
│    │   └── filter_matcher.go  - Filter matching              │
│    └── tlsutil/         - TLS configuration                  │
├──────────────────────────────────────────────────────────────┤
│  gRPC Protocol: api/proto/                                   │
│    ├── data.proto       - Packet streaming                   │
│    └── management.proto - Filter distribution & heartbeat    │
└──────────────────────────────────────────────────────────────┘
```

## Build Tags

**Build Tag:** `hunter` or `all`

```go
//go:build hunter || all
```

The hunt command is only included in:
- `hunter` builds (hunter-only binary ~18MB)
- `all` builds (complete suite ~22MB)

NOT included in `processor`, `cli`, or `tui` specialized builds.

## Command Structure

### Base Command: `hunt.go`

**File:** `cmd/hunt/hunt.go`

General-purpose hunter that forwards ALL captured packets (or BPF-filtered packets) to processor.

**Persistent Flags Pattern:**

```go
HuntCmd.PersistentFlags().StringVar(&processorAddr, "processor", "", "Processor address (host:port)")
_ = HuntCmd.MarkPersistentFlagRequired("processor")
```

**Why persistent?** The `voip` subcommand inherits these flags, avoiding duplication.

### VoIP Subcommand: `voip.go`

**File:** `cmd/hunt/voip.go`

VoIP hunter with intelligent call buffering and selective forwarding.

**Architecture Difference from Base:**

| Aspect | Base Hunter | VoIP Hunter |
|--------|-------------|-------------|
| Forwarding | All packets | Only matched calls |
| Buffering | No buffering | Per-call buffering |
| Filtering | BPF only | BPF + SIP user filters |
| Bandwidth | Full traffic | 90%+ reduction |
| Use Case | General monitoring | Targeted VoIP capture |

## Data Flow

### Base Hunter Flow

```
Network Interface → gopacket → Batching → gRPC Stream → Processor
                                  ↑
                          Flow Control ← Processor
```

### VoIP Hunter Flow

```
Network Interface → gopacket → Protocol Detection
                                      ↓
                              ┌───────┴────────┐
                              │                │
                         UDP Packets      TCP Packets
                              │                │
                         SIP Extraction   TCP Reassembly
                         RTP Detection    SIP Extraction
                              │                │
                              └────────┬───────┘
                                       ↓
                              BufferManager
                              (per-call buffers)
                                       ↓
                         Filter Subscription ← Processor
                              (SIP user filters)
                                       ↓
                              Filter Matching
                                       ↓
                                   Matched? → Yes → Forward to Processor
                                       ↓ No
                                     Drop
```

## Key Implementation Patterns

### 1. Hunter Lifecycle Pattern

**File:** `internal/pkg/hunter/hunter.go`

```go
// Create hunter
h, err := hunter.New(config)

// Start (blocking)
err = h.Start(ctx)

// Graceful shutdown via context
cancel()  // Triggers shutdown
```

**Lifecycle:**
1. **Init** - Create gRPC connection, setup capture
2. **Connect** - Establish stream to processor
3. **Capture** - Start packet capture loop
4. **Stream** - Forward packets in batches
5. **Heartbeat** - Send periodic health status
6. **Shutdown** - Graceful cleanup on context cancel

### 2. VoIP Buffering Pattern

**File:** `internal/pkg/voip/buffer_manager.go`

**Problem:** SIP calls take time to identify (need to parse SIP headers), but we must capture all packets (including RTP) from call start.

**Solution:** Buffer packets per-call until filter decision is made.

```go
bufferMgr := voip.NewBufferManager(maxAge, maxSize)

// Buffer packet with call-ID
bufferMgr.AddPacket(callID, packetData)

// On filter match: flush buffered packets
packets := bufferMgr.GetAndClearBuffer(callID)
// Forward all packets to processor

// On filter no-match: discard buffer
bufferMgr.ClearBuffer(callID)
```

**Memory Safety:**
- `maxAge`: Automatic expiration (default: 5s)
- `maxSize`: Per-buffer packet limit (default: 200 packets)
- Prevents unbounded growth

### 3. Filter Subscription Pattern

**File:** `internal/pkg/hunter/client.go`

Hunters subscribe to filter updates from processor:

```go
// Processor sends filter updates
filterUpdate := &pb.FilterUpdate{
    Filters: []*pb.Filter{
        {Type: "sipuser", Pattern: "alicent@example.com"},
    },
}

// Hunter receives and applies
h.onFilterUpdate(filterUpdate)
```

**Filter Types:**
- `sipuser` - Match SIP From/To/P-Asserted-Identity headers
- `callid` - Match SIP Call-ID
- `ip` - Match IP address or CIDR

**Pattern:** Push-based (processor pushes to hunters) vs. pull-based (hunters poll).

### 4. Batch Processing Pattern

**File:** `internal/pkg/hunter/hunter.go`

Packets are batched before sending to reduce gRPC overhead:

```go
type Batcher struct {
    packets  []*pb.Packet
    maxSize  int           // --batch-size flag
    timeout  time.Duration // --batch-timeout flag
}

// Accumulate packets
batcher.Add(packet)

// Send when batch full OR timeout expires
if len(batcher.packets) >= maxSize || time.Since(lastSend) > timeout {
    stream.Send(&pb.PacketBatch{Packets: batcher.packets})
}
```

**Tuning:**
- Small batch + short timeout = Low latency
- Large batch + long timeout = High throughput

### 5. Flow Control Pattern

**File:** `internal/pkg/hunter/hunter.go`

Processor sends flow control signals via heartbeat responses:

```go
type FlowControl int
const (
    CONTINUE FlowControl = 0  // Normal operation
    SLOW     FlowControl = 1  // Reduce rate
    PAUSE    FlowControl = 2  // Stop sending
    RESUME   FlowControl = 3  // Resume after pause
)
```

**Hunter Response:**
```go
switch flowControl {
case PAUSE:
    // Stop forwarding, buffer locally
case SLOW:
    // Increase batch timeout
case RESUME:
    // Resume normal operation
}
```

### 6. Resilience Patterns (Nuclear-Proof)

#### Disk Overflow Buffer

**Files:** `internal/pkg/hunter/buffer/disk_buffer.go`, `internal/pkg/hunter/forwarding/manager.go`

**Problem:** Memory queue (1000 batches ≈ 64K packets) fills during extended disconnections.

**Solution:** Overflow to disk when memory queue is full:

```go
// In forwarding/manager.go SendBatch()
select {
case m.batchQueue <- batch:
    // Successfully queued to memory
default:
    // Memory queue full - try disk overflow buffer
    if m.diskBuffer != nil {
        m.diskBuffer.Write(batch)
    }
}
```

**Background Refill:** Disk batches automatically refill memory queue when space available (100ms polling).

**Layout:** One protobuf batch per file, FIFO ordering, automatic cleanup.

#### Circuit Breaker Pattern

**File:** `internal/pkg/hunter/circuitbreaker/breaker.go`

**Problem:** Repeated connection attempts to dead processor exhaust resources.

**Solution:** Three-state circuit breaker wraps connection logic:

```go
// States: Closed (normal) → Open (failing) → Half-Open (testing) → Closed
err := circuitBreaker.Call(func() error {
    return connectAndRegister()
})
```

**Behavior:**
- **Closed:** Normal operation, all calls allowed
- **Open:** After 5 failures, reject calls for 30s (prevents thrashing)
- **Half-Open:** Allow 3 test calls, return to Closed on success or Open on failure

**Integration:** `internal/pkg/hunter/connection/manager.go` wraps `connectAndRegister()` call.

### 7. Security Patterns

#### Production Mode Enforcement

**File:** `cmd/hunt/hunt.go:114-120`

```go
productionMode := os.Getenv("LIPPYCAT_PRODUCTION") == "true"
if productionMode {
    if !tlsEnabled && !viper.GetBool("hunter.tls.enabled") {
        return fmt.Errorf("LIPPYCAT_PRODUCTION=true requires TLS (--tls)")
    }
}
```

**Why?** Prevents accidental unencrypted deployments in production.

#### TLS Secure-by-Default

**File:** `cmd/hunt/hunt.go:144-150`

```go
if !config.TLSEnabled && !getBoolConfig("insecure", insecureAllowed) {
    return fmt.Errorf("TLS is disabled but --insecure flag not set...")
}
```

**Pattern:** Require explicit `--insecure` flag to allow non-TLS connections.

#### Security Banner Pattern

Display prominent warnings when TLS is disabled:

```go
if !config.TLSEnabled {
    logger.Warn("═══════════════════════════════════════")
    logger.Warn("  SECURITY WARNING: TLS ENCRYPTION DISABLED")
    logger.Warn("  Packet data will be transmitted in CLEARTEXT")
    logger.Warn("═══════════════════════════════════════")
}
```

## gRPC Integration

### Packet Streaming

**Protocol:** `api/proto/data.proto`

```protobuf
service DataService {
    rpc StreamPackets(stream PacketBatch) returns (stream Ack);
}

message PacketBatch {
    string hunter_id = 1;
    repeated Packet packets = 2;
}
```

**Client-side streaming:** Hunter streams batches, processor acknowledges.

### Filter Distribution

**Protocol:** `api/proto/management.proto`

```protobuf
service ManagementService {
    rpc SubscribeFilters(FilterSubscription) returns (stream FilterUpdate);
}
```

**Server-side streaming:** Processor streams filter updates to hunter.

### Heartbeat Monitoring

**Protocol:** `api/proto/management.proto`

```protobuf
service ManagementService {
    rpc Heartbeat(stream HeartbeatRequest) returns (stream HeartbeatResponse);
}
```

**Bidirectional streaming:**
- Hunter → Processor: Health status, packet counts
- Processor → Hunter: Flow control signals

## Configuration Patterns

### Flag Inheritance

Base hunter flags are persistent, inherited by subcommands:

```go
// In hunt.go
HuntCmd.PersistentFlags().StringVar(&processorAddr, ...)

// In voip.go - voipHuntCmd automatically has processorAddr flag
```

### Viper Integration

Config file support for all flags:

```yaml
hunter:
  processor_addr: "processor.example.com:50051"
  hunter_id: "edge-01"
  interfaces: ["eth0"]
  batch_size: 64
  batch_timeout_ms: 100
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/hunter.crt"
```

### Helper Functions Pattern

**File:** `cmd/hunt/hunt.go:203-241`

```go
func getStringConfig(key, flagValue string) string {
    if flagValue != "" {
        return flagValue
    }
    return viper.GetString(key)
}
```

**Priority:** Flag > Config file > Default

## VoIP Hunter Specific Patterns

### Packet Processor Pattern

**File:** `cmd/hunt/voip.go:176`

```go
processor := voip.NewVoIPPacketProcessor(h, bufferMgr)
h.SetPacketProcessor(processor)
```

**Hook Pattern:** Hunter calls processor for each packet, processor decides to buffer/forward/drop.

### TCP Reassembly Integration

**File:** `cmd/hunt/voip.go:168-172`

```go
tcpHandler := voip.NewHunterForwardHandler(h, bufferMgr)
_ = voip.NewSipStreamFactory(ctx, tcpHandler)
```

**Pattern:** Factory creates stream handlers, handlers forward to hunter's packet processor.

## Performance Considerations

### Memory Management

**Per-Hunter Memory:**
- Packet capture buffer: `--buffer-size` packets (~10MB default)
- Batch queue: `--batch-queue-size` batches (~1-5MB)
- VoIP call buffers: `maxSize * numCalls` packets (~20-100MB with 100 calls)

**Total:** ~30-115MB depending on configuration and call volume.

### CPU Optimization

**Packet Processing Pipeline:**
1. Kernel → gopacket (zero-copy where possible)
2. BPF filter (kernel space)
3. VoIP detection (user space, GPU-accelerated optional)
4. Batching (minimal CPU)
5. Protobuf encoding (optimized)
6. gRPC streaming (async)

**Bottleneck:** Usually VoIP SIP parsing, hence GPU acceleration option.

### Network Optimization

**Batch Size Impact:**
- Larger batches: Lower network overhead, higher latency
- Smaller batches: Lower latency, higher network overhead

**Compression:** gRPC uses HTTP/2 with header compression automatically.

## Error Handling Patterns

### Reconnection Pattern

**File:** `internal/pkg/hunter/client.go`

```go
for {
    err := h.connectAndStream(ctx)
    if ctx.Err() != nil {
        return // Shutdown
    }

    logger.Warn("Connection lost, reconnecting...", "error", err)
    time.Sleep(reconnectDelay)
}
```

**Fast reconnection:** <100ms delay, exponential backoff optional.

### Graceful Shutdown

```go
cleanup := signals.SetupHandler(ctx, cancel)
defer cleanup()

<-ctx.Done()
logger.Info("Shutdown signal received, stopping hunter...")
```

**Pattern:** Context cancellation triggers cleanup in reverse init order.

## Testing Considerations

### Unit Testing

Mock gRPC server for testing hunter logic:

```go
server := grpc.NewServer()
pb.RegisterDataServiceServer(server, &mockProcessor{})
```

### Integration Testing

**File:** `test/tls_integration_test.go`

Tests full hunter-processor flow with TLS.

## Common Development Tasks

### Adding a New Filter Type

1. Update `api/proto/management.proto`:
```protobuf
message Filter {
    string type = 1;  // Add new type here
}
```

2. Implement in `internal/pkg/voip/filter_matcher.go`:
```go
case "newtype":
    return matchNewType(packet, pattern)
```

3. Regenerate proto:
```bash
make proto
```

### Modifying Batch Behavior

Edit `internal/pkg/hunter/hunter.go` batch logic.

## Dependencies

**External:**
- `google.golang.org/grpc` - gRPC client
- `github.com/google/gopacket` - Packet capture
- `github.com/spf13/cobra` - CLI framework

**Internal:**
- `internal/pkg/hunter` - Core hunter logic
- `internal/pkg/capture` - Capture abstraction
- `internal/pkg/voip` - VoIP filtering & buffering
- `api/gen/go` - Generated gRPC stubs

## Related Documentation

- [README.md](README.md) - User-facing command documentation
- [../process/CLAUDE.md](../process/CLAUDE.md) - Processor architecture
- [../../docs/DISTRIBUTED_MODE.md](../../docs/DISTRIBUTED_MODE.md) - Distributed system overview

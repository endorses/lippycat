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
│    │   ├── processor.go - Main aggregation logic               │
│    │   ├── config.go    - Configuration                        │
│    │   ├── server.go    - gRPC server                          │
│    │   ├── filters.go   - Filter management                    │
│    │   └── subscribers.go - TUI subscriber management          │
│    ├── detector/        - Protocol detection                   │
│    └── tlsutil/         - TLS configuration                    │
├────────────────────────────────────────────────────────────────┤
│  gRPC Protocol: api/proto/                                     │
│    ├── data.proto       - Packet streaming (hunter → proc)     │
│    ├── management.proto - Filter dist & heartbeat              │
│    └── monitoring.proto - TUI monitoring                       │
└────────────────────────────────────────────────────────────────┘
```

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
    pattern: "alice@example.com"
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

### 10. Resilience Patterns (Network Interruption Survival)

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

## Related Documentation

- [README.md](README.md) - User-facing command documentation
- [../hunt/CLAUDE.md](../hunt/CLAUDE.md) - Hunter architecture
- [../tui/CLAUDE.md](../tui/CLAUDE.md) - TUI client architecture
- [../../docs/DISTRIBUTED_MODE.md](../../docs/DISTRIBUTED_MODE.md) - Distributed system overview

# LI Package - Architecture & Implementation

This document describes the architecture and implementation patterns for the lawful interception (LI) package.

## Purpose

The `internal/pkg/li` package implements ETSI X1/X2/X3 interfaces for lawful interception:
- **X1**: Administration interface (XML/HTTPS) for task and destination management
- **X2**: IRI (Intercept Related Information) delivery - signaling metadata
- **X3**: CC (Content of Communication) delivery - media content

## Package Structure

```
internal/pkg/li/
├── CLAUDE.md              # This file
├── types.go               # Core domain types (no build tag - shared)
├── registry.go            # Task and destination storage
├── registry_test.go       # Registry unit tests
├── filters.go             # XID ↔ filter mapping
├── filters_test.go        # Filter mapping tests
├── manager.go             # Main coordinator (build tag: li)
├── manager_stub.go        # No-op stub (build tag: !li)
├── manager_test.go        # Manager unit tests
├── manager_bench_test.go  # Performance benchmarks
├── integration_test.go    # End-to-end integration tests
├── security_test.go       # Security-focused tests
│
├── x1/                    # X1 Administration Interface
│   ├── server.go          # HTTPS server for ADMF requests
│   ├── server_test.go     # Server unit tests
│   ├── client.go          # HTTPS client for ADMF notifications
│   ├── client_test.go     # Client unit tests
│   └── schema/            # Generated XSD types
│       ├── doc.go         # Package documentation
│       ├── x1.go          # ETSI TS 103 221-1 types
│       ├── common.go      # ETSI TS 103 280 common types
│       └── hashedid.go    # Hashed identifier types
│
├── x2x3/                  # X2/X3 Binary TLV Protocol
│   ├── pdu.go             # PDU header and TLV encoding
│   ├── pdu_test.go        # PDU encoding tests
│   ├── attributes.go      # Common TLV attributes
│   ├── attributes_test.go # Attribute tests
│   ├── x2_encoder.go      # SIP → IRI encoding
│   ├── x2_encoder_test.go # X2 encoder tests
│   ├── x2_encoder_bench_test.go  # X2 performance
│   ├── x3_encoder.go      # RTP → CC encoding
│   ├── x3_encoder_test.go # X3 encoder tests
│   └── x3_encoder_bench_test.go  # X3 performance
│
└── delivery/              # X2/X3 Delivery to MDF
    ├── destination.go     # Connection pool and management
    ├── destination_test.go # Destination tests
    ├── client.go          # Async delivery with queuing
    ├── client_test.go     # Delivery client tests
    └── client_bench_test.go # Delivery performance
```

## Build Tags

The LI package uses build tags to enable conditional compilation:

```go
//go:build li       // Included in LI builds
//go:build !li      // Excluded from LI builds (stubs)
```

**Files without build tags** (always included):
- `types.go` - Shared type definitions

**Files with `//go:build li`:**
- `manager.go` - Full LI Manager implementation
- `registry.go` - Task/destination storage
- `filters.go` - Filter mapping
- All x1/, x2x3/, delivery/ files

**Files with `//go:build !li`:**
- `manager_stub.go` - No-op Manager that does nothing

This ensures non-LI builds have zero LI code through dead code elimination.

## Core Components

### Manager

**File:** `manager.go`

The Manager is the main entry point and coordinator:

```go
type Manager struct {
    config   ManagerConfig
    registry *Registry        // Task and destination storage
    filters  *FilterManager   // XID ↔ filter mapping
    x1Client *x1.Client       // ADMF notification sender
    x1Server *x1.Server       // X1 administration interface
}
```

**Responsibilities:**
- Aggregates all LI components
- Provides unified API for processor integration
- Handles task activation/deactivation/modification
- Routes matched packets to delivery

**Key Methods:**
- `NewManager(config, callback)` - Creates manager with deactivation callback
- `Start()` - Starts X1 server and client, registry background tasks
- `Stop()` - Graceful shutdown with ADMF notification
- `ProcessPacket(pkt, matchedFilterIDs)` - Process matched packet
- `ActivateTask(task)` - Activate intercept via code (not X1)
- `DeactivateTask(xid)` - Deactivate intercept

### Registry

**File:** `registry.go`

Thread-safe storage for tasks and destinations:

```go
type Registry struct {
    mu           sync.RWMutex
    tasks        map[uuid.UUID]*InterceptTask
    destinations map[uuid.UUID]*Destination
    onDeactivation DeactivationCallback
}
```

**Key Features:**
- Atomic task modification (all-or-nothing updates)
- Automatic expiration checking for implicit deactivation
- Deactivation callback for ADMF notification
- Deep copies on read to prevent external modification

**Task Lifecycle States:**
- `Pending` - Task received but StartTime not reached
- `Active` - Actively intercepting
- `Suspended` - Temporarily paused
- `Deactivated` - Explicitly stopped
- `Failed` - Fatal error occurred

### FilterManager

**File:** `filters.go`

Maps ETSI target identities to lippycat filters:

```go
type FilterManager struct {
    xidToFilters map[uuid.UUID][]string  // XID → filter IDs
    filterToXID  map[string]uuid.UUID    // filter ID → XID
    filterStore  map[string]*management.Filter
    filterPusher FilterPusher            // Push to hunters
}
```

**Target Type Mapping:**

| ETSI Target | lippycat Filter | Notes |
|-------------|-----------------|-------|
| SIPURI | FILTER_SIP_URI | user@domain matching |
| TELURI | FILTER_PHONE_NUMBER | Phone number matching |
| NAI | FILTER_SIP_URI | Same as SIP URI |
| IPv4Address | FILTER_IP_ADDRESS | Hash map lookup |
| IPv4CIDR | FILTER_IP_ADDRESS | Radix tree lookup |
| IPv6Address | FILTER_IP_ADDRESS | Hash map lookup |
| IPv6CIDR | FILTER_IP_ADDRESS | Radix tree lookup |

**Filter ID Format:** `li-{xid_prefix}-{index}`

Example: `li-a1b2c3d4-0` for first target of task a1b2c3d4-...

## X1 Interface

### Server

**File:** `x1/server.go`

HTTPS server accepting ADMF requests:

```go
type Server struct {
    config       ServerConfig
    destManager  DestinationManager  // Interface to Manager
    taskManager  TaskManager         // Interface to Manager
    httpServer   *http.Server
}
```

**Supported Operations:**

| Request Type | Handler | Description |
|--------------|---------|-------------|
| CreateDestinationRequest | handleCreateDestination | Register MDF |
| ModifyDestinationRequest | handleModifyDestination | Update MDF |
| RemoveDestinationRequest | handleRemoveDestination | Delete MDF |
| ActivateTaskRequest | handleActivateTask | Start intercept |
| DeactivateTaskRequest | handleDeactivateTask | Stop intercept |
| ModifyTaskRequest | handleModifyTask | Update intercept |
| GetTaskDetailsRequest | handleGetTaskDetails | Query status |
| PingRequest | handlePing | Health check |

**XML Parsing:**
1. Detect root element to determine request type
2. Unmarshal into schema type
3. Validate required fields
4. Call appropriate Manager method
5. Build XML response

### Client

**File:** `x1/client.go`

HTTPS client for ADMF notifications:

```go
type Client struct {
    config     ClientConfig
    httpClient *http.Client
    stopChan   chan struct{}
}
```

**Notifications:**
- `ReportStartup()` - NE started
- `ReportShutdown()` - NE stopping
- `ReportTaskError()` - Task execution error
- `ReportDeliveryError()` - X2/X3 delivery failure
- `ReportDeliveryRecovered()` - Delivery restored
- `ReportTaskImplicitDeactivation()` - Task auto-expired

**Keepalive:** Background goroutine sends periodic ping if configured.

### Schema Types

**Directory:** `x1/schema/`

Generated from ETSI XSD schemas using `xuri/xgen`:

```go
// x1.go - TS 103 221-1 types
type ActivateTaskRequest struct {
    X1RequestMessage *X1RequestMessage
    TaskDetails      *TaskDetails
}

// common.go - TS 103 280 types
type TargetIdentifier struct {
    SipUri      *SipUri
    TelUri      *TelUri
    E164Number  *E164Number
    Ipv4Address *Ipv4Address
    // ...
}
```

## X2/X3 Protocol

### PDU Structure

**File:** `x2x3/pdu.go`

Binary PDU format per TS 103 221-2:

```go
type PDUHeader struct {
    Version       uint16      // Protocol version (5.0)
    Type          PDUType     // X2 (1) or X3 (2)
    HeaderLength  uint16      // Total header size
    PayloadFormat PayloadFormat
    PayloadLength uint32
    XID           uuid.UUID   // Task identifier
    CorrelationID uint64      // Links related PDUs
}

type TLVAttribute struct {
    Type  AttributeType
    Value []byte
}
```

**Wire Format (Big-Endian):**
```
Offset  Size  Field
------  ----  -----
0       2     Version
2       2     PDU Type
4       2     Header Length
6       2     Payload Format
8       4     Payload Length
12      16    XID (UUID)
28      8     Correlation ID
36      var   Conditional Attributes (TLV)
```

### X2 Encoder

**File:** `x2x3/x2_encoder.go`

Encodes SIP events to IRI PDUs:

```go
type X2Encoder struct {
    nfID string  // Network Function ID
    ipID string  // Interception Point ID
}

func (e *X2Encoder) EncodeSessionBegin(xid uuid.UUID, sip *SIPInfo) ([]byte, error)
func (e *X2Encoder) EncodeSessionAnswer(xid uuid.UUID, sip *SIPInfo) ([]byte, error)
func (e *X2Encoder) EncodeSessionEnd(xid uuid.UUID, sip *SIPInfo) ([]byte, error)
```

**IRI Event Types:**

| Event | SIP Trigger | IRIType Value |
|-------|-------------|---------------|
| SessionBegin | INVITE | 1 |
| SessionAnswer | 200 OK to INVITE | 2 |
| SessionEnd | BYE | 3 |
| SessionAttempt | CANCEL/4xx/5xx | 4 |
| Registration | REGISTER | 5 |
| RegistrationEnd | REGISTER (Exp: 0) | 6 |

### X3 Encoder

**File:** `x2x3/x3_encoder.go`

Encodes RTP to CC PDUs:

```go
type X3Encoder struct {
    nfID string
    ipID string
}

func (e *X3Encoder) Encode(xid uuid.UUID, rtp *RTPInfo, payload []byte) ([]byte, error)
```

**CC Attributes:**
- RTP SSRC (4 bytes)
- RTP Sequence Number (2 bytes)
- RTP Timestamp (4 bytes)
- RTP Payload Type (1 byte)
- Stream ID (8 bytes) - for X2 correlation
- Media Payload (variable)

### Buffer Pooling

Both encoders use `sync.Pool` for PDU buffers:

```go
var pduPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 0, 1500)  // MTU-sized
    },
}
```

## Delivery

### Destination Manager

**File:** `delivery/destination.go`

Connection pool per MDF destination:

```go
type Manager struct {
    destinations map[uuid.UUID]*destinationState
    tlsConfig    *tls.Config
}

type destinationState struct {
    dest    *Destination
    pool    chan *tls.Conn    // Connection pool
    stats   DestinationStats
}
```

**Connection Management:**
- Pool of TLS connections per destination
- Automatic reconnection with exponential backoff
- Connection health checking
- Statistics tracking

### Delivery Client

**File:** `delivery/client.go`

Async delivery with backpressure:

```go
type Client struct {
    manager   *Manager
    queue     chan *deliveryItem    // Bounded queue
    sequences map[streamKey]*uint32 // Per-stream sequence
}
```

**Key Features:**
- Async queue with configurable size (default: 10K)
- Batching for efficiency (default: 100 PDUs/batch)
- Per-XID+destination sequence numbering
- Multiple worker goroutines
- Backpressure via queue full errors

**Methods:**
- `SendX2(xid, destIDs, data)` - Queue X2 PDU (async)
- `SendX3(xid, destIDs, data)` - Queue X3 PDU (async)
- `SendX2Sync(ctx, xid, destIDs, data)` - Synchronous X2 delivery
- `SendX3Sync(ctx, xid, destIDs, data)` - Synchronous X3 delivery

## Processor Integration

### Configuration

```go
// processor.Config
type Config struct {
    // ... other fields ...
    LIEnabled             bool
    LIX1ListenAddr        string
    LIX1TLSCertFile       string
    LIX1TLSKeyFile        string
    LIX1TLSCAFile         string
    LIADMFEndpoint        string
    LIADMFTLSCertFile     string
    LIADMFTLSKeyFile      string
    LIADMFTLSCAFile       string
    LIDeliveryTLSCertFile string
    LIDeliveryTLSKeyFile  string
    LIDeliveryTLSCAFile   string
}
```

### Packet Processing Flow

```
1. Hunter matches packet using optimized filters
2. Processor receives packet with matched filter IDs
3. Processor calls li.Manager.ProcessPacket(pkt, filterIDs)
4. FilterManager.LookupMatches() finds XIDs for filter IDs
5. For each matching task:
   a. Check task is Active
   b. Call PacketProcessor callback
   c. Encode X2/X3 PDU based on packet type
   d. Queue for delivery to task's destinations
```

### Filter Pusher Interface

The processor implements `FilterPusher` to integrate with filter distribution:

```go
type FilterPusher interface {
    UpdateFilter(filter *management.Filter) error
    DeleteFilter(filterID string) error
}
```

When LI tasks are activated/modified/deactivated, the FilterManager calls these methods to push filter updates to hunters.

## Thread Safety

All components are thread-safe:

| Component | Synchronization |
|-----------|-----------------|
| Manager | sync.RWMutex for config/stats access |
| Registry | sync.RWMutex for task/dest maps |
| FilterManager | sync.RWMutex for filter maps |
| Delivery Client | Channels + atomic counters |
| Destination Manager | sync.RWMutex for destination states |

## Error Handling

### Task Errors

Task errors are reported to ADMF via X1:

```go
manager.ReportTaskError(xid, ErrorCodeGenericError, "details")
```

Errors cause task to enter Failed state.

### Delivery Errors

Delivery errors:
1. Logged with destination and error details
2. Connection invalidated (reconnect on next use)
3. Reported to ADMF if configured
4. Stats updated (X2Failed/X3Failed)

Recovery is automatic on reconnection.

## Performance

### Benchmarks

From `*_bench_test.go` files:

| Operation | Throughput | Latency |
|-----------|------------|---------|
| X2 Encode | ~500K/s | ~2µs |
| X3 Encode | ~1M/s | ~1µs |
| Filter Lookup | ~10M/s | ~100ns |
| Delivery Queue | ~1M/s | ~1µs |

### Memory

- PDU buffer pool reduces allocations
- Deep copies only on external API boundaries
- Per-stream sequence numbers use atomic operations

## Testing

### Unit Tests

Each component has dedicated unit tests:

```bash
# Run all LI tests
go test -tags li ./internal/pkg/li/...

# Run specific package
go test -tags li ./internal/pkg/li/x2x3/
```

### Integration Tests

**File:** `integration_test.go`

End-to-end tests with mock ADMF/MDF:

- Task activation → filter creation → delivery
- Task modification (atomic updates)
- Task deactivation → filter cleanup
- Implicit deactivation (EndTime expiration)
- Error handling and recovery

### Security Tests

**File:** `security_test.go`

- Mutual TLS enforcement
- Certificate validation
- Invalid certificate rejection
- Expired certificate handling

## Common Development Tasks

### Adding a New Target Type

1. Add to `types.go`:
   ```go
   const TargetTypeNewType TargetType = ...
   ```

2. Update `filters.go` mapping:
   ```go
   case TargetTypeNewType:
       return management.FilterType_FILTER_..., pattern, nil
   ```

3. Update X1 schema parsing in `x1/server.go`

4. Add tests for new target type

### Adding a New X1 Operation

1. Add handler in `x1/server.go`:
   ```go
   func (s *Server) handleNewOperation(req *schema.NewRequest) *schema.X1ResponseMessage
   ```

2. Add routing in `processRequestMessage()`

3. Add interface method if needed in `TaskManager` or `DestinationManager`

4. Add tests

### Adding a New TLV Attribute

1. Add constant in `x2x3/pdu.go`:
   ```go
   const AttrNewAttribute AttributeType = 0x...
   ```

2. Add encoding helper in `x2x3/attributes.go`

3. Use in X2/X3 encoder as needed

## Related Documentation

- [docs/LI_INTEGRATION.md](../../../docs/LI_INTEGRATION.md) - Deployment guide
- [docs/LI_CERTIFICATES.md](../../../docs/LI_CERTIFICATES.md) - Certificate management
- [cmd/process/CLAUDE.md](../../../cmd/process/CLAUDE.md) - Processor architecture

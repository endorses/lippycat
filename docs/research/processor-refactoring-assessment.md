# Processor.go Comprehensive Analysis

## Overview
**File**: `/home/grischa/Projects/lippycat/internal/pkg/processor/processor.go`
- **Total Lines**: 1,921
- **Test Coverage**: 31.4%
- **Package**: `processor`

---

## 1. STRUCT FIELDS ANALYSIS

### Config Struct (Lines 45-72)
Configuration container for Processor initialization. 28 fields organized by category:

**Core Settings** (3 fields):
- `ListenAddr` (string) - gRPC server bind address (REQUIRED)
- `ProcessorID` (string) - Unique processor identifier
- `UpstreamAddr` (string) - Optional parent processor address for hierarchy

**Resource Limits** (2 fields):
- `MaxHunters` (int) - Maximum concurrent hunter connections
- `MaxSubscribers` (int) - Maximum concurrent TUI subscribers (0=unlimited)

**File I/O** (2 fields):
- `WriteFile` (string) - Unified PCAP output file path
- `FilterFile` (string) - Filter persistence YAML file path

**PCAP Writers** (2 configs):
- `PcapWriterConfig` (*PcapWriterConfig) - Per-call PCAP writer config
- `AutoRotateConfig` (*AutoRotateConfig) - Auto-rotating PCAP writer config

**Protocol Detection** (1 field):
- `EnableDetection` (bool) - Enable centralized protocol detection
- DisplayStats (bool) - Display statistics

**TLS/Security** (6 fields):
- `TLSEnabled` (bool) - Enable gRPC TLS encryption
- `TLSCertFile` (string) - Server certificate path
- `TLSKeyFile` (string) - Server private key path
- `TLSCAFile` (string) - CA certificate for client auth
- `TLSClientAuth` (bool) - Require mutual TLS (mTLS)
- `AuthConfig` (*auth.Config) - API key authentication alternative

**Virtual Interface** (4 fields):
- `VirtualInterface` (bool) - Enable packet injection interface
- `VirtualInterfaceName` (string) - Interface name (default: lc0)
- `VirtualInterfaceType` (string) - tap or tun (default: tap)
- `VifBufferSize` (int) - Buffer size for interface
- `VifNetNS` (string) - Network namespace isolation
- `VifDropPrivilegesUser` (string) - User for privilege dropping

### Processor Struct (Lines 75-123)
Main processor instance managing all subsystems. 17 fields organized by system:

**Configuration & Context** (4 fields):
- `config` (Config) - Configuration copy
- `ctx` (context.Context) - Shutdown context
- `cancel` (context.CancelFunc) - Shutdown trigger
- `wg` (sync.WaitGroup) - Goroutine lifecycle

**gRPC Infrastructure** (2 fields):
- `grpcServer` (*grpc.Server) - Listens for hunters and downstream processors
- `listener` (net.Listener) - TCP listener for gRPC server

**Protocol Detection & Enrichment** (2 fields):
- `detector` (*detector.Detector) - Optional centralized detection (nil if disabled)
- `enricher` (*enrichment.Enricher) - Optional packet enrichment (paired with detector)

**Hunter Management** (2 fields):
- `hunterManager` (*hunter.Manager) - Tracks connected hunters (ALWAYS initialized)
- `hunterMonitor` (*hunter.Monitor) - Health checks and cleanup (ALWAYS initialized)

**Filtering System** (1 field):
- `filterManager` (*filtering.Manager) - Filter rules and subscriptions (ALWAYS initialized)

**Flow Control & Forwarding** (2 fields):
- `flowController` (*flow.Controller) - Backpressure management (ALWAYS initialized)
- `upstreamManager` (*upstream.Manager) - Connection to parent processor (nil if root)

**Subscriber Management** (2 fields):
- `subscriberManager` (*subscriber.Manager) - TUI client subscriptions (ALWAYS initialized)
- `downstreamManager` (*downstream.Manager) - Child processor management (ALWAYS initialized)

**Packet Statistics** (2 fields):
- `packetsReceived` (atomic.Uint64) - Total packets received from hunters
- `packetsForwarded` (atomic.Uint64) - Total packets forwarded upstream

**Statistics Collection** (1 field):
- `statsCollector` (*stats.Collector) - Aggregates metrics (ALWAYS initialized)

**PCAP Writing** (3 fields):
- `pcapWriter` (*pcap.Writer) - Unified PCAP writer (nil if not configured)
- `perCallPcapWriter` (*PcapWriterManager) - Per-call PCAP writer for VoIP (nil if disabled)
- `autoRotatePcapWriter` (*AutoRotatePcapWriter) - Auto-rotating writer for non-VoIP (nil if disabled)

**Call Analysis** (2 fields):
- `callAggregator` (*voip.CallAggregator) - VoIP call state aggregation (ALWAYS initialized)
- `callCorrelator` (*CallCorrelator) - B2BUA call correlation (ALWAYS initialized)

**Virtual Interface & Proxy** (2 fields):
- `vifManager` (vinterface.Manager) - Packet injection interface (nil if disabled or failed)
- `proxyManager` (*proxy.Manager) - Topology subscriptions and request routing (ALWAYS initialized)

**Embedded Interfaces** (2 interfaces):
- `data.UnimplementedDataServiceServer` - gRPC data service stub
- `management.UnimplementedManagementServiceServer` - gRPC management service stub

---

## 2. METHOD SIGNATURES & FIELD ACCESS

### Initialization Methods

**New() (Lines 126-323)**
- Creates Processor instance
- Returns: `(*Processor, error)`
- Lines of Code: 197
- Initializes ALL fields in order of dependency
- Key operations:
  1. Validates `config.ListenAddr` (required)
  2. Initializes `callAggregator` and `callCorrelator` (ALWAYS)
  3. Optionally initializes `detector` and `enricher` (if `EnableDetection=true`)
  4. Optionally initializes `perCallPcapWriter` (if `PcapWriterConfig.Enabled=true`)
  5. Optionally initializes `autoRotatePcapWriter` (if `AutoRotateConfig.Enabled=true`)
  6. Optionally initializes `vifManager` (if `VirtualInterface=true`, but logs if fails)
  7. Initializes `statsCollector` (ALWAYS)
  8. Creates stats callback and initializes `hunterManager` (ALWAYS)
  9. Initializes `hunterMonitor` (ALWAYS)
  10. Creates filter callback and initializes `filterManager` (ALWAYS)
  11. Initializes `flowController` (ALWAYS)
  12. Initializes `subscriberManager` (ALWAYS)
  13. Optionally initializes `upstreamManager` (if `UpstreamAddr` is set)
  14. Initializes `downstreamManager` (ALWAYS)
  15. Initializes `proxyManager` (ALWAYS)
  16. Sets up TLS credentials on `proxyManager` if enabled
  17. Wires topology event flow: `hunterManager` → `proxyManager` → subscribers

**Start(ctx context.Context) (Lines 326-505)**
- Starts processor operation (blocking)
- Returns: `error`
- Lines of Code: 179
- Key operations:
  1. Creates shutdown context from provided ctx
  2. Loads filters from `filterManager.Load()`
  3. Initializes main PCAP writer if `WriteFile` configured
  4. Configures `flowController` with PCAP queue metrics
  5. Creates SO_REUSEADDR TCP listener
  6. Builds gRPC server with TLS, auth, keepalive
  7. Registers gRPC services (DataService, ManagementService)
  8. Starts gRPC server in background goroutine
  9. Connects `upstreamManager` if configured
  10. Starts `hunterMonitor`
  11. Starts `vifManager` if available
  12. Waits for context cancellation (blocks)
  13. Performs graceful shutdown

**Shutdown() (Lines 509-567)**
- Graceful shutdown (primarily for testing)
- Returns: `error`
- Lines of Code: 58
- Key operations:
  1. Cancels context
  2. Shuts down `detector` if present
  3. Stops `callCorrelator`
  4. Closes `perCallPcapWriter`
  5. Closes `autoRotatePcapWriter`
  6. Shuts down `vifManager`
  7. Shuts down `proxyManager`
  8. Shuts down `downstreamManager`
  9. Gracefully stops `grpcServer`
  10. Waits for goroutines

### Data Service Methods (Packet Streaming)

**StreamPackets(stream data.DataService_StreamPacketsServer) (Lines 578-622)**
- Receives packet batches from hunters (bidirectional streaming)
- Returns: `error`
- Lines of Code: 44
- Accesses: `hunterManager`, `flowController`, `processBatch`
- Flow:
  1. Tracks `hunterID` from first batch
  2. Receives packet batches in loop
  3. Calls `processBatch(batch)`
  4. Determines flow control via `flowController.Determine()`
  5. Sends acknowledgment with flow control signal

**processBatch(batch *data.PacketBatch) (Lines 625-766)**
- Internal packet processing pipeline
- Returns: `void`
- Lines of Code: 141
- Accesses: MOST fields
- Critical processing order:
  1. Updates `hunterManager` with packet stats
  2. Queues packets to `pcapWriter` if configured
  3. Increments `packetsReceived` counter
  4. Enriches packets with `enricher` if enabled
  5. Aggregates VoIP calls via `callAggregator`
  6. Correlates calls via `callCorrelator`
  7. Writes VoIP packets to `perCallPcapWriter` (per-call files)
  8. Writes non-VoIP packets to `autoRotatePcapWriter`
  9. Forwards batch to `upstreamManager` (if configured)
  10. Broadcasts to `subscriberManager` (all TUI clients)
  11. Injects packets to `vifManager` (if configured)

**SubscribePackets(req *data.SubscribeRequest, stream) (Lines 1645-1735)**
- TUI client packet subscription
- Returns: `error`
- Lines of Code: 90
- Accesses: `subscriberManager`, `config.MaxSubscribers`
- Features:
  - Hunter filter support (selective subscription)
  - BPF filter support (TODO: not implemented)
  - DoS prevention via subscriber limits
  - Per-subscriber channel buffering

**SubscribeCorrelatedCalls(req *data.SubscribeRequest, stream) (Lines 1738-1780)**
- Streams B2BUA correlated call updates
- Returns: `error`
- Lines of Code: 42
- Accesses: `callCorrelator`
- Sends periodic snapshots every 1 second

### Management Service Methods (Hunter Management)

**RegisterHunter(ctx, req *management.HunterRegistration) (Lines 778-815)**
- Hunter registration RPC
- Returns: `(*management.RegistrationResponse, error)`
- Lines of Code: 37
- Accesses: `hunterManager`, `filterManager`, `config.ProcessorID`, `config.MaxHunters`
- Security note: Authentication via TLS/mTLS or (not recommended) open connection

**Heartbeat(stream management.ManagementService_HeartbeatServer) (Lines 818-862)**
- Bidirectional hunter heartbeat stream
- Returns: `error`
- Lines of Code: 44
- Accesses: `hunterManager`, `statsCollector`, `config.ProcessorID`
- Operations:
  1. Receives heartbeat with stats
  2. Updates `hunterManager` health stats
  3. Retrieves processor stats from `statsCollector`
  4. Sends response

### Filter Management Methods

**GetFilters(ctx, req *management.FilterRequest) (Lines 865-871)**
- Simple filter retrieval
- Returns: `(*management.FilterResponse, error)`
- Lines of Code: 6
- Accesses: `filterManager`

**SubscribeFilters(req, stream) (Lines 874-928)**
- Streaming filter updates to hunters
- Returns: `error`
- Lines of Code: 54
- Accesses: `filterManager`
- Operations:
  1. Adds channel to `filterManager` for this hunter
  2. Sends current filters immediately
  3. Streams filter updates as they occur

**UpdateFilter(ctx, filter *management.Filter) (Lines 1202-1218)**
- Local filter update
- Returns: `(*management.FilterUpdateResult, error)`
- Lines of Code: 16
- Accesses: `filterManager`

**DeleteFilter(ctx, req *management.FilterDeleteRequest) (Lines 1221-1237)**
- Local filter deletion
- Returns: `(*management.FilterUpdateResult, error)`
- Lines of Code: 16
- Accesses: `filterManager`

**UpdateFilterOnProcessor(ctx, req *management.ProcessorFilterRequest) (Lines 1241-1345)**
- Multi-level filter update with routing
- Returns: `(*management.FilterUpdateResult, error)`
- Lines of Code: 104
- Accesses: `proxyManager`, `filterManager`, `downstreamManager`, `config.ProcessorID`
- Features:
  - Auth token verification
  - Routing decision via `proxyManager`
  - Local handling or downstream forwarding
  - Audit logging

**DeleteFilterOnProcessor(ctx, req *management.ProcessorFilterDeleteRequest) (Lines 1349-1451)**
- Multi-level filter deletion with routing
- Returns: `(*management.FilterUpdateResult, error)`
- Lines of Code: 102
- Accesses: Same as UpdateFilterOnProcessor

**GetFiltersFromProcessor(ctx, req *management.ProcessorFilterQuery) (Lines 1455-1552)**
- Multi-level filter query with routing
- Returns: `(*management.FilterResponse, error)`
- Lines of Code: 97
- Accesses: Same as UpdateFilterOnProcessor

### Hunter Status Methods

**GetHunterStatus(ctx, req *management.StatusRequest) (Lines 931-963)**
- Current hunter status snapshot
- Returns: `(*management.StatusResponse, error)`
- Lines of Code: 32
- Accesses: `hunterManager`, `statsCollector`, `config.ProcessorID`

**ListAvailableHunters(ctx, req *management.ListHuntersRequest) (Lines 966-991)**
- List of all connected hunters (for TUI)
- Returns: `(*management.ListHuntersResponse, error)`
- Lines of Code: 25
- Accesses: `hunterManager`

### Processor Hierarchy Methods

**RegisterProcessor(ctx, req *management.ProcessorRegistration) (Lines 994-1088)**
- Downstream processor registration
- Returns: `(*management.ProcessorRegistrationResponse, error)`
- Lines of Code: 94
- Accesses: `downstreamManager`, `proxyManager`, `config.ProcessorID`
- Validation:
  1. Checks hierarchy depth limit (max 10)
  2. Detects cycles in upstream chain
  3. Publishes PROCESSOR_CONNECTED topology event

**GetTopology(ctx, req *management.TopologyRequest) (Lines 1091-1142)**
- Complete topology snapshot (synchronous)
- Returns: `(*management.TopologyResponse, error)`
- Lines of Code: 51
- Accesses: `hunterManager`, `statsCollector`, `upstreamManager`, `downstreamManager`, `config.ProcessorID`
- Recursively queries downstream processors

**SubscribeTopology(req, stream) (Lines 1146-1199)**
- Real-time topology updates (asynchronous)
- Returns: `error`
- Lines of Code: 53
- Accesses: `proxyManager`
- Registers subscriber and streams updates

**RequestAuthToken(ctx, req *management.AuthTokenRequest) (Lines 1557-1592)**
- Issues authorization token for proxied operations
- Returns: `(*management.AuthorizationToken, error)`
- Lines of Code: 35
- Accesses: `proxyManager`, `config.ProcessorID`

### Utility Methods

**GetStats() (Lines 1621-1623)**
- Get processor statistics
- Returns: `stats.Stats`
- Accesses: `statsCollector`

**buildTLSCredentials() (Lines 1626-1633)**
- Create TLS credentials for gRPC server
- Returns: `(credentials.TransportCredentials, error)`
- Accesses: `config` (TLS fields)

**SetProxyTLSCredentials(cert, key []byte) (Lines 571-575)**
- Set TLS credentials on proxy manager (testing)
- Returns: `void`
- Accesses: `proxyManager`

**convertChainErrorToStatus(err) (Lines 1599-1618)**
- Convert chain errors to gRPC status
- Returns: `error`
- Pure logic, no field access

---

## 3. CROSS-DEPENDENCIES & CALL GRAPH

### Initialization Dependencies (New() Function)
```
ListenAddr (validate)
    ↓
callAggregator ← voip.NewCallAggregator()
callCorrelator ← NewCallCorrelator()
    ↓
[Optional] detector ← detector.InitDefault()
[Optional] enricher ← enrichment.NewEnricher(detector)
    ↓
[Optional] perCallPcapWriter ← NewPcapWriterManager()
[Optional] autoRotatePcapWriter ← NewAutoRotatePcapWriter()
    ↓
[Optional] vifManager ← vinterface.NewManager()
    ↓
statsCollector ← stats.NewCollector(ProcessorID, &packetsReceived, &packetsForwarded)
    ↓
hunterManager ← hunter.NewManager(MaxHunters, onStatsChanged callback)
hunterMonitor ← hunter.NewMonitor(hunterManager)
    ↓
filterManager ← filtering.NewManager(FilterFile, ..., hunterManager, onFilterFailure callback)
    ↓
flowController ← flow.NewController(&packetsReceived, &packetsForwarded, hasUpstream)
    ↓
subscriberManager ← subscriber.NewManager(MaxSubscribers)
    ↓
[Optional] upstreamManager ← upstream.NewManager(config, &packetsForwarded)
    ↓
downstreamManager ← downstream.NewManager(...)
    ↓
proxyManager ← proxy.NewManager(logger, ProcessorID)
    ↓
[Wire topology flow]
hunterManager.SetTopologyPublisher(proxyManager)
downstreamManager.SetTopologyPublisher(proxyManager)
```

### Method Call Dependencies
```
Start()
├── filterManager.Load()
├── pcap.NewWriter() → pcapWriter.Start()
├── flowController.SetPCAPQueue()
├── createReuseAddrListener()
├── buildTLSCredentials()
├── grpcServer.NewServer()
├── grpcServer.Serve()
├── upstreamManager.Connect()
├── hunterMonitor.Start()
└── vifManager.Start()

StreamPackets()
├── processBatch()
│   ├── hunterManager.UpdatePacketStats()
│   ├── pcapWriter.QueuePackets()
│   ├── packetsReceived.Add()
│   ├── enricher.Enrich()
│   ├── callAggregator.ProcessPacket()
│   ├── callCorrelator.ProcessPacket()
│   ├── perCallPcapWriter.GetOrCreateWriter()
│   ├── perCallPcapWriter.WriteRTPPacket() / WriteSIPPacket()
│   ├── autoRotatePcapWriter.WritePacket()
│   ├── upstreamManager.Forward()
│   ├── subscriberManager.Broadcast()
│   └── vifManager.InjectPacketBatch()
└── flowController.Determine()

SubscribePackets()
└── subscriberManager operations:
    ├── CheckLimit()
    ├── SetFilter()
    ├── Add()
    └── Remove()

RegisterHunter()
├── hunterManager.Register()
└── filterManager.GetForHunter()

Heartbeat()
├── hunterManager.UpdateHeartbeat()
└── statsCollector.GetProto()

SubscribeFilters()
└── filterManager operations:
    ├── AddChannel()
    ├── GetForHunter()
    └── RemoveChannel()

RegisterProcessor()
├── downstreamManager.Register()
├── proxyManager.AddProcessor()
└── proxyManager.PublishTopologyUpdate()

GetTopology()
├── hunterManager.GetAll()
├── statsCollector.GetProto()
├── upstreamManager.GetUpstreamProcessorID()
└── downstreamManager.GetTopology()

SubscribeTopology()
└── proxyManager.RegisterSubscriber()

UpdateFilterOnProcessor()
├── proxyManager.RouteToProcessor()
├── filterManager.Update()
├── downstreamManager.ForwardUpdateFilter()
└── convertChainErrorToStatus()

RequestAuthToken()
└── proxyManager.IssueAuthToken()

Shutdown()
├── detector.Shutdown()
├── callCorrelator.Stop()
├── perCallPcapWriter.Close()
├── autoRotatePcapWriter.Close()
├── vifManager.Shutdown()
├── proxyManager.Shutdown()
├── downstreamManager.Shutdown()
├── grpcServer.GracefulStop()
└── wg.Wait()
```

### Field Access Matrix

**Fields accessed by >5 methods** (Hot paths):
- `hunterManager`: 7 methods (RegisterHunter, GetHunterStatus, ListAvailableHunters, processBatch, GetTopology, in callbacks)
- `filterManager`: 7 methods (RegisterHunter, SubscribeFilters, GetFilters, UpdateFilter, DeleteFilter, UpdateFilterOnProcessor, DeleteFilterOnProcessor, GetFiltersFromProcessor)
- `downstreamManager`: 5 methods (RegisterProcessor, GetTopology, UpdateFilterOnProcessor, DeleteFilterOnProcessor, GetFiltersFromProcessor)
- `proxyManager`: 6 methods (RegisterProcessor, SubscribeTopology, UpdateFilterOnProcessor, DeleteFilterOnProcessor, GetFiltersFromProcessor, RequestAuthToken)
- `statsCollector`: 4 methods (GetHunterStatus, Heartbeat, GetTopology, automatic updates in New)
- `callCorrelator`: 2 methods (processBatch, SubscribeCorrelatedCalls)
- `packetsReceived`: 2 fields (processBatch, flowController initialization)
- `packetsForwarded`: 2 fields (upstreamManager, flowController)

**Fields accessed by 1-3 methods** (Specialized):
- `detector`: 2 methods (processBatch, Shutdown)
- `enricher`: 1 method (processBatch)
- `callAggregator`: 1 method (processBatch)
- `pcapWriter`: 2 methods (Start, processBatch)
- `perCallPcapWriter`: 1 method (processBatch)
- `autoRotatePcapWriter`: 1 method (processBatch)
- `vifManager`: 2 methods (Start, processBatch)
- `upstreamManager`: 3 methods (Start, processBatch, GetTopology)
- `subscriberManager`: 3 methods (SubscribePackets, processBatch via Broadcast, internal)
- `flowController`: 2 methods (Start, StreamPackets)
- `grpcServer`: 2 methods (Start, Shutdown)

---

## 4. EXTERNAL DEPENDENCIES & IMPORTS

### Third-Party Packages
- `google.golang.org/grpc`: gRPC server/client, streaming, credentials
- `github.com/google/gopacket/layers`: Packet layer types
- `log/slog`: Structured logging

### Internal Package Dependencies (17 imports)
1. `github.com/endorses/lippycat/api/gen/data` - Generated gRPC data service
2. `github.com/endorses/lippycat/api/gen/management` - Generated gRPC management service
3. `github.com/endorses/lippycat/internal/pkg/auth` - API key authentication
4. `github.com/endorses/lippycat/internal/pkg/constants` - Shared constants (MaxGRPCMessageSize, MaxHierarchyDepth)
5. `github.com/endorses/lippycat/internal/pkg/detector` - Protocol detection
6. `github.com/endorses/lippycat/internal/pkg/logger` - Structured logging
7. `github.com/endorses/lippycat/internal/pkg/processor/downstream` - Downstream processor management
8. `github.com/endorses/lippycat/internal/pkg/processor/enrichment` - Packet enrichment
9. `github.com/endorses/lippycat/internal/pkg/processor/filtering` - Filter management
10. `github.com/endorses/lippycat/internal/pkg/processor/flow` - Flow control
11. `github.com/endorses/lippycat/internal/pkg/processor/hunter` - Hunter management
12. `github.com/endorses/lippycat/internal/pkg/processor/pcap` - PCAP writing
13. `github.com/endorses/lippycat/internal/pkg/processor/proxy` - Topology proxy and authorization
14. `github.com/endorses/lippycat/internal/pkg/processor/stats` - Statistics collection
15. `github.com/endorses/lippycat/internal/pkg/processor/subscriber` - Subscriber management
16. `github.com/endorses/lippycat/internal/pkg/processor/upstream` - Upstream processor connection
17. `github.com/endorses/lippycat/internal/pkg/tlsutil` - TLS utilities
18. `github.com/endorses/lippycat/internal/pkg/types` - Shared domain types
19. `github.com/endorses/lippycat/internal/pkg/vinterface` - Virtual interface management
20. `github.com/endorses/lippycat/internal/pkg/voip` - VoIP processing (CallAggregator)

### Standard Library
- `context` - Cancellation and timeouts
- `errors` - Error utilities
- `fmt` - String formatting
- `net` - TCP listener
- `os` - File operations, environment variables
- `sync` - Mutexes and WaitGroups
- `sync/atomic` - Atomic counters
- `syscall` - SO_REUSEADDR socket option
- `time` - Duration, timestamps, tickers

---

## 5. TEST FILES & COVERAGE

### Test Files (6 files in /internal/pkg/processor/)
1. **processor_core_test.go** (305 lines)
   - Tests New(), field initialization, filter operations
   - Tests: TestNew, TestGetHunterStatus, TestFlowControlConstants, TestFilterOperations, TestStats, TestContextCancellation, TestMaxHunters, TestConfigValidation
   - Coverage: Constructor validation, config validation

2. **processor_registration_test.go** (234 lines)
   - Tests processor hierarchy and validation
   - Tests: TestRegisterProcessor_CycleDetection, TestRegisterProcessor_DepthLimit, TestRegisterProcessor_CombinedValidation
   - Coverage: Cycle detection, hierarchy depth enforcement

3. **streaming_test.go** (11,190 lines - very large)
   - Tests packet streaming, processBatch
   - Likely covers: StreamPackets, flow control, packet broadcast

4. **grpc_errors_test.go** (8,572 lines)
   - Tests error handling in gRPC methods

5. **tls_test.go** (8,572 lines)
   - Tests TLS credential building and configuration

6. **topology_subscription_test.go** (17,336 lines)
   - Tests topology updates and subscription
   - Tests: GetTopology, SubscribeTopology, RegisterProcessor events

### Sub-package Tests
- **pcap_writer_test.go** - Per-call PCAP writer tests
- **auto_rotate_pcap.go** - Auto-rotating PCAP tests
- **call_correlator_test.go** - Call correlation tests
- Plus tests in hunter/, filtering/, flow/, subscriber/, upstream/, downstream/, proxy/ packages

### Test Coverage
- **Overall**: 31.4% statement coverage for processor package
- **Missing Coverage Areas**:
  - Integration tests (full Start/Shutdown lifecycle)
  - Virtual interface edge cases
  - Protocol detection integration
  - Per-call PCAP writing
  - Auto-rotating PCAP writing
  - Multi-level filter operations (likely covered by topology tests)

---

## 6. USAGE SITES

### Instantiation Sites
1. **cmd/process/main.go** - Primary instantiation point (file doesn't exist in current repo, check build)
2. **Integration tests** - processor_core_test.go, processor_registration_test.go
3. **Topology tests** - topology_subscription_test.go
4. **Streaming tests** - streaming_test.go

### Key Usage Patterns
```go
// In cmd/process/main.go (typical pattern)
config := processor.Config{
    ProcessorID:    processorID,
    ListenAddr:     listenAddr,
    UpstreamAddr:   upstreamAddr,     // optional
    MaxHunters:     maxHunters,
    MaxSubscribers: maxSubscribers,
    TLSEnabled:     tlsEnabled,
    TLSCertFile:    tlsCertFile,
    TLSKeyFile:     tlsKeyFile,
    // ... other config
}

proc, err := processor.New(config)
if err != nil {
    fatal(err)
}

// Blocking call - runs until context cancelled
err = proc.Start(context.Background())
```

---

## 7. SCOPE OF POTENTIAL REFACTORING

### Lines of Code Impact
- **processor.go**: 1,921 lines total
- **Core logic**: 1,200 lines (New + Start + Shutdown + processBatch + gRPC methods)
- **Utility/Helper**: 200 lines (audit logging, error conversion, listener creation)
- **Type definitions**: 521 lines (Config, Processor, auditContext)

### Method Signatures That Would Change
**If refactoring manager fields into a separate structure:**
- All 25 methods accessing multiple managers (direct field references)
- Method signatures would remain same (no parameter changes needed)
- Only internal implementation changes

**Critical Signatures (would need updates if managers are passed differently):**
1. `New()` - Would need to initialize managers differently
2. `processBatch()` - Accesses 9+ manager fields
3. All gRPC service methods - Access 1-3 managers each

### Circular Dependency Risks
**NONE DETECTED** - Good architecture separation:
- processors package depends on sub-packages (hunter, filtering, etc.)
- Sub-packages do NOT depend on processor package
- Sub-packages communicate via interfaces (TopologyPublisher, EventHandler)

### Recommended Extraction Candidates (for future refactoring)

**Option 1: Extract Manager Container**
```go
type ProcessorManagers struct {
    Hunter      *hunter.Manager
    Filter      *filtering.Manager
    Flow        *flow.Controller
    PCAP        *pcap.Writer
    PerCallPCAP *PcapWriterManager
    AutoPCAP    *AutoRotatePcapWriter
    Stats       *stats.Collector
    Subscriber  *subscriber.Manager
    Upstream    *upstream.Manager
    Downstream  *downstream.Manager
    Enricher    *enrichment.Enricher
    Detector    *detector.Detector
    Proxy       *proxy.Manager
    VIF         vinterface.Manager
}
```

**Option 2: Extract Streaming Logic**
```go
type PacketStreamingHandler struct {
    hunterManager       *hunter.Manager
    flowController      *flow.Controller
    processBatch        func(*data.PacketBatch)
}

func (p *Processor) StreamPackets(...) error {
    handler := NewPacketStreamingHandler(p.hunterManager, p.flowController, p.processBatch)
    return handler.Handle(stream)
}
```

**Option 3: Extract PCAP Writing Logic**
```go
type PCAPWritingPipeline struct {
    unified     *pcap.Writer
    perCall     *PcapWriterManager
    autoRotate  *AutoRotatePcapWriter
}

func (p *Processor) processBatch(...) {
    // ... existing logic ...
    p.pcapPipeline.Write(batch)
}
```

---

## 8. SUMMARY TABLE

| Aspect | Details |
|--------|---------|
| **Total Lines** | 1,921 |
| **Struct Fields** | 17 in Processor, 28 in Config |
| **Methods** | 25 receiver methods + 4 helper functions |
| **Field Access Hot Paths** | hunterManager, filterManager, proxyManager (7+ methods each) |
| **Always Initialized** | hunterManager, filterManager, flowController, statsCollector, subscriberManager, downstreamManager, proxyManager, callAggregator, callCorrelator, hunterMonitor |
| **Conditionally Initialized** | detector, enricher, perCallPcapWriter, autoRotatePcapWriter, upstreamManager, vifManager, pcapWriter, grpcServer |
| **Sub-packages Used** | 17 internal, 1 voip |
| **External Dependencies** | gRPC, gopacket, slog |
| **Test Coverage** | 31.4% |
| **Test Files** | 6 dedicated + sub-package tests |
| **Refactoring Impact** | Medium - manager fields accessed throughout, but clean interfaces allow extraction |

---

## 9. CRITICAL OBSERVATIONS FOR REFACTORING

### Strengths (Good for Refactoring)
1. **Clean Separation**: Managers are independent packages with defined interfaces
2. **No Circular Dependencies**: processor → subpackages, never reverse
3. **Interface-Based Communication**: TopologyPublisher, EventHandler prevent coupling
4. **Consistent Field Access Patterns**: Most fields accessed in predictable ways
5. **Clear Initialization Order**: Dependencies ordered logically in New()

### Challenges (Would Need Attention)
1. **Many Fields** (17): Refactoring container would be large
2. **Callback Patterns**: Stats callbacks and filter callbacks created in New() - would need restructuring
3. **Mixed Initialization**: Some fields optional, some required - complex initialization logic
4. **Goroutine Management**: WaitGroup and context management scattered across methods
5. **Error Handling**: Shutdown method ignores some errors intentionally - must preserve
6. **processBatch Complexity**: 141 lines accessing 9+ different managers - would need careful refactoring

### Effort Estimation
- **Small Refactoring** (extract one subsystem): 4-8 hours
- **Medium Refactoring** (extract manager container): 16-24 hours
- **Large Refactoring** (split into components): 40-60 hours
- **Test Updates Required**: 20-30 hours (31.4% current coverage)

---

## 10. PHASE 2.2 SPECIFIC ASSESSMENT: THREE-WAY SPLIT

This section specifically assesses the Phase 2.2 proposal from `docs/plan/code-review-remediation-2025-11-01.md` which calls for splitting processor.go into:
1. **ProcessorCore** - Packet processing logic
2. **ProcessorServer** - gRPC service layer
3. **ProcessorOrchestrator** - Lifecycle management

### 10.1 ProcessorCore Component Analysis

**Proposed Responsibilities** (from Phase 2.2):
- Protocol detection
- Enrichment
- Call tracking/aggregation

**Actual Implementation Requirements:**

**Fields Required:**
```go
type ProcessorCore struct {
    // Protocol detection & enrichment
    detector *detector.Detector      // Optional
    enricher *enrichment.Enricher    // Optional

    // Call analysis
    callAggregator *voip.CallAggregator  // Always initialized
    callCorrelator *CallCorrelator       // Always initialized

    // PCAP writing
    perCallPcapWriter    *PcapWriterManager     // Optional
    autoRotatePcapWriter *AutoRotatePcapWriter  // Optional

    // Virtual interface
    vifManager vinterface.Manager  // Optional

    // Statistics (shared counters)
    packetsReceived  *atomic.Uint64  // Pointer to shared counter
    packetsForwarded *atomic.Uint64  // Pointer to shared counter

    // Managers needed for processBatch
    hunterManager     *hunter.Manager
    pcapWriter        *pcap.Writer          // Optional
    upstreamManager   *upstream.Manager     // Optional
    subscriberManager *subscriber.Manager
}
```

**Methods:**
- `processBatch(batch *data.PacketBatch)` - 141 lines
  - Accesses: ALL fields above
  - Critical hot path - performance sensitive

**Initialization Logic:**
- Lines 138-168 from New() (protocol detection, PCAP writers)
- Lines 133-134 from New() (call aggregator/correlator)

**Challenges:**
1. **High Coupling**: processBatch needs 9+ different managers
2. **Shared State**: Needs access to hunterManager, upstreamManager, subscriberManager (not truly "core")
3. **Mixed Concerns**: PCAP writing, VIF injection, call analysis, enrichment all in one method
4. **Counter Sharing**: packetsReceived/packetsForwarded used by multiple components

**Lines of Code:**
- Fields: ~15 lines
- processBatch: ~141 lines
- Initialization: ~50 lines
- **Total: ~210 lines** (excluding manager dependencies)

**Actual Coupling Reality:**
ProcessorCore as proposed would still need access to:
- `hunterManager` (to update packet stats)
- `pcapWriter` (to queue packets)
- `upstreamManager` (to forward packets)
- `subscriberManager` (to broadcast packets)
- `vifManager` (to inject packets)

This means ProcessorCore wouldn't truly be "core packet processing" - it would still be a coordinator.

### 10.2 ProcessorServer Component Analysis

**Proposed Responsibilities** (from Phase 2.2):
- Hunter management
- Subscriber management
- Filter management
- Flow control

**Actual Implementation Requirements:**

**Fields Required:**
```go
type ProcessorServer struct {
    config Config  // Full config needed for TLS, auth, limits

    // gRPC infrastructure
    grpcServer *grpc.Server
    listener   net.Listener

    // Manager references
    hunterManager     *hunter.Manager
    hunterMonitor     *hunter.Monitor
    filterManager     *filtering.Manager
    flowController    *flow.Controller
    subscriberManager *subscriber.Manager
    downstreamManager *downstream.Manager
    upstreamManager   *upstream.Manager  // Needed for GetTopology
    proxyManager      *proxy.Manager
    statsCollector    *stats.Collector

    // Call data (for SubscribeCorrelatedCalls)
    callCorrelator *CallCorrelator

    // Context for shutdown
    ctx    context.Context
    cancel context.CancelFunc
    wg     sync.WaitGroup
}
```

**Methods** (21 gRPC service methods):
1. `StreamPackets()` - 44 lines (but calls processBatch which is in Core!)
2. `RegisterHunter()` - 37 lines
3. `Heartbeat()` - 44 lines
4. `GetFilters()` - 6 lines
5. `SubscribeFilters()` - 54 lines
6. `GetHunterStatus()` - 32 lines
7. `ListAvailableHunters()` - 25 lines
8. `RegisterProcessor()` - 94 lines
9. `GetTopology()` - 51 lines
10. `SubscribeTopology()` - 53 lines
11. `UpdateFilter()` - 16 lines
12. `DeleteFilter()` - 16 lines
13. `UpdateFilterOnProcessor()` - 104 lines
14. `DeleteFilterOnProcessor()` - 102 lines
15. `GetFiltersFromProcessor()` - 97 lines
16. `RequestAuthToken()` - 35 lines
17. `SubscribePackets()` - 90 lines
18. `SubscribeCorrelatedCalls()` - 42 lines
19. `buildTLSCredentials()` - 7 lines
20. `createReuseAddrListener()` - 15 lines
21. `correlatedCallToProto()` - 28 lines

**Helper Functions:**
- `convertChainErrorToStatus()` - 19 lines
- `extractAuditContext()` - 21 lines
- `logAuditOperationStart()` - 10 lines
- `logAuditAuthSuccess()` - 9 lines
- `logAuditAuthFailure()` - 9 lines
- `logAuditOperationResult()` - 19 lines

**Lines of Code:**
- Methods: ~1,089 lines
- Helpers: ~87 lines
- **Total: ~1,176 lines**

**Critical Problem:**
`StreamPackets()` receives packets and calls `processBatch()`. Where does processBatch live?
- If in ProcessorCore: ProcessorServer needs reference to Core
- If in ProcessorServer: Core can't process packets independently

**Circular Dependency Risk:**
```
ProcessorServer.StreamPackets()
    ↓
ProcessorCore.processBatch()
    ↓
subscriberManager.Broadcast() (in Server?)
upstreamManager.Forward() (in Server?)
```

### 10.3 ProcessorOrchestrator Component Analysis

**Proposed Responsibilities** (from Phase 2.2):
- Manager coordination
- Upstream/downstream management
- Virtual interface management
- Proxy topology

**Actual Implementation Requirements:**

**Fields Required:**
```go
type ProcessorOrchestrator struct {
    config Config

    // Components
    core   *ProcessorCore
    server *ProcessorServer

    // Or keep all managers here?
    hunterManager     *hunter.Manager
    filterManager     *filtering.Manager
    statsCollector    *stats.Collector
    // ... all other managers

    // Lifecycle
    ctx    context.Context
    cancel context.CancelFunc
    wg     sync.WaitGroup
}
```

**Methods:**
- `New()` - 197 lines (massive initialization)
- `Start()` - 179 lines (server startup, blocking)
- `Shutdown()` - 58 lines (cleanup)
- `GetStats()` - 2 lines
- `SetProxyTLSCredentials()` - 4 lines

**Lines of Code:**
- New: 197 lines
- Start: 179 lines
- Shutdown: 58 lines
- **Total: ~440 lines**

**Critical Questions:**
1. **Who owns the managers?**
   - Orchestrator owns and passes to Core/Server?
   - Or each component owns its managers?

2. **Who owns the gRPC server?**
   - Server owns grpcServer but Orchestrator.Start() creates it?

3. **How is processBatch accessed?**
   - StreamPackets (in Server) needs to call processBatch (in Core)

### 10.4 Dependency Graph After Split

**Current (Monolithic):**
```
Processor
├── owns all managers
├── implements all gRPC methods
├── has processBatch method
└── has Start/Shutdown lifecycle
```

**Proposed Split (Naive):**
```
ProcessorOrchestrator
├── owns: hunterManager, filterManager, statsCollector, etc.
├── creates: ProcessorCore, ProcessorServer
│
ProcessorCore
├── receives: detector, enricher, callAggregator, etc.
├── method: processBatch()
│
ProcessorServer
├── receives: hunterManager, filterManager, subscriberManager, etc.
├── implements: all gRPC methods
├── calls: ProcessorCore.processBatch()
```

**Problem**: ProcessorCore.processBatch() needs access to:
- hunterManager (owned by Orchestrator)
- subscriberManager (owned by Orchestrator)
- upstreamManager (owned by Orchestrator)

**Reality**: Either:
1. Pass all managers to processBatch as parameters (ugly)
2. Core holds references to all managers (defeats purpose)
3. Orchestrator coordinates by calling methods on Core and Server (complex)

### 10.5 Alternative Architecture Analysis

**Alternative 1: Keep Processor Monolithic, Extract Helpers**

Instead of splitting Processor into three components, extract helper functions:

```go
// processor.go (remains main file)
type Processor struct {
    // ... existing fields ...
}

// processor_packet_pipeline.go
func (p *Processor) processBatch(batch *data.PacketBatch) {
    // Existing implementation
}

func (p *Processor) enrichPackets(batch *data.PacketBatch) { ... }
func (p *Processor) aggregateCalls(batch *data.PacketBatch) { ... }
func (p *Processor) writePCAP(batch *data.PacketBatch) { ... }

// processor_grpc_handlers.go
func (p *Processor) StreamPackets(...) { ... }
func (p *Processor) RegisterHunter(...) { ... }
// ... other gRPC methods ...

// processor_lifecycle.go
func (p *Processor) Start(...) { ... }
func (p *Processor) Shutdown(...) { ... }
```

**Benefits:**
- No structural changes
- No manager ownership issues
- No circular dependencies
- Easy to implement
- Tests unchanged

**Drawbacks:**
- Doesn't reduce Processor size (still 17 fields)
- Doesn't create independent components
- File splitting only (cosmetic)

**Effort:** 4-8 hours

---

**Alternative 2: Extract Manager Container**

Create a container for all managers, reducing Processor fields:

```go
// processor_managers.go
type Managers struct {
    Hunter      *hunter.Manager
    Filter      *filtering.Manager
    Flow        *flow.Controller
    Stats       *stats.Collector
    Subscriber  *subscriber.Manager
    Upstream    *upstream.Manager
    Downstream  *downstream.Manager
    Proxy       *proxy.Manager
    PCAP        *pcap.Writer
    PerCallPCAP *PcapWriterManager
    AutoPCAP    *AutoRotatePcapWriter
    Enricher    *enrichment.Enricher
    Detector    *detector.Detector
    VIF         vinterface.Manager
}

// processor.go
type Processor struct {
    config Config
    mgr    *Managers  // Single field instead of 14

    // Protocol aggregators (frequently accessed)
    callAggregator *voip.CallAggregator
    callCorrelator *CallCorrelator

    // gRPC infrastructure
    grpcServer *grpc.Server
    listener   net.Listener

    // Lifecycle
    ctx    context.Context
    cancel context.CancelFunc
    wg     sync.WaitGroup
}

func (p *Processor) processBatch(batch *data.PacketBatch) {
    p.mgr.Hunter.UpdatePacketStats(...)
    p.mgr.PCAP.QueuePackets(...)
    // etc.
}
```

**Benefits:**
- Reduces Processor from 17 fields to ~7
- Clear manager grouping
- No circular dependencies
- Tests need minimal changes

**Drawbacks:**
- Adds indirection (p.mgr.Hunter instead of p.hunterManager)
- Slightly slower (one extra pointer dereference)
- Doesn't separate concerns (still one Processor)

**Effort:** 16-24 hours

---

**Alternative 3: Extract Packet Processing Pipeline**

Create a dedicated pipeline for packet processing:

```go
// packet_pipeline.go
type PacketPipeline struct {
    detector         *detector.Detector
    enricher         *enrichment.Enricher
    callAggregator   *voip.CallAggregator
    callCorrelator   *CallCorrelator
    pcapWriter       *pcap.Writer
    perCallPcap      *PcapWriterManager
    autoRotatePcap   *AutoRotatePcapWriter
    vifManager       vinterface.Manager

    packetsReceived  *atomic.Uint64
}

func (pp *PacketPipeline) Process(
    batch *data.PacketBatch,
    hunterID string,
    upstream *upstream.Manager,
    subscriber *subscriber.Manager,
) error {
    // Protocol detection & enrichment
    if pp.enricher != nil {
        pp.enricher.Enrich(batch.Packets)
    }

    // Call aggregation
    pp.callAggregator.ProcessPacket(...)
    pp.callCorrelator.ProcessPacket(...)

    // PCAP writing
    pp.pcapWriter.QueuePackets(...)
    pp.perCallPcap.Write(...)
    pp.autoRotatePcap.Write(...)

    // Forward/broadcast (still needs manager access)
    upstream.Forward(batch)
    subscriber.Broadcast(batch)

    return nil
}

// processor.go
type Processor struct {
    config   Config
    pipeline *PacketPipeline  // Extracted!

    // Managers
    hunterManager     *hunter.Manager
    filterManager     *filtering.Manager
    subscriberManager *subscriber.Manager
    upstreamManager   *upstream.Manager
    // ... other managers

    // gRPC
    grpcServer *grpc.Server
    listener   net.Listener
}

func (p *Processor) processBatch(batch *data.PacketBatch) {
    p.pipeline.Process(
        batch,
        hunterID,
        p.upstreamManager,
        p.subscriberManager,
    )
}
```

**Benefits:**
- Separates packet processing logic
- Reduces processBatch complexity
- Pipeline is testable independently
- Clear separation of concerns

**Drawbacks:**
- Pipeline still needs manager access (passed as parameters)
- Adds complexity (function parameters)
- Not a full "component" extraction

**Effort:** 12-16 hours

---

### 10.6 Recommended Approach Assessment

**For Phase 2.2's Stated Goals:**
The three-way split (ProcessorCore, ProcessorServer, ProcessorOrchestrator) has **significant architectural challenges**:

**Problems:**
1. **Circular Dependencies**: Server calls Core, Core needs managers from Orchestrator
2. **Manager Ownership**: Unclear who owns hunterManager, filterManager, etc.
3. **Shared State**: packetsReceived/packetsForwarded counters needed by multiple components
4. **processBatch Coupling**: Needs access to 9+ managers across all three components
5. **High Complexity**: 40-60 hours effort + 20-30 hours test updates

**Revised Recommendation:**

**Option A: Alternative 1 (File Splitting)**
- **Effort**: 4-8 hours
- **Risk**: Very low
- **Benefit**: Improved file organization, easier navigation
- **Drawback**: Doesn't reduce coupling or field count

**Option B: Alternative 2 (Manager Container)**
- **Effort**: 16-24 hours
- **Risk**: Low
- **Benefit**: Reduced field count (17 → 7), clearer grouping
- **Drawback**: Adds indirection layer

**Option C: Alternative 3 (Pipeline Extraction)**
- **Effort**: 12-16 hours
- **Risk**: Medium
- **Benefit**: Separates processing logic, testable pipeline
- **Drawback**: Parameter passing complexity

**Option D: Phase 2.2 As Proposed (Three-Way Split)**
- **Effort**: 40-60 hours + 20-30 hours testing
- **Risk**: High (circular dependencies, unclear ownership)
- **Benefit**: Full component separation
- **Drawback**: Complex architecture, may introduce bugs

**Recommendation for Phase 2.2:**
1. **Start with Option A** (file splitting) - quick win, low risk
2. **Evaluate Option B** (manager container) - medium effort, clear benefit
3. **Defer Option D** (three-way split) - too complex, unclear benefits outweigh risks

### 10.7 Specific Action Items for Phase 2.2

If proceeding with **Option A (File Splitting)**:

1. Create `processor_packet_pipeline.go`:
   - Move `processBatch()` method
   - Move packet processing helpers

2. Create `processor_grpc_handlers.go`:
   - Move all gRPC service methods (21 methods)
   - Move gRPC helper functions

3. Create `processor_lifecycle.go`:
   - Move `Start()` method
   - Move `Shutdown()` method
   - Move `createReuseAddrListener()` helper

4. Keep in `processor.go`:
   - Type definitions (Config, Processor)
   - `New()` constructor
   - `GetStats()` accessor
   - Embedded gRPC interfaces

5. Update imports in all files

6. Run tests: `make test`

7. Update documentation in `cmd/process/CLAUDE.md`

**Files Created:**
- `processor_packet_pipeline.go` (~200 lines)
- `processor_grpc_handlers.go` (~1,200 lines)
- `processor_lifecycle.go` (~250 lines)

**processor.go Remaining:**
- ~270 lines (Config, Processor struct, New(), imports)

**Result:**
- 1,921 lines → 4 files averaging ~480 lines each
- No structural changes
- All tests pass unchanged
- Low risk, quick implementation

---

If proceeding with **Option B (Manager Container)**:

1. Create `processor_managers.go` with Managers struct
2. Update `New()` to create Managers instance
3. Update all field references: `p.hunterManager` → `p.mgr.Hunter`
4. Update tests to access managers through container
5. Add documentation for manager container pattern

**Effort:** 16-24 hours + test updates

---

If proceeding with **Option D (Three-Way Split as Proposed)**:

**Pre-requisites:**
1. Resolve manager ownership model
2. Design interface for Core ↔ Server communication
3. Design interface for Orchestrator ↔ Core/Server coordination
4. Prototype processBatch refactoring to eliminate 9+ manager dependencies

**Implementation Steps:**
1. Create ProcessorCore with minimal dependencies
2. Create ProcessorServer with gRPC methods
3. Refactor ProcessorOrchestrator to coordinate both
4. Resolve circular dependencies via interfaces
5. Update all 6 test files
6. Update cmd/process/main.go
7. Update documentation

**Effort:** 40-60 hours + 20-30 hours testing
**Risk:** High - circular dependencies, unclear benefits

**Recommendation:** Defer until Option A or B proves insufficient.


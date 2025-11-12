# Protocol Analyzer Framework

## Overview

The `analyzer` package provides a compile-time protocol analysis framework for lippycat. Protocol modules are statically compiled into the binary and register themselves at initialization time, providing cross-platform compatibility without the maintenance burden of dynamic plugins.

## Architecture

### Design Principles

1. **Compile-Time Registration**: Protocol analyzers are compiled into the binary and register via `init()` functions
2. **Cross-Platform**: No dynamic loading (.so files) - works on all platforms including Windows
3. **Type-Safe**: Full compile-time type checking of all protocol implementations
4. **High Performance**: No dynamic loading overhead, direct function calls
5. **Simple Maintenance**: Standard Go interfaces and packages

### Key Components

- **`Protocol` Interface**: Defines the contract all protocol analyzers must implement
- **`Registry`**: Manages registered protocols and routes packets to appropriate analyzers
- **Protocol Modules**: Individual protocol implementations (VoIP, HTTP, DNS, etc.)

## Adding a New Protocol Analyzer

### Step 1: Create Protocol Implementation

Create a new file in `internal/pkg/analyzer/` (e.g., `http_protocol.go`):

```go
package analyzer

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
)

// HTTPProtocol implements Protocol for HTTP/HTTPS traffic analysis
type HTTPProtocol struct {
	name    string
	version string
	enabled atomic.Bool
	metrics httpMetrics
}

type httpMetrics struct {
	packetsProcessed atomic.Int64
	requestsSeen     atomic.Int64
	responsesSeen    atomic.Int64
	errorCount       atomic.Int64
	processingTime   atomic.Int64
}

// NewHTTPProtocol creates a new HTTP protocol analyzer
func NewHTTPProtocol() *HTTPProtocol {
	return &HTTPProtocol{
		name:    "HTTP Protocol Analyzer",
		version: "1.0.0",
	}
}

func (h *HTTPProtocol) Name() string {
	return h.name
}

func (h *HTTPProtocol) Version() string {
	return h.version
}

func (h *HTTPProtocol) SupportedProtocols() []string {
	return []string{"http", "https"}
}

func (h *HTTPProtocol) ProcessPacket(ctx context.Context, packet gopacket.Packet) (*Result, error) {
	if !h.enabled.Load() {
		return nil, nil
	}

	start := time.Now()
	defer func() {
		h.metrics.packetsProcessed.Add(1)
		h.metrics.processingTime.Add(time.Since(start).Nanoseconds())
	}()

	// TODO: Implement HTTP packet analysis
	// - Parse HTTP headers
	// - Extract session/flow identifiers
	// - Track request/response pairs
	// - Return Result with extracted metadata

	return nil, nil
}

func (h *HTTPProtocol) Initialize(config map[string]interface{}) error {
	h.enabled.Store(true)
	// TODO: Process configuration settings
	return nil
}

func (h *HTTPProtocol) Shutdown(ctx context.Context) error {
	h.enabled.Store(false)
	return nil
}

func (h *HTTPProtocol) HealthCheck() HealthStatus {
	if !h.enabled.Load() {
		return HealthStatus{
			Status:    HealthUnhealthy,
			Message:   "Analyzer disabled",
			Timestamp: time.Now(),
		}
	}

	return HealthStatus{
		Status:    HealthHealthy,
		Message:   "Operating normally",
		Timestamp: time.Now(),
		Details: map[string]interface{}{
			"packets_processed": h.metrics.packetsProcessed.Load(),
			"requests_seen":     h.metrics.requestsSeen.Load(),
			"responses_seen":    h.metrics.responsesSeen.Load(),
		},
	}
}

func (h *HTTPProtocol) Metrics() Metrics {
	return Metrics{
		PacketsProcessed: h.metrics.packetsProcessed.Load(),
		ProcessingTime:   time.Duration(h.metrics.processingTime.Load()),
		ErrorCount:       h.metrics.errorCount.Load(),
		CustomMetrics: map[string]interface{}{
			"requests_seen":  h.metrics.requestsSeen.Load(),
			"responses_seen": h.metrics.responsesSeen.Load(),
		},
	}
}

// Register the HTTP protocol analyzer at initialization
func init() {
	config := DefaultConfig()
	config.Priority = 50 // Medium priority
	config.Timeout = 2 * time.Second

	GetRegistry().MustRegister("http", NewHTTPProtocol(), config)
}
```

### Step 2: Import in Application

The protocol will be automatically registered when the package is imported. Add to your main package or anywhere in the import tree:

```go
import (
	_ "github.com/endorses/lippycat/internal/pkg/analyzer" // Registers all protocols
)
```

### Step 3: Use the Registry

```go
// Process a packet through all registered analyzers
registry := analyzer.GetRegistry()
results, err := registry.ProcessPacket(ctx, packet)
if err != nil {
	log.Printf("Analysis error: %v", err)
}

for _, result := range results {
	log.Printf("Detected %s protocol (confidence: %.2f)", result.Protocol, result.Confidence)
	// Handle protocol-specific result
}
```

## Protocol Priority

Protocols are processed in priority order (highest first). Use priority to control processing order:

- **100+**: Critical protocols (VoIP, time-sensitive)
- **50-99**: Standard protocols (HTTP, DNS)
- **0-49**: Generic/fallback analyzers

## Configuration

Protocol analyzers can be configured via YAML:

```yaml
analyzer:
  protocols:
    voip:
      enabled: true
      priority: 100
      timeout: 5s
      settings:
        track_rtp: true
        sip_ports: [5060, 5061]

    http:
      enabled: true
      priority: 50
      timeout: 2s
      settings:
        track_sessions: true
        max_body_size: 1048576
```

## Testing Protocol Analyzers

```go
func TestHTTPProtocol_ProcessPacket(t *testing.T) {
	protocol := NewHTTPProtocol()
	config := DefaultConfig()

	err := protocol.Initialize(config.Settings)
	require.NoError(t, err)

	// Create test packet
	packet := createHTTPTestPacket()

	// Process packet
	result, err := protocol.ProcessPacket(context.Background(), packet)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify result
	assert.Equal(t, "http", result.Protocol)
	assert.Greater(t, result.Confidence, 0.8)
}
```

## Metrics and Health Monitoring

```go
// Get all protocol health statuses
healthMap := registry.HealthCheck()
for name, health := range healthMap {
	log.Printf("%s: %s - %s", name, health.Status, health.Message)
}

// Get registry statistics
stats := registry.GetStats()
log.Printf("Total protocols: %d", stats.TotalProtocols.Load())
log.Printf("Active protocols: %d", stats.ActiveProtocols.Load())
log.Printf("Packets processed: %d", stats.PacketsProcessed.Load())
```

## Migration from Old Plugin System

The old `internal/pkg/voip/plugins/` system used Go's dynamic plugin loading (`.so` files), which had OS limitations. The new `analyzer` framework provides:

### Benefits of New System

| Feature | Old (plugins) | New (analyzer) |
|---------|--------------|----------------|
| **Platform Support** | Linux/macOS only | All platforms (Windows, Linux, macOS) |
| **Loading Method** | Dynamic .so files | Compile-time static |
| **Type Safety** | Runtime symbol lookup | Compile-time checking |
| **Performance** | Dynamic loading overhead | Direct function calls |
| **Maintenance** | Complex plugin lifecycle | Standard Go packages |
| **Testing** | Requires .so builds | Standard Go tests |
| **Deployment** | Multiple .so files | Single binary |

### Migration Path

1. **Phase 1**: Create new protocol modules in `analyzer/` package
2. **Phase 2**: Update references from `plugins.GetGlobalRegistry()` to `analyzer.GetRegistry()`
3. **Phase 3**: Remove old `internal/pkg/voip/plugins/` directory
4. **Phase 4**: Update documentation and examples

## Best Practices

### 1. Thread Safety
- Use `atomic` types for metrics counters
- Avoid shared mutable state in protocol analyzers
- Protocol instances are shared across goroutines

### 2. Performance
- Keep `ProcessPacket()` fast (<1ms for common cases)
- Use context timeouts to prevent hangs
- Return `nil` quickly for non-matching packets

### 3. Error Handling
- Return errors for unexpected conditions
- Log warnings for malformed packets
- Don't panic in packet processing

### 4. Resource Management
- Clean up resources in `Shutdown()`
- Respect context cancellation
- Monitor memory usage in metrics

### 5. Testing
- Test with real packet captures (testdata/*.pcap)
- Include edge cases (malformed packets, truncated data)
- Verify thread safety with `-race` flag

## Example: Complete Protocol Implementation

See `voip_protocol.go` for a complete example of:
- Protocol interface implementation
- Metrics tracking
- Health monitoring
- Init-based registration
- Context-aware processing

## Future Protocol Candidates

Potential protocols to add:

- **HTTP/HTTPS**: Web traffic analysis, session tracking
- **DNS**: Query/response tracking, domain monitoring
- **TLS**: Certificate inspection, version detection
- **MySQL/PostgreSQL**: Database query monitoring
- **MQTT**: IoT message tracking
- **gRPC**: RPC call monitoring

Each protocol module is independent and can be added without modifying existing analyzers.

## Architecture Diagram

```
┌─────────────────────────────────────────────┐
│          Packet Capture Layer               │
│         (gopacket + libpcap)                │
└───────────────┬─────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────┐
│       Protocol Detection Layer              │
│      (internal/pkg/detector)                │
│   - Signature-based detection               │
│   - Returns protocol hint                   │
└───────────────┬─────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────┐
│          Protocol Registry                  │
│      (analyzer.GetRegistry())               │
│   - Routes to appropriate analyzer          │
│   - Manages priority ordering               │
└───────────────┬─────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────┐
│       Protocol Analyzers (Parallel)         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
│  │  VoIP   │  │  HTTP   │  │  DNS    │    │
│  │ (prio100│  │ (prio50)│  │ (prio50)│    │
│  └─────────┘  └─────────┘  └─────────┘    │
│   - SIP/RTP     - Requests   - Queries     │
│   - Call track  - Sessions   - Responses   │
└───────────────┬─────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────┐
│           Analysis Results                  │
│   - Protocol metadata                       │
│   - Session/Call identifiers                │
│   - Confidence scores                       │
│   - Action recommendations                  │
└─────────────────────────────────────────────┘
```

## See Also

- [Protocol Detector](../detector/README.md) - Signature-based protocol detection
- [VoIP Analysis](../voip/README.md) - VoIP-specific call tracking
- [Capture Pipeline](../capture/README.md) - Packet capture infrastructure

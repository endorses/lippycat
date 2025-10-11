# lippycat - Network Traffic Sniffer

## Project Overview
lippycat is a Go-based CLI tool for sniffing and analyzing network traffic. It is a general-purpose network packet analyzer with a **plugin architecture** that allows it to support different protocol-specific analysis modules. It captures traffic from network interfaces or PCAP files and provides both CLI and TUI (Terminal User Interface) modes for real-time monitoring.

**Current Protocol Support**: As of now, lippycat includes a VoIP plugin that analyzes SIP (Session Initiation Protocol) and RTP (Real-time Transport Protocol) traffic.

## Architecture

### Distributed Architecture
lippycat supports a distributed capture architecture with two node types:

- **Hunter Nodes**: Lightweight capture agents that sniff packets on network interfaces and forward them to processor nodes for analysis. Hunters can be deployed across multiple network segments or hosts.
- **Processor Nodes**: Central analysis nodes that receive packets from multiple hunters, perform protocol analysis, and provide the TUI/CLI interface for monitoring and analysis.

This architecture allows for:
- **Distributed packet capture** across multiple network segments
- **Centralized analysis and monitoring** through a single TUI interface
- **Scalable deployment** with multiple hunters feeding one or more processors
- **Network segmentation** where hunters capture in restricted zones and processors analyze in monitoring zones

### Core Architecture
- **CLI Framework**: Uses Cobra CLI framework with Viper for configuration
- **Plugin System**: Extensible architecture allowing protocol-specific analyzers to be added
- **Build Tags**: Go build tags enable specialized binary variants (hunter, processor, cli, tui, all)
- **Main Components**:
  - `cmd/`: CLI command definitions with build-tag-based variants
  - `cmd/tui/`: Terminal User Interface with Bubbletea framework
  - `cmd/hunt/`: Hunter node implementation for distributed capture
  - `cmd/process/`: Processor node implementation for distributed analysis
  - `internal/pkg/types/`: Shared domain types (PacketDisplay, VoIPMetadata, EventHandler)
  - `internal/pkg/capture/`: Network packet capture functionality using gopacket
  - `internal/pkg/voip/`: VoIP protocol plugin (SIP, RTP, call tracking)
  - `internal/pkg/hunter/`: Hunter node core logic and gRPC client
  - `internal/pkg/processor/`: Processor node core logic and gRPC server
  - `internal/pkg/remotecapture/`: Remote capture infrastructure with EventHandler pattern
  - `internal/pkg/detector/`: Protocol detection with signature-based matching
  - `internal/pkg/simd/`: SIMD optimizations (AVX2/SSE4.2)
  - `internal/pkg/logger/`: Structured logging
  - `api/proto/`: gRPC protocol buffer definitions
  - `api/gen/`: Generated gRPC code for data and management services

## Key Dependencies
- `github.com/spf13/cobra`: CLI framework
- `github.com/spf13/viper`: Configuration management
- `github.com/google/gopacket`: Network packet capture and analysis
- `github.com/charmbracelet/bubbletea`: TUI framework
- `github.com/charmbracelet/lipgloss`: TUI styling
- `github.com/stretchr/testify`: Testing framework

## Build and Development Commands

### Build
```bash
# Development build (complete suite, unstripped)
make build        # ~31 MB with debug symbols

# Build all specialized variants (stripped, optimized)
make binaries

# Build specific variants (outputs to bin/ directory, all stripped)
make all          # Complete suite (22 MB) - all commands
make hunter       # Hunter node (18 MB) - edge capture with GPU filtering
make processor    # Processor node (14 MB) - central aggregation
make cli          # CLI tools only - sniff, debug, interfaces
make tui          # TUI only - terminal interface

# Optimized release build (stripped)
make build-release  # 22 MB

# Quick dev build (unstripped, no version info)
make dev           # ~31 MB

# Build with CUDA GPU acceleration
make build-cuda

# Profile-guided optimization build
make build-pgo
```

**Build Tags:** The project uses Go build tags to create specialized binaries:
- `all`: Complete suite with all commands (default)
- `hunter`: Hunter node only - includes GPU acceleration and protocol detection
- `processor`: Processor node only - includes protocol analysis and gRPC server
- `cli`: CLI commands only - sniff, debug, interfaces
- `tui`: TUI interface only - terminal UI with remote monitoring

Each specialized build is stripped (`-s -w`) and optimized to reduce binary size while maintaining full functionality for its role. Hunter nodes include all protocol detectors and GPU acceleration for edge filtering.

### Install
```bash
# Install to GOPATH/bin
make install

# Install system-wide to /usr/local/bin (requires sudo)
make install-system
```

### Test
```bash
make test          # Run all tests
make test-verbose  # Verbose test output
make test-coverage # Generate coverage report
make bench         # Run benchmarks
```

### Format and Lint
```bash
make fmt   # Format code
make vet   # Run go vet
```

### Module Management
```bash
make tidy  # Run go mod tidy
```

### Clean
```bash
make clean          # Remove build artifacts
make clean-binaries # Remove all specialized binaries
make clean-cuda     # Remove CUDA artifacts
```

## Development Guidelines

1. **Code Structure**: Follow Go module structure with internal packages
2. **Testing**: Use testify framework for unit tests (test pcap files are in `captures/`)
3. **Error Handling**: Use standard Go error handling patterns
4. **Concurrency**: Project uses goroutines and channels for concurrent packet processing
5. **Network Interfaces**: Requires elevated privileges for live network capture
6. **12-Factor App**: Follow the 12 factors.

## Security Considerations
- This is a **defensive security tool** for network monitoring and protocol analysis
- Requires appropriate permissions for network interface access
- Used for legitimate network diagnostics, troubleshooting, and security monitoring

## CLI Usage

### Available Commands
- `lc sniff`: CLI mode for packet capture with various output formats
- `lc sniff voip`: VoIP-specific packet capture with SIP/RTP analysis
- `lc tui`: TUI mode for interactive real-time packet monitoring on local interface
- `lc hunt`: Hunter node for distributed capture (forwards packets to processor)
- `lc process`: Processor node for distributed analysis (receives from hunters)
- `lc interfaces`: List available network interfaces
- `lc debug`: Debug and inspect TCP SIP processing components

### Standalone Mode
```bash
# General packet capture
sudo lc sniff --interface eth0 --filter "port 80"

# VoIP-specific capture
sudo lc sniff voip --interface eth0 --sipuser alice

# Interactive TUI
sudo lc tui
```

### Distributed Mode
```bash
# Start processor node (receives packets from hunters)
lc process --listen 0.0.0.0:50051

# Start hunter node (captures and forwards packets)
sudo lc hunt --interface eth0 --processor processor-host:50051

# Monitor remote nodes via TUI
lc tui --remote --nodes-file nodes.yaml
```

Configuration via YAML file (in priority order):
1. `$HOME/.config/lippycat/config.yaml` (preferred)
2. `$HOME/.config/lippycat.yaml` (XDG standard)
3. `$HOME/.lippycat.yaml` (legacy)

## Architecture Patterns

### EventHandler Pattern
The `internal/pkg/remotecapture` package uses the EventHandler pattern to decouple infrastructure from presentation:

```go
// internal/pkg/types/events.go
type EventHandler interface {
    OnPacketBatch(packets []PacketDisplay)
    OnHunterStatus(hunters []HunterInfo, processorID string)
    OnDisconnect(address string, err error)
}
```

This allows the remote capture client to work with different frontends (TUI, CLI, Web) without coupling to specific UI frameworks.

### Shared Types
`internal/pkg/types` provides domain types shared across packages:
- `PacketDisplay`: Common packet representation
- `VoIPMetadata`: VoIP-specific packet metadata
- `HunterInfo`: Hunter node status
- `EventHandler`: Event notification interface

This prevents circular dependencies and maintains clean architecture boundaries (cmd ← internal, never internal → cmd).

### Build Tag Architecture
Each command has build-tagged root files:
- `cmd/root_all.go`: Complete suite (`//go:build all`)
- `cmd/root_hunter.go`: Hunter only (`//go:build hunter && !all`)
- `cmd/root_processor.go`: Processor only (`//go:build processor && !all`)
- `cmd/root_cli.go`: CLI only (`//go:build cli && !all`)
- `cmd/root_tui.go`: TUI only (`//go:build tui && !all`)

Commands register themselves in their respective root files, allowing the compiler to exclude unused code paths.

### Flow Control Architecture
Flow control in the distributed system follows a hierarchical principle:

**Processor-Level Flow Control:**
- Hunters respond to processor-level overload (PCAP write queue, upstream backlog)
- Flow control states: CONTINUE, SLOW, PAUSE, RESUME
- Based on queue utilization thresholds (30%, 70%, 90%)

**Critical Architectural Decision (v0.2.4):**
TUI client drops do NOT affect hunter flow control because:
1. Multiple TUI clients may be connected simultaneously
2. Processor may be writing to PCAP files or forwarding upstream
3. There may be multiple downstream consumers
4. Slow clients are handled by per-subscriber channel buffering and selective drops

**Implementation:**
- `internal/pkg/processor/processor.go`: `determineFlowControl()` only checks PCAP queue
- Per-subscriber buffering prevents slow clients from blocking others
- Packet batches are cloned before broadcasting to prevent concurrent serialization races

### TLS/mTLS Security
The distributed system supports TLS encryption with mutual authentication:

**Features:**
- Optional TLS for all gRPC connections (hunter→processor, processor→processor, TUI→processor)
- Mutual TLS (mTLS) with client certificate verification
- Per-node TLS configuration in nodes.yaml
- Self-signed certificate generation scripts for testing

**Configuration:**
```yaml
# Global TLS config
tls:
  enabled: true
  ca_file: /path/to/ca.crt
  cert_file: /path/to/server.crt
  key_file: /path/to/server.key
  skip_verify: false  # Set to true only for testing

# Per-node TLS override in nodes.yaml
processors:
  - name: secure-processor
    address: processor.local:50051
    tls:
      enabled: true
      ca_file: /path/to/ca.crt
      cert_file: /path/to/client.crt
      key_file: /path/to/client.key
```

**Certificate Requirements:**
- Subject Alternative Name (SAN) must match hostname/IP
- CN field no longer sufficient (deprecated in Go 1.15+)
- See `test/testcerts/generate_test_certs.sh` for examples

### Hunter Subscription Management (v0.2.4)
TUI clients can selectively subscribe to specific hunters on a processor:

**Features:**
- Subscribe to all hunters on a processor (default)
- Subscribe to specific hunters by ID (selective monitoring)
- Unsubscribe from hunters to stop receiving packets
- Multi-select interface with visual feedback

**TUI Controls:**
- Press `s` on a processor to select hunters to subscribe to
- Press `d` on a hunter to unsubscribe or on a processor to remove it
- Multi-select with arrow keys and Enter to confirm

**Implementation Details:**
- Uses `has_hunter_filter` boolean to distinguish empty list from nil (Proto3 serialization)
- Prevents subscriber backpressure from affecting hunter flow control
- Packets are filtered at the processor before being sent to TUI clients

### TUI Modal Architecture

**IMPORTANT: All modals in the TUI MUST use the unified modal component.**

The TUI uses a standardized modal architecture to ensure consistency across all modal dialogs. There is ONE modal rendering function that all modal components must use:

**Unified Modal Component:** `cmd/tui/components/modal.go`

The `RenderModal()` function provides consistent modal chrome (border, centering, title, footer) for all modals in the codebase.

**Architecture Pattern:**

1. **Modal Content Components** manage their own:
   - State (selection, input, navigation)
   - Content rendering (building the modal body as a string)
   - Event handling (keyboard/mouse events)
   - Business logic (search, filtering, CRUD operations)

2. **Modal Content Components** call `RenderModal()` to wrap their content:
   ```go
   func (component *Component) View() string {
       if !component.active {
           return ""
       }

       // Build content string
       var content strings.Builder
       content.WriteString("My modal content...")

       // Use unified modal rendering
       return RenderModal(ModalRenderOptions{
           Title:      "My Modal Title",
           Content:    content.String(),
           Footer:     "Enter: Select | Esc: Cancel",
           Width:      component.width,
           Height:     component.height,
           Theme:      component.theme,
           ModalWidth: 60, // Optional: specific width
       })
   }
   ```

3. **Parent (model.go)** handles:
   - Checking if modal is active (`IsActive()`)
   - Routing events to the modal
   - Overlaying the modal on the main view

**Current Modal Components (all using unified RenderModal):**
- `ProtocolSelector` - Protocol filter selection (`cmd/tui/components/protocolselector.go`)
- `HunterSelector` - Hunter subscription selection (`cmd/tui/components/hunterselector.go`)
- `NodesView.renderAddNodeModal` - Add processor/hunter node (`cmd/tui/components/nodesview.go`)

**When Creating New Modals:**
- ✅ DO: Create a component that manages state and content
- ✅ DO: Call `RenderModal()` in your component's `View()` method
- ✅ DO: Follow the same lifecycle pattern (Activate/Deactivate/IsActive/View/Update)
- ❌ DON'T: Render modal chrome (border, centering) yourself
- ❌ DON'T: Create custom modal styling - use RenderModal for consistency
- ❌ DON'T: Duplicate modal rendering logic

**Benefits:**
- Consistent look and feel across all modals
- Centralized styling and theming
- Easy to maintain and update modal appearance
- Reduces code duplication
- Clear separation of concerns (content vs. chrome)

## Plugin Architecture
lippycat is designed with extensibility in mind. Protocol-specific analyzers can be added as plugins to support different types of traffic analysis beyond VoIP.

The hunter node includes protocol detection for multiple protocols (HTTP, DNS, TLS, MySQL, PostgreSQL, VoIP, VPN) with signature-based matching and GPU acceleration support for filtering at the edge.

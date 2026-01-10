# lippycat - Network Traffic Sniffer

## Project Overview
lippycat is a Go-based CLI tool for sniffing and analyzing network traffic. It is a general-purpose network packet analyzer with a **plugin architecture** that allows it to support different protocol-specific analysis modules. It captures traffic from network interfaces or PCAP files and provides both CLI and TUI (Terminal User Interface) modes for real-time monitoring.

**Current Protocol Support**: As of now, lippycat includes a VoIP plugin that analyzes SIP (Session Initiation Protocol) and RTP (Real-time Transport Protocol) traffic.

## Architecture

### Distributed Architecture
lippycat supports a distributed capture architecture with two node types:

- **Hunter Nodes**: Lightweight capture agents that sniff and filter packets on network interfaces and forward them to processor nodes for analysis. Hunters can be deployed across multiple network segments or hosts.
- **Processor Nodes**: Central analysis nodes that receive packets from multiple hunters, perform protocol analysis, write PCAP files (unified, per-call for VoIP, or auto-rotating for non-VoIP), and provide the TUI/CLI interface for monitoring and analysis.

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
  - `cmd/sniff/`: Packet capture command (CLI output)
  - `cmd/watch/`: TUI monitoring commands (live, file, remote)
  - `cmd/tap/`: Standalone capture with processor capabilities (local capture + TUI serving)
  - `cmd/hunt/`: Hunter node implementation for distributed capture
  - `cmd/process/`: Processor node implementation for distributed analysis
  - `cmd/list/`: Resource listing commands
  - `cmd/show/`: Diagnostics and information commands
  - `internal/pkg/tui/`: Terminal User Interface with Bubbletea framework
  - `internal/pkg/types/`: Shared domain types (PacketDisplay, VoIPMetadata, EventHandler)
  - `internal/pkg/capture/`: Network packet capture functionality using gopacket
  - `internal/pkg/voip/`: VoIP protocol plugin (SIP, RTP, call tracking)
  - `internal/pkg/hunter/`: Hunter node core logic and gRPC client
  - `internal/pkg/processor/`: Processor node core logic, gRPC server, per-call PCAP writing, and auto-rotating PCAP writing
  - `internal/pkg/remotecapture/`: Remote capture infrastructure with EventHandler pattern
  - `internal/pkg/detector/`: Protocol detection with signature-based matching
  - `internal/pkg/simd/`: SIMD optimizations (AVX2/SSE4.2)
  - `internal/pkg/logger/`: Structured logging
  - `api/proto/`: gRPC protocol buffer definitions
  - `api/gen/data/`: Generated gRPC code for data services
  - `api/gen/management/`: Generated gRPC code for management services

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
make tap          # Tap node - standalone capture with processor capabilities
make cli          # CLI tools only - sniff, debug, interfaces
make tui          # TUI only - terminal interface

# Optimized release build (stripped)
make build-release  # 22 MB

# Quick dev build (unstripped, no version info)
make dev           # ~31 MB

# LI (Lawful Interception) builds - requires -tags li
make build-li       # Complete suite with LI support
make processor-li   # Processor with LI support (LI delivery)
make tap-li         # Tap with LI support
make tap-li-cuda    # Tap with LI + CUDA (standalone GPU filtering + LI)
make binaries-li    # Build all LI variants
make verify-no-li   # Verify non-LI builds exclude LI code

# Note: Hunters filter (CUDA) but don't need LI. Processors deliver LI but don't filter.
#       Only tap (standalone) benefits from both LI + CUDA.

# Build with CUDA GPU acceleration
make build-cuda

# Profile-guided optimization build
make build-pgo
```

**Build Tags:** The project uses Go build tags to create specialized binaries:
- `all`: Complete suite with all commands (default)
- `hunter`: Hunter node only - includes GPU acceleration and protocol detection
- `processor`: Processor node only - includes protocol analysis and gRPC server
- `tap`: Tap node only - standalone capture with processor capabilities
- `cli`: CLI commands only - sniff, debug, interfaces
- `tui`: TUI interface only - terminal UI with remote monitoring
- `li`: Lawful Interception support (ETSI X1/X2/X3) - can be combined with other tags

Each specialized build is stripped (`-s -w`) and optimized to reduce binary size while maintaining full functionality for its role. Hunter nodes include all protocol detectors and GPU acceleration for edge filtering. LI support is optional and excluded from non-LI builds via dead code elimination.

**CUDA Build Tag Pattern:** The `cuda` build tag controls GPU acceleration. Files follow this pattern:
- `gpu_cuda_backend_impl.go` (`//go:build cuda`) - **Full CUDA implementation** with CGo bindings
- `gpu_cuda_backend.go` (`//go:build !cuda`) - Stub for non-CUDA builds (returns `ErrGPUNotAvailable`)

The stub file is NOT an indicator of missing GPU support - it exists only so non-CUDA builds compile cleanly.

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

### Version Management
```bash
# Bump version (updates VERSION, README.md, creates changelog entry)
./scripts/bump-version.sh [flags] <version> [changelog-message]

# Flags:
#   -y, --yes    Skip all prompts and auto-confirm (for automation/Claude Code)
#   -t, --tag    Create git tag (only with -y flag)

# Interactive mode (manual use)
./scripts/bump-version.sh 0.2.6 'Bug fixes and improvements'

# Non-interactive mode (Claude Code/automation)
./scripts/bump-version.sh -y 0.2.6 'Bug fixes and improvements'
./scripts/bump-version.sh -y -t 0.3.0 'Major feature release'

# The script will:
# 1. Update VERSION file and README.md status line
# 2. Add changelog entry (requires manual editing for details)
# 3. Show diff and commit (auto-commit with -y flag)
# 4. Optionally create git tag (with -t flag)
# 5. Remind to push: git push origin main && git push origin v<version>
```

## Development Guidelines

1. **Code Structure**: Follow Go module structure with internal packages
2. **Testing**: Use testify framework for unit tests (test pcap files are in `captures/`)
3. **Error Handling**:
   - **Never silently ignore errors** - All errors must be handled appropriately
   - **Close() operations**:
     - Error path cleanup: Log errors with structured context (`logger.Error()`)
     - Shutdown/cleanup: Log errors (can't return from `Shutdown()` methods)
     - Normal path: Return errors to caller or handle explicitly
   - **Wrap errors** with context using `fmt.Errorf(..., %w, err)`
   - **Structured logging**: Include relevant fields (file, operation, call_id, etc.)
   - See `CONTRIBUTING.md` for comprehensive error handling patterns
4. **Concurrency**: Project uses goroutines and channels for concurrent packet processing
5. **Network Interfaces**: Requires elevated privileges for live network capture
6. **12-Factor App**: Follow the 12 factors.

## Security Considerations
- This is a **defensive security tool** for network monitoring and protocol analysis
- Requires appropriate permissions for network interface access
- Used for legitimate network diagnostics, troubleshooting, and security monitoring

## CLI Usage

### Command Structure

lippycat follows a consistent `[verb] [object]` pattern:

```
lc [verb] [object] [flags]

VERBS:
  sniff     Capture packets from interface or file
  tap       Standalone capture with processor capabilities
  hunt      Distributed edge capture (hunter node)
  process   Central aggregation (processor node)
  watch     Monitor traffic (TUI)
  list      List resources
  show      Display information/diagnostics
```

### Available Commands

- **`lc sniff`** - CLI mode packet capture ([docs](cmd/sniff/CLAUDE.md))
- **`lc sniff voip`** - VoIP-specific capture with SIP/RTP analysis ([docs](cmd/sniff/CLAUDE.md))
- **`lc tap`** - Standalone capture with processor capabilities ([docs](cmd/tap/CLAUDE.md))
- **`lc tap voip`** - VoIP standalone capture with per-call PCAP ([docs](cmd/tap/CLAUDE.md))
- **`lc watch`** - Interactive TUI, defaults to live mode ([docs](cmd/watch/CLAUDE.md))
- **`lc watch live`** - Live capture TUI ([docs](cmd/watch/CLAUDE.md))
- **`lc watch file`** - PCAP file analysis TUI ([docs](cmd/watch/CLAUDE.md))
- **`lc watch remote`** - Remote node monitoring TUI ([docs](cmd/watch/CLAUDE.md))
- **`lc hunt`** - Hunter node for distributed edge capture ([docs](cmd/hunt/CLAUDE.md))
- **`lc hunt voip`** - VoIP hunter with call buffering ([docs](cmd/hunt/CLAUDE.md))
- **`lc process`** - Processor node for central aggregation ([docs](cmd/process/CLAUDE.md))
- **`lc list interfaces`** - List network interfaces ([docs](cmd/list/CLAUDE.md))
- **`lc show`** - TCP SIP diagnostics ([docs](cmd/show/CLAUDE.md))
  - `show health` - Health status
  - `show metrics` - Comprehensive metrics
  - `show alerts` - Active alerts
  - `show buffers` - Buffer statistics
  - `show streams` - Stream metrics
  - `show config` - Configuration display
  - `show summary` - System summary

### Quick Start Examples

**CLI VoIP Capture:**
```bash
# VoIP capture with balanced performance
sudo lc sniff voip --interface eth0 --sip-user alicent

# High-performance VoIP capture with GPU acceleration
sudo lc sniff voip -i eth0 \
  --tcp-performance-mode high_performance \
  --gpu-backend auto

# UDP-only VoIP capture (bypass TCP, reduces CPU on TCP-heavy networks)
sudo lc sniff voip -i eth0 --udp-only --sip-port 5060
```

**Standalone Tap Mode (Single Machine with TUI/PCAP):**
```bash
# Standalone VoIP capture with TUI serving and per-call PCAP
sudo lc tap voip -i eth0 --sip-user alicent --insecure

# Tap with TLS for production (TUI clients can connect)
sudo lc tap voip -i eth0 \
  --per-call-pcap --per-call-pcap-dir /var/voip/calls \
  --tls --tls-cert server.crt --tls-key server.key

# Tap with upstream forwarding (edge node)
sudo lc tap voip -i eth0 \
  --processor central-processor:50051 \
  --tls --tls-ca ca.crt
```

**Distributed Capture:**
```bash
# Processor (central aggregation)
lc process --listen 0.0.0.0:50051 \
  --tls --tls-cert server.crt --tls-key server.key

# Processor with per-call PCAP and command hooks
lc process --listen 0.0.0.0:50051 \
  --per-call-pcap --per-call-pcap-dir /var/capture/calls \
  --pcap-command 'gzip %pcap%' \
  --voip-command '/opt/scripts/process-call.sh %callid% %dirname%' \
  --tls --tls-cert server.crt --tls-key server.key

# Hunter (edge capture)
sudo lc hunt --processor processor:50051 \
  --interface eth0 \
  --tls --tls-ca ca.crt

# VoIP hunter with call filtering
sudo lc hunt voip --processor processor:50051 --tls --tls-ca ca.crt

# VoIP hunter with BPF filter optimization (UDP-only)
sudo lc hunt voip --processor processor:50051 \
  --udp-only --sip-port 5060 \
  --tls --tls-ca ca.crt
```

**Interactive Monitoring:**
```bash
# Local TUI (live capture)
sudo lc watch

# Analyze PCAP file
lc watch file -r capture.pcap

# Remote TUI (monitor distributed nodes)
lc watch remote --nodes-file nodes.yaml
```

### Environment Variables

- `LIPPYCAT_PRODUCTION=true` - Enforces TLS encryption (hunters and processors require `--tls`)

### Configuration

Configuration via YAML file (in priority order):
1. `$HOME/.config/lippycat/config.yaml` (preferred)
2. `$HOME/.config/lippycat.yaml` (XDG standard)
3. `$HOME/.lippycat.yaml` (legacy)

**See command-specific documentation:**
- User Documentation (README.md files):
  - [cmd/sniff/README.md](cmd/sniff/README.md) - Sniff command usage
  - [cmd/tap/README.md](cmd/tap/README.md) - Tap (standalone) command usage
  - [cmd/watch/README.md](cmd/watch/README.md) - Watch (TUI) command usage
  - [cmd/hunt/README.md](cmd/hunt/README.md) - Hunter node usage
  - [cmd/process/README.md](cmd/process/README.md) - Processor node usage
  - [cmd/list/README.md](cmd/list/README.md) - List command usage
  - [cmd/show/README.md](cmd/show/README.md) - Show (diagnostics) command usage

- Architecture Documentation (CLAUDE.md files for AI assistants):
  - [cmd/sniff/CLAUDE.md](cmd/sniff/CLAUDE.md) - Sniff architecture & patterns
  - [cmd/tap/CLAUDE.md](cmd/tap/CLAUDE.md) - Tap architecture & patterns
  - [cmd/watch/CLAUDE.md](cmd/watch/CLAUDE.md) - Watch command architecture
  - [cmd/hunt/CLAUDE.md](cmd/hunt/CLAUDE.md) - Hunter architecture & patterns
  - [cmd/process/CLAUDE.md](cmd/process/CLAUDE.md) - Processor architecture & patterns
  - [cmd/list/CLAUDE.md](cmd/list/CLAUDE.md) - List command architecture
  - [cmd/show/CLAUDE.md](cmd/show/CLAUDE.md) - Show command architecture
  - [internal/pkg/tui/CLAUDE.md](internal/pkg/tui/CLAUDE.md) - TUI architecture & Bubbletea patterns

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
The distributed system supports TLS encryption with mutual authentication for all gRPC connections (hunter→processor, processor→processor, TUI→processor).

**See [docs/SECURITY.md](docs/SECURITY.md#tls-transport-encryption) for complete TLS/mTLS configuration, certificate requirements, and troubleshooting.**

### TUI Architecture
The TUI (Terminal User Interface) provides interactive real-time packet monitoring with support for:
- Hunter subscription management (selective monitoring of specific hunters)
- Unified modal architecture for consistent dialogs
- FileDialog component for file operations
- Toast notifications for transient status messages

**For TUI architecture and development, see [internal/pkg/tui/CLAUDE.md](internal/pkg/tui/CLAUDE.md) (Bubbletea patterns, EventHandler integration, component architecture).**

## Plugin Architecture
lippycat is designed with extensibility in mind. Protocol-specific analyzers can be added as plugins to support different types of traffic analysis beyond VoIP.

The hunter node includes protocol detection for multiple protocols (HTTP, DNS, TLS, MySQL, PostgreSQL, VoIP, VPN) with signature-based matching and GPU acceleration support for filtering at the edge.

## Lawful Interception (LI)

lippycat supports ETSI X1/X2/X3 lawful interception interfaces for authorized interception.

**Build Requirement:** LI support requires the `li` build tag:
```bash
make processor-li   # Processor with LI support
make build-li       # Complete suite with LI
```

### ETSI Interfaces

| Interface | Purpose | Protocol | Specification |
|-----------|---------|----------|---------------|
| **X1** | Administration (ADMF ↔ NE) | XML/HTTPS | TS 103 221-1 |
| **X2** | IRI delivery (signaling) | Binary TLV/TLS | TS 103 221-2 |
| **X3** | CC delivery (content) | Binary TLV/TLS | TS 103 221-2 |

### Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     lippycat Processor                         │
│  ┌──────────┐  ┌─────────────┐  ┌───────────┐  ┌────────────┐  │
│  │X1 Server │←─│ LI Manager  │─→│ X2/X3     │─→│ Delivery   │  │
│  │ :8443    │  │ (registry,  │  │ Encoder   │  │ Client     │  │
│  └──────────┘  │  filters)   │  └───────────┘  └─────┬──────┘  │
│                └─────────────┘                       │         │
└──────────────────────────────────────────────────────┼─────────┘
       ▲ X1 (HTTPS/XML)                                │ X2/X3 (TLS)
       │                                               ▼
  ┌────┴────┐                                    ┌───────────┐
  │  ADMF   │                                    │    MDF    │
  └─────────┘                                    └───────────┘
```

### LI Package Structure

- `internal/pkg/li/` - Core LI types, manager, registry, filter mapping
- `internal/pkg/li/x1/` - X1 HTTPS server and client, XML schema types
- `internal/pkg/li/x2x3/` - Binary TLV PDU encoding
- `internal/pkg/li/delivery/` - Connection pool, async delivery with batching

### Quick Start

```bash
# Start processor with LI enabled
lc process --listen :50051 \
  --tls --tls-cert=server.crt --tls-key=server.key \
  --li-enabled \
  --li-x1-listen :8443 \
  --li-x1-tls-cert x1-server.crt \
  --li-x1-tls-key x1-server.key \
  --li-x1-tls-ca admf-ca.crt \
  --li-delivery-tls-cert delivery.crt \
  --li-delivery-tls-key delivery.key \
  --li-delivery-tls-ca mdf-ca.crt
```

### Filter Integration

LI tasks integrate with lippycat's optimized filter system:

| LI Target Type | Filter System | Description |
|----------------|---------------|-------------|
| SIP URI | Aho-Corasick | Pattern matching |
| Phone Number | PhoneNumberMatcher | Bloom filter + suffix |
| IP Address | Hash Map | O(1) lookup |
| IP CIDR | Radix Trie | O(prefix) lookup |

When tasks are activated via X1, the LI Manager creates filters that are pushed to hunters. Matched packets are encoded as X2 (IRI) or X3 (CC) PDUs and delivered to MDF endpoints.

**For detailed documentation, see:**
- [docs/LI_INTEGRATION.md](docs/LI_INTEGRATION.md) - Deployment guide
- [docs/LI_CERTIFICATES.md](docs/LI_CERTIFICATES.md) - Certificate management
- [internal/pkg/li/CLAUDE.md](internal/pkg/li/CLAUDE.md) - Architecture details

## Documentation Index

### User Documentation (README.md)
- [cmd/sniff/README.md](cmd/sniff/README.md) - Sniff command usage, flags, examples
- [cmd/watch/README.md](cmd/watch/README.md) - Watch (TUI) command usage and keybindings
- [cmd/hunt/README.md](cmd/hunt/README.md) - Hunter node setup and configuration
- [cmd/process/README.md](cmd/process/README.md) - Processor node setup and management
- [cmd/list/README.md](cmd/list/README.md) - List command usage
- [cmd/show/README.md](cmd/show/README.md) - Show (diagnostics) command usage

### Architecture Documentation (CLAUDE.md - for AI assistants)
- [cmd/sniff/CLAUDE.md](cmd/sniff/CLAUDE.md) - Sniff architecture, Viper patterns, TCP reassembly
- [cmd/watch/CLAUDE.md](cmd/watch/CLAUDE.md) - Watch command architecture
- [cmd/hunt/CLAUDE.md](cmd/hunt/CLAUDE.md) - Hunter architecture, gRPC client, VoIP buffering
- [cmd/process/CLAUDE.md](cmd/process/CLAUDE.md) - Processor architecture, gRPC server, broadcasting
- [cmd/list/CLAUDE.md](cmd/list/CLAUDE.md) - List command architecture
- [cmd/show/CLAUDE.md](cmd/show/CLAUDE.md) - Show command architecture
- [internal/pkg/tui/CLAUDE.md](internal/pkg/tui/CLAUDE.md) - TUI architecture, Bubbletea, EventHandler pattern

### Operational Guides
- [docs/DISTRIBUTED_MODE.md](docs/DISTRIBUTED_MODE.md) - Complete distributed architecture guide (hub-and-spoke, hierarchical)
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) - Performance tuning, TCP profiles, GPU optimization
- [docs/SECURITY.md](docs/SECURITY.md) - TLS/mTLS setup, certificate management, security features
- [docs/operational-procedures.md](docs/operational-procedures.md) - Production operations and procedures

### Specialized Topics
- [docs/TLS_DECRYPTION.md](docs/TLS_DECRYPTION.md) - TLS decryption with SSLKEYLOGFILE, Wireshark integration
- [docs/GPU_ACCELERATION.md](docs/GPU_ACCELERATION.md) - GPU backends (CUDA, OpenCL, SIMD), benchmarks
- [docs/GPU_TROUBLESHOOTING.md](docs/GPU_TROUBLESHOOTING.md) - GPU-specific troubleshooting
- [docs/tcp-troubleshooting.md](docs/tcp-troubleshooting.md) - TCP SIP capture troubleshooting
- [docs/TUI_REMOTE_CAPTURE.md](docs/TUI_REMOTE_CAPTURE.md) - Remote capture with TUI
- [docs/AF_XDP_SETUP.md](docs/AF_XDP_SETUP.md) - AF_XDP high-performance capture setup
- [docs/voip-build-tag-optimization.md](docs/voip-build-tag-optimization.md) - VoIP build tag optimization

### Lawful Interception (LI)
- [docs/LI_INTEGRATION.md](docs/LI_INTEGRATION.md) - LI deployment guide, X1/X2/X3 operations
- [docs/LI_CERTIFICATES.md](docs/LI_CERTIFICATES.md) - LI certificate generation and management
- [internal/pkg/li/CLAUDE.md](internal/pkg/li/CLAUDE.md) - LI package architecture

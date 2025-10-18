# lippycat - Network Traffic Sniffer

## Project Overview
lippycat is a Go-based CLI tool for sniffing and analyzing network traffic. It is a general-purpose network packet analyzer with a **plugin architecture** that allows it to support different protocol-specific analysis modules. It captures traffic from network interfaces or PCAP files and provides both CLI and TUI (Terminal User Interface) modes for real-time monitoring.

**Current Protocol Support**: As of now, lippycat includes a VoIP plugin that analyzes SIP (Session Initiation Protocol) and RTP (Real-time Transport Protocol) traffic.

## Architecture

### Distributed Architecture
lippycat supports a distributed capture architecture with two node types:

- **Hunter Nodes**: Lightweight capture agents that sniff and filter packets on network interfaces and forward them to processor nodes for analysis. Hunters can be deployed across multiple network segments or hosts.
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

lippycat provides several commands for different deployment modes:

- **`lc sniff`** - CLI mode packet capture ([docs](cmd/sniff/CLAUDE.md))
- **`lc sniff voip`** - VoIP-specific capture with SIP/RTP analysis, GPU acceleration, TCP performance tuning ([docs](cmd/sniff/CLAUDE.md))
- **`lc tui`** - Interactive TUI for local or remote monitoring ([docs](cmd/tui/CLAUDE.md))
- **`lc hunt`** - Hunter node for distributed edge capture ([docs](cmd/hunt/CLAUDE.md))
- **`lc hunt voip`** - VoIP hunter with call buffering and filtering ([docs](cmd/hunt/CLAUDE.md))
- **`lc process`** - Processor node for central aggregation and analysis ([docs](cmd/process/CLAUDE.md))
- **`lc debug`** - TCP SIP diagnostics and troubleshooting ([docs](cmd/debug/CLAUDE.md))
  - `debug health` - Health status
  - `debug metrics` - Comprehensive metrics
  - `debug alerts` - Active alerts
  - `debug buffers` - Buffer statistics
  - `debug streams` - Stream metrics
  - `debug config` - Configuration display
  - `debug summary` - System summary
- **`lc interfaces`** - List available network interfaces

### Quick Start Examples

**Standalone VoIP Capture:**
```bash
# VoIP capture with balanced performance
sudo lc sniff voip --interface eth0 --sipuser alicent

# High-performance VoIP capture with GPU acceleration
sudo lc sniff voip -i eth0 \
  --tcp-performance-mode high_performance \
  --gpu-backend auto
```

**Distributed Capture:**
```bash
# Processor (central aggregation)
lc process --listen 0.0.0.0:50051 \
  --tls --tls-cert server.crt --tls-key server.key

# Hunter (edge capture)
sudo lc hunt --processor processor:50051 \
  --interface eth0 \
  --tls --tls-ca ca.crt

# VoIP hunter with call filtering
sudo lc hunt voip --processor processor:50051 --tls --tls-ca ca.crt
```

**Interactive Monitoring:**
```bash
# Local TUI
sudo lc tui

# Remote TUI (monitor distributed nodes)
lc tui --remote --nodes-file nodes.yaml
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
  - [cmd/hunt/README.md](cmd/hunt/README.md) - Hunter node usage
  - [cmd/process/README.md](cmd/process/README.md) - Processor node usage
  - [cmd/debug/README.md](cmd/debug/README.md) - Debug commands usage
  - [cmd/tui/README.md](cmd/tui/README.md) - TUI usage

- Architecture Documentation (CLAUDE.md files for AI assistants):
  - [cmd/sniff/CLAUDE.md](cmd/sniff/CLAUDE.md) - Sniff architecture & patterns
  - [cmd/hunt/CLAUDE.md](cmd/hunt/CLAUDE.md) - Hunter architecture & patterns
  - [cmd/process/CLAUDE.md](cmd/process/CLAUDE.md) - Processor architecture & patterns
  - [cmd/debug/CLAUDE.md](cmd/debug/CLAUDE.md) - Debug command architecture
  - [cmd/tui/CLAUDE.md](cmd/tui/CLAUDE.md) - TUI architecture & Bubbletea patterns

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

**For TUI architecture and development, see [cmd/tui/CLAUDE.md](cmd/tui/CLAUDE.md) (Bubbletea patterns, EventHandler integration, component architecture).**

## Plugin Architecture
lippycat is designed with extensibility in mind. Protocol-specific analyzers can be added as plugins to support different types of traffic analysis beyond VoIP.

The hunter node includes protocol detection for multiple protocols (HTTP, DNS, TLS, MySQL, PostgreSQL, VoIP, VPN) with signature-based matching and GPU acceleration support for filtering at the edge.

## Documentation Index

### User Documentation (README.md)
- [cmd/sniff/README.md](cmd/sniff/README.md) - Sniff command usage, flags, examples
- [cmd/hunt/README.md](cmd/hunt/README.md) - Hunter node setup and configuration
- [cmd/process/README.md](cmd/process/README.md) - Processor node setup and management
- [cmd/debug/README.md](cmd/debug/README.md) - Debug command usage and troubleshooting
- [cmd/tui/README.md](cmd/tui/README.md) - TUI user guide and keybindings

### Architecture Documentation (CLAUDE.md - for AI assistants)
- [cmd/sniff/CLAUDE.md](cmd/sniff/CLAUDE.md) - Sniff architecture, Viper patterns, TCP reassembly
- [cmd/hunt/CLAUDE.md](cmd/hunt/CLAUDE.md) - Hunter architecture, gRPC client, VoIP buffering
- [cmd/process/CLAUDE.md](cmd/process/CLAUDE.md) - Processor architecture, gRPC server, broadcasting
- [cmd/debug/CLAUDE.md](cmd/debug/CLAUDE.md) - Debug command patterns, metrics collection
- [cmd/tui/CLAUDE.md](cmd/tui/CLAUDE.md) - TUI architecture, Bubbletea, EventHandler pattern

### Operational Guides
- [docs/DISTRIBUTED_MODE.md](docs/DISTRIBUTED_MODE.md) - Complete distributed architecture guide (hub-and-spoke, hierarchical)
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) - Performance tuning, TCP profiles, GPU optimization
- [docs/SECURITY.md](docs/SECURITY.md) - TLS/mTLS setup, certificate management, security features
- [docs/operational-procedures.md](docs/operational-procedures.md) - Production operations and procedures

### Specialized Topics
- [docs/GPU_ACCELERATION.md](docs/GPU_ACCELERATION.md) - GPU backends (CUDA, OpenCL, SIMD), benchmarks
- [docs/GPU_TROUBLESHOOTING.md](docs/GPU_TROUBLESHOOTING.md) - GPU-specific troubleshooting
- [docs/tcp-troubleshooting.md](docs/tcp-troubleshooting.md) - TCP SIP capture troubleshooting
- [docs/TUI_REMOTE_CAPTURE.md](docs/TUI_REMOTE_CAPTURE.md) - Remote capture with TUI
- [docs/AF_XDP_SETUP.md](docs/AF_XDP_SETUP.md) - AF_XDP high-performance capture setup
- [docs/voip-build-tag-optimization.md](docs/voip-build-tag-optimization.md) - VoIP build tag optimization

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
- **Main Components**:
  - `cmd/`: CLI command definitions and argument handling
  - `cmd/tui/`: Terminal User Interface with Bubbletea framework
  - `cmd/hunt/`: Hunter node implementation for distributed capture
  - `cmd/process/`: Processor node implementation for distributed analysis
  - `internal/pkg/capture/`: Network packet capture functionality using gopacket
  - `internal/pkg/voip/`: VoIP protocol plugin (SIP, RTP, call tracking)
  - `internal/pkg/hunter/`: Hunter node core logic and gRPC client
  - `internal/pkg/processor/`: Processor node core logic and gRPC server
  - `internal/pkg/remotecapture/`: Remote capture infrastructure
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
# Development build
make build

# Optimized release build
make build-release

# Build with CUDA GPU acceleration
make build-cuda

# Profile-guided optimization build
make build-pgo
```

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
make clean       # Remove build artifacts
make clean-cuda  # Remove CUDA artifacts
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

## Plugin Architecture
lippycat is designed with extensibility in mind. Protocol-specific analyzers can be added as plugins to support different types of traffic analysis beyond VoIP.

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
  - `cmd/`: CLI command definitions and argument handling, including TUI mode
  - `cmd/tui/`: Terminal User Interface with Bubbletea framework
  - `internal/pkg/capture/`: Network packet capture functionality using gopacket
  - `internal/pkg/voip/`: VoIP protocol plugin (SIP, RTP, call tracking)

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
go build -o lippycat
```

### Test
```bash
go test ./...
```

### Format and Lint
```bash
go fmt ./...
go vet ./...
```

### Module Management
```bash
go mod tidy
go mod download
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

### Standalone Mode
- `lippycat sniff`: CLI mode for packet capture with various output formats
- `lippycat tui`: TUI mode for interactive real-time packet monitoring on local interface

### Distributed Mode
- **Processor Node**: `lippycat tui --mode processor` - Start as processor node, accepting connections from hunters
- **Hunter Node**: `lippycat sniff --mode hunter --processor <address>` - Start as hunter node, forwarding packets to processor

Configuration via YAML file at `$HOME/.config/lippycat.yaml` (preferred) or `$HOME/.lippycat.yaml` (legacy)

## Plugin Architecture
lippycat is designed with extensibility in mind. Protocol-specific analyzers can be added as plugins to support different types of traffic analysis beyond VoIP.

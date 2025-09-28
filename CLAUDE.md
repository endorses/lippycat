# lippycat - VoIP Network Traffic Sniffer

## Project Overview
lippycat is a Go-based CLI tool for sniffing network traffic, specifically designed for VoIP (Voice over IP) analysis. It captures and analyzes SIP (Session Initiation Protocol) and RTP (Real-time Transport Protocol) traffic from network interfaces or PCAP files.

## Architecture
- **CLI Framework**: Uses Cobra CLI framework with Viper for configuration
- **Main Components**:
  - `cmd/`: CLI command definitions and argument handling
  - `internal/pkg/capture/`: Network packet capture functionality using gopacket
  - `internal/pkg/voip/`: VoIP-specific protocol handling (SIP, RTP, call tracking)

## Key Dependencies
- `github.com/spf13/cobra`: CLI framework
- `github.com/spf13/viper`: Configuration management
- `github.com/google/gopacket`: Network packet capture and analysis
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
- This is a **defensive security tool** for network monitoring and VoIP analysis
- Requires appropriate permissions for network interface access
- Used for legitimate network diagnostics and VoIP troubleshooting

## CLI Usage
- Main command: `lippycat`
- Subcommands available under `sniff` for different capture modes
- Configuration via YAML file at `$HOME/.lippycat.yaml`

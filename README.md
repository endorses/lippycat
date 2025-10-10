# lippycat 🫦🐱

Network traffic sniffer and protocol analyzer built with Go. Currently focused on VoIP (SIP/RTP) analysis with plans for multi-protocol support.

**Status:** v0.2.2 - Early development. Expect breaking changes.

## Features

- **VoIP Analysis**: SIP/RTP traffic capture, call tracking, user targeting
- **Distributed Capture**: Multi-node architecture with hunter/processor nodes
- **Performance**: SIMD optimizations, optional GPU acceleration, AF_XDP support
- **TUI & CLI**: Terminal UI and command-line interfaces
- **Flexible Output**: PCAP files, structured logging

## Installation

### Prerequisites
- Go 1.24+
- libpcap (`libpcap-dev` on Ubuntu/Debian)
- Root/sudo for live capture

### Build

#### Using Makefile (recommended)
```bash
git clone https://github.com/endorses/lippycat.git
cd lippycat

# Standard build with version info
make build

# Or quick dev build
make dev

# Build optimized release binary
make build-release

# Build with CUDA GPU acceleration (requires CUDA Toolkit)
make build-cuda
```

#### Building Specialized Binaries

lippycat uses Go build tags to create optimized binaries for specific deployment scenarios:

```bash
# Build all variants (output to bin/ directory)
make binaries

# Or build specific variants (all stripped and optimized):
make all        # Complete suite (22 MB) - all commands
make hunter     # Hunter node only (18 MB) - edge capture
make processor  # Processor node only (14 MB) - central aggregation
make cli        # CLI tools only - sniff, debug, interfaces
make tui        # TUI only - terminal interface
```

**Use cases:**
- **Hunter**: Edge deployment with GPU-accelerated filtering, minimal size
- **Processor**: Central aggregation servers without TUI/CLI overhead
- **CLI**: Headless servers for scripted packet capture
- **TUI**: Interactive monitoring without distributed mode
- **Complete suite**: All-in-one deployment with every feature

#### Using go build directly
```bash
# Build complete suite
go build -tags all -o lc

# Build specific variant
go build -tags hunter -o lc-hunt
go build -tags processor -o lc-process
go build -tags cli -o lc-cli
go build -tags tui -o lc-tui
```

**Note on Build Tags:** If you run `go build ./...` without specifying tags, you may see warnings about build constraints excluding files in the `cmd/` directory. This is expected behavior - the build system uses tags to exclude unused code paths for each specialized binary. Always use `make build` or specify a tag explicitly (e.g., `-tags all`) to build successfully.

#### Installing system-wide
```bash
# Install to $GOPATH/bin as 'lc'
make install

# Or install to /usr/local/bin (requires sudo)
make install-system
```

Run `make help` to see all available build targets.

## Quick Start

```bash
# List interfaces
lc interfaces

# Capture VoIP traffic
sudo lc sniff voip --interface eth0

# Target specific SIP users
sudo lc sniff voip --sipuser alice,bob

# Interactive TUI
sudo lc tui

# Distributed capture
lc process --listen :50051                         # Processor node
sudo lc hunt --interface eth0 --processor host:50051 # Hunter node
```

## Commands

| Command | Description |
|---------|-------------|
| `sniff` | Packet capture (general) |
| `sniff voip` | VoIP-specific capture with SIP/RTP analysis |
| `tui` | Terminal User Interface |
| `hunt` | Hunter node (distributed edge capture) |
| `process` | Processor node (distributed aggregation) |
| `interfaces` | List available network interfaces |
| `debug` | Debug TCP SIP processing |

Run `lc [command] --help` for detailed options.

## Configuration

Configuration files (priority order):
1. `~/.config/lippycat/config.yaml`
2. `~/.config/lippycat.yaml`
3. `~/.lippycat.yaml`

See `example-config.yaml` for configuration options.

### Basic Config Example
```yaml
voip:
  tcp_performance_mode: "balanced"  # balanced, throughput, latency, memory
  gpu_backend: "auto"               # auto, cuda, opencl, cpu-simd, disabled
  max_tcp_buffers: 10000
  enable_backpressure: true
```

## Performance

### GPU Acceleration
Supports GPU-accelerated pattern matching with multiple backends:

- **CUDA**: Full implementation for NVIDIA GPUs (requires CUDA Toolkit and `-tags cuda` build)
- **OpenCL**: Placeholder (planned)
- **CPU SIMD**: AVX2/SSE4.2 optimizations (always available, default fallback)

Standard builds use CPU SIMD. Use `make build-cuda` for GPU acceleration.

### Performance Modes
- **balanced**: General-purpose (default)
- **throughput**: High-volume traffic
- **latency**: Real-time monitoring
- **memory**: Resource-constrained environments

### AF_XDP Support
Kernel-bypass packet capture on Linux 4.18+ with XDP-capable NICs. See [docs/AF_XDP_SETUP.md](docs/AF_XDP_SETUP.md).

## Distributed Mode

Deploy hunters across network segments and aggregate to central processors.

```bash
# Processor
lc process --listen :50051 --write-file capture.pcap

# Hunter
sudo lc hunt --interface eth0 --processor processor:50051

# TUI monitoring
lc tui --remote --nodes-file nodes.yaml
```

See [docs/DISTRIBUTED_MODE.md](docs/DISTRIBUTED_MODE.md) for details.

## Documentation

- [Distributed Mode](docs/DISTRIBUTED_MODE.md) - Multi-node architecture
- [TUI Remote Capture](docs/TUI_REMOTE_CAPTURE.md) - Remote monitoring setup
- [GPU Acceleration](docs/GPU_ACCELERATION.md) - GPU/SIMD optimization
- [AF_XDP Setup](docs/AF_XDP_SETUP.md) - Kernel-bypass capture
- [Security Features](docs/SECURITY.md) - Encryption, sanitization, DoS protection
- [TCP Troubleshooting](docs/tcp-troubleshooting.md) - TCP stream debugging
- [GPU Troubleshooting](docs/GPU_TROUBLESHOOTING.md) - GPU backend issues
- [Operational Procedures](docs/operational-procedures.md) - Deployment guide

## Security

**Defensive use only.** This tool is for authorized network monitoring and analysis.

- ✅ Network diagnostics and troubleshooting
- ✅ VoIP security analysis
- ✅ Protocol analysis and testing
- ❌ Unauthorized surveillance

Requires root privileges for packet capture. Use responsibly and legally.

See [docs/SECURITY.md](docs/SECURITY.md) for security features (Call-ID sanitization, PCAP encryption, DoS protection).

## Development

### Testing
```bash
go test ./...
```

### Code Standards
- Follow Go conventions and `gofmt`
- Add tests for new features
- Update documentation

### Architecture
- Plugin-based protocol analyzers
- Distributed hunter/processor architecture
- gRPC for node communication
- Cobra CLI + Bubbletea TUI

## Roadmap

### Current (v0.2.2)
- VoIP/SIP analysis (UDP and TCP)
- Distributed capture architecture with build-tagged specialized binaries
- SIMD optimizations and optional GPU acceleration
- TUI and CLI interfaces
- Protocol detection with signature-based matching

### Planned
- HTTP/HTTPS protocol support
- DNS monitoring
- Additional protocol plugins
- Web dashboard
- Enhanced GPU acceleration

## Contributing

Contributions welcome! Please:
1. Fork and create a feature branch
2. Follow Go code standards
3. Add tests
4. Submit a pull request

For security issues, follow responsible disclosure practices.

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- [gopacket](https://github.com/google/gopacket) - Packet capture
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [Viper](https://github.com/spf13/viper) - Configuration
- [Bubbletea](https://github.com/charmbracelet/bubbletea) - TUI framework

---

**⚠️ Legal Notice**: For authorized network monitoring only. Users are responsible for legal compliance. Unauthorized interception may violate laws.

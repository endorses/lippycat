# Installation & Setup

## Building from Source

Requirements:
- Go 1.25 or later
- Make
- libpcap development headers (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora)

```bash
git clone https://github.com/endorses/lippycat.git
cd lippycat

# Development build (complete suite, with debug symbols)
make build

# Optimized release build (stripped)
make build-release

# Quick dev build (no version info)
make dev
```

### Specialized Builds

lippycat uses Go build tags to create smaller, purpose-specific binaries. If you only need a subset of functionality:

```bash
# Build all variants to bin/
make binaries
```

| Target | Binary | Purpose | Approximate Size |
|--------|--------|---------|-----------------|
| `make all` | `bin/lc` | Complete suite | 22 MB |
| `make hunter` | `bin/lc-hunt` | Edge capture agent | 18 MB |
| `make processor` | `bin/lc-process` | Central aggregation | 14 MB |
| `make tap` | `bin/lc-tap` | Standalone capture + processing | — |
| `make cli` | `bin/lc-cli` | CLI commands only | — |
| `make tui` | `bin/lc-tui` | TUI interface only | — |

For most users, the complete suite (`make build`) is the simplest option. Specialized builds are useful for production deployments where you want minimal binaries on each node.

### GPU Acceleration

For CUDA GPU acceleration (requires NVIDIA GPU and CUDA toolkit):

```bash
make build-cuda
```

See [Performance Optimization](../part5-advanced/performance.md) for details on GPU backends.

## Install Targets

```bash
# Install to $GOPATH/bin
make install

# Install system-wide to /usr/local/bin (requires sudo)
make install-system
```

## Permissions

Packet capture requires access to raw network sockets. You have two options:

### Option 1: Run with sudo

The simplest approach for development and testing:

```bash
sudo lc sniff -i eth0
```

### Option 2: Linux Capabilities (Recommended)

Grant only the specific capability needed:

```bash
sudo setcap cap_net_raw+ep $(which lc)
```

After this, `lc` can capture without sudo:

```bash
lc sniff -i eth0
```

> **Note**: The capability is set on the binary file. If you rebuild and overwrite the binary, you need to set the capability again.

## Configuration

lippycat looks for a YAML configuration file in these locations (in priority order):

1. `$HOME/.config/lippycat/config.yaml` (preferred)
2. `$HOME/.config/lippycat.yaml` (XDG standard)
3. `$HOME/.lippycat.yaml` (legacy)

**Precedence order** (highest wins):

```
CLI flags > Environment variables > Config file > Defaults
```

Example configuration:

```yaml
# PCAP read timeout (ms)
pcap_timeout_ms: 200

# Promiscuous mode
promiscuous: false

# DNS settings
dns:
  ports: "53"
  track_queries: true
  detect_tunneling: true

# VoIP settings
voip:
  tcp_performance_mode: balanced
```

A comprehensive `example-config.yaml` is included in the repository root with all available settings documented. See [Appendix B: Configuration Reference](../appendices/config-reference.md) for the full schema.

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `LIPPYCAT_PRODUCTION` | Set to `true` to enforce TLS encryption (blocks `--insecure` flag) |

## Verifying Installation

After installation, verify everything works:

```bash
# Check version
lc version

# List available network interfaces
lc list interfaces

# Show current configuration
lc show config
```

If `lc list interfaces` shows your network interfaces, you're ready to start capturing. Continue to [CLI Capture with `lc sniff`](../part2-local-capture/sniff.md).

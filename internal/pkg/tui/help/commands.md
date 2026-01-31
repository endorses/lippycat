# CLI Commands

## Command Structure

lippycat follows a `[verb] [object]` pattern:

```
lc [verb] [object] [flags]
```

## Commands

### sniff - Packet Capture

Capture packets from interface or file (CLI mode).

```bash
# Capture all traffic on interface
sudo lc sniff -i eth0

# VoIP capture with SIP analysis
sudo lc sniff voip -i eth0 --sipuser alice

# Read from PCAP file
lc sniff -r capture.pcap
```

**Common flags:**
- `-i, --interface` - Network interface
- `-r, --read` - Read from PCAP file
- `--sipuser` - Filter by SIP user
- `--udp-only` - UDP traffic only

### tap - Standalone Capture

Capture with processor capabilities (local capture + TUI serving).

```bash
# VoIP capture with per-call PCAP
sudo lc tap voip -i eth0 --per-call-pcap

# Tap with TUI serving
sudo lc tap voip -i eth0 --insecure
```

### watch - TUI Monitor

Interactive terminal interface for packet analysis.

```bash
# Live capture (default)
sudo lc watch

# Analyze PCAP file
lc watch file -r capture.pcap

# Monitor remote nodes
lc watch remote --nodes-file nodes.yaml
```

**Sub-commands:**
- `watch live` - Live interface capture
- `watch file` - PCAP file analysis
- `watch remote` - Remote node monitoring

### hunt - Hunter Node

Distributed edge capture (forwards to processor).

```bash
# Basic hunter
sudo lc hunt --processor host:55555 -i eth0

# VoIP hunter with TLS
sudo lc hunt voip --processor host:55555 \
  --tls --tls-ca ca.crt
```

### process - Processor Node

Central aggregation node (receives from hunters).

```bash
# Start processor
lc process --listen 0.0.0.0:55555

# With per-call PCAP
lc process --listen 0.0.0.0:55555 \
  --per-call-pcap --per-call-pcap-dir /var/calls
```

### list - List Resources

```bash
# List network interfaces
lc list interfaces
```

### show - Display Information

Diagnostics and system information.

```bash
lc show health     # Health status
lc show metrics    # Performance metrics
lc show alerts     # Active alerts
lc show buffers    # Buffer statistics
lc show streams    # Stream metrics
lc show config     # Configuration
lc show summary    # System summary
```

## Common Options

**TLS Options:**
- `--tls` - Enable TLS
- `--tls-cert` - TLS certificate file
- `--tls-key` - TLS key file
- `--tls-ca` - CA certificate file
- `--insecure` - Disable TLS (dev only)

**Performance Options:**
- `--tcp-performance-mode` - TCP performance profile
- `--gpu-backend` - GPU acceleration (auto/cuda/opencl)
- `--buffer-size` - Capture buffer size

## Configuration

Config file locations (priority order):
1. `$HOME/.config/lippycat/config.yaml`
2. `$HOME/.config/lippycat.yaml`
3. `$HOME/.lippycat.yaml`

Environment variables:
- `LIPPYCAT_PRODUCTION=true` - Enforce TLS

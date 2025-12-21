# Tap Command - Standalone Capture Mode

The `tap` command runs lippycat in standalone mode, combining local packet capture with full processor capabilities on a single machine.

## Overview

Tap mode is ideal for single-machine deployments where you want the full power of the processor without the distributed hunter/processor architecture. It:

- Captures packets from local network interfaces (like hunters)
- Provides management gRPC API for TUI connections (like processors)
- Writes PCAP files (unified, per-call, auto-rotating)
- Supports upstream forwarding in hierarchical mode
- No separate hunter/processor required

## Basic Usage

```bash
# Standalone capture on eth0
sudo lc tap --interface eth0 --insecure

# With TLS for TUI connections
sudo lc tap -i eth0 --tls --tls-cert server.crt --tls-key server.key

# With per-call PCAP writing
sudo lc tap -i eth0 --per-call-pcap --per-call-pcap-dir /var/pcaps --insecure

# Hierarchical mode (forward to central processor)
sudo lc tap -i eth0 --upstream central-processor:50051 --tls --tls-ca ca.crt
```

## Commands

### `lc tap` - General Standalone Capture

Captures all packets (or BPF-filtered packets) and provides processor capabilities.

### `lc tap voip` - VoIP Standalone Capture

VoIP-optimized capture with SIP/RTP analysis, per-call PCAP writing enabled by default.

```bash
# VoIP capture with SIP user filtering
sudo lc tap voip --interface eth0 --sipuser alicent --insecure

# UDP-only VoIP capture (bypass TCP reassembly)
sudo lc tap voip -i eth0 --udp-only --sip-port 5060 --insecure

# High-performance VoIP capture
sudo lc tap voip -i eth0 --tcp-performance-mode high_performance --insecure
```

## Command Flags

### Capture Configuration

- `-i, --interface` - Network interfaces to capture (comma-separated, default: `any`)
- `-f, --filter` - BPF filter expression
- `-p, --promisc` - Enable promiscuous mode
- `-b, --buffer-size` - Packet buffer size (default: 10000)
- `--batch-size` - Packets per batch (default: 100)
- `--batch-timeout` - Batch timeout in milliseconds (default: 100)

### Management Interface

- `-l, --listen` - Listen address for TUI connections (default: `:50051`)
- `--tap-id` - Unique tap identifier (default: hostname-tap)
- `--max-subscribers` - Maximum concurrent TUI subscribers (default: 100, 0 = unlimited)

### Upstream Forwarding

- `-u, --upstream` - Upstream processor address for hierarchical mode (host:port)

### PCAP Writing

#### Unified PCAP

- `-w, --write-file` - Write all received packets to one PCAP file

#### Per-Call PCAP (VoIP)

- `--per-call-pcap` - Enable per-call PCAP writing for VoIP traffic
- `--per-call-pcap-dir` - Output directory (default: `./pcaps`)
- `--per-call-pcap-pattern` - Filename pattern (default: `{timestamp}_{callid}.pcap`)

```bash
lc tap voip -i eth0 \
  --per-call-pcap \
  --per-call-pcap-dir /var/capture/calls \
  --per-call-pcap-pattern "{timestamp}_{callid}.pcap" \
  --insecure
```

**Output:**
```
20250123_143022_abc123_sip.pcap   # SIP signaling
20250123_143022_abc123_rtp.pcap   # RTP media
```

**Pattern Placeholders:**
- `{callid}` - SIP Call-ID
- `{from}` - SIP From user
- `{to}` - SIP To user
- `{timestamp}` - Call start time (YYYYMMDD_HHMMSS)

#### Auto-Rotating PCAP (Non-VoIP)

- `--auto-rotate-pcap` - Enable auto-rotating PCAP writing for non-VoIP traffic
- `--auto-rotate-pcap-dir` - Output directory (default: `./auto-rotate-pcaps`)
- `--auto-rotate-pcap-pattern` - Filename pattern (default: `{timestamp}.pcap`)
- `--auto-rotate-idle-timeout` - Close file after idle time (default: `30s`)
- `--auto-rotate-max-size` - Max file size before rotation (default: `100M`)

### Command Hooks

- `--pcap-command` - Command to execute when PCAP file closes (supports `%pcap%` placeholder)
- `--voip-command` - Command to execute when VoIP call completes (supports `%callid%`, `%dirname%`, etc.)
- `--command-timeout` - Timeout for command execution (default: `30s`)
- `--command-concurrency` - Maximum concurrent command executions (default: `10`)

```bash
# Compress PCAP files after writing
lc tap voip -i eth0 --pcap-command 'gzip %pcap%' --insecure

# Notify on call completion
lc tap voip -i eth0 --voip-command 'notify.sh %callid% %caller% %called%' --insecure
```

### Virtual Interface

- `--virtual-interface` - Enable virtual network interface for packet injection
- `--vif-name` - Virtual interface name (default: `lc0`)
- `--vif-type` - Interface type: `tap` or `tun` (default: `tap`)
- `--vif-buffer-size` - Injection queue buffer size (default: 65536)
- `--vif-netns` - Network namespace for interface isolation
- `--vif-drop-privileges` - Drop privileges to specified user after interface creation

### Protocol Detection

- `-d, --detect` - Enable protocol detection (default: true)

### TLS/Security

- `--tls` - Enable TLS encryption for management interface
- `--tls-cert` - Path to server TLS certificate
- `--tls-key` - Path to server TLS key
- `--tls-ca` - Path to CA certificate for client verification
- `--tls-client-auth` - Require client certificate authentication
- `--api-key-auth` - Enable API key authentication
- `--insecure` - Allow insecure connections without TLS

### VoIP-Specific Flags (tap voip)

- `-u, --sipuser` - SIP user/phone to match (comma-separated, supports wildcards)
- `--udp-only` - Capture UDP only, bypass TCP SIP
- `--sip-port` - Restrict SIP capture to specific port(s)
- `--rtp-port-range` - Custom RTP port range(s)
- `--pattern-algorithm` - Pattern matching algorithm: `auto`, `linear`, `aho-corasick`
- `--pattern-buffer-mb` - Memory budget for pattern buffer in MB
- `--tcp-performance-mode` - TCP performance mode: `minimal`, `balanced`, `high_performance`, `low_latency`

## Use Cases

### Single-Machine VoIP Capture

When you need full VoIP analysis on a single machine:

```bash
sudo lc tap voip -i eth0 \
  --sipuser alicent,robb \
  --per-call-pcap \
  --per-call-pcap-dir /var/voip/calls \
  --tls --tls-cert server.crt --tls-key server.key
```

Monitor via TUI:
```bash
lc watch remote --addr localhost:50051 --tls --tls-ca ca.crt
```

### Edge Node with Upstream Forwarding

Deploy tap nodes at edge locations, forwarding to central processor:

```bash
# Edge tap node
sudo lc tap voip -i eth0 \
  --upstream central-processor:50051 \
  --tls --tls-cert edge.crt --tls-key edge.key --tls-ca ca.crt

# Central processor (receives from multiple edge taps)
lc process --listen 0.0.0.0:50051 \
  --tls --tls-cert server.crt --tls-key server.key --tls-ca ca.crt \
  --tls-client-auth
```

### Development/Testing

Quick capture without TLS:

```bash
sudo lc tap -i lo --insecure
```

### Virtual Interface Integration

Expose filtered traffic to third-party tools:

```bash
# Capture and expose on virtual interface
sudo lc tap voip -i eth0 --virtual-interface --insecure

# Monitor with Wireshark
wireshark -i lc0
```

## Security

### Production Mode Enforcement

Set `LIPPYCAT_PRODUCTION=true` to enforce TLS:

```bash
export LIPPYCAT_PRODUCTION=true
lc tap -i eth0  # ERROR: requires --tls
lc tap -i eth0 --tls --tls-cert server.crt --tls-key server.key  # OK
```

### TLS Configuration

**Server TLS (One-Way Authentication):**
```bash
lc tap -i eth0 \
  --tls \
  --tls-cert /etc/lippycat/certs/server.crt \
  --tls-key /etc/lippycat/certs/server.key
```

**Mutual TLS (Two-Way Authentication):**
```bash
lc tap -i eth0 \
  --tls \
  --tls-cert /etc/lippycat/certs/server.crt \
  --tls-key /etc/lippycat/certs/server.key \
  --tls-ca /etc/lippycat/certs/ca.crt \
  --tls-client-auth
```

See [docs/SECURITY.md](../../docs/SECURITY.md) for complete TLS setup.

## Configuration File

All flags can be specified in `~/.config/lippycat/config.yaml`:

```yaml
tap:
  interfaces:
    - eth0
  bpf_filter: ""
  promiscuous: false
  buffer_size: 10000
  batch_size: 100
  batch_timeout_ms: 100

  # Management interface
  listen_addr: ":50051"
  tap_id: "edge-tap-01"
  max_subscribers: 100
  upstream_addr: ""

  # PCAP writing
  write_file: ""
  per_call_pcap:
    enabled: true
    output_dir: "/var/capture/calls"
    file_pattern: "{timestamp}_{callid}.pcap"
  auto_rotate_pcap:
    enabled: false
    output_dir: "/var/capture/bursts"
    idle_timeout: "30s"
    max_size: "100M"

  # Command hooks
  pcap_command: "gzip %pcap%"
  voip_command: ""
  command_timeout: "30s"
  command_concurrency: 10

  # Protocol detection
  enable_detection: true

  # TLS
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/server.crt"
    key_file: "/etc/lippycat/certs/server.key"
    ca_file: "/etc/lippycat/certs/ca.crt"
    client_auth: false

  # VoIP-specific (for tap voip)
  voip:
    sipuser: ""
    udp_only: false
    sip_ports: ""
    rtp_port_ranges: ""
    pattern_algorithm: "auto"
    pattern_buffer_mb: 64
    tcp_performance_mode: "balanced"
```

## Comparison with Other Modes

| Feature | `lc sniff` | `lc tap` | `lc hunt` + `lc process` |
|---------|-----------|----------|--------------------------|
| Local capture | Yes | Yes | Hunt only |
| TUI server | No | Yes | Process only |
| Per-call PCAP | No | Yes | Process only |
| Upstream forwarding | No | Yes | Process only |
| Distributed capture | No | No | Yes |
| Deployment | Single machine | Single machine | Multi-machine |
| Use case | Quick analysis | Standalone production | Distributed production |

## Performance Tuning

### Batch Configuration

```bash
# Low latency
lc tap -i eth0 --batch-size 32 --batch-timeout 50 --insecure

# High throughput
lc tap -i eth0 --batch-size 256 --batch-timeout 500 --insecure
```

### VoIP TCP Performance

```bash
# Balanced (default)
lc tap voip -i eth0 --tcp-performance-mode balanced --insecure

# High-traffic environments
lc tap voip -i eth0 --tcp-performance-mode high_performance --insecure

# Low latency real-time analysis
lc tap voip -i eth0 --tcp-performance-mode low_latency --insecure
```

## Troubleshooting

### Permission Issues

```bash
# Check interface permissions
ip link show eth0

# Run with sudo or set capabilities
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/lc
```

### TUI Connection Issues

```bash
# Verify tap is listening
ss -tlnp | grep 50051

# Test TLS connection
openssl s_client -connect localhost:50051 -CAfile ca.crt
```

### High Memory Usage

```bash
# Reduce buffer sizes
lc tap -i eth0 --buffer-size 5000 --max-subscribers 20 --insecure
```

## See Also

- [cmd/sniff/README.md](../sniff/README.md) - CLI-only packet capture
- [cmd/hunt/README.md](../hunt/README.md) - Distributed edge capture
- [cmd/process/README.md](../process/README.md) - Central aggregation
- [cmd/watch/README.md](../watch/README.md) - TUI monitoring
- [docs/SECURITY.md](../../docs/SECURITY.md) - TLS/mTLS setup
- [docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) - Performance tuning
- [docs/VIRTUAL_INTERFACE.md](../../docs/VIRTUAL_INTERFACE.md) - Virtual interface guide

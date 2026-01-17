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

TLS is enabled by default. Use `--insecure` for local testing without TLS.

```bash
# Standalone capture on eth0 (insecure, local testing only)
sudo lc tap --interface eth0 --insecure

# With TLS for TUI connections (secure, production)
sudo lc tap -i eth0 --tls-cert server.crt --tls-key server.key

# With auto-rotating PCAP writing (insecure, local testing)
sudo lc tap -i eth0 --auto-rotate-pcap --auto-rotate-pcap-dir /var/pcaps --insecure

# Hierarchical mode (forward to central processor)
sudo lc tap -i eth0 --processor central-processor:50051 --tls-ca ca.crt
```

## Commands

### `lc tap` - General Standalone Capture

Captures all packets (or BPF-filtered packets) and provides processor capabilities.

### `lc tap voip` - VoIP Standalone Capture

VoIP-optimized capture with SIP/RTP analysis, per-call PCAP writing enabled by default.

```bash
# VoIP capture with SIP user filtering
sudo lc tap voip --interface eth0 --sip-user alicent --insecure

# UDP-only VoIP capture (bypass TCP reassembly)
sudo lc tap voip -i eth0 --udp-only --sip-port 5060 --insecure

# High-performance VoIP capture
sudo lc tap voip -i eth0 --tcp-performance-mode high_performance --insecure
```

### `lc tap dns` - DNS Standalone Capture

DNS-optimized capture with tunneling detection and alerting.

```bash
# DNS capture with tunneling detection
sudo lc tap dns --interface eth0 --insecure

# DNS capture with custom ports
sudo lc tap dns -i eth0 --dns-port 53,5353 --udp-only --insecure

# DNS capture with tunneling alerts
sudo lc tap dns -i eth0 \
  --tunneling-command 'echo "ALERT: %domain% score=%score%" >> /var/log/tunneling.log' \
  --tunneling-threshold 0.7 \
  --tunneling-debounce 5m \
  --insecure
```

### `lc tap email` - Email Standalone Capture

Email-optimized capture for SMTP, IMAP, and POP3 protocols.

```bash
# Email capture (all protocols)
sudo lc tap email --interface eth0 --insecure

# SMTP only
sudo lc tap email -i eth0 --protocol smtp --insecure

# IMAP only with mailbox filtering
sudo lc tap email -i eth0 --protocol imap --mailbox "INBOX" --insecure

# Filter by sender/recipient
sudo lc tap email -i eth0 --sender "*@suspicious.com" --insecure
sudo lc tap email -i eth0 --recipient "admin@*" --insecure

# Email capture with auto-rotating PCAP
sudo lc tap email -i eth0 \
  --auto-rotate-pcap \
  --auto-rotate-pcap-dir /var/email/pcaps \
  --insecure
```

### `lc tap http` - HTTP Standalone Capture

HTTP-optimized capture with content filtering and HTTPS decryption support.

```bash
# HTTP capture
sudo lc tap http --interface eth0 --insecure

# Filter by host
sudo lc tap http -i eth0 --host "*.example.com" --insecure

# Filter by path
sudo lc tap http -i eth0 --path "/api/*" --insecure

# Filter by method
sudo lc tap http -i eth0 --method "POST,PUT,DELETE" --insecure

# HTTPS decryption with keylog
sudo lc tap http -i eth0 --tls-keylog /tmp/sslkeys.log --insecure

# HTTP capture with auto-rotating PCAP
sudo lc tap http -i eth0 \
  --auto-rotate-pcap \
  --auto-rotate-pcap-dir /var/http/pcaps \
  --insecure
```

### `lc tap tls` - TLS Standalone Capture

TLS-optimized capture with fingerprint analysis and SNI filtering.

```bash
# TLS capture
sudo lc tap tls --interface eth0 --insecure

# Filter by SNI pattern
sudo lc tap tls -i eth0 --sni "*.example.com" --insecure

# Multiple TLS ports
sudo lc tap tls -i eth0 --tls-port 443,8443 --insecure

# TLS capture with auto-rotating PCAP
sudo lc tap tls -i eth0 \
  --auto-rotate-pcap \
  --auto-rotate-pcap-dir /var/tls/pcaps \
  --insecure
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
- `-I, --id` - Unique tap identifier (default: hostname-tap)
- `--max-subscribers` - Maximum concurrent TUI subscribers (default: 100, 0 = unlimited)

### Upstream Forwarding

- `-P, --processor` - Upstream processor address for hierarchical mode (host:port)

### PCAP Writing

#### Unified PCAP

- `-w, --write-file` - Write all received packets to one PCAP file

#### Auto-Rotating PCAP

- `--auto-rotate-pcap` - Enable auto-rotating PCAP writing for non-VoIP traffic
- `--auto-rotate-pcap-dir` - Output directory (default: `./auto-rotate-pcaps`)
- `--auto-rotate-pcap-pattern` - Filename pattern (default: `{timestamp}.pcap`)
- `--auto-rotate-idle-timeout` - Close file after idle time (default: `30s`)
- `--auto-rotate-max-size` - Max file size before rotation (default: `100M`)

### Command Hooks

- `--pcap-command` - Command to execute when PCAP file closes (supports `%pcap%` placeholder)
- `--command-timeout` - Timeout for command execution (default: `30s`)
- `--command-concurrency` - Maximum concurrent command executions (default: `10`)

```bash
# Compress PCAP files after writing
lc tap -i eth0 --auto-rotate-pcap --pcap-command 'gzip %pcap%' --insecure
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

TLS is enabled by default unless `--insecure` is explicitly set.

- `--tls-cert` - Path to server TLS certificate (required unless --insecure)
- `--tls-key` - Path to server TLS key (required unless --insecure)
- `--tls-ca` - Path to CA certificate for client verification
- `--tls-client-auth` - Require client certificate authentication
- `--api-key-auth` - Enable API key authentication
- `--insecure` - Allow insecure connections without TLS (NOT RECOMMENDED for production)

### VoIP-Specific Flags (tap voip only)

These flags are only available with the `lc tap voip` subcommand:

#### SIP Filtering

- `-u, --sip-user` - SIP user/phone to match (comma-separated, supports wildcards)
- `--udp-only` - Capture UDP only, bypass TCP SIP
- `--sip-port` - Restrict SIP capture to specific port(s)
- `--rtp-port-range` - Custom RTP port range(s)

#### Per-Call PCAP

- `--per-call-pcap` - Enable per-call PCAP writing (enabled by default for tap voip)
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

#### VoIP Command Hook

- `--voip-command` - Command to execute when VoIP call completes (supports `%callid%`, `%dirname%`, etc.)

```bash
# Notify on call completion
lc tap voip -i eth0 --voip-command 'notify.sh %callid% %caller% %called%' --insecure
```

#### Performance Tuning

- `--pattern-algorithm` - Pattern matching algorithm: `auto`, `linear`, `aho-corasick`
- `--pattern-buffer-mb` - Memory budget for pattern buffer in MB
- `--tcp-performance-mode` - TCP performance mode: `minimal`, `balanced`, `high_performance`, `low_latency`

### DNS-Specific Flags (tap dns only)

These flags are only available with the `lc tap dns` subcommand:

#### DNS Filtering

- `--dns-port` - DNS port(s) to capture, comma-separated (default: `53`)
- `--udp-only` - Capture UDP DNS only (ignore TCP DNS)
- `--domain` - Filter by domain pattern (glob-style, e.g., `*.example.com`)
- `--domains-file` - Load domain patterns from file (one per line, # for comments)
- `--detect-tunneling` - Enable DNS tunneling detection (default: `true`)

#### DNS Tunneling Command Hook

- `--tunneling-command` - Command to execute when DNS tunneling is detected
- `--tunneling-threshold` - DNS tunneling score threshold for triggering command (0.0-1.0, default: `0.7`)
- `--tunneling-debounce` - Minimum time between alerts per domain (default: `5m`)

### Email-Specific Flags (tap email only)

These flags are only available with the `lc tap email` subcommand:

#### Protocol Selection

- `--protocol` - Email protocol to capture: `smtp`, `imap`, `pop3`, `all` (default: `all`)

#### Port Configuration

- `--smtp-port` - SMTP port(s) to capture, comma-separated (default: `25,587,465`)
- `--imap-port` - IMAP port(s) to capture, comma-separated (default: `143,993`)
- `--pop3-port` - POP3 port(s) to capture, comma-separated (default: `110,995`)

#### Email Filtering

- `--address` - Filter by email address pattern (matches sender OR recipient, glob-style)
- `--sender` - Filter by sender address pattern (MAIL FROM, glob-style)
- `--recipient` - Filter by recipient address pattern (RCPT TO, glob-style)
- `--subject` - Filter by subject pattern (glob-style)
- `--mailbox` - Filter by IMAP mailbox name (glob-style)
- `--command` - Filter by IMAP/POP3 command (glob-style, e.g., `FETCH`, `RETR`)

#### Email Pattern Files

- `--addresses-file` - Load address patterns from file (one per line)
- `--senders-file` - Load sender patterns from file (one per line)
- `--recipients-file` - Load recipient patterns from file (one per line)
- `--subjects-file` - Load subject patterns from file (one per line)
- `--keywords-file` - Load keywords from file for subject/body matching (Aho-Corasick)

#### Body Capture

- `--capture-body` - Enable email body content capture (for keyword matching)
- `--max-body-size` - Maximum body size to capture in bytes (default: 64KB)

### HTTP-Specific Flags (tap http only)

These flags are only available with the `lc tap http` subcommand:

#### Port Configuration

- `--http-port` - HTTP port(s) to capture, comma-separated (default: `80,8080,8000,3000,8888`)

#### HTTP Filtering

- `--host` - Filter by host pattern (glob-style)
- `--path` - Filter by path/URL pattern (glob-style)
- `--method` - Filter by HTTP methods (comma-separated, e.g., `GET,POST`)
- `--status` - Filter by status codes (e.g., `404`, `4xx`, `400-499`)
- `--user-agent` - Filter by User-Agent pattern (glob-style)
- `--content-type` - Filter by Content-Type pattern (glob-style)

#### HTTP Pattern Files

- `--hosts-file` - Load host patterns from file (one per line)
- `--paths-file` - Load path patterns from file (one per line)
- `--user-agents-file` - Load user-agent patterns from file (one per line)
- `--content-types-file` - Load content-type patterns from file (one per line)
- `--keywords-file` - Load keywords from file for body matching (Aho-Corasick)

#### Body Capture

- `--capture-body` - Enable HTTP body content capture (for keyword matching)
- `--max-body-size` - Maximum body size to capture in bytes (default: 64KB)

#### TLS Decryption (HTTPS)

- `--tls-keylog` - Path to SSLKEYLOGFILE for TLS decryption (HTTPS traffic)
- `--tls-keylog-pipe` - Path to named pipe for real-time TLS key injection

### TLS-Specific Flags (tap tls only)

These flags are only available with the `lc tap tls` subcommand:

#### Port Configuration

- `--tls-port` - TLS port(s) to capture, comma-separated (default: `443`)

#### SNI Filtering

- `--sni` - Filter by SNI pattern (glob-style, e.g., `*.example.com`)
- `--sni-file` - Load SNI patterns from file (one per line)

```bash
# Alert on DNS tunneling detection
sudo lc tap dns -i eth0 \
  --tunneling-command 'echo "ALERT: %domain% score=%score%" >> /var/log/tunneling.log' \
  --tunneling-threshold 0.7 \
  --tunneling-debounce 5m \
  --insecure

# Send to SIEM
sudo lc tap dns -i eth0 \
  --tunneling-command 'curl -X POST https://siem.example.com/alert \
    -d "domain=%domain%&score=%score%&entropy=%entropy%&queries=%queries%&srcips=%srcips%&time=%timestamp%"' \
  --tunneling-threshold 0.8 \
  --insecure
```

**Tunneling Command Placeholders:**

| Placeholder | Description | Example |
|-------------|-------------|---------|
| `%domain%` | Suspicious domain (or parent) | `evil.example.com` |
| `%score%` | Tunneling score (0.0-1.0) | `0.85` |
| `%entropy%` | Entropy score | `4.20` |
| `%queries%` | Query count observed | `1523` |
| `%srcips%` | Source IPs (comma-separated) | `192.168.1.10,192.168.1.20` |
| `%hunter%` | Hunter ID ("local" for tap mode) | `local` |
| `%timestamp%` | Detection time (RFC3339) | `2025-01-11T14:30:22Z` |

**Alerting Behavior:**
- Alerts trigger when a domain's tunneling score crosses the threshold
- Debounce prevents alert fatigue (same domain won't alert again until debounce expires)
- Commands execute asynchronously (don't block packet processing)

## Use Cases

### Single-Machine VoIP Capture

When you need full VoIP analysis on a single machine:

```bash
sudo lc tap voip -i eth0 \
  --sip-user alicent,robb \
  --per-call-pcap \
  --per-call-pcap-dir /var/voip/calls \
  --tls-cert server.crt --tls-key server.key
```

Monitor via TUI:
```bash
lc watch remote --addr localhost:50051 --tls-ca ca.crt
```

### Single-Machine DNS Capture

When you need DNS monitoring with tunneling detection on a single machine:

```bash
sudo lc tap dns -i eth0 \
  --auto-rotate-pcap \
  --auto-rotate-pcap-dir /var/dns/pcaps \
  --tunneling-command '/opt/scripts/alert.sh %domain% %score% %srcips%' \
  --tunneling-threshold 0.7 \
  --tls-cert server.crt --tls-key server.key
```

Monitor via TUI:
```bash
lc watch remote --addr localhost:50051 --tls-ca ca.crt
```

### Edge Node with Upstream Forwarding

Deploy tap nodes at edge locations, forwarding to central processor:

```bash
# Edge tap node
sudo lc tap voip -i eth0 \
  --processor central-processor:50051 \
  --tls-cert edge.crt --tls-key edge.key --tls-ca ca.crt

# Central processor (receives from multiple edge taps)
lc process --listen 0.0.0.0:50051 \
  --tls-cert server.crt --tls-key server.key --tls-ca ca.crt \
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

TLS is enabled by default. Use `--insecure` for local testing without TLS.

### Production Mode Enforcement

Set `LIPPYCAT_PRODUCTION=true` to enforce TLS (blocks `--insecure`):

```bash
export LIPPYCAT_PRODUCTION=true
lc tap -i eth0 --insecure  # ERROR: cannot use --insecure in production mode
lc tap -i eth0 --tls-cert server.crt --tls-key server.key  # OK
```

### TLS Configuration

**Server TLS (One-Way Authentication):**
```bash
lc tap -i eth0 \
  --tls-cert /etc/lippycat/certs/server.crt \
  --tls-key /etc/lippycat/certs/server.key
```

**Mutual TLS (Two-Way Authentication):**
```bash
lc tap -i eth0 \
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
  id: "edge-tap-01"
  max_subscribers: 100
  processor_addr: ""

  # PCAP writing
  write_file: ""
  auto_rotate_pcap:
    enabled: false
    output_dir: "/var/capture/bursts"
    idle_timeout: "30s"
    max_size: "100M"

  # Command hooks
  pcap_command: "gzip %pcap%"
  command_timeout: "30s"
  command_concurrency: 10

  # VoIP-specific PCAP (only applies to tap voip)
  per_call_pcap:
    enabled: true
    output_dir: "/var/capture/calls"
    file_pattern: "{timestamp}_{callid}.pcap"
  voip_command: ""

  # Protocol detection
  enable_detection: true

  # TLS (enabled by default unless --insecure is set)
  tls:
    cert_file: "/etc/lippycat/certs/server.crt"
    key_file: "/etc/lippycat/certs/server.key"
    ca_file: "/etc/lippycat/certs/ca.crt"
    client_auth: false

  # VoIP-specific (for tap voip)
  voip:
    sip_user: ""
    udp_only: false
    sip_ports: ""
    rtp_port_ranges: ""
    pattern_algorithm: "auto"
    pattern_buffer_mb: 64
    tcp_performance_mode: "balanced"

  # DNS-specific (for tap dns)
  dns:
    ports: "53"
    udp_only: false
    domain_pattern: ""
    domains_file: ""
    detect_tunneling: true

# DNS tunneling detection alerts (applies to processor and tap dns)
processor:
  tunneling_command: "/opt/scripts/alert.sh %domain% %score% %srcips%"
  tunneling_threshold: 0.7
  tunneling_debounce: "5m"
```

## Comparison with Other Modes

| Feature | `lc sniff` | `lc tap` | `lc tap voip` | `lc tap dns` | `lc tap email` | `lc tap http` | `lc tap tls` | `lc hunt` + `lc process` |
|---------|-----------|----------|---------------|--------------|----------------|---------------|--------------|--------------------------|
| Local capture | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Hunt only |
| TUI server | No | Yes | Yes | Yes | Yes | Yes | Yes | Process only |
| Per-call PCAP | No | No | Yes (default) | No | No | No | No | Process only |
| Auto-rotate PCAP | No | Yes | Yes | Yes (default) | Yes (default) | Yes (default) | Yes (default) | Process only |
| DNS tunneling detection | No | No | No | Yes | No | No | No | Process only |
| HTTPS decryption | No | No | No | No | No | Yes | No | Process only |
| Fingerprinting | No | No | No | No | No | No | JA3/JA3S/JA4 | Process only |
| Upstream forwarding | No | Yes | Yes | Yes | Yes | Yes | Yes | Process only |
| Distributed capture | No | No | No | No | No | No | No | Yes |
| Deployment | Single machine | Single machine | Single machine | Single machine | Single machine | Single machine | Single machine | Multi-machine |
| Use case | Quick analysis | General capture | VoIP calls | DNS monitoring | Email capture | HTTP/HTTPS | TLS analysis | Distributed production |

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

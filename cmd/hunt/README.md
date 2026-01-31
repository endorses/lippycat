# Hunt Command - Hunter Node Operation

The `hunt` command runs lippycat as a hunter node - a lightweight edge capture agent that forwards packets to a central processor node.

## Overview

Hunters capture packets at the network edge and forward matched packets to processor nodes via gRPC. This distributed architecture allows:
- Scalable packet capture across multiple network segments
- Edge filtering to reduce bandwidth
- Centralized analysis and monitoring
- Network segmentation (capture in restricted zones, analyze elsewhere)

## Basic Usage

```bash
# Standard hunter mode
lc hunt --processor processor.example.com:55555 --interface eth0

# Multiple interfaces
lc hunt --processor 192.168.1.100:55555 -i eth0,eth1

# With custom hunter ID
lc hunt --processor processor:55555 --id edge-01

# VoIP hunter with call buffering
lc hunt voip --processor processor:55555
```

## Commands

### `lc hunt` - General Hunter Mode

Captures all packets (or BPF-filtered packets) and forwards to processor.

**Required Flags:**
- `-P, --processor` - Processor address (host:port) **[REQUIRED]**

**Hunter Configuration:**
- `-I, --id` - Unique hunter identifier (default: hostname)
- `-i, --interface` - Network interfaces to capture (comma-separated, default: any)
- `-f, --filter` - BPF filter expression
- `-p, --promisc` - Enable promiscuous mode

**Performance Tuning:**
- `-b, --buffer-size` - Packet buffer size (default: 10000)
- `--batch-size` - Packets per batch sent to processor (default: 64)
- `--batch-timeout` - Batch timeout in milliseconds (default: 100ms)
- `--batch-queue-size` - Batch queue buffer size (default: 1000, 0 = auto)

**VoIP Filtering:**
- `--enable-voip-filter` - Enable GPU-accelerated VoIP filtering at edge
- `--gpu-backend` - GPU backend: `auto`, `cuda`, `opencl`, `cpu-simd` (default: auto)
- `--gpu-batch-size` - Batch size for GPU processing (default: 100)

**Pattern Matching Algorithm:**
- `--pattern-algorithm` - Pattern matching algorithm: `auto`, `linear`, `aho-corasick` (default: auto)
  - `auto`: Selects Aho-Corasick for 100+ patterns, linear scan otherwise
  - `linear`: O(n×m) linear scan - simple, low memory, good for <100 patterns
  - `aho-corasick`: O(n+m+z) Aho-Corasick automaton - ~265x faster at 10K patterns
- `--pattern-buffer-mb` - Memory budget for pattern buffer in MB (default: 64)

**Disk Buffer (Nuclear-Proof Resilience):**
- `--disk-buffer` - Enable disk overflow buffer for extended disconnections
- `--disk-buffer-dir` - Directory for buffer files (default: /var/tmp/lippycat-buffer)
- `--disk-buffer-max-mb` - Maximum disk buffer size in MB (default: 1024)

**TLS/Security (TLS enabled by default):**
- `--tls-cert` - Path to client TLS certificate (for mutual TLS)
- `--tls-key` - Path to client TLS key (for mutual TLS)
- `--tls-ca` - Path to CA certificate for server verification (required for TLS)
- `--tls-skip-verify` - Skip TLS certificate verification (INSECURE - testing only)
- `--insecure` - Disable TLS encryption (must be explicitly set, NOT RECOMMENDED)

### `lc hunt dns` - DNS Hunter Mode

DNS hunter mode captures and forwards DNS queries/responses to the processor.

**Features:**
- DNS query/response capture
- Domain pattern filtering at edge
- DNS tunneling detection forwarding
- UDP and TCP DNS support

**DNS-Specific Flags:**
- `--dns-port` - DNS port(s) to capture, comma-separated (default: `53`)
- `--udp-only` - Capture UDP DNS only (ignore TCP DNS)

**Example:**

```bash
# DNS hunter with TLS
lc hunt dns \
  --processor processor:55555 \
  -i eth0 \
  --tls-ca ca.crt

# DNS hunter UDP-only with custom port
lc hunt dns \
  --processor processor:55555 \
  -i eth0 \
  --dns-port 53,5353 \
  --udp-only \
  --tls-ca ca.crt
```

### `lc hunt email` - Email Hunter Mode

Email hunter mode captures and forwards email protocol traffic (SMTP, IMAP, POP3) to the processor.

**Features:**
- SMTP, IMAP, POP3 capture
- Protocol-specific filtering at edge
- Session correlation forwarding
- Address pattern matching

**Email-Specific Flags:**
- `--protocol` - Email protocol: `smtp`, `imap`, `pop3`, `all` (default: `all`)
- `--smtp-port` - SMTP port(s) (default: `25,587,465`)
- `--imap-port` - IMAP port(s) (default: `143,993`)
- `--pop3-port` - POP3 port(s) (default: `110,995`)
- `--address` - Filter by email address pattern (glob-style)
- `--sender` - Filter by sender address pattern (glob-style)
- `--recipient` - Filter by recipient address pattern (glob-style)

**Example:**

```bash
# Email hunter capturing all protocols
lc hunt email \
  --processor processor:55555 \
  -i eth0 \
  --tls-ca ca.crt

# SMTP-only hunter with sender filtering
lc hunt email \
  --processor processor:55555 \
  -i eth0 \
  --protocol smtp \
  --sender "*@suspicious.com" \
  --tls-ca ca.crt
```

### `lc hunt http` - HTTP Hunter Mode

HTTP hunter mode captures and forwards HTTP traffic to the processor for content analysis.

**Features:**
- HTTP request/response capture
- Host/path filtering at edge
- Method and status filtering
- TCP stream forwarding

**HTTP-Specific Flags:**
- `--http-port` - HTTP port(s) (default: `80,8080,8000,3000,8888`)
- `--host` - Filter by host pattern (glob-style)
- `--path` - Filter by path pattern (glob-style)
- `--method` - Filter by HTTP methods (comma-separated)

**Example:**

```bash
# HTTP hunter
lc hunt http \
  --processor processor:55555 \
  -i eth0 \
  --tls-ca ca.crt

# HTTP hunter with host filtering
lc hunt http \
  --processor processor:55555 \
  -i eth0 \
  --host "*.example.com" \
  --http-port 80,8080 \
  --tls-ca ca.crt
```

### `lc hunt tls` - TLS Hunter Mode

TLS hunter mode captures TLS handshakes and forwards them to the processor for fingerprint analysis.

**Features:**
- TLS ClientHello/ServerHello capture
- JA3/JA3S/JA4 fingerprint extraction
- SNI filtering at edge
- Efficient forwarding to processor

**Note:** SNI and fingerprint filtering is managed by the processor and pushed to hunters.

**TLS-Specific Flags:**
- `--tls-port` - TLS port(s) to capture, comma-separated (default: `443`)

**Example:**

```bash
# TLS hunter
lc hunt tls \
  --processor processor:55555 \
  -i eth0 \
  --tls-ca ca.crt

# TLS hunter with multiple ports
lc hunt tls \
  --processor processor:55555 \
  -i eth0 \
  --tls-port 443,8443 \
  --tls-ca ca.crt
```

### `lc hunt voip` - VoIP Hunter Mode

VoIP hunter mode provides intelligent call buffering and filtering:

**Features:**
- SIP header extraction (From, To, P-Asserted-Identity)
- SDP parsing for RTP port discovery
- Per-call packet buffering (SIP + RTP packets)
- Filter matching using processor-provided filters
- Selective forwarding (only matched calls sent to processor)
- TCP SIP reassembly with buffering
- BPF filter optimization for high-traffic networks

**BPF Filter Optimization Flags:**
- `--udp-only` - Capture UDP only, bypass TCP SIP (reduces CPU on TCP-heavy networks)
- `--sip-port` - Restrict SIP capture to specific port(s), comma-separated
- `--rtp-port-range` - Custom RTP port range(s), comma-separated (default: 10000-32768)

**How It Works:**

1. Hunter captures SIP/RTP packets
2. Packets are buffered locally until call is identified
3. Filter subscription receives filters from processor
4. Buffered packets are matched against filters
5. Only matched calls (SIP + associated RTP) are forwarded
6. Reduces bandwidth by 90%+ for targeted monitoring

**Example:**

```bash
# VoIP hunter with TLS (TLS enabled by default)
lc hunt voip \
  --processor processor.example.com:55555 \
  --interface eth0 \
  --tls-ca /etc/lippycat/certs/ca.crt

# VoIP hunter with client certificate (mutual TLS)
lc hunt voip \
  --processor processor:55555 \
  --tls-cert /etc/lippycat/certs/hunter.crt \
  --tls-key /etc/lippycat/certs/hunter.key \
  --tls-ca /etc/lippycat/certs/ca.crt

# VoIP hunter with BPF filter optimization (UDP-only)
lc hunt voip \
  --processor processor:55555 \
  --interface eth0 \
  --udp-only \
  --tls-ca ca.crt

# VoIP hunter with specific SIP port
lc hunt voip \
  --processor processor:55555 \
  --interface eth0 \
  --sip-port 5060 \
  --tls-ca ca.crt

# VoIP hunter with custom RTP port range
lc hunt voip \
  --processor processor:55555 \
  --interface eth0 \
  --rtp-port-range 8000-9000 \
  --tls-ca ca.crt
```

**Filter Management:**

Filters are managed centrally by the processor and pushed to hunters via the filter subscription mechanism. Hunters do NOT configure filters locally - they receive them from the processor.

**Wildcard Pattern Support:**

Filters support wildcard patterns for flexible matching:

| Pattern | Type | Description |
|---------|------|-------------|
| `alice` | Contains | Substring match (backward compatible) |
| `*456789` | Suffix | Matches any prefix + `456789` |
| `alice*` | Prefix | Matches `alice` + any suffix |

This is particularly useful for phone number matching where the same number may appear in different formats (E.164, 00-prefix, tech prefixes like `*31#`).

To add filters, configure them in the processor's filter file (see [cmd/process/README.md](../process/README.md#filter-management)).

## Security

### Production Mode Enforcement

Set `LIPPYCAT_PRODUCTION=true` to block the `--insecure` flag:

```bash
export LIPPYCAT_PRODUCTION=true
lc hunt --processor processor:55555 --insecure  # ERROR: --insecure not allowed
lc hunt --processor processor:55555 --tls-ca ca.crt  # OK (TLS is default)
```

### TLS Configuration

TLS is enabled by default. Hunters support three TLS modes:

**1. Server TLS (One-Way Authentication)**

Hunter verifies processor's certificate (default when `--tls-ca` is provided):

```bash
lc hunt --processor processor:55555 \
  --tls-ca /etc/lippycat/certs/ca.crt
```

**2. Mutual TLS (Two-Way Authentication) ⭐ Recommended**

Both hunter and processor verify each other:

```bash
lc hunt --processor processor:55555 \
  --tls-cert /etc/lippycat/certs/hunter.crt \
  --tls-key /etc/lippycat/certs/hunter.key \
  --tls-ca /etc/lippycat/certs/ca.crt
```

**3. Insecure Mode (No TLS) ⚠️**

Only for testing on trusted networks. Must explicitly disable TLS:

```bash
lc hunt --processor localhost:55555 --insecure
```

**Security Warning:** Displays prominent banner when TLS is disabled.

See [docs/SECURITY.md](../../docs/SECURITY.md#tls-transport-encryption) for complete TLS setup.

## Resilience Features

### Disk Overflow Buffer

When enabled, hunters buffer packets to disk when the memory queue is full (during extended disconnections):

```bash
# Enable 2GB disk buffer
lc hunt --processor processor:55555 \
  --disk-buffer \
  --disk-buffer-max-mb 2048
```

**Behavior:**
- Memory queue holds ~64K packets (1000 batches × 64 packets)
- When memory queue is full, batches overflow to disk
- Disk buffer can hold millions of packets (1GB ≈ 15M packets)
- Automatic refill: When connection restored, disk batches feed back to memory queue
- FIFO ordering: Oldest packets sent first
- Graceful degradation: If disk is full, oldest batches are dropped

**Use Cases:**
- Laptop sleep/resume scenarios
- Extended network outages (hours/days)
- Processor maintenance windows
- Network partition recovery

### Circuit Breaker

Automatically prevents connection thrashing when processor is down:
- Opens circuit after 5 consecutive connection failures
- Waits 30s before retry (prevents resource exhaustion)
- Half-open state: Limited test connections before full recovery

## Performance Tuning

### Batch Configuration

Batching controls how hunters aggregate packets before sending to processor:

```bash
# Low latency (send quickly, smaller batches)
lc hunt --processor processor:55555 \
  --batch-size 16 \
  --batch-timeout 50

# High throughput (larger batches, less frequent sends)
lc hunt --processor processor:55555 \
  --batch-size 256 \
  --batch-timeout 500

# Balanced (default)
lc hunt --processor processor:55555 \
  --batch-size 64 \
  --batch-timeout 100
```

**Guidelines:**
- **Low latency**: batch-size 16-32, timeout 50-100ms
- **Balanced**: batch-size 64-128, timeout 100-200ms
- **High throughput**: batch-size 256-512, timeout 500-1000ms

### GPU Acceleration

Enable GPU acceleration for VoIP pattern matching at the edge:

```bash
# Auto-detect best backend
lc hunt --enable-voip-filter --gpu-backend auto

# Force CUDA (NVIDIA GPUs)
lc hunt --enable-voip-filter --gpu-backend cuda --gpu-batch-size 200

# CPU SIMD only (no GPU)
lc hunt --enable-voip-filter --gpu-backend cpu-simd
```

**When to use:**
- High packet rates (>10,000 pps)
- Many concurrent SIP calls
- Hunter has dedicated GPU
- Want to minimize processor load

## Configuration File

All flags can be specified in `~/.config/lippycat/config.yaml`:

```yaml
hunter:
  processor_addr: "processor.example.com:55555"
  id: "edge-hunter-01"
  interfaces:
    - "eth0"
    - "eth1"
  bpf_filter: "port 5060 or portrange 10000-20000"

  # Performance
  buffer_size: 10000
  batch_size: 64
  batch_timeout_ms: 100
  batch_queue_size: 1000

  # VoIP filtering
  voip_filter:
    enabled: true
    gpu_backend: "auto"
    gpu_batch_size: 100

  # Pattern matching algorithm (for VoIP user/phone filtering)
  pattern_algorithm: "auto"    # auto, linear, or aho-corasick
  pattern_buffer_mb: 64        # Memory budget for pattern buffer

  # VoIP BPF filter optimization (for lc hunt voip)
  voip:
    udp_only: false
    sip_ports: "5060"
    rtp_port_ranges: "10000-32768"

  # TLS security
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/hunter.crt"
    key_file: "/etc/lippycat/certs/hunter.key"
    ca_file: "/etc/lippycat/certs/ca.crt"
    skip_verify: false

promiscuous: false
```

## Best Practices

1. **Always use TLS in production** - TLS is enabled by default, use mutual authentication for best security
2. **Set meaningful hunter IDs** - Use `--hunter-id` for easier monitoring
3. **Use BPF filters** - Reduce capture scope with `--filter` (e.g., "port 5060")
4. **Tune batch parameters** - Balance latency vs. throughput for your use case
5. **Monitor hunter health** - Use processor's monitoring API to track hunter status
6. **Use VoIP mode for targeted monitoring** - `hunt voip` reduces bandwidth by 90%+
7. **Test TLS setup** - Verify certificates work before deploying to production

## Troubleshooting

### Connection Issues

```bash
# Test connectivity without TLS
lc hunt --processor processor:55555 --insecure

# Verify TLS certificate
openssl s_client -connect processor:55555 -showcerts -CAfile ca.crt

# Check DNS resolution
ping processor.example.com
```

### Performance Issues

```bash
# Check if hunter is dropping packets
# (look for drop statistics in logs)

# Increase buffer sizes
lc hunt --processor processor:55555 --buffer-size 20000 --batch-queue-size 2000

# Reduce batch timeout for lower latency
lc hunt --processor processor:55555 --batch-timeout 50
```

### VoIP Filter Not Working

```bash
# Verify filter subscription in logs
# Look for "Received filter update" messages

# Check processor has filters configured
# (see processor's filter file or management API)

# Test GPU backend
lc hunt --enable-voip-filter --gpu-backend cpu-simd  # Fallback to CPU
```

## See Also

- [cmd/process/CLAUDE.md](../process/CLAUDE.md) - Processor node configuration and filter management
- [docs/SECURITY.md](../../docs/SECURITY.md) - TLS/mTLS setup and certificate management
- [docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md) - Production deployment patterns
- [docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) - Performance tuning guide

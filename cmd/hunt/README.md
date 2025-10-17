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
lc hunt --processor processor.example.com:50051 --interface eth0

# Multiple interfaces
lc hunt --processor 192.168.1.100:50051 -i eth0,eth1

# With custom hunter ID
lc hunt --processor processor:50051 --hunter-id edge-01

# VoIP hunter with call buffering
lc hunt voip --processor processor:50051
```

## Commands

### `lc hunt` - General Hunter Mode

Captures all packets (or BPF-filtered packets) and forwards to processor.

**Required Flags:**
- `--processor` - Processor address (host:port) **[REQUIRED]**

**Hunter Configuration:**
- `--hunter-id` - Unique hunter identifier (default: hostname)
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

**TLS/Security:**
- `--tls` - Enable TLS encryption (recommended for production)
- `--tls-cert` - Path to client TLS certificate (for mutual TLS)
- `--tls-key` - Path to client TLS key (for mutual TLS)
- `--tls-ca` - Path to CA certificate for server verification
- `--tls-skip-verify` - Skip TLS certificate verification (INSECURE - testing only)
- `--insecure` - Allow insecure connections without TLS (must be explicitly set)

### `lc hunt voip` - VoIP Hunter Mode

VoIP hunter mode provides intelligent call buffering and filtering:

**Features:**
- SIP header extraction (From, To, P-Asserted-Identity)
- SDP parsing for RTP port discovery
- Per-call packet buffering (SIP + RTP packets)
- Filter matching using processor-provided filters
- Selective forwarding (only matched calls sent to processor)
- TCP SIP reassembly with buffering

**How It Works:**

1. Hunter captures SIP/RTP packets
2. Packets are buffered locally until call is identified
3. Filter subscription receives filters from processor
4. Buffered packets are matched against filters
5. Only matched calls (SIP + associated RTP) are forwarded
6. Reduces bandwidth by 90%+ for targeted monitoring

**Example:**

```bash
# VoIP hunter with TLS
lc hunt voip \
  --processor processor.example.com:50051 \
  --interface eth0 \
  --tls \
  --tls-ca /etc/lippycat/certs/ca.crt

# VoIP hunter with client certificate (mutual TLS)
lc hunt voip \
  --processor processor:50051 \
  --tls \
  --tls-cert /etc/lippycat/certs/hunter.crt \
  --tls-key /etc/lippycat/certs/hunter.key \
  --tls-ca /etc/lippycat/certs/ca.crt
```

**Filter Management:**

Filters are managed centrally by the processor and pushed to hunters via the filter subscription mechanism. Hunters do NOT configure filters locally - they receive them from the processor.

To add filters, use the processor's management API or filter file (see [cmd/process/CLAUDE.md](../process/CLAUDE.md#filter-management)).

## Security

### Production Mode Enforcement

Set `LIPPYCAT_PRODUCTION=true` to enforce TLS:

```bash
export LIPPYCAT_PRODUCTION=true
lc hunt --processor processor:50051  # ERROR: requires --tls
lc hunt --processor processor:50051 --tls --tls-ca ca.crt  # OK
```

### TLS Configuration

Hunters support three TLS modes:

**1. Server TLS (One-Way Authentication)**

Hunter verifies processor's certificate:

```bash
lc hunt --processor processor:50051 \
  --tls \
  --tls-ca /etc/lippycat/certs/ca.crt
```

**2. Mutual TLS (Two-Way Authentication) ⭐ Recommended**

Both hunter and processor verify each other:

```bash
lc hunt --processor processor:50051 \
  --tls \
  --tls-cert /etc/lippycat/certs/hunter.crt \
  --tls-key /etc/lippycat/certs/hunter.key \
  --tls-ca /etc/lippycat/certs/ca.crt
```

**3. Insecure Mode (No TLS) ⚠️**

Only for testing on trusted networks:

```bash
lc hunt --processor localhost:50051 --insecure
```

**Security Warning:** Displays prominent banner when TLS is disabled.

See [docs/SECURITY.md](../../docs/SECURITY.md#tls-transport-encryption) for complete TLS setup.

## Performance Tuning

### Batch Configuration

Batching controls how hunters aggregate packets before sending to processor:

```bash
# Low latency (send quickly, smaller batches)
lc hunt --processor processor:50051 \
  --batch-size 16 \
  --batch-timeout 50

# High throughput (larger batches, less frequent sends)
lc hunt --processor processor:50051 \
  --batch-size 256 \
  --batch-timeout 500

# Balanced (default)
lc hunt --processor processor:50051 \
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
  processor_addr: "processor.example.com:50051"
  hunter_id: "edge-hunter-01"
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

1. **Always use TLS in production** - Use `--tls` with mutual authentication
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
lc hunt --processor processor:50051 --insecure

# Verify TLS certificate
openssl s_client -connect processor:50051 -showcerts -CAfile ca.crt

# Check DNS resolution
ping processor.example.com
```

### Performance Issues

```bash
# Check if hunter is dropping packets
# (look for drop statistics in logs)

# Increase buffer sizes
lc hunt --processor processor:50051 --buffer-size 20000 --batch-queue-size 2000

# Reduce batch timeout for lower latency
lc hunt --processor processor:50051 --batch-timeout 50
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

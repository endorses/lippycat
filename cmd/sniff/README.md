# Sniff Command - CLI Packet Capture

The `sniff` command provides CLI-mode packet capture with support for general packet capture and VoIP-specific analysis.

## Commands

### General Packet Capture

```bash
# Live capture with JSON output (default)
lc sniff --interface eth0 --filter "port 80"
lc sniff -i eth0 -f "tcp and port 5060"

# Read from PCAP file
lc sniff --read-file capture.pcap

# Text format output (legacy)
lc sniff -i eth0 --format text
```

**Common Flags:**
- `-i, --interface` - Network interface to capture from
- `-f, --filter` - BPF filter expression
- `-r, --read-file` - Read from PCAP file instead of live capture
- `--format` - Output format: `json` (default), `text`
- `-q, --quiet` - Quiet mode - don't print packets (only statistics to stderr)

## Output Formats

### JSON Format (Default)

JSON Lines format - one JSON object per line, suitable for streaming and parsing:

```bash
# Capture to JSON (default)
lc sniff -r testdata/pcaps/sip.pcap 2>/dev/null | head -1
```

**Output:**
```json
{"Timestamp":"2025-09-28T18:59:18.000001+02:00","SrcIP":"192.168.1.100","DstIP":"192.168.1.101","SrcPort":"5060","DstPort":"5060","Protocol":"TCP","Length":74,"Info":"Flags: [SYN]","RawData":null,"NodeID":"Local","Interface":"sip.pcap","VoIPData":null,"LinkType":1}
```

**Parse with jq:**
```bash
lc sniff -r capture.pcap 2>/dev/null | jq -r '"\(.Timestamp) \(.SrcIP):\(.SrcPort) → \(.DstIP):\(.DstPort) \(.Protocol) \(.Info)"'
```

**Output:**
```
2025-09-28T18:59:18.000001+02:00 192.168.1.100:5060 → 192.168.1.101:5060 TCP Flags: [SYN]
```

**Filter with jq:**
```bash
# Only TCP packets
lc sniff -r capture.pcap 2>/dev/null | jq 'select(.Protocol == "TCP")'

# Only packets to port 443
lc sniff -r capture.pcap 2>/dev/null | jq 'select(.DstPort == "443")'

# Extract specific fields
lc sniff -r capture.pcap 2>/dev/null | jq '{time: .Timestamp, src: .SrcIP, dst: .DstIP, proto: .Protocol}'
```

### Text Format

Legacy gopacket text representation:

```bash
lc sniff -r capture.pcap --format text 2>/dev/null | head -1
```

### stdout/stderr Separation

Following Unix conventions:
- **stdout**: Packet data only (JSON or text format)
- **stderr**: Structured logs (JSON format)

```bash
# Redirect logs to file, packets to stdout
lc sniff -i eth0 2>logs.json | process-packets.py

# Suppress logs entirely
lc sniff -i eth0 2>/dev/null | jq .

# Only show statistics (quiet mode suppresses packet output)
lc sniff -r capture.pcap --quiet
```

**Example stderr logs:**
```json
{"time":"2025-10-19T13:18:04.33104697+02:00","level":"INFO","msg":"Starting packet sniffer"}
{"time":"2025-10-19T13:18:04.332556652+02:00","level":"INFO","msg":"Packet processing completed","total_packets":5}
```

## Offline Mode (PCAP Files)

When reading from PCAP files (`--read-file`), the command automatically:
- Exits cleanly when all packets are processed (no need for Ctrl+C)
- Works with pipes and `head` commands
- Processes at maximum speed (no rate limiting)

```bash
# Process entire file and exit
lc sniff -r capture.pcap 2>/dev/null | wc -l

# Process first 100 packets and exit
lc sniff -r capture.pcap 2>/dev/null | head -100

# Extract all SIP packets
lc sniff -r capture.pcap -f "port 5060" 2>/dev/null | jq -c .
```

### VoIP-Specific Capture

```bash
lc sniff voip --interface eth0 --sipuser alicent
lc sniff voip -i eth0 -u alicent,robb --write-file
lc sniff voip --read-file voip-capture.pcap --sipuser alicent
```

The `sniff voip` subcommand provides SIP/RTP-specific capture with advanced filtering, TCP reassembly, and optional GPU acceleration.

## VoIP Mode Features

### SIP User Filtering

**Purpose:** Capture traffic for specific SIP users by filtering on SIP headers (From, To, P-Asserted-Identity).

```bash
# Single user
lc sniff voip -i eth0 --sipuser alicent@example.com

# Multiple users (comma-separated)
lc sniff voip -i eth0 --sipuser alicent,robb,charlie

# User without domain
lc sniff voip -i eth0 --sipuser alicent
```

### PCAP File Writing

**Flag:** `--write-file` / `-w`

Enables writing captured VoIP packets to PCAP files for later analysis.

```bash
lc sniff voip -i eth0 -u alicent --write-file
```

### GPU Acceleration

**Purpose:** Accelerate pattern matching for SIP header extraction using GPU or SIMD instructions.

**Flags:**
- `--gpu-enable` - Enable GPU acceleration (default: true)
- `--gpu-backend` - Backend selection: `auto`, `cuda`, `opencl`, `cpu-simd`, `disabled`
- `--gpu-batch-size` - Batch size for GPU processing (default: 1024)
- `--gpu-max-memory` - Maximum GPU memory in bytes (0 = auto)

**Examples:**

```bash
# Auto-detect best available backend
lc sniff voip -i eth0 --gpu-backend auto

# Force CUDA backend
lc sniff voip -i eth0 --gpu-backend cuda --gpu-batch-size 2048

# Use CPU SIMD only (no GPU)
lc sniff voip -i eth0 --gpu-backend cpu-simd

# Disable acceleration entirely
lc sniff voip -i eth0 --gpu-enable=false
```

**Backend Selection:**
- `auto` - Automatically selects best available: CUDA > OpenCL > CPU SIMD
- `cuda` - NVIDIA GPU acceleration (requires CUDA)
- `opencl` - OpenCL GPU acceleration (AMD/Intel/NVIDIA)
- `cpu-simd` - CPU SIMD instructions (AVX2/SSE4.2)
- `disabled` - No acceleration (pure Go implementation)

### TCP Performance Tuning

VoIP mode includes extensive TCP reassembly configuration for handling SIP over TCP.

#### Performance Profiles (Recommended)

**Flag:** `--tcp-performance-mode`

Use predefined performance profiles that auto-configure 17+ TCP parameters:

```bash
# Balanced (default) - Good for most use cases
lc sniff voip -i eth0 --tcp-performance-mode balanced

# Minimal - Low memory usage (embedded/constrained environments)
lc sniff voip -i eth0 --tcp-performance-mode minimal

# High Performance - Maximum throughput (high-traffic environments)
lc sniff voip -i eth0 --tcp-performance-mode high_performance

# Low Latency - Minimize processing delay (real-time analysis)
lc sniff voip -i eth0 --tcp-performance-mode low_latency
```

**Profile Characteristics:**

| Profile | Memory | Throughput | Latency | Use Case |
|---------|--------|------------|---------|----------|
| `minimal` | 25MB | Low | Medium | Embedded systems, low traffic |
| `balanced` | 100MB | Medium | Medium | General purpose (default) |
| `high_performance` | 500MB | High | Higher | High-traffic production |
| `low_latency` | 200MB | Medium | Low | Real-time analysis |

See [docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) for detailed profile specifications.

#### Fine-Grained TCP Configuration

For advanced users, individual TCP parameters can be overridden:

**Resource Limits:**
- `--tcp-max-goroutines` - Maximum concurrent TCP stream processing goroutines (0 = auto)
- `--max-tcp-buffers` - Maximum number of TCP packet buffers (0 = use profile default)
- `--tcp-assembler-max-pages` - Maximum pages for TCP assembler (0 = use profile default)

**Timing Parameters:**
- `--tcp-cleanup-interval` - Resource cleanup interval (0 = use profile default)
- `--tcp-buffer-max-age` - Maximum age for TCP packet buffers (0 = use profile default)
- `--tcp-stream-max-queue-time` - Maximum time a stream can wait in queue (0 = use profile default)
- `--tcp-stream-timeout` - Timeout for TCP stream processing (0 = use profile default)

**Strategy Options:**
- `--tcp-buffer-strategy` - Buffering strategy: `adaptive`, `fixed`, `ring` (default: adaptive)
- `--enable-backpressure` - Enable backpressure handling for TCP streams
- `--memory-optimization` - Enable memory usage optimizations

**Examples:**

```bash
# Override specific parameters while using balanced profile
lc sniff voip -i eth0 \
  --tcp-performance-mode balanced \
  --max-tcp-buffers 10000 \
  --enable-backpressure

# Full manual configuration (not recommended - use profiles instead)
lc sniff voip -i eth0 \
  --tcp-max-goroutines 8 \
  --max-tcp-buffers 5000 \
  --tcp-buffer-strategy adaptive \
  --tcp-stream-timeout 300s \
  --enable-backpressure \
  --memory-optimization
```

## Configuration File Support

All flags can be specified in the configuration file (`~/.config/lippycat/config.yaml`):

```yaml
voip:
  # GPU acceleration
  gpu_enable: true
  gpu_backend: "auto"
  gpu_batch_size: 1024
  gpu_max_memory: 0

  # TCP performance
  tcp_performance_mode: "balanced"
  enable_backpressure: true
  memory_optimization: false

  # Fine-grained TCP config (optional)
  max_goroutines: 0
  max_tcp_buffers: 5000
  tcp_cleanup_interval: 60s
  tcp_buffer_max_age: 300s
  tcp_stream_max_queue_time: 120s
  tcp_stream_timeout: 300s
  tcp_assembler_max_pages: 100
  tcp_buffer_strategy: "adaptive"
```

## Virtual Interface Integration

**Status:** Production-ready (v0.2.10+, Linux only)

Expose filtered packet streams to third-party tools (Wireshark, tcpdump, Snort) via virtual TAP/TUN interface.

### Quick Start

```bash
# PCAP replay with filtering (tcpreplay alternative)
sudo lc sniff voip -r capture.pcap --sipuser alice --virtual-interface

# Monitor in another terminal
wireshark -i lc0
```

### Use Cases

#### 1. PCAP Replay Filtering
```bash
# Replay large PCAP, filter for specific user
sudo lc sniff voip -r 10GB-capture.pcap --sipuser alice --virtual-interface

# Capture filtered stream
tcpdump -i lc0 -w alice-calls.pcap
```

#### 2. Live VoIP Monitoring
```bash
# Capture only VoIP traffic
sudo lc sniff voip -i eth0 --virtual-interface

# Multiple tools can monitor simultaneously
wireshark -i lc0 &
snort -i lc0 -c voip-rules.conf &
```

#### 3. Timing Replay
```bash
# Preserve PCAP timing (like tcpreplay)
sudo lc sniff voip -r capture.pcap --virtual-interface --vif-replay-timing

# Verify timing with tcpdump
tcpdump -i lc0 -tttt -n
```

### Configuration

```bash
--virtual-interface              # Enable virtual interface
--vif-name lc0                   # Interface name (default: lc0)
--vif-type tap                   # Interface type: tap or tun (default: tap)
--vif-buffer-size 4096           # Injection queue size
--vif-startup-delay 3s           # Delay before injection starts
--vif-replay-timing              # Respect PCAP timestamps
```

### Permissions

Requires `CAP_NET_ADMIN` capability:

```bash
# Recommended: File capabilities
sudo setcap cap_net_admin+ep /usr/local/bin/lc
lc sniff voip -i eth0 --virtual-interface

# Alternative: Run as root
sudo lc sniff voip -i eth0 --virtual-interface
```

**See:** [docs/VIRTUAL_INTERFACE.md](../../docs/VIRTUAL_INTERFACE.md) for complete guide and tool integration examples.

## Best Practices

1. **Start with profiles** - Use `--tcp-performance-mode` instead of manual tuning
2. **Monitor memory usage** - Check `lc debug metrics` to verify profile fits your environment
3. **Use GPU acceleration** - Significant performance improvement for SIP parsing (default: enabled)
4. **Enable backpressure** - Prevents memory exhaustion under heavy load
5. **Test with sample traffic** - Validate configuration with representative PCAP files first

## See Also

- [docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) - Detailed performance tuning guide
- [docs/VIRTUAL_INTERFACE.md](../../docs/VIRTUAL_INTERFACE.md) - Virtual interface guide and tool integration
- [cmd/debug/CLAUDE.md](../debug/CLAUDE.md) - Debug commands for monitoring TCP health
- [docs/SECURITY.md](../../docs/SECURITY.md) - Security features and configuration

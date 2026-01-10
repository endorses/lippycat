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
lc sniff voip --interface eth0 --sip-user alicent
lc sniff voip -i eth0 -u alicent,robb --write-file
lc sniff voip --read-file voip-capture.pcap --sip-user alicent
```

The `sniff voip` subcommand provides SIP/RTP-specific capture with advanced filtering, TCP reassembly, and optional GPU acceleration.

## VoIP Mode Features

### SIP User Filtering

**Purpose:** Capture traffic for specific SIP users by filtering on SIP headers (From, To, P-Asserted-Identity).

```bash
# Single user
lc sniff voip -i eth0 --sip-user alicent@example.com

# Multiple users (comma-separated)
lc sniff voip -i eth0 --sip-user alicent,robb,charlie

# User without domain
lc sniff voip -i eth0 --sip-user alicent
```

#### Wildcard Pattern Matching

Wildcard patterns allow flexible matching for international phone number formats and username variations:

| Pattern | Type | Description |
|---------|------|-------------|
| `alice` | Contains | Substring match (backward compatible) |
| `*456789` | Suffix | Matches any prefix + `456789` |
| `alice*` | Prefix | Matches `alice` + any suffix |
| `*alice*` | Contains | Explicit contains (same as no wildcards) |
| `\*alice` | Literal | Escaped `*` treated as literal character |

**Examples:**

```bash
# Match phone numbers ending in 456789 (handles E.164, 00-prefix, tech prefixes)
# Matches: +49123456789, 0049123456789, *31#+49123456789
lc sniff voip -i eth0 --sip-user '*456789'

# Match usernames starting with "alice"
# Matches: alice, alicent, alice-backup
lc sniff voip -i eth0 --sip-user 'alice*'

# Combine multiple patterns
lc sniff voip -i eth0 --sip-user '*456789,*999000,admin*'

# Match literal asterisk (tech prefix)
lc sniff voip -i eth0 --sip-user '\*31#'
```

**Note:** Quote patterns containing `*` to prevent shell expansion.

### BPF Filter Optimization

**Purpose:** Optimize BPF filters for high-traffic networks where TCP overhead overwhelms SIP handling.

**Flags:**
- `--udp-only` - Capture UDP only, bypass TCP SIP (reduces CPU on TCP-heavy networks)
- `--sip-port` - Restrict SIP capture to specific port(s), comma-separated
- `--rtp-port-range` - Custom RTP port range(s), comma-separated (default: 10000-32768)

**Examples:**

```bash
# UDP-only VoIP capture (bypass TCP reassembly)
lc sniff voip -i eth0 --udp-only

# Restrict SIP to port 5060
lc sniff voip -i eth0 --sip-port 5060

# Multiple SIP ports
lc sniff voip -i eth0 --sip-port 5060,5061,5080

# Custom RTP port range
lc sniff voip -i eth0 --rtp-port-range 8000-9000

# Multiple RTP ranges
lc sniff voip -i eth0 --rtp-port-range 8000-9000,40000-50000

# Combined: UDP-only with specific SIP port
lc sniff voip -i eth0 --udp-only --sip-port 5060

# With host filter
lc sniff voip -i eth0 --filter "host 10.0.0.1" --sip-port 5060
```

**Generated BPF Filters:**

| Input | Generated BPF Filter |
|-------|---------------------|
| `--udp-only` | `udp` |
| `--sip-port 5060` | `(port 5060) or (udp portrange 10000-32768)` |
| `--sip-port 5060 --udp-only` | `udp and ((port 5060) or (portrange 10000-32768))` |
| `--rtp-port-range 8000-9000` | `(udp portrange 8000-9000)` |
| `--filter "host 10.0.0.1" --sip-port 5060` | `(host 10.0.0.1) and ((port 5060) or (udp portrange 10000-32768))` |

**When to use:**
- Networks with high non-VoIP TCP traffic (web servers, databases)
- UDP-only SIP environments (most SIP deployments)
- Custom SIP port configurations
- Non-standard RTP port ranges

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

### Pattern Matching Algorithm

**Purpose:** Select the algorithm for matching SIP usernames and phone numbers against filter patterns.

**Flags:**
- `--pattern-algorithm` - Pattern matching algorithm: `auto`, `linear`, `aho-corasick` (default: auto)
- `--pattern-buffer-mb` - Memory budget for pattern buffer in MB (default: 64)

**Algorithm Selection:**
| Algorithm | Complexity | Best For | Description |
|-----------|------------|----------|-------------|
| `auto` | Adaptive | General use | Selects Aho-Corasick for ≥100 patterns, linear otherwise |
| `linear` | O(n×m) | <100 patterns | Simple linear scan, low memory overhead |
| `aho-corasick` | O(n+m+z) | ≥100 patterns | Trie-based automaton, ~265x faster at 10K patterns |

**Examples:**

```bash
# Auto-select algorithm (recommended)
lc sniff voip -i eth0 --pattern-algorithm auto

# Force Aho-Corasick for large pattern sets
lc sniff voip -i eth0 --pattern-algorithm aho-corasick

# Force linear scan for small pattern sets with minimal memory
lc sniff voip -i eth0 --pattern-algorithm linear --pattern-buffer-mb 16
```

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
  # BPF filter optimization
  udp_only: false
  sip_ports: "5060,5061"
  rtp_port_ranges: "10000-32768"

  # GPU acceleration
  gpu_enable: true
  gpu_backend: "auto"
  gpu_batch_size: 1024
  gpu_max_memory: 0

  # Pattern matching algorithm
  pattern_algorithm: "auto"    # auto, linear, or aho-corasick
  pattern_buffer_mb: 64        # Memory budget for pattern buffer in MB

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

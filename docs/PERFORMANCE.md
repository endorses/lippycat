# Performance Tuning Guide

This document provides comprehensive guidance for optimizing lippycat's performance across different deployment scenarios and traffic patterns.

## Table of Contents

- [TCP Performance Profiles](#tcp-performance-profiles)
- [GPU Acceleration](#gpu-acceleration)
- [Pattern Matching Algorithm](#pattern-matching-algorithm)
- [VoIP Filter Regression Benchmark](#voip-filter-regression-benchmark)
- [Network Capture Optimization](#network-capture-optimization)
- [Distributed Mode Performance](#distributed-mode-performance)
- [Memory Management](#memory-management)
- [Monitoring and Diagnostics](#monitoring-and-diagnostics)
- [Environment-Specific Tuning](#environment-specific-tuning)

## TCP Performance Profiles

TCP performance profiles provide pre-configured settings for different use cases. Profiles automatically configure 17-19 parameters for optimal performance.

### Available Profiles

#### 1. Minimal Profile

**Use Case:** Embedded systems, low-traffic environments, resource-constrained deployments

**Characteristics:**
- Memory: 25MB
- Max Buffers: 500
- Throughput: Low
- Latency: Medium

**Configuration:**
```bash
lc sniff voip --tcp-performance-mode minimal
```

**Detailed Settings:**
```yaml
voip:
  tcp_performance_mode: "minimal"
  # Auto-configured parameters:
  # - tcp_batch_size: 8
  # - max_tcp_buffers: 500
  # - tcp_buffer_strategy: fixed
  # - tcp_memory_limit: 25MB
  # - stream_queue_buffer: 50
  # - tcp_stream_max_queue_time: 60s
  # - tcp_buffer_max_age: 120s
  # - tcp_cleanup_interval: 30s
  # - memory_optimization: true
  # - enable_backpressure: true
  # - tcp_stream_timeout: 180s
  # - tcp_assembler_max_pages: 25
  # - tcp_io_threads: 1
```

**When to Use:**
- Raspberry Pi or embedded devices
- Test/development environments
- Low call volume (<10 concurrent calls)
- Memory <512MB available

#### 2. Balanced Profile (Default)

**Use Case:** General-purpose deployments, production environments with moderate traffic

**Characteristics:**
- Memory: 100MB
- Max Buffers: 5,000
- Throughput: Medium
- Latency: Medium

**Configuration:**
```bash
lc sniff voip --tcp-performance-mode balanced
# Or omit flag (balanced is default)
lc sniff voip
```

**Detailed Settings:**
```yaml
voip:
  tcp_performance_mode: "balanced"
  # Auto-configured parameters:
  # - tcp_batch_size: 32
  # - max_tcp_buffers: 5000
  # - tcp_buffer_strategy: adaptive
  # - tcp_memory_limit: 100MB
  # - stream_queue_buffer: 250
  # - tcp_stream_max_queue_time: 120s
  # - tcp_buffer_max_age: 300s
  # - tcp_cleanup_interval: 60s
  # - memory_optimization: false
  # - enable_auto_tuning: true
  # - enable_backpressure: true
  # - tcp_stream_timeout: 300s
  # - tcp_assembler_max_pages: 100
  # - tcp_io_threads: NumCPU
```

**When to Use:**
- Standard production deployments
- 10-100 concurrent calls
- Memory 2-8GB available
- Balanced CPU/memory trade-off needed

#### 3. High Performance Profile

**Use Case:** High-traffic environments, data center deployments, maximum throughput

**Characteristics:**
- Memory: 500MB
- Max Buffers: 20,000
- Throughput: High
- Latency: Higher (due to batching)

**Configuration:**
```bash
lc sniff voip --tcp-performance-mode high_performance
```

**Detailed Settings:**
```yaml
voip:
  tcp_performance_mode: "high_performance"
  # Auto-configured parameters:
  # - tcp_batch_size: 64
  # - max_tcp_buffers: 20000
  # - tcp_buffer_strategy: ring
  # - tcp_memory_limit: 500MB
  # - stream_queue_buffer: 1000
  # - tcp_stream_max_queue_time: 180s
  # - tcp_buffer_max_age: 600s
  # - tcp_cleanup_interval: 120s
  # - memory_optimization: false
  # - enable_auto_tuning: true
  # - enable_backpressure: false
  # - tcp_stream_timeout: 600s
  # - tcp_assembler_max_pages: 500
  # - tcp_io_threads: NumCPU * 2
  # - tcp_compression_level: 0  # No compression
```

**When to Use:**
- High call volume (100-1000+ concurrent calls)
- Memory >8GB available
- Data center environments
- Maximum throughput priority

#### 4. Low Latency Profile

**Use Case:** Real-time analysis, immediate processing requirements, minimal delay

**Characteristics:**
- Memory: 200MB
- Max Buffers: 2,000
- Throughput: Medium
- Latency: Low

**Configuration:**
```bash
lc sniff voip --tcp-performance-mode low_latency
```

**Detailed Settings:**
```yaml
voip:
  tcp_performance_mode: "low_latency"
  # Auto-configured parameters:
  # - tcp_batch_size: 1
  # - max_tcp_buffers: 2000
  # - tcp_buffer_strategy: fixed
  # - tcp_memory_limit: 200MB
  # - stream_queue_buffer: 100
  # - tcp_stream_max_queue_time: 30s
  # - tcp_buffer_max_age: 60s
  # - tcp_cleanup_interval: 15s
  # - memory_optimization: false
  # - enable_auto_tuning: false
  # - enable_backpressure: false
  # - tcp_stream_timeout: 120s
  # - tcp_assembler_max_pages: 50
  # - tcp_io_threads: NumCPU
  # - tcp_latency_optimization: true
```

**When to Use:**
- Real-time call analysis
- Fraud detection systems
- Call quality monitoring
- Sub-second processing requirements

### Profile Comparison

| Metric | Minimal | Balanced | High Perf | Low Latency |
|--------|---------|----------|-----------|-------------|
| Memory | 25MB | 100MB | 500MB | 200MB |
| Max Buffers | 500 | 5,000 | 20,000 | 2,000 |
| Batch Size | 8 | 32 | 64 | 1 |
| IO Threads | 1 | NumCPU | NumCPU*2 | NumCPU |
| Buffer Strategy | Fixed | Adaptive | Ring | Fixed |
| Backpressure | Yes | Yes | No | No |
| Auto-Tuning | No | Yes | Yes | No |
| Best For | Embedded | Production | High Traffic | Real-Time |

### Overriding Profile Settings

You can override specific profile parameters:

```bash
# Use balanced profile but increase buffers
lc sniff voip \
  --tcp-performance-mode balanced \
  --max-tcp-buffers 10000

# Use high_performance but enable backpressure
lc sniff voip \
  --tcp-performance-mode high_performance \
  --enable-backpressure

# Use minimal but increase timeout
lc sniff voip \
  --tcp-performance-mode minimal \
  --tcp-stream-timeout 300s
```

## GPU Acceleration

GPU acceleration is used by capture-side application filters to match already extracted values, such as SIP users and URIs, against large filter sets. SIP parsing and Call-ID extraction run on the CPU.

### Backend Selection

lippycat supports CUDA acceleration with automatic CPU SIMD fallback:

**Priority Order:** CUDA > CPU SIMD > Pure Go

The `opencl` backend name is accepted for configuration compatibility, but the OpenCL implementation is currently a stub and is not selected by auto-detection. If requested explicitly, initialization fails and matching falls back to the CPU path.

#### Auto Detection (Recommended)

```bash
lc sniff voip --gpu-backend auto
```

Automatically selects the best available backend.

#### CUDA Backend

**Requirements:**
- NVIDIA GPU (Compute Capability 6.0+)
- CUDA Toolkit 11.0+
- nvidia-driver 470+

**Configuration:**
```bash
lc sniff voip --gpu-backend cuda --gpu-batch-size 2048
```

**Best For:**
- NVIDIA GPU available
- Very high packet rates (>100K pps)
- Maximum throughput needed

#### CPU SIMD Backend

**Requirements:** None (always available)

**Configuration:**
```bash
lc sniff voip --gpu-backend cpu-simd
```

**Best For:**
- No GPU available
- Moderate performance improvement needed
- Default fallback

### GPU Tuning Parameters

**Batch Size:**
```bash
# Small batches (low latency)
--gpu-batch-size 256

# Medium batches (balanced)
--gpu-batch-size 1024

# Large batches (high throughput)
--gpu-batch-size 4096
```

**Memory Limits:**
```bash
# Auto-detect available GPU memory
--gpu-max-memory 0

# Limit to 2GB
--gpu-max-memory 2147483648
```

These flags are registered for `sniff voip` only in CUDA builds. A regular non-CUDA `sniff` binary does not expose them. Hunter and tap application filtering can still use the built-in CPU matching path without CUDA.

## Pattern Matching Algorithm

lippycat uses configurable pattern matching algorithms for filtering SIP usernames and phone numbers against filter patterns.

### Algorithm Selection

**Flag:** `--pattern-algorithm`

| Algorithm | Complexity | Memory | Best For |
|-----------|------------|--------|----------|
| `auto` | Adaptive | Variable | General use (default) |
| `linear` | O(n×m) | Low | <100 patterns |
| `aho-corasick` | O(n+m+z) | Higher | ≥100 patterns |

Where:
- n = input length (username)
- m = total pattern length
- z = number of matches

**Auto Mode Behavior:**
- Uses Aho-Corasick for ≥100 patterns
- Falls back to linear scan for fewer patterns
- Provides optimal balance of speed and memory

### Configuration

```bash
# Auto-select (recommended for most cases)
lc sniff voip -i eth0 --pattern-algorithm auto

# Force Aho-Corasick for LI-scale workloads
lc sniff voip -i eth0 --pattern-algorithm aho-corasick

# Linear scan for small pattern sets
lc sniff voip -i eth0 --pattern-algorithm linear

# Increase pattern buffer for large pattern sets
lc sniff voip -i eth0 --pattern-algorithm aho-corasick --pattern-buffer-mb 128
```

**Config File:**
```yaml
voip:
  pattern_algorithm: "auto"
  pattern_buffer_mb: 64
```

### Benchmark Results

Performance comparison at various pattern counts:

| Pattern Count | Linear Scan | Aho-Corasick | Speedup |
|---------------|-------------|--------------|---------|
| 10 | 1.2 µs | 0.8 µs | 1.5x |
| 100 | 12 µs | 0.9 µs | 13x |
| 1,000 | 120 µs | 1.0 µs | 120x |
| 10,000 | 1.2 ms | 1.1 µs | ~1,100x |
| 100,000 | 12 ms | 1.3 µs | ~9,200x |

**Key Observations:**
- Aho-Corasick has ~constant match time regardless of pattern count
- Linear scan time scales linearly with pattern count
- At 10K patterns, AC is ~265x faster than linear scan
- Build time is higher for AC but amortized across all matches

### LI-Scale Workloads

For lawful intercept scale deployments (10K-100K patterns):

```bash
# Recommended settings
lc hunt voip --processor processor:55555 \
  --pattern-algorithm aho-corasick \
  --pattern-buffer-mb 128 \
  --gpu-backend auto
```

**Memory Usage:**
- ~1 byte per pattern character for automaton
- 100K patterns (avg 20 chars) ≈ 2MB automaton
- Dense state tables add ~1MB per 1K states
- Total: <100MB for 100K patterns

## VoIP Filter Regression Benchmark

The v0.11.3 validation includes a generated, media-heavy VoIP workload to guard
against classified RTP being treated as possible SIP. These measurements are
regression evidence, not a throughput commitment: capture hardware, enabled
sinks, filter distribution, and traffic shape determine production capacity.

The application-filter microbenchmark was measured before and after the fix on
the same generic CPU-only environment (Linux/amd64, Go 1.26.3, benchmark
concurrency 32, 13th-generation Intel Core i9 class CPU):

| Revision | Identity filters | ns/op | B/op | allocs/op |
|----------|-----------------:|------:|-----:|----------:|
| Before | 400 | 4,449–4,879 | 2,259 | 52 |
| After | 500 | 1,536–1,616 | 1,475 | 18 |

The post-fix run deliberately uses the Phase 4 minimum of 500 identity filters,
so this is a conservative comparison rather than an identical-input
microbenchmark. It shows that classified media no longer pays the former SIP
identity-parsing cost even with a larger configured filter set.

The LocalSource benchmark uses a 100-packet generated cycle: three SDP INVITEs,
92 classified RTP packets, and five SIP OPTIONS requests. The RTP cases include
selected inherited-only traffic, unselected traffic, and direct IP-filter-only
traffic. Five repeated one-second runs produced:

| ns/op | packets/s | B/op | allocs/op | LocalSource full calls/op | packet-level calls/op | processor SIP full calls/op |
|------:|----------:|-----:|----------:|--------------------------:|----------------------:|----------------------------:|
| 4,295–4,821 | 207,415–232,834 | 2,241 | 35 | 0 | 0.92 | 0.08 |

The benchmark exercises packet classification, VoIP call association, direct
and inherited selection, local packet conversion and normalization, batching,
and cleanup callbacks. It excludes capture-device and kernel I/O, live BPF
installation, downstream processor and subscriber sinks, PCAP/log writing,
gRPC transport, and TUI rendering. Its timing must therefore not be read as
whole-node packet capacity.

Run the checks with:

```bash
go test -tags all ./internal/pkg/hunter \
  -run '^TestApplicationFilterClassifiedRTPPacketLevelAllocationCeiling$'
go test -tags all ./internal/pkg/processor/source -run '^$' \
  -bench '^BenchmarkLocalSourceMixedVoIP$' -benchmem
```

The structural allocation check requires zero allocations in the classified
RTP packet-level filter operation. The LocalSource benchmark also asserts the
matching boundary directly: classified media accounts for exactly 0.92
packet-level calls per packet and zero LocalSource full-match calls; only the
eight SIP control packets per cycle enter the processor's full matcher.

A bounded two-second run of this generated workload produced CPU and allocation
profiles. Inspection of their complete node lists found no
`hunter.extractSIPHeaders` or hunter identity-matching frames. SIP parser frames
remain expected because eight percent of the workload is intentional SIP
control traffic. Generate equivalent temporary profiles without writing capture
data into the repository:

```bash
go test -tags all ./internal/pkg/processor/source -run '^$' \
  -bench '^BenchmarkLocalSourceMixedVoIP$' -benchtime=2s -count=1 \
  -cpuprofile=/tmp/lippycat-voip-cpu.prof \
  -memprofile=/tmp/lippycat-voip-mem.prof
```

## Network Capture Optimization

### Interface Configuration

**Promiscuous Mode:**
```bash
# Enable for shared network segments
lc hunt --processor processor:55555 --promisc

# Disable for switched networks (default)
lc hunt --processor processor:55555
```

**Buffer Sizes:**
```bash
# Default (10,000 packets)
--buffer-size 10000

# High traffic (increase buffer)
--buffer-size 50000

# Low traffic (reduce memory)
--buffer-size 5000
```

### BPF Filters

Use BPF filters to reduce capture scope and improve performance:

```bash
# SIP only (UDP + TCP)
--filter "port 5060"

# SIP + RTP range
--filter "port 5060 or portrange 10000-20000"

# Specific hosts
--filter "host 192.168.1.100 and port 5060"

# Complex filter
--filter "port 5060 or (udp and portrange 10000-20000)"
```

**Performance Impact:** BPF filters are applied in kernel space and significantly reduce overhead.

## Distributed Mode Performance

### Hunter Configuration

**Batch Parameters:**

```bash
# Low latency
lc hunt --processor processor:55555 \
  --batch-size 16 \
  --batch-timeout 50

# Balanced
lc hunt --processor processor:55555 \
  --batch-size 64 \
  --batch-timeout 100

# High throughput
lc hunt --processor processor:55555 \
  --batch-size 256 \
  --batch-timeout 500
```

**VoIP Filtering at Edge:**

Enable VoIP filtering at hunters to reduce bandwidth:

```bash
lc hunt voip --processor processor:55555 \
  --enable-voip-filter \
  --gpu-backend auto
```

**Bandwidth Reduction:** 90%+ when using targeted filters.

### Processor Configuration

**Connection Limits:**

```bash
# Default (100 hunters, 100 subscribers)
lc process --max-hunters 100 --max-subscribers 100

# High scale (500 hunters)
lc process --max-hunters 500 --max-subscribers 200

# Unlimited subscribers
lc process --max-subscribers 0
```

**Resource Usage:**
- Per hunter: ~5-10MB RAM
- Per subscriber: ~2-5MB RAM

### Hierarchical Mode

Use hierarchical processors for gradual aggregation:

```
Edge (50 hunters) → Regional (10 edge procs) → Central (5 regional procs)
```

**Benefits:**
- Reduced central load
- Geographic distribution
- Gradual filtering and aggregation

See [docs/DISTRIBUTED_MODE.md](DISTRIBUTED_MODE.md#hierarchical-mode) for complete setup.

## Memory Management

### Memory Profiling

**Enable pprof on loopback:**
```bash
# Start a node with the debug listener enabled
lc tap voip -i eth0 --debug-listen 127.0.0.1:6060

# Capture heap profile
go tool pprof http://localhost:6060/debug/pprof/heap
```

`--debug-listen` is available on `tap`, `process`, and `hunt`. Non-loopback
binds are refused unless `--debug-allow-non-loopback` is set. Existing
deployments may still use `LC_PPROF_ADDR=127.0.0.1:6060` as a compatibility
fallback when the flag is omitted.

### Memory Optimization Flags

```bash
# Enable memory optimization
lc sniff voip --memory-optimization

# Reduce TCP buffers
lc sniff voip --max-tcp-buffers 2000

# Use minimal profile
lc sniff voip --tcp-performance-mode minimal
```

### Identifying Memory Leaks

```bash
# Monitor memory over time
watch -n 10 'ps aux | grep lc'

# Monitor process stats
top -p $(pgrep -f 'lc (sniff|hunt|process|tap)')
```

## Monitoring and Diagnostics

### Real-Time Monitoring

```bash
# Processor health monitoring (requires connection to processor)
watch -n 5 'lc show status -P localhost:55555 --insecure'

# Hunter status
watch -n 5 'lc list hunters -P localhost:55555 --insecure'
```

### Configuration Verification

```bash
# Show local TCP SIP configuration
lc show config

# Show processor topology
lc show topology -P processor:55555 --tls-ca ca.crt
```

### Integration with Monitoring Systems

**Prometheus/Grafana:**
```bash
# Export processor status periodically
*/5 * * * * lc show status -P localhost:55555 --insecure > /var/metrics/lippycat-status.json
```

See [cmd/show/README.md](../cmd/show/README.md) for complete show command reference.

## Environment-Specific Tuning

### Embedded Systems (Raspberry Pi)

```bash
lc sniff voip \
  --tcp-performance-mode minimal \
  --gpu-backend disabled \
  --buffer-size 5000 \
  --memory-optimization
```

**Expected Performance:** 10-50 concurrent calls

### Virtual Machines

```bash
lc sniff voip \
  --tcp-performance-mode balanced \
  --gpu-backend cpu-simd \
  --buffer-size 10000
```

**Considerations:**
- CPU SIMD works well in VMs
- Avoid GPU passthrough complexity
- Adjust buffers based on allocated RAM

### Bare Metal Servers

```bash
lc sniff voip \
  --tcp-performance-mode high_performance \
  --gpu-backend auto \
  --buffer-size 50000 \
  --max-tcp-buffers 20000
```

**Expected Performance:** 100-1000+ concurrent calls

### Kubernetes/Containers

```bash
# Set resource limits
resources:
  limits:
    memory: "4Gi"
    cpu: "4"
  requests:
    memory: "2Gi"
    cpu: "2"

# Tune accordingly
lc sniff voip \
  --tcp-performance-mode balanced \
  --max-tcp-buffers 5000
```

**Considerations:**
- Match profile to memory limits
- Use CPU SIMD (no GPU in containers)
- Monitor with debug commands

## Troubleshooting Performance Issues

### High CPU Usage

**Symptoms:**
- CPU >80% consistently
- System becoming unresponsive

**Solutions:**
```bash
# Reduce batch processing
--tcp-batch-size 16

# Enable backpressure
--enable-backpressure

# Switch to lower performance mode
--tcp-performance-mode balanced
```

### High Memory Usage

**Symptoms:**
- Memory continuously increasing
- OOM killer triggered

**Solutions:**
```bash
# Use minimal profile
--tcp-performance-mode minimal

# Reduce buffers
--max-tcp-buffers 2000

# Enable memory optimization
--memory-optimization
```

### Packet Drops

**Symptoms:**
- Buffer drop rate >5%
- Missing calls in capture

**Solutions:**
```bash
# Increase buffers
--max-tcp-buffers 10000
--buffer-size 20000

# Disable backpressure
--enable-backpressure=false

# Use high performance mode
--tcp-performance-mode high_performance
```

### High Latency

**Symptoms:**
- Slow call processing
- Delayed SIP message extraction

**Solutions:**
```bash
# Use low latency profile
--tcp-performance-mode low_latency

# Reduce batch size
--tcp-batch-size 1

# Reduce timeouts
--tcp-stream-max-queue-time 30s
```

## Best Practices

1. **Start with profiles** - Use predefined profiles before manual tuning
2. **Monitor continuously** - Use `lc show` commands during testing
3. **Test with real traffic** - Validate with representative PCAP files
4. **Use BPF filters** - Reduce capture scope to what's needed
5. **Enable GPU acceleration** - Significant performance improvement
6. **Distribute when possible** - Use hunter/processor for scale
7. **Match resources to traffic** - Choose profile based on expected load
8. **Monitor processor status** - Watch for capacity warnings
9. **Baseline performance** - Establish baseline before production
10. **Document configuration** - Save working configs for reproducibility

## See Also

- [cmd/sniff/CLAUDE.md](../cmd/sniff/CLAUDE.md) - Sniff command reference
- [cmd/show/README.md](../cmd/show/README.md) - Show commands for diagnostics
- [docs/tcp-troubleshooting.md](tcp-troubleshooting.md) - TCP troubleshooting
- [docs/GPU_ACCELERATION.md](GPU_ACCELERATION.md) - GPU acceleration guide
- [docs/DISTRIBUTED_MODE.md](DISTRIBUTED_MODE.md) - Distributed mode guide

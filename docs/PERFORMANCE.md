# Performance Tuning Guide

This document provides comprehensive guidance for optimizing lippycat's performance across different deployment scenarios and traffic patterns.

## Table of Contents

- [TCP Performance Profiles](#tcp-performance-profiles)
- [GPU Acceleration](#gpu-acceleration)
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

GPU acceleration provides significant performance improvements for pattern matching and SIP parsing.

### Backend Selection

lippycat supports multiple GPU backends with automatic fallback:

**Priority Order:** CUDA > OpenCL > CPU SIMD > Pure Go

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

**Performance:**
- Pattern matching: ~29.7K packets/second
- Call-ID extraction: ~19.4K packets/second
- Latency: ~33.6 µs/batch (64 packets)

**Best For:**
- NVIDIA GPU available
- Very high packet rates (>100K pps)
- Maximum throughput needed

#### OpenCL Backend

**Requirements:**
- OpenCL 1.2+ compatible GPU
- OpenCL runtime

**Configuration:**
```bash
lc sniff voip --gpu-backend opencl --gpu-batch-size 1024
```

**Best For:**
- AMD/Intel GPUs
- Cross-platform deployment
- Moderate GPU acceleration needed

#### CPU SIMD Backend

**Requirements:** None (always available)

**Configuration:**
```bash
lc sniff voip --gpu-backend cpu-simd
```

**Performance:**
- Pattern matching: ~29.9K packets/second
- Call-ID extraction: ~18.9K packets/second
- Uses AVX2/SSE4.2 instructions

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

### Performance Benchmarks

See [docs/GPU_ACCELERATION.md](GPU_ACCELERATION.md) for detailed benchmarks and optimization guide.

## Network Capture Optimization

### Interface Configuration

**Promiscuous Mode:**
```bash
# Enable for shared network segments
lc hunt --processor processor:50051 --promisc

# Disable for switched networks (default)
lc hunt --processor processor:50051
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
lc hunt --processor processor:50051 \
  --batch-size 16 \
  --batch-timeout 50

# Balanced
lc hunt --processor processor:50051 \
  --batch-size 64 \
  --batch-timeout 100

# High throughput
lc hunt --processor processor:50051 \
  --batch-size 256 \
  --batch-timeout 500
```

**VoIP Filtering at Edge:**

Enable VoIP filtering at hunters to reduce bandwidth:

```bash
lc hunt voip --processor processor:50051 \
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

**Enable pprof:**
```bash
# Add to configuration
export LIPPYCAT_PPROF_ENABLED=true

# Capture heap profile
go tool pprof http://localhost:6060/debug/pprof/heap
```

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
watch -n 10 'ps aux | grep lippycat'

# Check debug metrics
lc debug buffers
lc debug metrics
```

## Monitoring and Diagnostics

### Real-Time Monitoring

```bash
# Health monitoring
watch -n 2 'lc debug health'

# Comprehensive summary
watch -n 5 'lc debug summary'

# Buffer statistics
watch -n 5 'lc debug buffers'
```

### Performance Metrics

```bash
# Stream metrics
lc debug streams

# Alert monitoring
lc debug alerts --active-only

# Configuration verification
lc debug config
```

### Integration with Monitoring Systems

**Prometheus/Grafana:**
```bash
# Export metrics periodically
*/5 * * * * lc debug metrics --json > /var/metrics/lippycat.json
```

See [cmd/debug/CLAUDE.md](../cmd/debug/CLAUDE.md) for complete debug command reference.

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
2. **Monitor continuously** - Use `lc debug` commands during testing
3. **Test with real traffic** - Validate with representative PCAP files
4. **Use BPF filters** - Reduce capture scope to what's needed
5. **Enable GPU acceleration** - Significant performance improvement
6. **Distribute when possible** - Use hunter/processor for scale
7. **Match resources to traffic** - Choose profile based on expected load
8. **Monitor alerts** - Watch for capacity warnings
9. **Baseline performance** - Establish baseline before production
10. **Document configuration** - Save working configs for reproducibility

## See Also

- [cmd/sniff/CLAUDE.md](../cmd/sniff/CLAUDE.md) - Sniff command reference
- [cmd/debug/CLAUDE.md](../cmd/debug/CLAUDE.md) - Debug commands
- [docs/tcp-troubleshooting.md](tcp-troubleshooting.md) - TCP troubleshooting
- [docs/GPU_ACCELERATION.md](GPU_ACCELERATION.md) - GPU acceleration guide
- [docs/DISTRIBUTED_MODE.md](DISTRIBUTED_MODE.md) - Distributed mode guide

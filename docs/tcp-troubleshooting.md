# TCP SIP Troubleshooting Guide

## Overview
This guide provides comprehensive troubleshooting procedures for TCP SIP capture issues in lippycat. It covers common problems, diagnostic techniques, and resolution strategies for production deployments.

## Common Issues and Solutions

### 1. TCP Stream Processing Issues

#### Issue: No TCP SIP messages being captured
**Symptoms:**
- Zero active streams in metrics
- No PCAP files created for TCP SIP calls
- TCP buffer stats show no activity

**Diagnostic Steps:**
```bash
# Check if TCP SIP traffic is reaching the interface
sudo tcpdump -i any -n port 5060 and tcp

# Verify lippycat is processing TCP packets
sudo ./lippycat sniff voip --interface any --tcp-performance-mode latency
```

**Common Causes & Solutions:**
1. **Wrong Interface:** SIP traffic on different interface
   - Solution: Use `--interface any` or specify correct interface

2. **Firewall Blocking:** Local firewall dropping packets
   - Solution: Check iptables/firewall rules for port 5060

3. **Non-standard SIP Port:** SIP traffic on non-5060 port
   - Solution: Currently only port 5060 supported, contact development for custom ports

#### Issue: TCP streams created but no SIP messages processed
**Symptoms:**
- Active streams > 0 in metrics
- No call IDs detected
- TCP buffers accumulating but not flushed

**Diagnostic Steps:**
```bash
# Enable debug logging
export LIPPYCAT_LOG_LEVEL=debug
sudo ./lippycat sniff voip --tcp-performance-mode latency

# Check TCP assembler health
# (Use debugging commands - see section below)
```

**Common Causes & Solutions:**
1. **Fragmented SIP Messages:** TCP segments not reassembling correctly
   - Solution: Increase `tcp_stream_timeout` in config
   - Solution: Use `tcp_performance_mode: latency` for faster processing

2. **Invalid SIP Format:** Malformed SIP messages
   - Solution: Verify SIP message format with tcpdump
   - Solution: Check Content-Length headers match body size

### 2. Performance Issues

#### Issue: High memory usage
**Symptoms:**
- Memory usage continuously increasing
- System becoming unresponsive
- TCP buffer stats showing high packet counts

**Diagnostic Steps:**
```bash
# Check current memory usage
ps aux | grep lippycat

# Monitor TCP buffer statistics
# (Use debugging commands to get real-time stats)

# Check for memory leaks
go tool pprof http://localhost:6060/debug/pprof/heap
```

**Solutions:**
1. **Enable Memory Optimization:**
   ```yaml
   voip:
     tcp_performance_mode: "memory"
     memory_optimization: true
     tcp_memory_limit: 52428800  # 50MB
   ```

2. **Reduce Buffer Limits:**
   ```yaml
   voip:
     max_tcp_buffers: 1000
     tcp_buffer_max_age: 120s
     tcp_cleanup_interval: 30s
   ```

3. **Use Adaptive Buffering:**
   ```yaml
   voip:
     tcp_buffer_strategy: "adaptive"
   ```

#### Issue: High CPU usage
**Symptoms:**
- CPU usage near 100%
- System lag and responsiveness issues
- High goroutine count in metrics

**Solutions:**
1. **Reduce Goroutine Limit:**
   ```yaml
   voip:
     max_goroutines: 500
   ```

2. **Enable Backpressure:**
   ```yaml
   voip:
     enable_backpressure: true
   ```

3. **Batch Processing for High Volume:**
   ```yaml
   voip:
     tcp_performance_mode: "throughput"
     tcp_batch_size: 64
   ```

#### Issue: Packet drops and missed calls
**Symptoms:**
- Dropped streams metric increasing
- Missing SIP calls in output
- Queue utilization near 100%

**Solutions:**
1. **Increase Queue Capacity:**
   ```yaml
   voip:
     stream_queue_buffer: 1000
   ```

2. **Throughput Mode:**
   ```yaml
   voip:
     tcp_performance_mode: "throughput"
     max_goroutines: 2000
   ```

3. **Ring Buffer Strategy:**
   ```yaml
   voip:
     tcp_buffer_strategy: "ring"
   ```

### 3. Configuration Issues

#### Issue: Configuration not taking effect
**Symptoms:**
- Changes to config file not reflected in behavior
- Default values still being used

**Diagnostic Steps:**
```bash
# Verify config file location
ls -la ~/.lippycat.yaml

# Test with explicit config
sudo ./lippycat sniff voip --config /path/to/config.yaml

# Check config validation
sudo ./lippycat sniff voip --tcp-performance-mode invalid  # Should show error
```

**Solutions:**
1. **Correct Config Location:** Place config at `~/.lippycat.yaml`
2. **Proper YAML Format:** Validate YAML syntax
3. **Restart Application:** Configuration loaded at startup

### 4. Network Interface Issues

#### Issue: Permission denied accessing network interface
**Symptoms:**
- "Operation not permitted" errors
- Cannot capture live traffic

**Solutions:**
```bash
# Run with sudo
sudo ./lippycat sniff voip

# Or set capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip ./lippycat
```

#### Issue: Interface not found
**Symptoms:**
- "No such device" errors
- Interface name errors

**Diagnostic Steps:**
```bash
# List available interfaces
ip link show

# Test with 'any' interface
sudo ./lippycat sniff voip --interface any
```

## Diagnostic Tools and Commands

### Built-in Health Monitoring

TCP stream health can be monitored through the built-in metrics system:

```go
// Example Go code to check health programmatically
health := voip.GetTCPAssemblerHealth()
if !health["healthy"].(bool) {
    log.Printf("TCP assembler unhealthy: %+v", health)
}

metrics := voip.GetTCPAssemblerMetrics()
log.Printf("TCP metrics: %+v", metrics)
```

### Log Analysis

Enable debug logging for detailed troubleshooting:

```bash
# Set debug level
export LIPPYCAT_LOG_LEVEL=debug

# Capture logs to file
sudo ./lippycat sniff voip 2> lippycat-debug.log

# Monitor logs in real-time
tail -f lippycat-debug.log | grep -i "tcp\|sip\|error"
```

### System Resource Monitoring

Monitor system resources during capture:

```bash
# Monitor memory usage
watch -n 1 'ps aux | grep lippycat'

# Monitor network utilization
iftop -i eth0

# Monitor file descriptors
lsof -p $(pgrep lippycat)
```

## Performance Tuning

### Baseline Configuration
Start with baseline configuration for your environment:

```yaml
# Basic production config
voip:
  tcp_performance_mode: "balanced"
  max_goroutines: 1000
  tcp_cleanup_interval: 60s
  enable_backpressure: true
```

### High-Volume Environments
For high SIP call volume (>1000 calls/minute):

```yaml
voip:
  tcp_performance_mode: "throughput"
  max_goroutines: 2000
  tcp_buffer_strategy: "ring"
  tcp_batch_size: 64
  stream_queue_buffer: 1000
  enable_backpressure: true
```

### Low-Latency Requirements
For real-time monitoring with <1ms latency:

```yaml
voip:
  tcp_performance_mode: "latency"
  tcp_batch_size: 1
  tcp_cleanup_interval: 30s
  tcp_latency_optimization: true
```

### Resource-Constrained Environments
For limited memory/CPU environments:

```yaml
voip:
  tcp_performance_mode: "memory"
  max_goroutines: 100
  max_tcp_buffers: 1000
  memory_optimization: true
  tcp_memory_limit: 52428800  # 50MB
```

## Emergency Procedures

### Immediate Actions for System Overload
1. **Stop Processing:** Kill lippycat process immediately
2. **Check Resources:** Verify system memory/CPU availability
3. **Restart with Conservative Settings:**
   ```bash
   sudo ./lippycat sniff voip --tcp-performance-mode memory --max-goroutines 100
   ```

### Data Recovery
If PCAP files are corrupted or incomplete:

1. **Check Disk Space:** Ensure sufficient storage for PCAP files
2. **Verify File Permissions:** Check write permissions for output directory
3. **Restart with File Output:** Use `--write-file` flag to ensure PCAP creation

### Health Check Script
Create a monitoring script for production environments:

```bash
#!/bin/bash
# tcp-health-check.sh

# Check if lippycat is running
if ! pgrep -f "lippycat.*voip" > /dev/null; then
    echo "CRITICAL: lippycat not running"
    exit 2
fi

# Check memory usage (threshold: 500MB)
MEM_KB=$(ps -o rss= -p $(pgrep -f "lippycat.*voip") | awk '{print $1}')
MEM_MB=$((MEM_KB / 1024))

if [ $MEM_MB -gt 500 ]; then
    echo "WARNING: High memory usage: ${MEM_MB}MB"
    exit 1
fi

# Check CPU usage (threshold: 80%)
CPU=$(ps -o pcpu= -p $(pgrep -f "lippycat.*voip") | awk '{print int($1)}')

if [ $CPU -gt 80 ]; then
    echo "WARNING: High CPU usage: ${CPU}%"
    exit 1
fi

echo "OK: lippycat healthy (Memory: ${MEM_MB}MB, CPU: ${CPU}%)"
exit 0
```

## Support and Escalation

### Information to Collect
When reporting issues, collect:

1. **Configuration:** Full config file content
2. **Environment:** OS version, Go version, network setup
3. **Logs:** Debug logs with error messages
4. **Metrics:** Output from health monitoring
5. **Network Sample:** Sample PCAP file if possible

### Contact Information
- **Issues:** GitHub Issues for bug reports
- **Feature Requests:** GitHub Issues for enhancements
- **Security Issues:** security@endorses.com (private)

### Known Limitations
1. **Port Support:** Currently only standard SIP port 5060
2. **Protocol Support:** TCP SIP only (UDP SIP separately supported)
3. **Scale Limits:** Tested up to 10,000 concurrent TCP streams
4. **Platform Support:** Linux/macOS primary platforms

## Appendix

### Configuration Parameter Reference

| Parameter | Default | Description | Tuning Notes |
|-----------|---------|-------------|--------------|
| `max_goroutines` | 1000 | Max concurrent processing threads | Increase for high volume |
| `tcp_cleanup_interval` | 60s | Resource cleanup frequency | Decrease for memory optimization |
| `tcp_buffer_max_age` | 300s | Max buffer retention time | Adjust based on call duration |
| `max_tcp_buffers` | 10000 | Maximum packet buffers | Reduce for memory constraints |
| `tcp_performance_mode` | "balanced" | Performance optimization mode | Choose based on use case |
| `tcp_buffer_strategy` | "adaptive" | Buffer management strategy | "ring" for high volume |
| `enable_backpressure` | true | Enable load management | Always recommended |
| `tcp_batch_size` | 32 | Packets per processing batch | 1 for latency, 64 for throughput |

### Error Code Reference

| Error Code | Meaning | Action |
|------------|---------|--------|
| TCP-001 | Stream creation failed | Check goroutine limits |
| TCP-002 | Buffer overflow | Enable memory optimization |
| TCP-003 | Assembly timeout | Increase stream timeout |
| TCP-004 | Invalid SIP format | Check input data |
| TCP-005 | Resource exhaustion | Restart with conservative settings |
# Debug Command - TCP SIP Diagnostics

The `debug` command provides tools for inspecting and troubleshooting TCP SIP processing in VoIP capture mode.

## Overview

The debug command helps diagnose issues with TCP SIP reassembly, stream processing, and resource utilization. It provides real-time metrics, health monitoring, and configuration inspection.

**Important:** Debug commands only work when TCP SIP processing is active (i.e., when running `lc sniff voip` with TCP SIP traffic).

## Subcommands

### `lc debug health` - Health Status

Display current health status of the TCP assembler:

```bash
lc debug health
```

**Output:**
- Overall health status (HEALTHY/UNHEALTHY)
- Goroutine utilization
- Queue utilization
- Active streams count
- Last metrics update timestamp

**Example Output:**

```
=== TCP Assembler Health Status ===
✅ Status: HEALTHY

🔄 Goroutines: 12/50 (24.0%)
📋 Queue: 15/250 (6.0%)
🔗 Active Streams: 8
📊 Last Update: 2s ago
```

**Warnings:**
- Goroutine utilization >90%: "Consider increasing max_goroutines"
- Goroutine utilization >70%: "Monitor for potential capacity issues"
- Queue utilization >80%: "Consider increasing stream_queue_buffer"
- Metrics age >2 minutes: "Metrics may be stale"

**Use Cases:**
- Quick health check
- Capacity planning
- Real-time monitoring during traffic spikes

### `lc debug metrics` - Comprehensive Metrics

Display detailed TCP processing metrics:

```bash
lc debug metrics

# JSON output
lc debug metrics --json
```

**Metrics Displayed:**
- Health status
- Stream statistics (active, created, completed, failed, queued, dropped)
- Buffer statistics (total buffers, total packets, drops)
- Success/failure rates
- Drop rates

**Example Output:**

```
=== TCP Comprehensive Metrics ===

🏥 Health Status:
   Status: ✅ HEALTHY

🔗 Stream Metrics:
   Active Streams: 12
   Total Created: 547
   Total Completed: 532
   Total Failed: 3
   Queued Streams: 2
   Dropped Streams: 0
   Success Rate: 97.3%
   Failure Rate: 0.5%

📦 Buffer Statistics:
   Total Buffers: 3421
   Total Packets: 28934
   Buffers Dropped: 0
   Total Packets Buffered: 28934
   Last Stats Update: 1s ago

📅 Report Generated: 2025-10-17 14:32:15
```

**Warnings:**
- Failure rate >10%: "HIGH failure rate - check logs for errors"
- Buffer count >8000: "HIGH buffer count - consider memory optimization"

**Use Cases:**
- Performance analysis
- Troubleshooting packet loss
- Capacity planning
- Integration with monitoring systems (use --json)

### `lc debug alerts` - Alert Management

Show active alerts and alert history:

```bash
# All alerts
lc debug alerts

# Active alerts only
lc debug alerts --active-only

# JSON output
lc debug alerts --json
```

**Alert Levels:**
- 🔴 **Critical** - Immediate action required
- 🟡 **Warning** - Attention needed
- 🔵 **Info** - Informational

**Example Output:**

```
=== Active Alerts ===
LEVEL      COMPONENT           STATUS   TIME      MESSAGE
-----      ---------           ------   ----      -------
🔴 CRITICAL tcp_assembler      ACTIVE   14:30:12  Goroutine pool near capacity (95%)
🟡 WARNING  tcp_buffers        ACTIVE   14:29:45  Buffer count high: 7500
```

**Alert Types:**
- Goroutine pool capacity warnings
- Buffer count warnings
- Queue utilization warnings
- Stream timeout warnings
- Memory pressure warnings

**Use Cases:**
- Monitoring production systems
- Troubleshooting performance issues
- Capacity planning
- Historical analysis (all alerts mode)

### `lc debug buffers` - Buffer Statistics

Show TCP packet buffer statistics:

```bash
lc debug buffers

# JSON output
lc debug buffers --json
```

**Statistics Displayed:**
- Total buffers
- Total packets
- Buffers dropped
- Average packets per buffer
- Buffer drop rate

**Example Output:**

```
=== TCP Buffer Statistics ===
Total Buffers: 3421
Total Packets: 28934
Buffers Dropped: 12
Total Packets Buffered: 28934
Last Stats Update: 1s ago
Avg Packets/Buffer: 8.5
Buffer Drop Rate: 0.4%
```

**Warnings:**
- Drop rate >5%: "HIGH drop rate - consider increasing max_tcp_buffers"

**Use Cases:**
- Memory usage analysis
- Buffer tuning
- Identifying packet loss

### `lc debug streams` - Stream Processing Metrics

Show TCP stream processing statistics:

```bash
lc debug streams

# JSON output
lc debug streams --json
```

**Metrics Displayed:**
- Active streams
- Total created/completed/failed
- Queued streams
- Dropped streams
- Success/failure/drop rates

**Example Output:**

```
=== TCP Stream Metrics ===
Active Streams: 12
Total Created: 547
Total Completed: 532
Total Failed: 3
Queued Streams: 2
Dropped Streams: 0
Last Update: 1s ago

Performance Metrics:
Success Rate: 97.3%
Failure Rate: 0.5%
Drop Rate: 0.0%
```

**Warnings:**
- Failure rate >10%: "HIGH failure rate - check error logs"
- Drop rate >5%: "HIGH drop rate - consider increasing capacity"

**Use Cases:**
- Stream processing analysis
- Troubleshooting failed streams
- Capacity planning

### `lc debug config` - Configuration Display

Show current TCP SIP configuration:

```bash
lc debug config

# JSON output
lc debug config --json
```

**Configuration Displayed:**
- Performance mode (minimal/balanced/high_performance/low_latency)
- Buffer strategy (adaptive/fixed/ring)
- Resource limits (goroutines, buffers, memory)
- Timeout values
- Optimization flags

**Example Output:**

```
=== TCP SIP Configuration ===
Performance Mode: balanced
Buffer Strategy: adaptive
Max Goroutines: 50
Max TCP Buffers: 5000
Cleanup Interval: 1m0s
Buffer Max Age: 5m0s
Stream Timeout: 5m0s
Batch Size: 32
Memory Limit: 100 MB
Backpressure Enabled: true
Memory Optimization: false
Latency Optimization: false

Recommendations:
⚖️  Balanced configuration for general use
```

**Recommendations by Mode:**
- `throughput`: "📈 Optimized for high-volume processing"
- `latency`: "⚡ Optimized for low-latency real-time processing"
- `memory`: "💾 Optimized for minimal memory usage"
- `balanced`: "⚖️ Balanced configuration for general use"

**Use Cases:**
- Verifying configuration
- Documenting production settings
- Troubleshooting configuration issues
- Configuration auditing

### `lc debug summary` - System Summary

Show comprehensive system status summary:

```bash
lc debug summary
```

**Summary Includes:**
- Overall health status
- Goroutine utilization
- Queue utilization
- Active alerts (critical/warning counts)
- Buffer statistics
- Active streams
- Stream success rate
- Performance mode

**Example Output:**

```
=== lippycat TCP SIP Processing Summary ===

🟢 Overall Status: HEALTHY

🔄 Goroutine Utilization: 24.0% (12/50)
📋 Queue Utilization: 6.0% (15/250)
✅ Active Alerts: None
📦 TCP Buffers: 3421 (packets: 28934)
🔗 Active Streams: 12
📊 Stream Success Rate: 97.3%
⚙️  Performance Mode: balanced

💡 Use 'lippycat debug <subcommand>' for detailed information:
   health   - Detailed health status
   metrics  - Comprehensive metrics
   alerts   - Alert management
   config   - Configuration details
```

**Use Cases:**
- Quick system overview
- Dashboard/monitoring integration
- Periodic health checks
- Troubleshooting entry point

## Common Flags

- `--json` - Output in JSON format (supported by: metrics, alerts, buffers, streams, config)
- `--active-only` - Show only active alerts (alerts subcommand only)

## Usage Patterns

### Real-Time Monitoring

Monitor system health during active capture:

```bash
# Terminal 1: Start VoIP capture
sudo lc sniff voip -i eth0 --tcp-performance-mode balanced

# Terminal 2: Monitor health
watch -n 2 'lc debug health'

# Or: Monitor comprehensive metrics
watch -n 5 'lc debug summary'
```

### Troubleshooting High Memory Usage

```bash
# Check overall status
lc debug summary

# Inspect buffer statistics
lc debug buffers

# Check configuration
lc debug config

# Look for buffer-related alerts
lc debug alerts --active-only
```

**Resolution:**
- High buffer count: Switch to `--tcp-performance-mode minimal`
- High drop rate: Increase `--max-tcp-buffers`
- Enable `--memory-optimization`

### Troubleshooting Failed Streams

```bash
# Check stream metrics
lc debug streams

# Look for failure alerts
lc debug alerts

# Check configuration timeouts
lc debug config
```

**Resolution:**
- High failure rate: Increase `--tcp-stream-timeout`
- Check application logs for specific errors
- Consider switching to `--tcp-performance-mode latency`

### Integration with Monitoring Systems

Export metrics in JSON for Prometheus/Grafana/etc:

```bash
# Periodic metrics export
*/5 * * * * lc debug metrics --json > /var/metrics/lippycat-metrics.json

# Alert export
*/1 * * * * lc debug alerts --active-only --json > /var/metrics/lippycat-alerts.json
```

### Performance Baseline

Establish performance baseline during testing:

```bash
# Capture baseline metrics
lc debug metrics --json > baseline-balanced.json
lc debug config --json > config-balanced.json

# Test different performance modes
sudo lc sniff voip --tcp-performance-mode high_performance &
sleep 60
lc debug metrics --json > baseline-high-performance.json

# Compare results
diff baseline-balanced.json baseline-high-performance.json
```

## Interpreting Results

### Health Status

**HEALTHY:**
- Goroutine utilization <70%
- Queue utilization <80%
- No critical alerts
- Metrics updated recently (<2 min)

**UNHEALTHY:**
- Goroutine pool exhausted (>90%)
- Queue nearly full (>80%)
- Critical alerts active
- Stale metrics (>2 min old)

### Performance Indicators

**Good Performance:**
- Stream success rate >95%
- Stream failure rate <5%
- Buffer drop rate <1%
- Active alerts: 0

**Poor Performance:**
- Stream success rate <90%
- Stream failure rate >10%
- Buffer drop rate >5%
- Multiple critical alerts

### Capacity Planning

**Approaching Capacity:**
- Goroutine utilization >70%
- Queue utilization >60%
- Buffer count >6000
- Warning alerts appearing

**Actions:**
- Increase resource limits
- Switch to memory-optimized profile
- Enable backpressure
- Scale horizontally (use distributed mode)

## Troubleshooting Tips

### "TCP factory not initialized"

**Cause:** Debug command run when no VoIP capture is active

**Solution:** Start VoIP capture first:
```bash
sudo lc sniff voip -i eth0
```

### Stale Metrics

**Cause:** TCP processing stopped or crashed

**Solution:**
1. Check if capture process is running
2. Check application logs for errors
3. Restart capture

### High Failure Rates

**Common Causes:**
- TCP stream timeouts too short
- Malformed SIP messages
- Network packet loss

**Solutions:**
- Increase `--tcp-stream-timeout`
- Check packet captures with tcpdump
- Verify network health

## See Also

- [cmd/sniff/CLAUDE.md](../sniff/CLAUDE.md) - VoIP sniff command and TCP configuration
- [docs/tcp-troubleshooting.md](../../docs/tcp-troubleshooting.md) - Complete TCP troubleshooting guide
- [docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) - Performance tuning guide

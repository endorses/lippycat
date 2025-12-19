# Show Command - Diagnostics and Information

The `show` command displays diagnostics and information for TCP SIP processing components. Use these commands to monitor system health, debug issues, and inspect configuration.

## Commands

### Summary

```bash
# Overall system status
lc show summary
```

Displays health status, resource utilization, active alerts, and quick metrics.

### Health

```bash
# TCP assembler health status
lc show health
```

Shows goroutine usage, queue status, active streams, and health indicators.

### Metrics

```bash
# Comprehensive TCP metrics
lc show metrics

# JSON output
lc show metrics --json
```

**Metrics include:**
- Health status
- Stream metrics (active, created, completed, failed)
- Buffer statistics (count, packets, drops)
- Success/failure rates

### Alerts

```bash
# Show active alerts
lc show alerts

# Show all alerts including resolved
lc show alerts --all

# Clear all alerts
lc show alerts --clear

# JSON output
lc show alerts --json
```

**Alert levels:** Critical, Warning, Info

### Buffers

```bash
# TCP buffer statistics
lc show buffers

# JSON output
lc show buffers --json
```

Shows buffer count, packet count, dropped buffers, and utilization.

### Streams

```bash
# TCP stream processing metrics
lc show streams

# JSON output
lc show streams --json
```

Shows active/completed/failed streams, queue depth, and drop counts.

### Config

```bash
# Current configuration
lc show config

# JSON output
lc show config --json
```

Displays TCP performance settings, buffer limits, and tuning parameters.

## Common Output Flags

- `--json` - Output in JSON format for scripting/automation

## Usage Examples

### Health Check Script

```bash
#!/bin/bash
# Check if TCP assembler is healthy
lc show health | grep -q "HEALTHY" && echo "OK" || echo "UNHEALTHY"
```

### Metrics Collection

```bash
# Collect metrics to JSON file
lc show metrics --json > metrics-$(date +%Y%m%d-%H%M%S).json
```

### Alert Monitoring

```bash
# Watch for critical alerts
watch -n 5 'lc show alerts | head -20'
```

## When to Use

| Symptom | Command |
|---------|---------|
| General issues | `lc show summary` |
| Goroutine exhaustion | `lc show health` |
| High memory usage | `lc show buffers` |
| Stream failures | `lc show streams` |
| Configuration problems | `lc show config` |
| Active problems | `lc show alerts` |

## Prerequisites

Show commands display information about an **active VoIP capture session**. If no capture is running, most commands will indicate "TCP factory not initialized".

Start a capture first:
```bash
# In another terminal
sudo lc sniff voip -i eth0
```

## See Also

- [cmd/sniff/README.md](../sniff/README.md) - VoIP capture with TCP reassembly
- [docs/tcp-troubleshooting.md](../../docs/tcp-troubleshooting.md) - TCP debugging guide
- [docs/PERFORMANCE.md](../../docs/PERFORMANCE.md) - Performance tuning

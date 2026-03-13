# Operations Runbook

This chapter covers deploying, monitoring, and maintaining lippycat in production. It includes systemd service configuration, health checks, log management, incident response, and maintenance procedures.

## Deployment

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| RAM | 4 GB | 8 GB (high-volume) |
| Disk | Depends on PCAP retention | ~1 GB per 1,000 VoIP calls |
| Network | Interface access | Dedicated monitoring interface |
| Privileges | `CAP_NET_RAW` | `CAP_NET_RAW` + `CAP_NET_ADMIN` |
| Libraries | libpcap | libpcap-dev |

### Install the Binary

```bash
# Build from source
make build-release
sudo cp bin/lc /usr/local/bin/
sudo chmod +x /usr/local/bin/lc

# Grant capture capabilities (avoids running as root)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lc
```

### Create Configuration

```bash
sudo mkdir -p /etc/lippycat/certs
sudo cp config.yaml /etc/lippycat/
sudo chown root:root /etc/lippycat/config.yaml
sudo chmod 600 /etc/lippycat/config.yaml
```

### systemd Services

#### Standalone Capture (Sniff)

```ini
# /etc/systemd/system/lippycat.service
[Unit]
Description=lippycat Network Traffic Capture
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/lc sniff voip -i eth0 --config /etc/lippycat/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

#### Processor Node

```ini
# /etc/systemd/system/lippycat-processor.service
[Unit]
Description=lippycat Processor Node
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lc process \
  --listen 0.0.0.0:55555 \
  --tls-cert /etc/lippycat/certs/server.crt \
  --tls-key /etc/lippycat/certs/server.key \
  --per-call-pcap --per-call-pcap-dir /var/capture/calls \
  --filter-file /etc/lippycat/filters.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

#### Hunter Node

```ini
# /etc/systemd/system/lippycat-hunter.service
[Unit]
Description=lippycat Hunter Node
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/lc hunt voip -i eth0 \
  --processor processor.internal:55555 \
  --tls-ca /etc/lippycat/certs/ca.crt
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

#### Enable and Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable lippycat-processor
sudo systemctl start lippycat-processor
sudo systemctl status lippycat-processor
```

## Health Checks

### Quick Status Check

```bash
# Service running?
systemctl is-active lippycat-processor

# Processor healthy?
lc show status -P localhost:55555 --tls-ca ca.crt

# Hunters connected?
lc list hunters -P localhost:55555 --tls-ca ca.crt
```

### Daily Health Check Script

```bash
#!/bin/bash
# daily-health-check.sh

echo "=== lippycat Health Check — $(date) ==="

# Service status
echo "1. Service Status:"
systemctl is-active lippycat-processor
systemctl is-active lippycat-hunter

# Resource usage
echo -e "\n2. Resource Usage:"
ps aux | grep "[l]c " | head -5

# Disk space for PCAP files
echo -e "\n3. PCAP Storage:"
df -h /var/capture/ 2>/dev/null || echo "PCAP directory not configured"

# Processor status (distributed deployments)
echo -e "\n4. Processor Status:"
lc show status -P localhost:55555 --tls-ca /etc/lippycat/certs/ca.crt 2>&1

# Recent errors in logs
echo -e "\n5. Recent Errors (last 24h):"
journalctl -u 'lippycat*' --since "24 hours ago" --priority=err --no-pager -q

echo -e "\n=== Health Check Complete ==="
```

### Monitoring Hunter Connections

```bash
# Watch hunter count in real time
watch -n 5 'lc show status -P localhost:55555 --tls-ca ca.crt | \
  jq "{total: .total_hunters, healthy: .healthy_hunters}"'

# Alert on missing hunters
#!/bin/bash
expected=3
actual=$(lc show status -P localhost:55555 --tls-ca ca.crt 2>/dev/null | \
  jq -r '.healthy_hunters')
if [ "$actual" -lt "$expected" ]; then
    echo "ALERT: Only $actual/$expected hunters connected"
    exit 1
fi
```

## Log Management

lippycat uses structured logging to stdout/stderr. When running under systemd, logs go to the journal.

### Viewing Logs

```bash
# Follow live logs
journalctl -u lippycat-processor -f

# Last hour of logs
journalctl -u lippycat-processor --since "1 hour ago"

# Errors only
journalctl -u lippycat-processor --priority=err

# Logs from all lippycat services
journalctl -u 'lippycat*' --since today
```

### Log Rotation

If logging to files instead of the journal:

```
# /etc/logrotate.d/lippycat
/var/log/lippycat/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
```

### Log Analysis

```bash
#!/bin/bash
# Quick error summary from journal
echo "Error Summary (last 24h):"
journalctl -u 'lippycat*' --since "24 hours ago" --priority=err --no-pager | \
  awk '{for(i=5;i<=NF;i++) printf "%s ", $i; print ""}' | \
  sort | uniq -c | sort -nr | head -10
```

## Incident Response

### High Memory Usage

**Severity**: Critical — may lead to OOM kill

1. Check current usage:
   ```bash
   ps aux | grep "[l]c "
   top -p $(pgrep -f "lc.*process")
   ```

2. Switch to memory-optimized mode:
   ```bash
   sudo systemctl stop lippycat-processor
   # Edit config: tcp_performance_mode: "memory"
   sudo systemctl start lippycat-processor
   ```

3. Emergency restart if memory exceeds limits:
   ```bash
   sudo systemctl restart lippycat-processor
   ```

### Service Down

1. Check status and recent logs:
   ```bash
   sudo systemctl status lippycat-processor
   journalctl -u lippycat-processor --lines=50
   ```

2. Attempt restart:
   ```bash
   sudo systemctl restart lippycat-processor
   sleep 5
   sudo systemctl status lippycat-processor
   ```

3. If restart fails, try minimal configuration:
   ```bash
   sudo systemctl stop lippycat-processor
   lc process --listen :55555 --insecure  # Minimal, no PCAP, no TLS
   ```

### Hunter Disconnections

Hunters reconnect automatically with exponential backoff (see [Chapter 7: Resilience](../part3-distributed/hunt.md#resilience-and-flow-control)). If hunters stay disconnected:

1. Check hunter service status on the edge node:
   ```bash
   ssh edge-node systemctl status lippycat-hunter
   ```

2. Verify network connectivity:
   ```bash
   ssh edge-node nc -zv processor.internal 55555
   ```

3. Check for TLS certificate issues:
   ```bash
   journalctl -u lippycat-hunter --since "1 hour ago" | grep -i tls
   ```

### Diagnostic Data Collection

```bash
#!/bin/bash
# collect-diagnostics.sh
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DIAG_DIR="/tmp/lippycat_diag_$TIMESTAMP"
mkdir -p "$DIAG_DIR"

echo "Collecting diagnostics..."

# System info
uname -a > "$DIAG_DIR/system.txt"
cat /etc/os-release >> "$DIAG_DIR/system.txt"

# Service status
systemctl status 'lippycat*' > "$DIAG_DIR/services.txt" 2>&1

# Process info
ps aux | grep "[l]c " > "$DIAG_DIR/processes.txt"
free -h > "$DIAG_DIR/memory.txt"
df -h > "$DIAG_DIR/disk.txt"

# Network
ip addr show > "$DIAG_DIR/interfaces.txt"
ss -tlnp | grep 55555 > "$DIAG_DIR/listeners.txt"

# Processor status (if running)
lc show status -P localhost:55555 --tls-ca /etc/lippycat/certs/ca.crt \
  > "$DIAG_DIR/processor_status.json" 2>&1
lc show topology -P localhost:55555 --tls-ca /etc/lippycat/certs/ca.crt \
  > "$DIAG_DIR/topology.json" 2>&1

# Recent logs
journalctl -u 'lippycat*' --since "2 hours ago" > "$DIAG_DIR/logs.txt"

# Configuration (sanitize if needed)
lc show config > "$DIAG_DIR/config.json" 2>&1

# Archive
tar -czf "/tmp/lippycat_diag_$TIMESTAMP.tar.gz" -C /tmp "lippycat_diag_$TIMESTAMP"
rm -rf "$DIAG_DIR"
echo "Saved: /tmp/lippycat_diag_$TIMESTAMP.tar.gz"
```

## Maintenance

### PCAP Storage Management

PCAP files accumulate quickly in production. Set up automated cleanup:

```bash
#!/bin/bash
# pcap-cleanup.sh — run from cron
PCAP_DIR="/var/capture"
RETENTION_DAYS=30

# Remove old PCAP files
find "$PCAP_DIR" -name "*.pcap" -mtime +$RETENTION_DAYS -delete
find "$PCAP_DIR" -name "*.pcap.gz" -mtime +$RETENTION_DAYS -delete

# Remove empty directories
find "$PCAP_DIR" -type d -empty -delete

# Report disk usage
echo "PCAP storage: $(du -sh "$PCAP_DIR" | cut -f1)"
```

Add to cron:

```bash
# Daily PCAP cleanup at 3 AM
0 3 * * * /opt/scripts/pcap-cleanup.sh >> /var/log/pcap-cleanup.log 2>&1
```

### Capacity Planning

#### Estimating Disk Usage

| Traffic Type | Approximate Rate |
|-------------|-----------------|
| VoIP (per-call PCAP) | ~1 GB per 1,000 calls |
| General capture (unified PCAP) | Depends on link speed and BPF filter |
| Auto-rotating PCAP | Bounded by `--auto-rotate-max-size` |

#### Estimating Processor Resources

| Metric | Rule of Thumb |
|--------|--------------|
| Memory per hunter | ~5-10 MB |
| Memory per TUI subscriber | ~2-5 MB |
| Max hunters (default) | 100 |
| Packets per hunter at peak | ~10,000/sec |

Scale horizontally with multiple processors if one can't handle the load (see [Chapter 6: Multi-Processor Topology](../part3-distributed/architecture.md#multi-processor)).

### Security Review Checklist

Run monthly:

- [ ] Binary has minimal capabilities (`getcap /usr/local/bin/lc`)
- [ ] Config file has restrictive permissions (`ls -la /etc/lippycat/config.yaml`)
- [ ] TLS certificates are not expired (`openssl x509 -enddate -noout -in cert.crt`)
- [ ] `LIPPYCAT_PRODUCTION=true` is set (blocks `--insecure`)
- [ ] No unauthorized hunters connected (`lc list hunters -P ...`)
- [ ] PCAP directories have appropriate permissions
- [ ] Firewall rules restrict port 55555 to authorized hosts

### Upgrading

1. Download or build the new version
2. Stop the service: `sudo systemctl stop lippycat-processor`
3. Replace the binary: `sudo cp lc /usr/local/bin/`
4. Restore capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lc`
5. Start the service: `sudo systemctl start lippycat-processor`
6. Verify: `lc show status -P localhost:55555 --tls-ca ca.crt`

Hunters will reconnect automatically after the processor restarts.

## Escalation Levels

| Level | Trigger | Action |
|-------|---------|--------|
| **1 — Automatic** | Service restarts on its own | Monitor for patterns |
| **2 — Operator** | Service fails to restart, resource exhaustion | Follow incident response procedures above |
| **3 — Engineering** | Persistent failures, unknown errors | Collect diagnostics and escalate |

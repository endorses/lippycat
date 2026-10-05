# Operations Runbook {#operations-runbook}

This chapter covers deploying, monitoring, and maintaining lippycat in production. It includes systemd service configuration, health checks, log management, incident response, and maintenance procedures.

## Deployment {#deployment}

### System Requirements {#system-requirements}

| Requirement | Minimum                   | Recommended                     |
| ----------- | ------------------------- | ------------------------------- |
| RAM         | 4 GB                      | 8 GB (high-volume)              |
| Disk        | Depends on PCAP retention | ~1 GB per 1,000 VoIP calls      |
| Network     | Interface access          | Dedicated monitoring interface  |
| Privileges  | `CAP_NET_RAW`             | `CAP_NET_RAW` + `CAP_NET_ADMIN` |
| Libraries   | libpcap                   | libpcap-dev                     |

### Install the Binary {#install-the-binary}

Build from source:

<!-- i18n:skip -->

```bash
make build-release
```

<!-- i18n:skip -->

```bash
sudo cp bin/lc /usr/local/bin/
```

<!-- i18n:skip -->

```bash
sudo chmod +x /usr/local/bin/lc
```

Grant capture capabilities to avoid running as root:

<!-- i18n:skip -->

```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lc
```

### Create Configuration {#create-configuration}

<!-- i18n:skip -->

```bash
sudo mkdir -p /etc/lippycat/certs
```

<!-- i18n:skip -->

```bash
sudo cp config.yaml /etc/lippycat/
```

<!-- i18n:skip -->

```bash
sudo chown root:root /etc/lippycat/config.yaml
```

<!-- i18n:skip -->

```bash
sudo chmod 600 /etc/lippycat/config.yaml
```

### systemd Services {#systemd-services}

#### Standalone Capture (Sniff) {#standalone-capture-sniff}

<!-- i18n:skip -->

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

#### Processor Node {#processor-node}

<!-- i18n:skip -->

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

#### Hunter Node {#hunter-node}

<!-- i18n:skip -->

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

#### Enable and Start {#enable-and-start}

<!-- i18n:skip -->

```bash
sudo systemctl daemon-reload
```

<!-- i18n:skip -->

```bash
sudo systemctl enable lippycat-processor
```

<!-- i18n:skip -->

```bash
sudo systemctl start lippycat-processor
```

<!-- i18n:skip -->

```bash
sudo systemctl status lippycat-processor
```

## Health Checks {#health-checks}

### Normalized event transport {#normalized-event-transport}

Confirm event-mode negotiation in node logs, generate a known DNS or HTTP
transaction, and find it in the processor structured log and TUI event timeline.
Alert on producer spool or processor WAL exhaustion, rejected batches,
compatibility omissions, and event sequence gaps. Verify local tap PCAP
separately when packet evidence is required.

TUI subscription version 1 starts at a live boundary and never replays a
disconnect interval. A reconnect gap is expected after interruption. It differs
from **local eviction**, where the bounded TUI ring removes an older row that had
already arrived. Transport loss affects completeness; eviction affects only the
display window.

During rolling upgrades, update processors before event producers and keep
packet mode as the compatibility baseline. Opt into fallback only after checking
its bandwidth and privacy impact. Keep sensitive-field and file-metadata gates
disabled unless required, and protect event spools, WALs, logs, and TUI transport
as capture evidence.

### Event spool storage and recovery {#event-spool-storage-and-recovery}

Reliable event forwarding stores unacknowledged batches in an exclusive spool
directory. Never share that directory between processes or edit its files while
the owner is running. The 4 MiB encoded-payload limit remains active when the
total logical byte limit is disabled.

The configured limit and pending status describe logical bytes awaiting
acknowledgement. Physical disk use can be higher while acknowledged or evicted
files await cleanup, so monitor filesystem free space separately. Cleanup is
retried on startup and during later spool updates; retired records are not sent
again.

If storage cannot retain an event and its exact loss coverage, forwarding stops
instead of reporting successful delivery. A durability-uncertain error likewise
blocks forwarding and spool changes. Stop the affected node and reopen the same
directory to recover its last complete state. On ownership, corruption, or
recovery errors, preserve the entire directory, correct the reported cause, and
restart. Move it aside only when you explicitly accept all outstanding events
as lost.

Before an upgrade that changes the event analysis policy fingerprint, drain
pending events-mode spool records with the prior version and its original
configuration. Stop new capture, allow outstanding batches to be acknowledged,
and verify the pending count reaches zero before stopping the old process.
Incompatible pending records intentionally block startup under the new policy;
the application does not silently discard or reinterpret them. If startup reports
a policy mismatch, preserve the directory and reopen it with the prior version
and configuration to finish delivery.

### Quick Status Check {#quick-status-check}

Check whether the service is running:

<!-- i18n:skip -->

```bash
systemctl is-active lippycat-processor
```

Check whether the processor is healthy:

<!-- i18n:skip -->

```bash
lc show status -P localhost:55555 --tls-ca ca.crt
```

Check which hunters are connected:

<!-- i18n:skip -->

```bash
lc list hunters -P localhost:55555 --tls-ca ca.crt
```

### Daily Health Check Script {#daily-health-check-script}

<!-- i18n:skip -->

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

### Monitoring Hunter Connections {#monitoring-hunter-connections}

Watch the hunter count in real time:

<!-- i18n:skip -->

```bash
watch -n 5 'lc show status -P localhost:55555 --tls-ca ca.crt | \
  jq "{total: .total_hunters, healthy: .healthy_hunters}"'
```

Use this script to alert on missing hunters:

<!-- i18n:skip -->

```bash
#!/bin/bash
expected=3
actual=$(lc show status -P localhost:55555 --tls-ca ca.crt 2>/dev/null | \
  jq -r '.healthy_hunters')
if [ "$actual" -lt "$expected" ]; then
    echo "ALERT: Only $actual/$expected hunters connected"
    exit 1
fi
```

## Log Management {#log-management}

lippycat uses structured logging to stdout/stderr. When running under systemd, logs go to the journal.

### Viewing Logs {#viewing-logs}

Follow live logs:

<!-- i18n:skip -->

```bash
journalctl -u lippycat-processor -f
```

Show logs from the last hour:

<!-- i18n:skip -->

```bash
journalctl -u lippycat-processor --since "1 hour ago"
```

Show errors only:

<!-- i18n:skip -->

```bash
journalctl -u lippycat-processor --priority=err
```

Show logs from all lippycat services:

<!-- i18n:skip -->

```bash
journalctl -u 'lippycat*' --since today
```

### Log Rotation {#log-rotation}

If logging to files instead of the journal:

<!-- i18n:skip -->

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

### Log Analysis {#log-analysis}

<!-- i18n:skip -->

```bash
#!/bin/bash
# Quick error summary from journal
echo "Error Summary (last 24h):"
journalctl -u 'lippycat*' --since "24 hours ago" --priority=err --no-pager | \
  awk '{for(i=5;i<=NF;i++) printf "%s ", $i; print ""}' | \
  sort | uniq -c | sort -nr | head -10
```

## Incident Response {#incident-response}

### High Memory Usage {#high-memory-usage}

**Severity**: Critical — may lead to OOM kill

1. Check current usage:

   <!-- i18n:skip -->

   ```bash
   ps aux | grep "[l]c "
   top -p $(pgrep -f "lc.*process")
   ```

2. Switch to memory-optimized mode:

   <!-- i18n:skip -->

   ```bash
   sudo systemctl stop lippycat-processor
   # Edit config: tcp_performance_mode: "memory"
   sudo systemctl start lippycat-processor
   ```

3. Emergency restart if memory exceeds limits:
   <!-- i18n:skip -->

   ```bash
   sudo systemctl restart lippycat-processor
   ```

### Service Down {#service-down}

1. Check status and recent logs:

   <!-- i18n:skip -->

   ```bash
   sudo systemctl status lippycat-processor
   journalctl -u lippycat-processor --lines=50
   ```

2. Attempt restart:

   <!-- i18n:skip -->

   ```bash
   sudo systemctl restart lippycat-processor
   sleep 5
   sudo systemctl status lippycat-processor
   ```

3. If restart fails, try minimal configuration:
   <!-- i18n:skip -->

   ```bash
   sudo systemctl stop lippycat-processor
   lc process --listen :55555 --insecure  # Minimal, no PCAP, no TLS
   ```

### Hunter Disconnections {#hunter-disconnections}

Hunters reconnect automatically with exponential backoff (see [Chapter 7: Resilience](../part3-distributed/hunt.md#resilience-and-flow-control)). If hunters stay disconnected:

1. Check hunter service status on the edge node:

   <!-- i18n:skip -->

   ```bash
   ssh edge-node systemctl status lippycat-hunter
   ```

2. Verify network connectivity:

   <!-- i18n:skip -->

   ```bash
   ssh edge-node nc -zv processor.internal 55555
   ```

3. Check for TLS certificate issues:
   <!-- i18n:skip -->

   ```bash
   journalctl -u lippycat-hunter --since "1 hour ago" | grep -i tls
   ```

### Diagnostic Data Collection {#diagnostic-data-collection}

<!-- i18n:skip -->

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

## Maintenance {#maintenance}

### PCAP Storage Management {#pcap-storage-management}

PCAP files accumulate quickly in production. Set up automated cleanup:

<!-- i18n:skip -->

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

<!-- i18n:skip -->

```bash
# Daily PCAP cleanup at 3 AM
0 3 * * * /opt/scripts/pcap-cleanup.sh >> /var/log/pcap-cleanup.log 2>&1
```

### Capacity Planning {#capacity-planning}

#### Estimating Disk Usage {#estimating-disk-usage}

| Traffic Type                   | Approximate Rate                     |
| ------------------------------ | ------------------------------------ |
| VoIP (per-call PCAP)           | ~1 GB per 1,000 calls                |
| General capture (unified PCAP) | Depends on link speed and BPF filter |
| Auto-rotating PCAP             | Bounded by `--auto-rotate-max-size`  |

#### Estimating Processor Resources {#estimating-processor-resources}

| Metric                     | Rule of Thumb |
| -------------------------- | ------------- |
| Memory per hunter          | ~5-10 MB      |
| Memory per TUI subscriber  | ~2-5 MB       |
| Max hunters (default)      | 100           |
| Packets per hunter at peak | ~10,000/sec   |

Scale horizontally with multiple processors if one can't handle the load (see [Chapter 6: Multi-Processor Topology](../part3-distributed/architecture.md#multi-processor)).

### Security Review Checklist {#security-review-checklist}

Run monthly:

- [ ] Binary has minimal capabilities (`getcap /usr/local/bin/lc`)
- [ ] Config file has restrictive permissions (`ls -la /etc/lippycat/config.yaml`)
- [ ] TLS certificates are not expired (`openssl x509 -enddate -noout -in cert.crt`)
- [ ] `LIPPYCAT_PRODUCTION=true` is set (blocks `--insecure`)
- [ ] No unauthorized hunters connected (`lc list hunters -P ...`)
- [ ] PCAP directories have appropriate permissions
- [ ] Firewall rules restrict port 55555 to authorized hosts

### Upgrading {#upgrading}

1. Download or build the new version
2. Stop the service: `sudo systemctl stop lippycat-processor`
3. Replace the binary: `sudo cp lc /usr/local/bin/`
4. Restore capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lc`
5. Start the service: `sudo systemctl start lippycat-processor`
6. Verify: `lc show status -P localhost:55555 --tls-ca ca.crt`

Hunters will reconnect automatically after the processor restarts.

## Escalation Levels {#escalation-levels}

| Level               | Trigger                                       | Action                                    |
| ------------------- | --------------------------------------------- | ----------------------------------------- |
| **1 — Automatic**   | Service restarts on its own                   | Monitor for patterns                      |
| **2 — Operator**    | Service fails to restart, resource exhaustion | Follow incident response procedures above |
| **3 — Engineering** | Persistent failures, unknown errors           | Collect diagnostics and escalate          |

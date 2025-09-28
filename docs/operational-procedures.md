# TCP SIP Operational Procedures

## Overview
This document provides standardized operational procedures for managing lippycat TCP SIP capture in production environments. It includes deployment guidelines, monitoring procedures, incident response, and maintenance tasks.

## Production Deployment

### Pre-Deployment Checklist

#### System Requirements
- [ ] Go 1.19+ installed
- [ ] libpcap development libraries installed
- [ ] Root/sudo access for network capture
- [ ] Minimum 4GB RAM, 8GB recommended for high-volume environments
- [ ] Adequate disk space for PCAP files (estimate 1GB per 1000 calls)
- [ ] Network interfaces configured and accessible

#### Configuration Validation
```bash
# Test configuration syntax
./lippycat sniff voip --config /etc/lippycat/lippycat.yaml --validate-config

# Test with sample traffic
./lippycat sniff voip --read-file test-sip-tcp.pcap --tcp-performance-mode balanced

# Verify debug commands work
./lippycat debug health
./lippycat debug config
```

#### Performance Baseline
```bash
# Establish baseline metrics
./lippycat debug summary > baseline-metrics.txt

# Test resource limits
./lippycat sniff voip --tcp-performance-mode memory --max-goroutines 100
./lippycat sniff voip --tcp-performance-mode throughput --max-goroutines 2000
```

### Deployment Procedure

1. **Install Binary**
   ```bash
   sudo cp lippycat /usr/local/bin/
   sudo chmod +x /usr/local/bin/lippycat
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lippycat
   ```

2. **Create Configuration**
   ```bash
   sudo mkdir -p /etc/lippycat
   sudo cp lippycat.yaml /etc/lippycat/
   sudo chown root:root /etc/lippycat/lippycat.yaml
   sudo chmod 600 /etc/lippycat/lippycat.yaml
   ```

3. **Create Service (systemd)**
   ```bash
   sudo tee /etc/systemd/system/lippycat.service << EOF
   [Unit]
   Description=lippycat VoIP Network Traffic Sniffer
   After=network.target

   [Service]
   Type=simple
   User=root
   ExecStart=/usr/local/bin/lippycat sniff voip --config /etc/lippycat/lippycat.yaml
   Restart=always
   RestartSec=5
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   EOF

   sudo systemctl daemon-reload
   sudo systemctl enable lippycat
   ```

4. **Start and Verify**
   ```bash
   sudo systemctl start lippycat
   sudo systemctl status lippycat

   # Wait 30 seconds, then check health
   sleep 30
   lippycat debug health
   ```

## Daily Operations

### Health Monitoring

#### Daily Health Check
```bash
#!/bin/bash
# daily-health-check.sh

echo "=== Daily lippycat Health Check - $(date) ==="

# Service status
echo "1. Service Status:"
systemctl is-active lippycat
systemctl is-enabled lippycat

# Health check
echo -e "\n2. TCP Health:"
lippycat debug health

# Active alerts
echo -e "\n3. Active Alerts:"
lippycat debug alerts --active-only

# Resource usage
echo -e "\n4. Resource Usage:"
ps aux | grep lippycat | grep -v grep

# Disk space for PCAP files
echo -e "\n5. PCAP Storage:"
df -h /var/lib/lippycat/pcap/ 2>/dev/null || echo "PCAP directory not configured"

# Recent errors in logs
echo -e "\n6. Recent Errors (last 24h):"
journalctl -u lippycat --since "24 hours ago" --priority=err --no-pager -q

echo -e "\n=== Health Check Complete ==="
```

#### Continuous Monitoring
Set up monitoring with your preferred system (Prometheus, Nagios, etc.):

```bash
# Example monitoring script for integration
#!/bin/bash
# lippycat-metrics.sh

# Export metrics in Prometheus format
echo "# HELP lippycat_tcp_healthy TCP assembler health status"
echo "# TYPE lippycat_tcp_healthy gauge"
if lippycat debug health >/dev/null 2>&1; then
    echo "lippycat_tcp_healthy 1"
else
    echo "lippycat_tcp_healthy 0"
fi

# Get detailed metrics
METRICS=$(lippycat debug metrics --json 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "$METRICS" | jq -r '
        .streams | to_entries[] |
        "lippycat_tcp_streams_\(.key) \(.value)"
    '
fi
```

### Log Management

#### Log Rotation Configuration
```bash
# /etc/logrotate.d/lippycat
/var/log/lippycat/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        systemctl reload lippycat > /dev/null 2>&1 || true
    endscript
}
```

#### Log Analysis Scripts
```bash
# error-analysis.sh
#!/bin/bash
LOG_FILE="/var/log/lippycat/lippycat.log"

echo "=== Error Analysis - Last 24 Hours ==="
echo "TCP Errors:"
grep -i "tcp.*error" "$LOG_FILE" | tail -20

echo -e "\nSIP Errors:"
grep -i "sip.*error" "$LOG_FILE" | tail -20

echo -e "\nMemory Warnings:"
grep -i "memory\|mem" "$LOG_FILE" | grep -i "warn\|error" | tail -10

echo -e "\nError Summary:"
grep -i "error\|critical\|fatal" "$LOG_FILE" |
    awk '{print $4}' | sort | uniq -c | sort -nr | head -10
```

### Performance Monitoring

#### Performance Dashboard Script
```bash
#!/bin/bash
# performance-dashboard.sh

while true; do
    clear
    echo "=== lippycat Performance Dashboard - $(date) ==="
    echo

    # Quick health overview
    lippycat debug summary

    # Resource usage
    echo "=== System Resources ==="
    echo "Memory Usage:"
    free -h | grep -E "Mem|Swap"

    echo -e "\nCPU Usage:"
    top -bn1 | grep "lippycat" | head -1

    echo -e "\nNetwork Interfaces:"
    ss -i | grep -E "State|lippycat" | head -5

    echo -e "\n=== Refresh in 10 seconds (Ctrl+C to exit) ==="
    sleep 10
done
```

## Incident Response

### Critical Alerts Response

#### High Memory Usage (>500MB)
**Severity:** Critical
**Response Time:** Immediate

**Immediate Actions:**
1. Check current memory usage:
   ```bash
   lippycat debug buffers
   ps aux | grep lippycat
   ```

2. If memory continues growing:
   ```bash
   # Switch to memory optimization mode
   sudo systemctl stop lippycat
   # Edit config: tcp_performance_mode: "memory"
   sudo systemctl start lippycat
   ```

3. If memory critical (>1GB):
   ```bash
   # Emergency restart
   sudo systemctl restart lippycat
   ```

#### High Failure Rate (>15%)
**Severity:** High
**Response Time:** 15 minutes

**Investigation Steps:**
1. Check stream metrics:
   ```bash
   lippycat debug streams
   lippycat debug alerts
   ```

2. Analyze recent errors:
   ```bash
   journalctl -u lippycat --since "1 hour ago" --priority=err
   ```

3. Check network issues:
   ```bash
   netstat -i
   tcpdump -i any -c 100 port 5060
   ```

#### Service Down
**Severity:** Critical
**Response Time:** Immediate

**Recovery Steps:**
1. Check service status:
   ```bash
   sudo systemctl status lippycat
   journalctl -u lippycat --lines=50
   ```

2. Attempt restart:
   ```bash
   sudo systemctl restart lippycat
   sleep 30
   lippycat debug health
   ```

3. If restart fails, safe mode:
   ```bash
   # Start with minimal configuration
   sudo lippycat sniff voip --tcp-performance-mode memory --max-goroutines 100
   ```

### Escalation Procedures

#### Level 1: Automatic Recovery
- Service restarts automatically
- Alerts generated but system recovers
- **Action:** Monitor for patterns

#### Level 2: Operator Intervention
- Service fails to restart automatically
- Critical resource exhaustion
- **Action:** Follow incident response procedures

#### Level 3: Engineering Escalation
- Persistent failures after operator intervention
- Unknown error conditions
- **Action:** Collect diagnostic data and escalate

#### Diagnostic Data Collection
```bash
#!/bin/bash
# collect-diagnostics.sh

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DIAG_DIR="/tmp/lippycat_diagnostics_$TIMESTAMP"
mkdir -p "$DIAG_DIR"

echo "Collecting lippycat diagnostic data..."

# System information
uname -a > "$DIAG_DIR/system_info.txt"
cat /etc/os-release >> "$DIAG_DIR/system_info.txt"

# Service status
systemctl status lippycat > "$DIAG_DIR/service_status.txt"

# Configuration
cp /etc/lippycat/lippycat.yaml "$DIAG_DIR/config.yaml" 2>/dev/null

# Recent logs
journalctl -u lippycat --since "2 hours ago" > "$DIAG_DIR/recent_logs.txt"

# Debug output
lippycat debug summary > "$DIAG_DIR/debug_summary.txt" 2>&1
lippycat debug metrics --json > "$DIAG_DIR/metrics.json" 2>&1
lippycat debug health > "$DIAG_DIR/health.txt" 2>&1
lippycat debug config --json > "$DIAG_DIR/effective_config.json" 2>&1

# System resources
ps aux | grep lippycat > "$DIAG_DIR/process_info.txt"
free -h > "$DIAG_DIR/memory_info.txt"
df -h > "$DIAG_DIR/disk_info.txt"
ss -tuln | grep 5060 > "$DIAG_DIR/network_info.txt"

# Network interfaces
ip addr show > "$DIAG_DIR/interfaces.txt"

# Create archive
tar -czf "lippycat_diagnostics_$TIMESTAMP.tar.gz" -C /tmp "lippycat_diagnostics_$TIMESTAMP"
rm -rf "$DIAG_DIR"

echo "Diagnostic data collected: lippycat_diagnostics_$TIMESTAMP.tar.gz"
```

## Maintenance Procedures

### Weekly Maintenance

#### Performance Review
```bash
#!/bin/bash
# weekly-performance-review.sh

echo "=== Weekly Performance Review - $(date) ==="

# Calculate average metrics over the week
echo "1. Stream Processing Statistics (Last 7 days):"
journalctl -u lippycat --since "7 days ago" | grep "Stream completed" | wc -l

echo -e "\n2. Error Summary (Last 7 days):"
journalctl -u lippycat --since "7 days ago" --priority=err |
    grep -o "error: [^\"]*" | sort | uniq -c | sort -nr

echo -e "\n3. Resource Usage Trends:"
# Implementation would depend on your monitoring system
echo "Check Grafana/monitoring dashboard for trends"

echo -e "\n4. Configuration Optimization Recommendations:"
CURRENT_MODE=$(lippycat debug config --json | jq -r '.tcp_performance_mode')
echo "Current performance mode: $CURRENT_MODE"

# Add logic to recommend optimizations based on metrics
```

#### Log Cleanup
```bash
#!/bin/bash
# log-cleanup.sh

echo "Cleaning up old log files..."

# Remove logs older than 90 days
find /var/log/lippycat/ -name "*.log" -mtime +90 -delete

# Compress logs older than 7 days
find /var/log/lippycat/ -name "*.log" -mtime +7 -exec gzip {} \;

# Clean up old PCAP files if configured
PCAP_DIR="/var/lib/lippycat/pcap"
if [ -d "$PCAP_DIR" ]; then
    # Remove PCAP files older than 30 days
    find "$PCAP_DIR" -name "*.pcap" -mtime +30 -delete
    echo "Cleaned up old PCAP files"
fi

echo "Log cleanup complete"
```

### Monthly Maintenance

#### Configuration Review
```bash
#!/bin/bash
# monthly-config-review.sh

echo "=== Monthly Configuration Review ==="

# Current configuration
echo "1. Current Configuration:"
lippycat debug config

# Performance analysis
echo -e "\n2. Performance Analysis:"
echo "Average memory usage: [implement based on monitoring]"
echo "Average CPU usage: [implement based on monitoring]"
echo "Peak concurrent streams: [implement based on monitoring]"

# Recommendations
echo -e "\n3. Optimization Recommendations:"
METRICS=$(lippycat debug metrics --json)
GOROUTINE_UTIL=$(echo "$METRICS" | jq -r '.health.goroutine_utilization // 0')

if (( $(echo "$GOROUTINE_UTIL > 0.8" | bc -l) )); then
    echo "- Consider increasing max_goroutines"
fi

if (( $(echo "$GOROUTINE_UTIL < 0.3" | bc -l) )); then
    echo "- Consider decreasing max_goroutines to save memory"
fi
```

#### Security Review
```bash
#!/bin/bash
# security-review.sh

echo "=== Monthly Security Review ==="

# Check file permissions
echo "1. File Permissions:"
ls -la /usr/local/bin/lippycat
ls -la /etc/lippycat/lippycat.yaml

# Check capabilities
echo -e "\n2. Binary Capabilities:"
getcap /usr/local/bin/lippycat

# Check service user
echo -e "\n3. Service User:"
systemctl show lippycat | grep User

# Check for security updates
echo -e "\n4. Go Version:"
go version

echo -e "\nRecommendations:"
echo "- Ensure binary has minimal required capabilities"
echo "- Verify configuration file has restrictive permissions"
echo "- Update Go runtime if security patches available"
```

## Emergency Procedures

### Complete System Recovery

#### Service Won't Start
1. **Check Configuration:**
   ```bash
   lippycat sniff voip --config /etc/lippycat/lippycat.yaml --validate-config
   ```

2. **Reset to Minimal Configuration:**
   ```bash
   sudo cp /etc/lippycat/lippycat.yaml /etc/lippycat/lippycat.yaml.backup
   sudo tee /etc/lippycat/lippycat.yaml.minimal << EOF
   voip:
     tcp_performance_mode: "memory"
     max_goroutines: 100
     max_tcp_buffers: 1000
   EOF
   sudo systemctl restart lippycat
   ```

3. **Manual Debugging Start:**
   ```bash
   sudo systemctl stop lippycat
   sudo /usr/local/bin/lippycat sniff voip --config /etc/lippycat/lippycat.yaml.minimal
   ```

#### Data Recovery
1. **PCAP File Recovery:**
   ```bash
   # Check for corrupted PCAP files
   find /var/lib/lippycat/pcap -name "*.pcap" -exec file {} \; | grep -v "tcpdump"

   # Attempt repair with tcpdump
   tcpdump -r corrupted.pcap -w recovered.pcap 2>/dev/null
   ```

2. **Configuration Recovery:**
   ```bash
   # Restore from backup
   sudo cp /etc/lippycat/lippycat.yaml.backup /etc/lippycat/lippycat.yaml

   # Or regenerate default config
   lippycat config generate > /tmp/default-config.yaml
   ```

### Disaster Recovery

#### Complete Reinstallation
```bash
#!/bin/bash
# disaster-recovery.sh

echo "=== lippycat Disaster Recovery ==="

# Stop service
sudo systemctl stop lippycat
sudo systemctl disable lippycat

# Backup critical data
mkdir -p /tmp/lippycat-backup
cp -r /etc/lippycat /tmp/lippycat-backup/ 2>/dev/null
cp -r /var/lib/lippycat /tmp/lippycat-backup/ 2>/dev/null

# Reinstall binary
wget -O /tmp/lippycat https://github.com/endorses/lippycat/releases/latest/download/lippycat
sudo cp /tmp/lippycat /usr/local/bin/
sudo chmod +x /usr/local/bin/lippycat
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lippycat

# Restore configuration
sudo cp -r /tmp/lippycat-backup/lippycat /etc/

# Test and restart
lippycat debug config
sudo systemctl enable lippycat
sudo systemctl start lippycat

echo "Disaster recovery complete"
```

## Contact Information

### Support Escalation
- **Level 1:** Operations team (immediate response)
- **Level 2:** Engineering team (within 4 hours)
- **Level 3:** Development team (next business day)

### Emergency Contacts
- **Operations:** ops@example.com
- **Engineering:** engineering@example.com
- **Security Issues:** security@endorses.com

### Documentation Updates
This document should be reviewed and updated:
- After any major configuration changes
- Following significant incidents
- Monthly during maintenance reviews
- When new features are deployed

---

**Last Updated:** [Date]
**Version:** 1.0
**Next Review:** [Date + 3 months]
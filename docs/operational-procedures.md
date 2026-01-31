# Operational Procedures

## Overview
This document provides standardized operational procedures for managing lippycat in production environments. It includes deployment guidelines, monitoring procedures, incident response, and maintenance tasks.

## Production Deployment

### Pre-Deployment Checklist

#### System Requirements
- [ ] Go 1.24+ installed (for building)
- [ ] libpcap development libraries installed
- [ ] Root/sudo access for network capture
- [ ] Minimum 4GB RAM, 8GB recommended for high-volume environments
- [ ] Adequate disk space for PCAP files (estimate 1GB per 1000 calls)
- [ ] Network interfaces configured and accessible

#### Configuration Validation
```bash
# Test with sample traffic
lc sniff voip --read-file test-sip-tcp.pcap --tcp-performance-mode balanced

# Verify configuration is loaded
lc show config

# Test resource limits
lc sniff voip --tcp-performance-mode memory --max-goroutines 100
lc sniff voip --tcp-performance-mode throughput --max-goroutines 2000
```

### Deployment Procedure

1. **Install Binary**
   ```bash
   make build
   sudo cp lc /usr/local/bin/
   sudo chmod +x /usr/local/bin/lc
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lc
   ```

2. **Create Configuration**
   ```bash
   sudo mkdir -p /etc/lippycat
   sudo cp config.yaml /etc/lippycat/
   sudo chown root:root /etc/lippycat/config.yaml
   sudo chmod 600 /etc/lippycat/config.yaml
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
   ExecStart=/usr/local/bin/lc sniff voip --config /etc/lippycat/config.yaml
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
   journalctl -u lippycat -f  # Monitor logs
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

# Resource usage
echo -e "\n2. Resource Usage:"
ps aux | grep lc | grep -v grep

# Disk space for PCAP files
echo -e "\n3. PCAP Storage:"
df -h /var/lib/lippycat/pcap/ 2>/dev/null || echo "PCAP directory not configured"

# Recent errors in logs
echo -e "\n4. Recent Errors (last 24h):"
journalctl -u lippycat --since "24 hours ago" --priority=err --no-pager -q

echo -e "\n=== Health Check Complete ==="
```

#### For Distributed Deployments
```bash
# Check processor status (requires running processor)
lc show status -P processor:55555 --tls-ca ca.crt

# List connected hunters
lc show hunters -P processor:55555 --tls-ca ca.crt

# View topology
lc show topology -P processor:55555 --tls-ca ca.crt
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

## Incident Response

### Critical Alerts Response

#### High Memory Usage (>500MB)
**Severity:** Critical
**Response Time:** Immediate

**Immediate Actions:**
1. Check current memory usage:
   ```bash
   ps aux | grep lc
   top -p $(pgrep -f "lc.*sniff")
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
   sudo systemctl status lippycat
   ```

3. If restart fails, safe mode:
   ```bash
   # Start with minimal configuration
   sudo lc sniff voip --tcp-performance-mode memory --max-goroutines 100
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
cp /etc/lippycat/config.yaml "$DIAG_DIR/config.yaml" 2>/dev/null
lc show config > "$DIAG_DIR/effective_config.json" 2>&1

# Recent logs
journalctl -u lippycat --since "2 hours ago" > "$DIAG_DIR/recent_logs.txt"

# System resources
ps aux | grep lc > "$DIAG_DIR/process_info.txt"
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

#### Security Review
```bash
#!/bin/bash
# security-review.sh

echo "=== Monthly Security Review ==="

# Check file permissions
echo "1. File Permissions:"
ls -la /usr/local/bin/lc
ls -la /etc/lippycat/config.yaml

# Check capabilities
echo -e "\n2. Binary Capabilities:"
getcap /usr/local/bin/lc

# Check service user
echo -e "\n3. Service User:"
systemctl show lippycat | grep User

echo -e "\nRecommendations:"
echo "- Ensure binary has minimal required capabilities"
echo "- Verify configuration file has restrictive permissions"
echo "- Update to latest release if security patches available"
```

## Emergency Procedures

### Complete System Recovery

#### Service Won't Start
1. **Check Configuration:**
   ```bash
   lc show config
   ```

2. **Reset to Minimal Configuration:**
   ```bash
   sudo cp /etc/lippycat/config.yaml /etc/lippycat/config.yaml.backup
   sudo tee /etc/lippycat/config.yaml.minimal << EOF
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
   sudo /usr/local/bin/lc sniff voip --config /etc/lippycat/config.yaml.minimal
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
   sudo cp /etc/lippycat/config.yaml.backup /etc/lippycat/config.yaml
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
wget -O /tmp/lc https://github.com/endorses/lippycat/releases/latest/download/lc
sudo cp /tmp/lc /usr/local/bin/
sudo chmod +x /usr/local/bin/lc
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lc

# Restore configuration
sudo cp -r /tmp/lippycat-backup/lippycat /etc/

# Test and restart
lc show config
sudo systemctl enable lippycat
sudo systemctl start lippycat

echo "Disaster recovery complete"
```

## Contact Information

### Support Escalation
- **Level 1:** Operations team (immediate response)
- **Level 2:** Engineering team (within 4 hours)
- **Level 3:** Development team (next business day)

### Documentation Updates
This document should be reviewed and updated:
- After any major configuration changes
- Following significant incidents
- Monthly during maintenance reviews
- When new features are deployed

---

**Last Updated:** 2026-01-10
**Version:** 2.0

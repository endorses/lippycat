# TUI Remote Capture Mode

## Overview

The lippycat TUI supports **remote capture mode**, allowing you to monitor distributed hunter and processor nodes from a centralized Terminal User Interface. This enables real-time visualization of packet capture across multiple network segments, hosts, and interfaces.

## Features

- **Multi-Node Monitoring**: Connect to and monitor multiple hunter/processor nodes simultaneously
- **Hunter Subscription** (v0.2.4+): Selectively subscribe to specific hunters for targeted monitoring
- **TLS/mTLS Security** (v0.2.4+): Encrypted connections with mutual authentication
- **Real-Time Statistics**: View live packet counts, bandwidth, and node health metrics
- **Node Management**: Add, remove, and manage remote nodes via the TUI
- **YAML Configuration**: Define node connections in a configuration file with per-node TLS
- **Visual Node Tree**: Hunters grouped by processor in an intuitive tree view
- **Status Indicators**: Visual indicators for node connection status and health

## Quick Start

### Prerequisites

1. **Running Nodes**: You need at least one processor or hunter node running:
   ```bash
   # Start a processor node
   lc process --listen 0.0.0.0:50051

   # Start a hunter node
   sudo lc hunt --interface eth0 --processor processor-host:50051
   ```

2. **Network Access**: Ensure TUI host can reach nodes on configured ports (default: 50051)

### Launch Remote Mode

#### Option 1: Command Line with Nodes File

```bash
# Using default nodes file location (~/.config/lippycat/nodes.yaml or ./nodes.yaml)
lc watch remote

# Using custom nodes file path
lc watch remote --nodes-file /path/to/nodes.yaml
```

#### Option 2: Launch and Configure Interactively

```bash
# Start in remote mode without nodes file
lc watch remote

# Then add nodes via the TUI:
# 1. Navigate to "Nodes" tab
# 2. Press Enter in the input field
# 3. Type node address (e.g., "192.168.1.10:50051")
# 4. Press Enter to connect
```

## Nodes Configuration File

### File Location Priority

The TUI searches for `nodes.yaml` in the following order:

1. Path specified by `--nodes-file` flag
2. `~/.config/lippycat/nodes.yaml`
3. `./nodes.yaml` (current directory)

### Configuration Format

Create a `nodes.yaml` file with the following structure:

```yaml
# lippycat Nodes Configuration

# Processor nodes (collect traffic from hunters)
processors:
  - name: main-processor
    address: 192.168.1.100:50051
    # Optional: Per-node TLS configuration
    tls:
      enabled: true
      ca_file: /path/to/ca.crt
      cert_file: /path/to/client.crt
      key_file: /path/to/client.key
      skip_verify: false  # Only true for testing!

  - name: backup-processor
    address: 192.168.1.101:50051

# Hunter nodes (capture packets on network interfaces)
# Note: Hunters connect to processors, not directly to TUI
# TUI connects to processors to monitor hunters
hunters:
  - name: edge-hunter-01
    address: 192.168.1.10:50051

  - name: edge-hunter-02
    address: 192.168.1.11:50051

  - name: datacenter-hunter
    address: 10.0.0.50:50051
```

### Configuration Fields

| Field | Description | Required | Example |
|-------|-------------|----------|---------|
| `name` | Friendly display name for the node | Yes | `edge-hunter-01` |
| `address` | Network address in `host:port` format | Yes | `192.168.1.10:50051` |
| `tls.enabled` | Enable TLS for this node | No | `true` |
| `tls.ca_file` | Path to CA certificate | No | `/certs/ca.crt` |
| `tls.cert_file` | Path to client certificate | No | `/certs/client.crt` |
| `tls.key_file` | Path to client key | No | `/certs/client.key` |
| `tls.skip_verify` | Skip certificate verification (insecure!) | No | `false` |
| `subscribed_hunters` | List of hunter IDs to subscribe to | No | `["hunter-01", "hunter-02"]` |

**Note**: The TUI will automatically combine both `hunters` and `processors` sections into a unified node list.

## Using the TUI in Remote Mode

### Nodes Tab

The **Nodes** tab displays all connected remote nodes and provides management capabilities.

#### Node Tree View

Nodes are displayed in a tree structure:

```
┌─ Nodes ────────────────────────────────────────────┐
│                                                    │
│  Processor: 192.168.1.100:50051                    │
│  ├─ edge-hunter-01 (192.168.1.10:50051)            │
│  │  Status: ACTIVE | Packets: 1,234 | Dropped: 0   │
│  │  Interfaces: eth0                               │
│  │                                                 │
│  └─ edge-hunter-02 (192.168.1.11:50051)            │
│     Status: ACTIVE | Packets: 5,678 | Dropped: 2   │
│     Interfaces: eth1, wlan0                        │
│                                                    │
│  [Enter node address to add...]                    │
└────────────────────────────────────────────────────┘
```

#### Node Information Display

Each hunter node shows:
- **Status**: Connection state (ACTIVE, IDLE, DISCONNECTED)
- **Packets Captured**: Total packets seen by hunter
- **Packets Matched**: Packets matching current filters
- **Packets Forwarded**: Packets sent to processor
- **Packets Dropped**: Packets lost due to buffer overflow
- **Active Filters**: Number of filters applied
- **Interfaces**: Network interfaces being monitored
- **Last Heartbeat**: Time since last health check

### Adding Nodes Manually

1. Navigate to the **Nodes** tab (press `3`)
2. Click on the input field or press `Enter`
3. Type the node address in `host:port` format
4. Press `Enter` to connect

The TUI will attempt to connect and display connection status.

### Keyboard Controls

| Key | Action |
|-----|--------|
| `Tab` | Switch between tabs |
| `1-6` | Jump directly to tab (1=Packets, 2=Details, 3=Nodes, etc.) |
| `s` | Select hunters to subscribe to (when focused on processor) |
| `d` | Unsubscribe from hunter or remove processor |
| `Enter` | Focus/edit node input field, or toggle hunter selection in modal |
| `Esc` | Exit input field, close modal, or quit TUI |
| `↑`/`↓` or `j`/`k` | Navigate node/hunter list |
| `Space` | Pause/resume packet capture |
| `q` | Quit application |

### Hunter Subscription Controls (v0.2.4+)

**To selectively monitor hunters:**
1. Navigate to a processor in the Nodes tab
2. Press `s` to open the hunter selector modal
3. Use arrow keys (`↑`/`↓`) or vim keys (`j`/`k`) to navigate
4. Press `Enter` to toggle hunter selection (cyan highlight)
5. Press `Enter` again on "Confirm Selection" to apply
6. Press `Esc` to cancel

**To unsubscribe from a hunter:**
1. Navigate to the hunter in the Nodes tab
2. Press `d` to unsubscribe (stops receiving packets)

**To unsubscribe from all hunters on a processor:**
1. Navigate to the processor
2. Press `s` to open hunter selector
3. Deselect all hunters and confirm

**Benefits:**
- Reduces network bandwidth by filtering at processor
- Focus on specific network segments
- Multiple TUI clients can have different subscriptions

### Settings Tab

The **Settings** tab allows you to configure the nodes file path:

1. Navigate to **Settings** tab (press `6`)
2. Locate the "Nodes File" setting
3. Enter the path to your `nodes.yaml` file
4. Apply settings to reload nodes

## Architecture

### Remote Mode vs. Local Mode

| Feature | Local Mode | Remote Mode |
|---------|------------|-------------|
| Packet Capture | Direct interface capture | Receives from remote nodes |
| Resource Usage | Local CPU/memory for capture | Minimal (display only) |
| Network Scope | Single host/interface | Multiple hosts/interfaces |
| Latency | Minimal | Network-dependent |
| Use Case | Development, single-host debugging | Production monitoring, distributed capture |

### Communication Protocol

- **Protocol**: gRPC (protocol buffers)
- **Port**: Default 50051 (configurable per node)
- **Streaming**: Bidirectional streaming for real-time updates
- **Heartbeat**: Periodic health checks (100ms interval)
- **Status Updates**: Hunter status sent with each heartbeat

### Security Considerations

✅ **Security Features (v0.2.4+)**:
- TLS/mTLS encryption for all gRPC connections
- Mutual authentication with client certificates
- Per-node TLS configuration
- Certificate verification (skip_verify only for testing)

⚠️ **Current Limitations**:
- No role-based access control (RBAC)
- No token-based authentication
- Certificate-based auth only

**Best Practices**:
- Always enable TLS in production (`tls.enabled: true`)
- Never use `skip_verify: true` in production
- Use proper CA-signed certificates with SAN fields
- Deploy in trusted networks with firewall rules
- Monitor connection logs for unauthorized access
- Rotate certificates regularly

**TLS Configuration Example:**
```yaml
processors:
  - name: production-processor
    address: processor.prod.local:50051
    tls:
      enabled: true
      ca_file: /etc/lippycat/certs/ca.crt
      cert_file: /etc/lippycat/certs/tui-client.crt
      key_file: /etc/lippycat/certs/tui-client.key
      skip_verify: false
```

**Certificate Requirements:**
- Must include Subject Alternative Name (SAN) matching hostname/IP
- CN field is deprecated and insufficient
- See `test/testcerts/generate_test_certs.sh` for examples

**Future Enhancements**:
- Token-based authentication
- Role-based access control (RBAC)
- Session management and audit logging

## Troubleshooting

### Connection Issues

**Problem**: "Failed to connect to node"

**Possible Causes**:
1. Node is not running or crashed
2. Firewall blocking port 50051
3. Incorrect address or port
4. Network connectivity issues

**Solutions**:
```bash
# Verify node is running
ps aux | grep lippycat

# Test network connectivity
nc -zv processor-host 50051

# Check firewall rules (Linux)
sudo iptables -L -n | grep 50051

# Verify processor is listening
sudo netstat -tlnp | grep 50051
```

### No Packets Displayed

**Problem**: TUI shows no packets despite nodes being connected

**Possible Causes**:
1. Hunter is running but not capturing traffic
2. BPF filter too restrictive
3. No traffic on monitored interface
4. Processor not forwarding packets to TUI

**Solutions**:
```bash
# Check hunter logs for capture errors
journalctl -u lippycat-hunter -f

# Verify traffic exists on interface
sudo tcpdump -i eth0 -c 10

# Test without BPF filter
lc watch remote  # No filter

# Check processor status
lc show status -P processor-host:50051 --insecure
```

### High Latency

**Problem**: Packets appear delayed in TUI

**Possible Causes**:
1. Network latency between nodes
2. Processor overloaded
3. Too many concurrent hunters
4. Insufficient bandwidth

**Solutions**:
- Reduce hunter count per processor
- Deploy processor closer to hunters (same subnet)
- Increase processor resources (CPU/RAM)
- Use latency-optimized performance mode on hunters:
  ```bash
  sudo lc hunt --tcp-performance-mode latency --processor ...
  ```

### Node Disconnections

**Problem**: Nodes frequently disconnect and reconnect

**Possible Causes**:
1. Network instability
2. Processor resource exhaustion
3. Heartbeat timeout too aggressive
4. gRPC connection limits

**Solutions**:
```bash
# Increase system connection limits
ulimit -n 4096

# Monitor processor resource usage
top -p $(pgrep lippycat)

# Check for network packet loss
ping -c 100 processor-host

# Review processor logs for errors
tail -f /var/log/lippycat/processor.log
```

## Use Cases

### Multi-Site Network Monitoring

Deploy hunters at multiple physical locations and monitor centrally:

```yaml
# nodes.yaml for multi-site deployment
processors:
  - name: central-processor
    address: monitoring.company.com:50051

hunters:
  - name: nyc-office
    address: nyc-gateway.company.com:50051

  - name: sf-office
    address: sf-gateway.company.com:50051

  - name: london-office
    address: lon-gateway.company.com:50051
```

### Network Segmentation

Monitor different network segments from a single pane:

```yaml
hunters:
  - name: dmz-hunter
    address: 192.168.1.10:50051  # DMZ network

  - name: internal-hunter
    address: 10.0.0.50:50051     # Internal network

  - name: guest-wifi-hunter
    address: 172.16.0.20:50051   # Guest network
```

### High-Availability Setup

Use multiple processors for redundancy:

```yaml
processors:
  - name: primary-processor
    address: proc1.company.com:50051

  - name: secondary-processor
    address: proc2.company.com:50051
```

## Advanced Configuration

### Custom Ports

```yaml
# Using non-default ports
processors:
  - name: secure-processor
    address: processor.company.com:9443

hunters:
  - name: hunter-01
    address: hunter1.company.com:8443
```

### Localhost Development

```yaml
# Testing on localhost with multiple ports
hunters:
  - name: local-hunter-1
    address: localhost:50051

  - name: local-hunter-2
    address: localhost:50052

  - name: local-hunter-3
    address: localhost:50053
```

### Docker/Kubernetes Deployments

```yaml
# Kubernetes service addresses
processors:
  - name: k8s-processor
    address: lippycat-processor.monitoring.svc.cluster.local:50051

hunters:
  - name: k8s-hunter-edge
    address: lippycat-hunter-edge.monitoring.svc.cluster.local:50051
```

## Performance Considerations

### TUI Resource Usage

Remote mode TUI is lightweight:
- **CPU**: ~1-5% (display rendering only)
- **Memory**: ~50-100MB (packet buffer size dependent)
- **Network**: Minimal (receives processed data, not raw packets)

### Scalability

Recommended limits:
- **Hunters per Processor**: 10-50 (depends on packet rate)
- **Processors per TUI**: 5-10 (for UI responsiveness)
- **Total Nodes**: 50-100 (varies by network latency)

### Optimization Tips

1. **Use BPF Filters**: Reduce traffic at hunter level
   ```bash
   sudo lc hunt --filter "port 5060" --processor ...
   ```

2. **Adjust Buffer Sizes**: Tune TUI buffer for your workload
   ```bash
   lc watch remote --buffer-size 50000
   ```

3. **Performance Modes**: Use appropriate mode for hunters
   ```bash
   # High packet rate
   sudo lc hunt --tcp-performance-mode throughput ...

   # Low latency required
   sudo lc hunt --tcp-performance-mode latency ...
   ```

## Best Practices

1. **Node Naming**: Use descriptive names indicating location/purpose
   ```yaml
   hunters:
     - name: dc1-web-dmz-hunter
     - name: dc2-db-internal-hunter
   ```

2. **Version Management**: Keep nodes.yaml in version control
   ```bash
   git add ~/.config/lippycat/nodes.yaml
   git commit -m "Update hunter nodes for DC2"
   ```

3. **Documentation**: Comment complex configurations
   ```yaml
   # Production VoIP monitoring setup
   hunters:
     - name: sip-proxy-monitor  # Monitors SIP trunk traffic
       address: 10.1.1.100:50051
   ```

4. **Monitoring**: Track node health and connectivity
   - Set up alerts for node disconnections
   - Monitor packet drop rates
   - Log connection events

5. **Security**: Follow security best practices
   - Restrict network access to node ports
   - Use dedicated monitoring VLANs
   - Regularly audit node configurations
   - Plan for TLS/mTLS when available

## Related Documentation

- [DISTRIBUTED_MODE.md](DISTRIBUTED_MODE.md) - Distributed architecture overview
- [operational-procedures.md](operational-procedures.md) - Deployment procedures
- [SECURITY.md](SECURITY.md) - Security considerations

## Support

For issues with remote capture mode:
1. Check the [Troubleshooting](#troubleshooting) section above
2. Review processor/hunter logs for errors
3. Report issues at [GitHub Issues](https://github.com/endorses/lippycat/issues)
4. Include nodes.yaml configuration (redact sensitive addresses)

---

**Last Updated**: 2025-10-11
**Version**: 2.0
**Compatibility**: lippycat v0.2.4+

**New in v0.2.4:**
- Hunter subscription management (selective monitoring)
- TLS/mTLS support for encrypted connections
- Per-node TLS configuration in nodes.yaml
- Improved reconnection resilience (~100ms)
- Visual hunter selector modal with multi-select

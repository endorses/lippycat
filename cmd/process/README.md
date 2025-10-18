# Process Command - Processor Node Operation

The `process` command runs lippycat as a processor node - a central aggregation point that receives packets from multiple hunter nodes, performs protocol analysis, and provides monitoring interfaces.

## Overview

Processors are the central hub in lippycat's distributed architecture. They:
- Receive packets from multiple hunter nodes via gRPC
- Perform centralized protocol detection and analysis
- Distribute filters to connected hunters
- Write captured traffic to PCAP files
- Provide monitoring APIs for TUI clients
- Optionally forward filtered traffic to upstream processors (hierarchical mode)

## Basic Usage

```bash
# Start processor on default port
lc process --listen :50051

# Processor with TLS
lc process --listen 0.0.0.0:50051 \
  --tls \
  --tls-cert /etc/lippycat/certs/server.crt \
  --tls-key /etc/lippycat/certs/server.key

# Hierarchical mode (forward to upstream processor)
lc process --listen :50051 --upstream parent-processor:50051

# With PCAP writing
lc process --listen :50051 --write-file /var/capture/packets.pcap
```

## Command Flags

### Required Flags

- `-l, --listen` - Listen address for hunter connections (default: `:50051`)

### Processor Configuration

- `--processor-id` - Unique processor identifier (default: hostname)
- `-u, --upstream` - Upstream processor address for hierarchical mode (host:port)
- `-m, --max-hunters` - Maximum concurrent hunter connections (default: 100)
- `--max-subscribers` - Maximum TUI/monitoring subscribers (default: 100, 0 = unlimited)
- `-s, --stats` - Display statistics (default: true)

### PCAP File Writing

Processors can write all received packets to PCAP files for forensics and compliance:

- `-w, --write-file` - Write received packets to PCAP file

**Example:**

```bash
lc process --listen :50051 --write-file /var/capture/packets.pcap
```

**Use Cases:**
- Compliance/audit trails
- Forensic analysis
- Traffic replay
- Long-term storage

**Note:** PCAP writing is independent of hunter selection. The processor writes ALL packets received from all hunters, not just those displayed in the TUI.

### Protocol Detection

- `-d, --enable-detection` - Enable centralized protocol detection (default: true)

When enabled, the processor performs protocol detection on received packets to identify:
- HTTP
- DNS
- TLS/SSL
- MySQL
- PostgreSQL
- VoIP (SIP/RTP)
- VPN protocols

Detection results are available via the monitoring API and TUI.

### Filter Management

- `-f, --filter-file` - Path to filter persistence file (YAML)
  - Default: `~/.config/lippycat/filters.yaml`

Filters are stored in YAML format and automatically distributed to connected hunters.

**Filter File Format:**

```yaml
filters:
  - id: "filter-001"
    type: "sipuser"
    pattern: "alice@example.com"
    action: "forward"
    enabled: true

  - id: "filter-002"
    type: "sipuser"
    pattern: "bob@example.com"
    action: "forward"
    enabled: true

  - id: "filter-003"
    type: "ip"
    pattern: "192.168.1.0/24"
    action: "forward"
    enabled: false
```

**Filter Types:**
- `sipuser` - Match SIP user (From, To, P-Asserted-Identity headers)
- `callid` - Match SIP Call-ID
- `ip` - Match IP address or CIDR range

**Management:**
Filters can be managed via:
1. Direct YAML file editing (requires processor restart)
2. gRPC management API (future)
3. TUI interface (future)

Hunters automatically receive filter updates via the filter subscription mechanism.

### TLS/Security

- `--tls` - Enable TLS encryption (recommended for production)
- `--tls-cert` - Path to server TLS certificate
- `--tls-key` - Path to server TLS key
- `--tls-ca` - Path to CA certificate for client verification (mutual TLS)
- `--tls-client-auth` - Require client certificate authentication (mutual TLS)
- `--insecure` - Allow insecure connections without TLS (must be explicitly set)

## Security

### Production Mode Enforcement

Set `LIPPYCAT_PRODUCTION=true` to enforce TLS and mutual authentication:

```bash
export LIPPYCAT_PRODUCTION=true

# ERROR: requires --tls and --tls-client-auth
lc process --listen :50051

# OK: TLS with mutual authentication
lc process --listen :50051 \
  --tls \
  --tls-cert server.crt \
  --tls-key server.key \
  --tls-ca ca.crt \
  --tls-client-auth
```

### TLS Configuration

Processors support three security modes:

**1. No TLS (Insecure) ⚠️**

Only for testing on trusted networks:

```bash
lc process --listen :50051 --insecure
```

**Security Warning:** Displays prominent banner when TLS is disabled.

**2. Server TLS (One-Way Authentication)**

Hunters verify processor's certificate:

```bash
lc process --listen :50051 \
  --tls \
  --tls-cert /etc/lippycat/certs/server.crt \
  --tls-key /etc/lippycat/certs/server.key
```

**3. Mutual TLS (Two-Way Authentication) ⭐ Recommended**

Both processor and hunters verify each other:

```bash
lc process --listen :50051 \
  --tls \
  --tls-cert /etc/lippycat/certs/server.crt \
  --tls-key /etc/lippycat/certs/server.key \
  --tls-ca /etc/lippycat/certs/ca.crt \
  --tls-client-auth
```

This prevents unauthorized hunters from connecting.

See [docs/SECURITY.md](../../docs/SECURITY.md#tls-transport-encryption) for complete TLS setup and certificate management.

## Hierarchical Mode

Processors can forward filtered traffic to upstream processors for multi-tier aggregation:

```
     Hunters         Edge          Regional       Central
┌──────────┐      ┌──────┐      ┌──────┐      ┌──────┐
│ Hunter 1 │─────→│      │      │      │      │      │
└──────────┘      │ Edge │─────→│ Rgnl │─────→│ Ctrl │
┌──────────┐      │ Proc │      │ Proc │      │ Proc │
│ Hunter 2 │─────→│      │      │      │      │      │
└──────────┘      └──────┘      └──────┘      └──────┘
```

**Edge Processor:**
```bash
lc process --listen :50051 \
  --processor-id edge-01 \
  --upstream regional-processor:50051 \
  --max-hunters 50
```

**Regional Processor:**
```bash
lc process --listen :50051 \
  --processor-id regional-west \
  --upstream central-processor:50051 \
  --max-hunters 10  # Receives from edge processors
```

**Central Processor:**
```bash
lc process --listen :50051 \
  --processor-id central \
  --write-file /var/capture/all-traffic.pcap \
  --max-hunters 5
```

**Use Cases:**
- Geographic distribution
- Network segmentation
- Gradual aggregation with filtering
- Fault isolation

See [docs/DISTRIBUTED_MODE.md](../../docs/DISTRIBUTED_MODE.md#hierarchical-mode) for complete hierarchical setup.

## Configuration File

All flags can be specified in `~/.config/lippycat/config.yaml`:

```yaml
processor:
  listen_addr: "0.0.0.0:50051"
  processor_id: "prod-processor-01"
  upstream_addr: ""  # Empty for no upstream
  max_hunters: 100
  max_subscribers: 100
  write_file: "/var/capture/packets.pcap"
  display_stats: true
  enable_detection: true
  filter_file: "~/.config/lippycat/filters.yaml"

  # TLS security
  tls:
    enabled: true
    cert_file: "/etc/lippycat/certs/server.crt"
    key_file: "/etc/lippycat/certs/server.key"
    ca_file: "/etc/lippycat/certs/ca.crt"
    client_auth: true  # Mutual TLS
```

## Monitoring

Processors expose several monitoring interfaces:

### 1. Statistics Display

When `--stats` is enabled (default), processors log periodic statistics:

```
INFO: Processor statistics
  hunters=5
  active_connections=5
  packets_received=125430
  packets_forwarded=98234
  packets_dropped=0
  bytes_received=87234567
```

### 2. TUI Client Connections

TUI clients can connect to processors for real-time monitoring:

```bash
# Monitor remote processor
lc tui --remote --nodes-file nodes.yaml
```

See [cmd/tui/CLAUDE.md](../tui/CLAUDE.md) for TUI usage.

### 3. Hunter Health Monitoring

Processors track hunter health via heartbeat streaming:
- Connection status
- Packet statistics
- Flow control state
- Latency metrics

## Performance Tuning

### Connection Limits

```bash
# Support many hunters (adjust based on RAM)
lc process --max-hunters 500 --max-subscribers 200

# Unlimited TUI subscribers
lc process --max-subscribers 0
```

**Guidelines:**
- Each hunter: ~5-10MB RAM
- Each subscriber: ~2-5MB RAM
- Monitor system resources under load

### PCAP Write Performance

When writing to PCAP files at high packet rates:

```bash
# Use fast disk (SSD/NVMe)
lc process --write-file /fast-disk/capture.pcap

# Consider PCAP rotation (future feature)
# Currently, processor writes a single continuous PCAP file
```

### Flow Control

Processors automatically manage flow control with hunters:
- `CONTINUE` - Normal operation
- `SLOW` - Queue 30-70% full, slow down
- `PAUSE` - Queue >90% full, stop sending
- `RESUME` - Queue below threshold, resume

Flow control prevents memory exhaustion when processor cannot keep up with hunter traffic.

## Resilience Features

Processors are designed to survive network disruptions and temporary outages:

### Network Interruption Tolerance

**Lenient keepalive settings** tolerate temporary delays (laptop standby, network hiccups):
- 30s ping interval (vs. aggressive 10s)
- 20s timeout for acknowledgment
- Combined with TCP keepalive on hunter connections

**Benefit:** Hunters survive brief disconnections (<50s) without reconnecting.

### Stale Hunter Detection

**Fast cleanup** removes truly dead hunters while allowing recovery:
- 2min cleanup interval (check for stale hunters)
- 5min grace period (hunter must be unresponsive for 5min to be removed)

**Benefit:** Dead hunters cleaned up quickly, live hunters with temporary issues aren't prematurely removed.

## Best Practices

1. **Always use mutual TLS in production** - `--tls --tls-client-auth`
2. **Set meaningful processor IDs** - Use `--processor-id` for identification
3. **Configure filter files** - Use `--filter-file` for persistent filter storage
4. **Monitor hunter connections** - Use TUI or check logs for hunter health
5. **Use hierarchical mode for scale** - Deploy edge processors to reduce central load
6. **Enable protocol detection** - Provides valuable metadata (minimal overhead)
7. **Write PCAPs for compliance** - Use `--write-file` for audit trails
8. **Set connection limits** - Use `--max-hunters` to prevent resource exhaustion

## Troubleshooting

### No Hunters Connecting

```bash
# Check processor is listening
ss -tlnp | grep 50051

# Verify TLS configuration
openssl s_client -connect processor:50051 -CAfile ca.crt

# Check firewall
sudo iptables -L -n | grep 50051
```

### High Memory Usage

```bash
# Reduce connection limits
lc process --max-hunters 50 --max-subscribers 20

# Check for hunter packet floods
# (look for hunters with very high packet rates in logs)

# Disable PCAP writing if not needed
lc process --write-file ""  # Empty string disables
```

### Filter Distribution Not Working

```bash
# Verify filter file exists and is valid YAML
cat ~/.config/lippycat/filters.yaml

# Check processor logs for filter load errors
# Look for "Loaded N filters" message

# Verify hunters are subscribing to filters
# (check hunter logs for "Received filter update")
```

## See Also

- [cmd/hunt/CLAUDE.md](../hunt/CLAUDE.md) - Hunter node configuration
- [cmd/tui/CLAUDE.md](../tui/CLAUDE.md) - TUI monitoring interface
- [docs/DISTRIBUTED_MODE.md](../../docs/DISTRIBUTED_MODE.md) - Complete distributed architecture guide
- [docs/SECURITY.md](../../docs/SECURITY.md) - TLS/mTLS setup and security best practices
- [docs/operational-procedures.md](../../docs/operational-procedures.md) - Production operations guide

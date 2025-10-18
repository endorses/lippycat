# Distributed Mode - Complete Documentation

## Overview

Lippycat supports a fully distributed packet capture architecture that allows you to deploy multiple capture nodes (hunters) across your network and aggregate traffic to central processors. This enables scalable, multi-site packet capture with hierarchical aggregation.

### Key Features

- **Multi-node capture** across network segments
- **Hierarchical aggregation** (edge → regional → central)
- **Real-time monitoring** via TUI with selective hunter subscription
- **TLS/mTLS security** for encrypted node communication
- **Automatic fault recovery** with fast reconnection (<100ms)
- **Filter distribution** from processor to hunters
- **Health monitoring** with heartbeat streaming
- **Scalable** to hundreds of capture nodes

---

## Architecture

### Hub-and-Spoke Mode

Simple architecture where hunters connect directly to a central processor:

```
┌─────────┐  ┌─────────┐  ┌─────────┐
│Hunter 1 │  │Hunter 2 │  │Hunter 3 │
└────┬────┘  └────┬────┘  └────┬────┘
     │            │            │
     └────────┬───┴────────────┘
              │
       ┌──────▼──────┐
       │  Processor  │
       │             │
       │ - Aggregates│
       │ - Filters   │
       │ - Writes    │
       └─────────────┘
```

### Hierarchical Mode

Multi-tier architecture for geographic or network segmentation:

```
     Hunters         Edge         Regional       Central
┌──────────┐      ┌──────┐      ┌──────┐      ┌──────┐
│ Hunter 1 │─────→│      │      │      │      │      │
└──────────┘      │ Edge │─────→│ Rgnl │─────→│ Ctrl │
┌──────────┐      │      │      │      │      │      │
│ Hunter 2 │─────→└──────┘      └──────┘      └──────┘
└──────────┘
```

---

## Components

### Hunter (Edge Capture Node)

Hunters capture packets at the network edge and forward them to processors.

**Features:**
- Live packet capture from network interfaces
- BPF filtering support
- Packet batching (default: 64 packets per batch)
- gRPC streaming to processor
- Automatic reconnection on failure
- Real-time filter updates from processor
- Health status reporting via heartbeat

**Resource Usage:**
- Memory: ~50MB per hunter
- CPU: Minimal (depends on traffic volume)
- Network: Depends on captured traffic

### Processor (Central Aggregation Node)

Processors receive packets from multiple hunters and optionally forward to upstream processors.

**Features:**
- Receives from multiple hunters
- Writes packets to PCAP file
- Distributes filters to hunters
- Monitors hunter health
- Flow control and acknowledgments
- Optional upstream forwarding (hierarchical mode)
- Statistics aggregation

**Resource Usage:**
- Memory: Scales with number of hunters
- CPU: Minimal overhead per hunter
- Disk I/O: Depends on packet volume

---

## Quick Start

### 1. Build

```bash
go build -o lippycat
```

### 2. Basic Setup (Hub-and-Spoke)

**Terminal 1 - Start Processor:**
```bash
sudo ./lippycat process --listen :50051 --write-file /tmp/captured.pcap --stats
```

**Terminal 2 - Start Hunter:**
```bash
sudo ./lippycat hunt --processor localhost:50051 --interface any
```

### 3. Hierarchical Setup (3-Tier)

**Terminal 1 - Central Processor:**
```bash
sudo ./lippycat process --listen :50053 --write-file /tmp/central.pcap
```

**Terminal 2 - Regional Processor:**
```bash
sudo ./lippycat process --listen :50052 --upstream localhost:50053
```

**Terminal 3 - Edge Processor:**
```bash
sudo ./lippycat process --listen :50051 --upstream localhost:50052
```

**Terminal 4 - Hunter:**
```bash
sudo ./lippycat hunt --processor localhost:50051 --interface any
```

---

## Configuration

### Command-Line Flags

#### Hunter

```bash
lippycat hunt [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--processor <host:port>` | Processor address (required) | - |
| `--hunter-id <id>` | Unique hunter identifier | hostname |
| `--interface <iface>` | Network interface to capture | any |
| `--filter <bpf>` | BPF filter expression | "" |
| `--batch-size <n>` | Packets per batch | 64 |
| `--batch-timeout <ms>` | Batch timeout in milliseconds | 100 |
| `--buffer-size <n>` | Packet buffer size | 10000 |

#### Processor

```bash
lippycat process [flags]
```

| Flag | Description | Default |
|------|-------------|---------|
| `--listen <host:port>` | Listen address for hunters | :50051 |
| `--upstream <host:port>` | Upstream processor (hierarchical) | "" |
| `--max-hunters <n>` | Maximum concurrent hunters | 100 |
| `--write-file <path>` | PCAP output file | "" |
| `--stats` | Display statistics | true |

### Configuration File

Create `~/.config/lippycat.yaml`:

```yaml
hunter:
  processor_addr: "processor.example.com:50051"
  hunter_id: "edge-node-01"
  interfaces:
    - eth0
    - eth1
  bpf_filter: "port 5060 or port 5061"
  buffer_size: 10000
  batch_size: 64
  batch_timeout_ms: 100

processor:
  listen_addr: ":50051"
  upstream_addr: "central.example.com:50051"
  max_hunters: 100
  write_file: "/var/log/lippycat/captured.pcap"
  display_stats: true
```

---

## Features

### Packet Capture and Forwarding

**Capture:**
- Live network interface capture using libpcap
- Offline PCAP file reading (hunters can read from files)
- BPF filtering at capture time
- Configurable ring buffer

**Batching:**
- Packets are batched before transmission
- Configurable batch size (default: 64 packets)
- Configurable timeout (default: 100ms)
- 64x reduction in gRPC overhead

**Forwarding:**
- Bidirectional gRPC streaming
- Flow control with acknowledgments
- Preserves original timestamps
- Maintains hunter ID through all tiers

**Performance:**
- ~10,000 packets/sec per hunter
- <100ms end-to-end latency
- Minimal CPU and memory overhead

### Filter Distribution

Processors can distribute filters to hunters in real-time.

**Filter Types:**
- `FILTER_SIP_USER` - SIP From/To headers
- `FILTER_PHONE_NUMBER` - Phone numbers with wildcards
- `FILTER_IP_ADDRESS` - IP addresses or CIDR ranges
- `FILTER_CALL_ID` - SIP Call-IDs
- `FILTER_CODEC` - Audio/video codecs
- `FILTER_BPF` - Custom BPF filters

**Operations:**
- `UPDATE_ADD` - Add new filter
- `UPDATE_MODIFY` - Modify existing filter
- `UPDATE_DELETE` - Delete filter

**Targeting:**
- Broadcast to all hunters
- Target specific hunter by ID

**Example (using grpcurl):**
```bash
# Add filter to all hunters
grpcurl -plaintext -d '{
  "id": "filter-1",
  "type": "FILTER_IP_ADDRESS",
  "pattern": "192.168.1.0/24",
  "enabled": true,
  "description": "Local network filter"
}' localhost:50051 lippycat.management.ManagementService/UpdateFilter

# Add filter to specific hunter
grpcurl -plaintext -d '{
  "id": "filter-2",
  "type": "FILTER_SIP_USER",
  "pattern": "alicent@example.com",
  "target_hunters": ["hunter-1"],
  "enabled": true
}' localhost:50051 lippycat.management.ManagementService/UpdateFilter

# Delete filter
grpcurl -plaintext -d '{
  "filter_id": "filter-1"
}' localhost:50051 lippycat.management.ManagementService/DeleteFilter
```

**Note:** Filters are currently distributed and stored but not yet applied to packet processing. Use BPF filters on hunters for active filtering.

### Health Monitoring

**Heartbeat Streaming:**
- Hunters send heartbeat every 5 seconds
- Includes current statistics and status
- Processors respond with acknowledgment
- Stale detection after 30 seconds

**Hunter Status:**
- `STATUS_HEALTHY` - Normal operation
- `STATUS_WARNING` - Buffer >80% or drop rate >10%
- `STATUS_ERROR` - Connection timeout or critical error
- `STATUS_STOPPING` - Graceful shutdown in progress

**Statistics Reported:**
- Packets captured
- Packets matched (by filters)
- Packets forwarded
- Packets dropped
- Buffer usage
- Active filters count

**Processor Monitoring:**
- Tracks all connected hunters
- Aggregates statistics
- Detects stale/disconnected hunters
- Reports health status

### Automatic Reconnection

Hunters automatically reconnect when connection is lost.

**Reconnection Strategy:**
- **Detection:** Immediate on stream error
- **Backoff:** Exponential (1s, 2s, 4s, 8s, 16s, 32s, 60s max)
- **Max Attempts:** 10 (configurable)
- **Total Time:** ~5 minutes before giving up

**Reconnection Flow:**
1. Detect connection failure
2. Mark as disconnected
3. Wait for exponential backoff
4. Attempt reconnection
5. On success: restore all services
6. On failure: retry with longer backoff

**During Reconnection:**
- Packet capture continues
- Packets are buffered (up to buffer size)
- Failed sends are counted as drops
- After reconnection, forwarding resumes

**Backoff Schedule:**

| Attempt | Backoff | Total Time |
|---------|---------|------------|
| 1 | 1s | 1s |
| 2 | 2s | 3s |
| 3 | 4s | 7s |
| 4 | 8s | 15s |
| 5 | 16s | 31s |
| 6 | 32s | 63s |
| 7-10 | 60s | 123s - 303s |

**Logs During Reconnection:**
```
ERROR Failed to send heartbeat error=<...>
WARN Connection lost, will attempt reconnection
INFO Attempting reconnection attempt=1 max=10 backoff=1s
ERROR Reconnection failed error=connection refused attempt=1
INFO Attempting reconnection attempt=2 max=10 backoff=2s
INFO Reconnection successful attempt=2
INFO Starting heartbeat stream to processor
INFO Heartbeat stream established
```

### TUI Monitoring

The TUI includes a "Nodes" tab for monitoring hunters.

**Access:**
```bash
./lippycat tui
# Press Tab key twice to switch to Nodes tab
```

**Display:**
- Hunter ID
- Hostname
- Status (color-coded)
- Uptime
- Packets captured
- Packets forwarded
- Active filters count

**Navigation:**
- `j` / `↓` - Select next hunter
- `k` / `↑` - Select previous hunter
- `Tab` - Next tab
- `Shift+Tab` - Previous tab
- `q` - Quit

**Status Colors:**
- Green (HEALTHY) - Normal operation
- Yellow (WARNING) - High buffer or drops
- Red (ERROR) - Connection timeout
- Gray (STOPPING) - Shutting down

**Note:** Currently shows placeholder until processor integration is complete. Hunters are monitored via processor logs and stats output.

---

## Use Cases

### 1. Multi-Site VoIP Monitoring

Capture SIP/RTP traffic across multiple office locations:

```
Office A Hunters → Office A Processor ──┐
Office B Hunters → Office B Processor ──┼→ Central Processor → Analysis
Office C Hunters → Office C Processor ──┘
```

**Configuration:**
```yaml
# Hunter at each office
hunter:
  bpf_filter: "port 5060 or port 5061 or (udp and portrange 10000-20000)"

# Regional processors forward to central
processor:
  upstream_addr: "central.company.com:50051"
```

### 2. DMZ and Internal Network Segmentation

Capture from both DMZ and internal networks:

```
DMZ Hunters → DMZ Processor ────┐
                                ├→ Internal Processor → PCAP
Internal Hunters → Internal Processor
```

**Security:** DMZ processor forwards through firewall to internal processor.

### 3. Geographic Distribution

Global packet capture with regional aggregation:

```
US-West Hunters → US-West Processor ──┐
US-East Hunters → US-East Processor ──┼→ Global HQ Processor
EMEA Hunters → EMEA Processor ────────┘
```

### 4. Load Distribution

Distribute load across multiple edge processors:

```
Hunters 1-100   → Edge Processor 1 ──┐
Hunters 101-200 → Edge Processor 2 ──┼→ Central Processor
Hunters 201-300 → Edge Processor 3 ──┘
```

---

## Production Deployment

### Prerequisites

- Go 1.21+ (for building)
- Root/sudo access for packet capture
- Network connectivity between nodes
- Open port 50051 (or configured port)

### Installation

**1. Build binary:**
```bash
go build -o lippycat
sudo cp lippycat /usr/local/bin/
```

**2. Set capabilities (optional, avoids sudo):**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/lippycat
```

**3. Create configuration:**
```bash
mkdir -p ~/.config
vi ~/.config/lippycat.yaml
```

### Systemd Services

**Processor Service (`/etc/systemd/system/lippycat-processor.service`):**
```ini
[Unit]
Description=Lippycat Processor
After=network.target

[Service]
Type=simple
User=lippycat
ExecStart=/usr/local/bin/lippycat process --listen :50051 --write-file /var/log/lippycat/capture.pcap
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Hunter Service (`/etc/systemd/system/lippycat-hunter.service`):**
```ini
[Unit]
Description=Lippycat Hunter
After=network.target

[Service]
Type=simple
User=lippycat
ExecStart=/usr/local/bin/lippycat hunt --processor processor.example.com:50051
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable and start:**
```bash
sudo systemctl enable lippycat-processor
sudo systemctl start lippycat-processor

sudo systemctl enable lippycat-hunter
sudo systemctl start lippycat-hunter
```

### Firewall Configuration

**Processor:**
```bash
# Allow hunters to connect
sudo iptables -A INPUT -p tcp --dport 50051 -j ACCEPT
```

**Hunter:**
```bash
# Allow outbound to processor
sudo iptables -A OUTPUT -p tcp --dport 50051 -j ACCEPT
```

### Monitoring

**Check status:**
```bash
# Processor stats (every 5s)
sudo ./lippycat process --listen :50051 --stats

# Hunter logs
sudo journalctl -u lippycat-hunter -f

# Processor logs
sudo journalctl -u lippycat-processor -f
```

**Verify PCAP output:**
```bash
# Check file is being written
ls -lh /var/log/lippycat/capture.pcap

# View packets
tcpdump -r /var/log/lippycat/capture.pcap | head -20

# Or use Wireshark
wireshark /var/log/lippycat/capture.pcap
```

---

## Performance Tuning

### High-Throughput Capture

For high packet rates:

```bash
# Hunter: larger batches, higher buffer
sudo ./lippycat hunt \
  --processor localhost:50051 \
  --batch-size 256 \
  --buffer-size 50000 \
  --batch-timeout 500
```

### Low-Latency Forwarding

For minimal latency:

```bash
# Hunter: small batches, short timeout
sudo ./lippycat hunt \
  --processor localhost:50051 \
  --batch-size 16 \
  --batch-timeout 10
```

### Memory-Constrained

For limited memory:

```bash
# Hunter: small buffer
sudo ./lippycat hunt \
  --processor localhost:50051 \
  --buffer-size 1000 \
  --batch-size 32
```

### Large-Scale Deployment

For many hunters:

```bash
# Processor: increase limits
sudo ./lippycat process \
  --listen :50051 \
  --max-hunters 1000 \
  --stats=false
```

---

## Troubleshooting

### Hunter Can't Connect

**Error:** `failed to connect to processor: connection refused`

**Solutions:**
1. Verify processor is running:
   ```bash
   sudo netstat -tlnp | grep 50051
   ```

2. Check firewall:
   ```bash
   sudo iptables -L -n | grep 50051
   ```

3. Test connection:
   ```bash
   telnet processor-host 50051
   ```

### No Packets Being Forwarded

**Checklist:**
1. Verify hunter is capturing:
   ```bash
   # Check hunter logs for "Sent packet batch"
   sudo journalctl -u lippycat-hunter -f
   ```

2. Verify processor is receiving:
   ```bash
   # Check processor logs for "Received packet batch"
   sudo journalctl -u lippycat-processor -f
   ```

3. Check BPF filter:
   ```bash
   # Test filter
   sudo tcpdump -i any <your-bpf-filter>
   ```

4. Check interface:
   ```bash
   # List interfaces
   ./lippycat interfaces
   ```

### Reconnection Issues

**Hunter keeps reconnecting:**

1. Check network connectivity:
   ```bash
   ping processor-host
   ```

2. Check processor is accepting connections:
   ```bash
   sudo netstat -tlnp | grep 50051
   ```

3. Check hunter logs for errors:
   ```bash
   sudo journalctl -u lippycat-hunter -f
   ```

**Max attempts exceeded:**
- Hunter gives up after 10 attempts (~5 minutes)
- Check processor availability
- Verify network path
- Check firewall rules

### PCAP File Issues

**File is empty:**
- Wait for batch flush (default 100ms)
- Or use Ctrl+C for graceful shutdown
- Check processor logs for write errors

**File is huge:**
- Apply BPF filter to reduce capture
- Use filter distribution to be more selective
- Rotate PCAP files periodically

### High Packet Drops

**Hunter reporting drops:**

1. Increase buffer size:
   ```bash
   --buffer-size 50000
   ```

2. Increase batch size:
   ```bash
   --batch-size 128
   ```

3. Reduce batch timeout:
   ```bash
   --batch-timeout 50
   ```

4. Check system resources:
   ```bash
   top
   htop
   ```

---

## Protocol Details

### gRPC Services

**Data Service (Port 50051):**
```protobuf
service DataService {
  rpc StreamPackets(stream PacketBatch) returns (stream StreamControl);
}
```

**Management Service (Port 50051):**
```protobuf
service ManagementService {
  rpc RegisterHunter(HunterRegistration) returns (RegistrationResponse);
  rpc Heartbeat(stream HunterHeartbeat) returns (stream ProcessorHeartbeat);
  rpc GetFilters(FilterRequest) returns (FilterResponse);
  rpc SubscribeFilters(FilterRequest) returns (stream FilterUpdate);
  rpc GetHunterStatus(StatusRequest) returns (StatusResponse);
  rpc UpdateFilter(Filter) returns (FilterUpdateResult);
  rpc DeleteFilter(FilterDeleteRequest) returns (FilterUpdateResult);
}
```

### Message Flow

**Startup:**
1. Hunter connects to processor (gRPC)
2. Hunter registers (RegisterHunter RPC)
3. Processor responds with initial filters
4. Hunter subscribes to filter updates
5. Hunter starts heartbeat stream
6. Hunter starts packet stream

**Normal Operation:**
1. Hunter captures packets
2. Hunter batches packets (64 default)
3. Hunter sends batch via StreamPackets
4. Processor receives and processes batch
5. Processor sends acknowledgment
6. Processor writes to PCAP file

**Hierarchical Forwarding:**
1. Edge processor receives from hunter
2. Edge writes to local PCAP (optional)
3. Edge forwards to regional processor
4. Regional forwards to central processor
5. Central writes to PCAP
6. Acks flow back down the chain

**Reconnection:**
1. Stream error detected
2. Hunter marks disconnected
3. Monitor triggers reconnection
4. Exponential backoff wait
5. Reconnect and re-register
6. Re-subscribe to filters
7. Resume packet forwarding

---

## Security Features (v0.2.4+)

### TLS/mTLS Support

All gRPC connections support TLS encryption with mutual authentication:

**Command Line Flags:**
```bash
# Processor with TLS
lc process --listen :50051 \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key \
  --tls-ca /path/to/ca.crt

# Hunter with TLS
sudo lc hunt --processor processor.example.com:50051 \
  --tls-cert /path/to/client.crt \
  --tls-key /path/to/client.key \
  --tls-ca /path/to/ca.crt
```

**Configuration File:**
```yaml
# Global TLS config
tls:
  enabled: true
  ca_file: /etc/lippycat/certs/ca.crt
  cert_file: /etc/lippycat/certs/node.crt
  key_file: /etc/lippycat/certs/node.key
  skip_verify: false  # Only set to true for testing!

# Per-node TLS in nodes.yaml
processors:
  - name: secure-processor
    address: processor.local:50051
    tls:
      enabled: true
      ca_file: /certs/ca.crt
      cert_file: /certs/client.crt
      key_file: /certs/client.key
```

**Certificate Generation:**
See `test/testcerts/generate_test_certs.sh` for example certificate generation with proper SAN fields.

**Important:** Certificates MUST include Subject Alternative Name (SAN) matching the hostname/IP. The CN field is deprecated and no longer sufficient.

### Hunter Subscription (v0.2.4+)

TUI clients can selectively subscribe to specific hunters:

**Usage:**
1. Connect to a processor in TUI remote mode
2. Press `s` on a processor to open hunter selector
3. Use arrow keys to navigate, Enter to toggle selection
4. Selected hunters highlighted in cyan
5. Press Enter again to confirm subscription
6. Press `d` on a hunter to unsubscribe

**Benefits:**
- Reduce bandwidth by only receiving packets from relevant hunters
- Focus monitoring on specific network segments
- Multiple TUI clients can subscribe to different hunters independently

## Known Limitations

1. **No Packet Buffering During Disconnect**
   - Packets captured during reconnection are dropped
   - Mitigation: Increase buffer size
   - Future: Add disk-backed buffer queue

2. **Filters Not Applied to Packets**
   - Filters are distributed and stored but not applied
   - Mitigation: Use BPF filter on hunter
   - Future: Implement SIP/RTP metadata filtering

3. **No Token-Based Authentication**
   - TLS provides encryption and certificate-based auth
   - No role-based access control (RBAC)
   - Mitigation: Network segmentation, firewall rules
   - Future: Add token-based authentication and RBAC

---

## Future Enhancements

### Planned Features

**High Priority:**
- Persistent packet buffering during disconnect
- Sequence tracking and batch resume
- Filter application (SIP user, phone number matching)
- Role-based access control (RBAC)

**Medium Priority:**
- Token-based authentication
- Compression (zstd/lz4)
- Metrics export (Prometheus)
- Enhanced filtering capabilities

**Low Priority:**
- Web dashboard
- OpenTelemetry tracing
- Kubernetes operator
- Multi-region replication

---

## Performance Characteristics

### Throughput
- **Per Hunter:** ~10,000 packets/sec
- **Batch Size:** 64 packets (default)
- **Batch Timeout:** 100ms (default)
- **gRPC Efficiency:** 64x reduction in calls

### Latency
- **End-to-End:** <100ms
- **Heartbeat Interval:** 5 seconds
- **Stale Detection:** 30 seconds

### Scalability
- **Max Hunters:** Configurable (default 100)
- **Tested:** Up to 10 concurrent hunters
- **Memory per Hunter:** ~50MB

### Reconnection
- **Detection:** Immediate on error
- **Max Attempts:** 10 (configurable)
- **Max Backoff:** 60 seconds
- **Total Retry Time:** ~5 minutes

---

## FAQ

**Q: Can hunters read from PCAP files?**
A: Yes, specify a PCAP file path instead of interface name.

**Q: How do I stop capturing without losing packets?**
A: Use Ctrl+C for graceful shutdown. Hunter will flush remaining batches.

**Q: Can I change filters without restarting?**
A: Yes, use UpdateFilter/DeleteFilter RPCs via grpcurl or custom client.

**Q: What happens if processor dies?**
A: Hunter automatically reconnects with exponential backoff (up to 10 attempts).

**Q: How many tiers can I have?**
A: Unlimited. Each processor can forward to an upstream processor.

**Q: Are packets encrypted?**
A: No, connections are plaintext gRPC. Use VPN or add TLS support.

**Q: Can I capture on multiple interfaces?**
A: Yes, specify multiple interfaces: `--interface eth0,eth1` or run multiple hunters.

**Q: How do I rotate PCAP files?**
A: Use external tools (logrotate) or restart processor with new filename.

**Q: What protocols are supported?**
A: All protocols. Lippycat captures raw packets. Built-in VoIP analysis available.

---

## Support

For issues or questions:
- Check logs: `journalctl -u lippycat-hunter -f`
- Review troubleshooting section above
- Check GitHub issues: https://github.com/endorses/lippycat/issues

---

## License

See LICENSE file in repository.

# Virtual Interface Guide

## Overview

lippycat can create virtual network interfaces (TAP/TUN) to expose filtered packet streams to third-party tools like Wireshark, tcpdump, Snort, and Suricata. This transforms lippycat into a **universal packet broker** with filtering, protocol analysis, and tool integration capabilities.

**Status:** Production-ready (Linux only, v0.2.10+)

## Quick Start

```bash
# PCAP replay with VoIP filtering (tcpreplay alternative)
sudo lc sniff voip -r capture.pcap --sipuser alice --virtual-interface

# Monitor with Wireshark
wireshark -i lc0

# Or with tcpdump
tcpdump -i lc0 -nn
```

## Use Cases

### 1. PCAP Replay with Protocol Filtering

**Problem:** You have a 10GB PCAP file and need to filter for a specific SIP user before analyzing in Wireshark.

**Solution:** Use lippycat as a filtering replay engine:

```bash
# Terminal 1: Replay with filtering
sudo lc sniff voip -r huge.pcap --sipuser alice --virtual-interface

# Terminal 2: Capture filtered stream
wireshark -i lc0
```

**Benefits:**
- No need to pre-filter with tcpdump/editcap
- Real-time filtering during replay
- Works with lippycat's protocol analyzers (VoIP call tracking, etc.)

### 2. Live Capture with VoIP-Specific Filtering

**Problem:** Monitor only VoIP traffic on a busy interface.

**Solution:** Use lippycat for protocol detection and filtering:

```bash
# Terminal 1: Capture VoIP traffic only
sudo lc sniff voip -i eth0 --virtual-interface

# Terminal 2: Multiple tools can monitor simultaneously
tcpdump -i lc0 -w voip-archive.pcap &
wireshark -i lc0 &
snort -i lc0 -c voip-rules.conf &
```

**Benefits:**
- VoIP-specific protocol detection before tool integration
- Multiple tools can consume the same stream
- Pre-filtered stream reduces tool overhead

### 3. Distributed Capture Aggregation

**Problem:** Need to monitor traffic from multiple network segments in a single Wireshark instance.

**Solution:** Use lippycat's distributed mode with virtual interface:

```bash
# Edge site 1: Hunter
sudo lc hunt --processor central:50051 --interface eth0 --tls --tls-ca ca.crt

# Edge site 2: Hunter
sudo lc hunt --processor central:50051 --interface eth0 --tls --tls-ca ca.crt

# Central site: Processor with virtual interface
lc process --listen 0.0.0.0:50051 --virtual-interface --tls --tls-cert server.crt --tls-key server.key

# Monitor aggregated stream from all edge sites
wireshark -i lc0
```

**Benefits:**
- Centralized monitoring of geographically distributed capture
- Single Wireshark instance shows traffic from all hunters
- Encrypted transmission between sites (TLS)

### 4. IDS/IPS Integration

**Problem:** Need to run Snort on lippycat's filtered stream.

**Solution:**

```bash
# Terminal 1: Filter for specific traffic
sudo lc sniff voip -i eth0 --virtual-interface

# Terminal 2: Run Snort on filtered stream
snort -i lc0 -c /etc/snort/snort.conf -A full
```

**Benefits:**
- Reduced IDS overhead (pre-filtered stream)
- Protocol-specific rules can focus on relevant traffic
- Works with any IDS/IPS that supports network interfaces

## Configuration

### CLI Flags

All commands that support virtual interfaces (`lc sniff`, `lc sniff voip`, `lc process`) share these flags:

```bash
--virtual-interface              # Enable virtual interface (required)
--vif-name lc0                   # Interface name (default: lc0)
--vif-type tap                   # Interface type: tap or tun (default: tap)
--vif-buffer-size 4096           # Injection queue size (default: 4096)
--vif-startup-delay 3s           # Delay before injection starts (default: 3s)
--vif-replay-timing              # Respect PCAP timestamps (tcpreplay-like, sniff only)
```

### YAML Configuration

Create `~/.config/lippycat/config.yaml`:

```yaml
virtual_interface:
  enabled: true
  name: lc0
  type: tap
  buffer_size: 4096
  startup_delay: 3s
  replay_timing: true  # For PCAP replay only
```

**Note:** CLI flags override YAML configuration.

### Interface Types

#### TAP (Layer 2 - Ethernet)

**Default mode.** Injects full Ethernet frames with reconstructed MAC headers.

**Use when:**
- Full packet visibility needed
- Protocol dissectors require Ethernet headers
- General-purpose analysis in Wireshark

**Example:**
```bash
sudo lc sniff voip -i eth0 --virtual-interface --vif-type tap
```

#### TUN (Layer 3 - IP)

Strips Ethernet headers, injects IP packets only.

**Use when:**
- IP-layer analysis only
- Slightly lower overhead needed
- Routing integration

**Example:**
```bash
sudo lc sniff voip -i eth0 --virtual-interface --vif-type tun
```

## Permission Requirements

Creating TAP/TUN interfaces requires the `CAP_NET_ADMIN` capability.

### Option 1: File Capabilities (Recommended)

```bash
# Grant CAP_NET_ADMIN to lippycat binary
sudo setcap cap_net_admin+ep /usr/local/bin/lc

# Verify
getcap /usr/local/bin/lc
# Output: /usr/local/bin/lc = cap_net_admin+ep

# Now run without sudo
lc sniff voip -i eth0 --virtual-interface
```

**Benefits:**
- No need to run entire process as root
- Capability is dropped after interface creation
- Follows principle of least privilege

### Option 2: Run as Root (Not Recommended)

```bash
sudo lc sniff voip -i eth0 --virtual-interface
```

**Drawbacks:**
- Entire process runs with root privileges
- Increases security risk
- Not necessary with file capabilities

**See:** [SECURITY.md](SECURITY.md) for detailed security considerations.

## Tool Integration Examples

### tcpdump

```bash
# Basic capture
tcpdump -i lc0 -nn

# Write to PCAP file
tcpdump -i lc0 -w filtered-capture.pcap

# Filter specific traffic
tcpdump -i lc0 -nn 'port 5060'
```

### Wireshark

```bash
# Live capture
wireshark -i lc0

# Or from GUI: Capture → Options → select lc0
```

### Snort

```bash
# Run Snort in IDS mode
snort -i lc0 -c /etc/snort/snort.conf -A full

# Alert-only mode
snort -i lc0 -c /etc/snort/snort.conf -A console
```

### Suricata

```bash
# Run Suricata on virtual interface
suricata -i lc0 -c /etc/suricata/suricata.yaml
```

### Zeek (Bro)

```bash
# Run Zeek on virtual interface
zeek -i lc0 /usr/share/zeek/site/local.zeek
```

## Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| Injection rate | 546k pps | Measured with batch processing |
| Latency (avg) | 1.83µs | Capture → TAP write |
| Memory/packet | 1177 bytes | Buffered channel overhead |
| Queue size | 4096 packets | Configurable via `--vif-buffer-size` |
| Drop rate | < 0.1% | Under normal load (< 100k pps) |

**Tuning for higher throughput:**

```bash
# Increase buffer size
lc sniff voip -i eth0 --virtual-interface --vif-buffer-size 16384

# Increase kernel txqueuelen
sudo ip link set lc0 txqueuelen 5000
```

## Timing Replay (tcpreplay Alternative)

When replaying PCAP files, you can preserve original packet timing:

```bash
# Replay with original timing
sudo lc sniff voip -r capture.pcap --virtual-interface --vif-replay-timing

# Monitor in another terminal
tcpdump -i lc0 -tttt -n
```

**How it works:**
- Calculates inter-packet delays from PCAP timestamps
- Sleeps between injections to match original timing
- Useful for realistic traffic replay scenarios

**Comparison with tcpreplay:**

| Feature | lippycat | tcpreplay |
|---------|----------|-----------|
| Filtering during replay | ✅ Yes | ❌ No (requires pre-filtering) |
| Protocol analysis | ✅ Yes (VoIP call tracking) | ❌ No |
| Timing preservation | ✅ Yes | ✅ Yes |
| Speed multiplier | ❌ No (Phase 3) | ✅ Yes |

## Troubleshooting

### Permission Denied

**Symptom:**
```
ERROR Failed to create virtual interface: permission denied
```

**Solution:**
```bash
# Option 1: File capabilities
sudo setcap cap_net_admin+ep /usr/local/bin/lc

# Option 2: Run as root
sudo lc sniff voip -i eth0 --virtual-interface
```

### Interface Already Exists

**Symptom:**
```
ERROR Failed to create virtual interface: file exists
```

**Cause:** Interface `lc0` already exists from previous run.

**Solution:**
```bash
# Delete existing interface
sudo ip link delete lc0

# Or use custom name
lc sniff voip -i eth0 --virtual-interface --vif-name lc-voip0
```

### No Packets Visible in Wireshark

**Symptom:** Wireshark shows interface but no packets.

**Possible causes:**
1. **Startup delay:** Wait 3 seconds for injection to start (default `--vif-startup-delay`)
2. **Filters:** Packets may be filtered out by lippycat's filters (e.g., `--sipuser` filter)
3. **Permissions:** Wireshark may need `CAP_NET_RAW` to capture

**Solution:**
```bash
# Reduce startup delay for testing
lc sniff voip -i eth0 --virtual-interface --vif-startup-delay 1s

# Grant Wireshark capture permissions
sudo setcap cap_net_raw+ep /usr/bin/dumpcap
```

### Packet Drops

**Symptom:** `lc` logs show `Packets dropped: X` on shutdown.

**Cause:** Injection queue overflow (consumer too slow or buffer too small).

**Solution:**
```bash
# Increase buffer size
lc sniff voip -i eth0 --virtual-interface --vif-buffer-size 16384

# Reduce packet rate at source
lc sniff voip -i eth0 --virtual-interface --bpf "not icmp"
```

### Interface Not Deleted After Exit

**Symptom:** `lc0` interface remains after Ctrl+C.

**Cause:** Unclean shutdown (SIGKILL, crash).

**Solution:**
```bash
# Manual cleanup
sudo ip link delete lc0

# Always use SIGTERM/SIGINT (Ctrl+C) for clean shutdown
```

## Platform Support

| Platform | TAP | TUN | Status |
|----------|-----|-----|--------|
| Linux    | ✅  | ✅  | Production |
| macOS    | ❌  | ❌  | Unsupported |
| Windows  | ❌  | ❌  | Unsupported |

**Workarounds for unsupported platforms:**

### macOS
```bash
# Use Docker with Linux VM
docker run -it --rm --privileged --network host \
  -v $(pwd):/data lippycat/lippycat:latest \
  lc sniff voip -r /data/capture.pcap --virtual-interface
```

### Windows
```bash
# Use WSL2 (full Linux kernel support)
wsl --install
wsl
sudo lc sniff voip -i eth0 --virtual-interface
```

## Advanced Scenarios

### Multi-Consumer Pattern

Multiple tools can consume the same virtual interface simultaneously:

```bash
# Terminal 1: Start lippycat
sudo lc sniff voip -i eth0 --virtual-interface

# Terminal 2: Archive with tcpdump
tcpdump -i lc0 -w /archive/voip-$(date +%Y%m%d-%H%M%S).pcap

# Terminal 3: Real-time analysis with Wireshark
wireshark -i lc0

# Terminal 4: IDS alerting
snort -i lc0 -c /etc/snort/snort.conf -A console
```

### Custom Interface Names

Useful for multiple simultaneous virtual interfaces:

```bash
# VoIP-specific interface
sudo lc sniff voip -i eth0 --virtual-interface --vif-name lc-voip0

# DNS-specific interface (future)
sudo lc sniff dns -i eth0 --virtual-interface --vif-name lc-dns0
```

### Hierarchical Aggregation

Combine distributed mode with virtual interface:

```bash
# Level 1: Hunters at edge sites
sudo lc hunt --processor region1:50051 --interface eth0

# Level 2: Regional processor with virtual interface
lc process --listen 0.0.0.0:50051 \
  --upstream central:50051 \
  --virtual-interface --vif-name lc-region1

# Level 3: Central processor with virtual interface
lc process --listen 0.0.0.0:50051 \
  --virtual-interface --vif-name lc-central

# Monitor centralized stream
wireshark -i lc-central
```

## Future Enhancements (Phase 3)

- **Network namespace isolation:** Create interface in isolated namespace
- **Per-hunter interfaces:** `lc-hunter1`, `lc-hunter2` for selective monitoring
- **Rate limiting:** Token bucket to prevent tool flooding
- **Speed multiplier:** Replay faster/slower than original timing (like tcpreplay `-M`)
- **Cross-platform support:** macOS TUN, Windows TAP via OpenVPN driver

## Security Considerations

1. **Privilege requirements:** Use file capabilities instead of running as root
2. **Network isolation:** Phase 3 will add namespace isolation
3. **Packet integrity:** Virtual interface only exposes packets that pass lippycat's filters
4. **Encrypted transmission:** Use TLS in distributed mode to protect hunter→processor streams

**See:** [SECURITY.md](SECURITY.md#virtual-interface-security) for complete security guidance.

## Related Documentation

- [cmd/sniff/README.md](../cmd/sniff/README.md) - Sniff command usage
- [cmd/process/README.md](../cmd/process/README.md) - Processor node usage
- [internal/pkg/vinterface/CLAUDE.md](../internal/pkg/vinterface/CLAUDE.md) - Virtual interface architecture
- [SECURITY.md](SECURITY.md) - Security considerations
- [PERFORMANCE.md](PERFORMANCE.md) - Performance tuning

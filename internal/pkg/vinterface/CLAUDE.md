# Virtual Interface Package

## Overview
`internal/pkg/vinterface` provides virtual network interface (TAP/TUN) creation and packet injection for exposing lippycat's packet stream to third-party tools (Wireshark, tcpdump, Snort, Suricata).

**Status:** Production-ready (Linux only)

## Architecture

### Core Components
- **Manager Interface** (`manager.go`): Platform-agnostic interface for virtual interface operations
- **Linux Implementation** (`manager_linux.go`): TAP/TUN interface via netlink and `/dev/net/tun`
- **Packet Conversion** (`conversion.go`): PacketDisplay → Ethernet/IP frames
- **Timing Replay** (`timing.go`): PCAP timestamp-based packet replay (tcpreplay-like)

### Design Principles
1. **Reusable**: Shared across all commands (sniff, process)
2. **Non-blocking**: Async injection queue, drops on overflow (never blocks capture)
3. **Graceful Degradation**: Commands continue on virtual interface failures
4. **Opt-in**: Activated via `--virtual-interface` flag

## Platform Support

| Platform | TAP | TUN | Status |
|----------|-----|-----|--------|
| Linux    | ✅  | ✅  | Production |
| macOS    | ❌  | ❌  | Unsupported |
| Windows  | ❌  | ❌  | Unsupported |

**Workarounds:** Use WSL2 (Windows) or Docker (macOS).

## Interface Types

### TAP (Layer 2 - Ethernet)
- **Default mode** for full packet visibility
- Injects Ethernet frames with reconstructed MAC headers
- Compatible with all protocol dissectors
- Use case: Full packet analysis in Wireshark

### TUN (Layer 3 - IP)
- Strips Ethernet headers, injects IP packets only
- Slightly lower overhead (no Ethernet reconstruction)
- Use case: IP-layer analysis, routing integration

## Packet Conversion

### TAP Mode (ConvertToEthernet)
```
PacketDisplay → Ethernet Frame
├── Ethernet Header (14 bytes)
│   ├── Dst MAC: 00:00:00:00:00:01
│   ├── Src MAC: 00:00:00:00:00:02
│   └── EtherType: IPv4/IPv6
└── Payload (from PacketDisplay.Payload)
```

### TUN Mode (ConvertToIP)
```
PacketDisplay → IP Packet
└── Payload (Ethernet headers stripped)
```

**Fallbacks:**
- Missing payload → Skip packet (logged)
- Malformed IP header → Skip packet (logged)

## Performance

| Metric | Value | Notes |
|--------|-------|-------|
| Injection rate | 546k pps | Measured with batch processing |
| Latency (avg) | 1.83µs | Capture → TAP write |
| Memory/packet | 1177 bytes | Buffered channel overhead |
| Queue size | 4096 packets | Configurable via `--vif-buffer-size` |

## Configuration

### CLI Flags
```bash
--virtual-interface              # Enable virtual interface
--vif-name lc0                   # Interface name (default: lc0)
--vif-type tap                   # Interface type: tap or tun (default: tap)
--vif-buffer-size 4096           # Injection queue size (default: 4096)
--vif-startup-delay 3s           # Delay before injection starts (default: 3s)
--vif-replay-timing              # Respect PCAP timestamps (tcpreplay-like)
```

### YAML Configuration
```yaml
virtual_interface:
  enabled: true
  name: lc0
  type: tap
  buffer_size: 4096
  startup_delay: 3s
  replay_timing: true
```

## Integration Pattern

### Command Integration
```go
import "github.com/yourusername/lippycat/internal/pkg/vinterface"

// 1. Check if enabled
if viper.GetBool("virtual_interface.enabled") {
    // 2. Create manager
    mgr, err := vinterface.NewManager(vinterface.Config{
        Name:       viper.GetString("virtual_interface.name"),
        Type:       vinterface.InterfaceType(viper.GetString("virtual_interface.type")),
        BufferSize: viper.GetInt("virtual_interface.buffer_size"),
    })
    if err != nil {
        logger.Error("Failed to create virtual interface: %v", err)
        // Continue without virtual interface
    } else {
        defer mgr.Shutdown()

        // 3. Start manager
        if err := mgr.Start(); err != nil {
            logger.Error("Failed to start virtual interface: %v", err)
        }

        // 4. Inject packets in capture loop
        if err := mgr.InjectPacketBatch(packets); err != nil {
            logger.Debug("Injection failed: %v", err)
        }
    }
}
```

### Timing Replay (PCAP files)
```go
import "github.com/yourusername/lippycat/internal/pkg/vinterface"

// Create timing replayer
replayer := vinterface.NewTimingReplayer(viper.GetBool("virtual_interface.replay_timing"))

// In packet loop
for packet := range packets {
    // Respect PCAP timing if enabled
    replayer.Sleep(packet.Timestamp)

    // Inject packet
    mgr.InjectPacket(packet)
}
```

## Error Handling

### Permission Errors
**Symptom:** `permission denied` when creating interface

**Cause:** Missing `CAP_NET_ADMIN` capability

**Solution:**
```bash
# Option 1: File capabilities (preferred)
sudo setcap cap_net_admin+ep /path/to/lc

# Option 2: Run as root (not recommended)
sudo lc sniff voip --virtual-interface
```

### Interface Name Conflicts
**Symptom:** `file exists` error

**Cause:** Interface `lc0` already exists

**Solution:**
```bash
# Check existing interfaces
ip link show

# Delete conflicting interface
sudo ip link delete lc0

# Or use custom name
lc sniff voip --virtual-interface --vif-name lc-voip0
```

## Metrics

### Stats Struct
```go
type Stats struct {
    PacketsInjected   uint64  // Total packets written to TAP/TUN
    PacketsDropped    uint64  // Dropped due to queue overflow
    InjectionErrors   uint64  // Write errors
    QueueUtilization  float64 // Current queue usage (0.0-1.0)
}
```

### Shutdown Logging
Metrics are automatically logged on graceful shutdown:
```
INFO[0010] Virtual interface statistics    interface=lc0 injected=12543 dropped=0 errors=0
```

## Testing

### Unit Tests
- `conversion_test.go`: IPv4/IPv6 TCP/UDP packet conversion
- `manager_test.go`: Error handling, configuration validation

### Integration Tests
- `integration_test.go`: End-to-end TAP → tcpdump validation
- `performance_test.go`: Throughput and latency benchmarks

**Run tests:**
```bash
go test ./internal/pkg/vinterface/...
```

## Security Considerations

### Privilege Requirements
- **Creating interfaces:** Requires `CAP_NET_ADMIN`
- **Writing packets:** Requires write access to `/dev/net/tun`

### Best Practices
1. Use file capabilities instead of root: `setcap cap_net_admin+ep`
2. Run interface in isolated network namespace (Phase 3)
3. Validate packet integrity before injection
4. Never inject untrusted packet payloads

## Limitations

1. **Linux-only:** No native support for macOS/Windows
2. **No filtering:** Packet filtering happens at capture/analysis layer (not in vinterface)
3. **No rate limiting:** Phase 3 feature
4. **Single interface per process:** Multi-interface support in Phase 3

## Future Enhancements (Phase 3)

- Network namespace isolation
- Per-hunter virtual interfaces (multi-interface)
- Rate limiting (token bucket)
- Cross-platform support (macOS/Windows)
- Privilege dropping after interface creation

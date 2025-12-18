# VoIP BPF Filter Optimization Research Report

**Date:** 2025-12-18
**Author:** Research conducted via Claude Code
**Context:** Investigating solutions for high-traffic network scenarios where TCP reassembly overhead impacts VoIP capture performance

---

## Executive Summary

This report investigates the need for optimized BPF filtering in VoIP capture mode. The problem arose when `lc sniff voip` was used on a high-traffic network where TCP reassembly overhead from non-VoIP TCP traffic overwhelmed the SIP handler, even though all SIP traffic on that network was UDP-only.

**Key Finding:** The current architecture processes ALL captured packets through the TCP reassembly engine, regardless of whether TCP SIP is expected. On networks with high TCP traffic but UDP-only SIP, this creates unnecessary overhead.

**Proposed Solution:** Three new flags that work for both `lc sniff voip` and `lc hunt voip`:
1. `--udp-only` - Captures only UDP traffic, bypassing TCP entirely
2. `--sip-port` - Restricts SIP detection to specific port(s) while still capturing RTP on the configured port ranges
3. `--rtp-port-range` - Configures custom RTP port range(s) for environments using non-standard ports

All flags are also configurable via the YAML configuration file.

**Abstraction Point:** A shared `VoIPFilterBuilder` in `internal/pkg/voip/filter.go` that both commands can use to construct optimized BPF filters.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Current Architecture Analysis](#2-current-architecture-analysis)
3. [Proposed Solution](#3-proposed-solution)
4. [Filter Construction Logic](#4-filter-construction-logic)
5. [Shared Abstraction Design](#5-shared-abstraction-design)
6. [Impact Analysis](#6-impact-analysis)
7. [Edge Cases and Considerations](#7-edge-cases-and-considerations)
8. [Configuration Examples](#8-configuration-examples)

---

## 1. Problem Statement

### Scenario

A user ran `lc sniff voip` on a high-traffic network with the following characteristics:
- SIP signaling: **UDP only** on port 5060
- RTP media: UDP on dynamically negotiated ports
- Network also has: High volume of non-VoIP TCP traffic (web, database, etc.)

### Observed Issue

The TCP SIP handler was unable to keep up with the high TCP traffic volume. The gopacket `tcpassembly` engine processes every TCP packet, even those that will never contain SIP, creating significant CPU overhead.

### Current Workaround

Using `--filter "udp"` works but is not discoverable. Users don't know this option exists or that it solves the performance problem.

### The Deeper Problem

If the user sets `--filter "port 5060"` to restrict SIP capture, they lose ALL RTP traffic because RTP uses different ports negotiated in SDP. There's currently no way to say "capture SIP on port 5060, but also capture the RTP that correlates to it."

---

## 2. Current Architecture Analysis

### BPF Filter Flow

#### `lc sniff voip`

```
cmd/sniff/sniff.go
    │
    ├── filter variable (default: "")
    │   └── User sets via --filter flag
    │
    └── voip.StartLiveVoipSniffer(interfaces, filter)
            │
            └── capture.StartLiveSniffer(interfaces, filter, StartVoipSniffer)
                    │
                    └── BPF filter applied at kernel level
```

**File:** `cmd/sniff/sniff.go:83`
```go
SniffCmd.PersistentFlags().StringVarP(&filter, "filter", "f", "", "bpf filter to apply")
```

The filter passes through unchanged to gopacket's `handle.SetBPFFilter(filter)`.

#### `lc hunt voip`

```
cmd/hunt/hunt.go
    │
    ├── bpfFilter variable (default: "")
    │   └── User sets via --filter flag
    │
    └── hunter.Config{BPFFilter: bpfFilter}
            │
            └── internal/pkg/hunter/capture/manager.go
                    │
                    └── buildCombinedBPFFilter()
                            │
                            └── Combines base filter + dynamic filters + port exclusions
```

**File:** `cmd/hunt/hunt.go:72`
```go
HuntCmd.PersistentFlags().StringVarP(&bpfFilter, "filter", "f", "", "BPF filter expression")
```

The hunter has more sophisticated filter building in `internal/pkg/hunter/capture/manager.go:190-250` which combines multiple filter sources.

### Packet Processing Path

Both commands follow similar processing paths after capture:

```
Captured Packet
      │
      ├── TCP? → tcpassembly.Assembler.AssembleWithTimestamp()
      │              │
      │              └── SIP Stream Factory → TCP reassembly → SIP parsing
      │
      └── UDP? → handleUdpPackets()
                     │
                     ├── Is SIP? (content detection) → Process SIP
                     │
                     └── Is RTP? (port correlation) → Process RTP
```

**Key Insight:** Every TCP packet goes through the assembler, regardless of whether it could possibly be SIP.

### RTP Port Ranges

From `internal/pkg/detector/signatures/voip/rtp.go:124-136`:

| Range | Description | Restriction |
|-------|-------------|-------------|
| 16384-32768 | IANA recommended RTP range | Even ports only |
| 10000-20000 | Legacy RTP range | Even ports only |

These ranges are used for heuristic RTP detection when SIP correlation is not available.

### SIP Port Constants

From `internal/pkg/voip/constants.go:10-12`:
```go
SIPPort    = 5060 // SIP over UDP/TCP
SIPPortTLS = 5061 // SIP over TLS (SIPS)
```

---

## 3. Proposed Solution

### New Flags

#### `--udp-only`

**Purpose:** Capture only UDP traffic, completely bypassing TCP processing.

**Behavior:**
- Adds `udp` to the BPF filter
- TCP packets never reach the packet processor
- Zero TCP reassembly overhead

**Use Case:** Networks where SIP is UDP-only and TCP processing overhead is problematic.

#### `--sip-port <port>[,<port>...]`

**Purpose:** Restrict SIP detection to specific port(s) while automatically including RTP port ranges.

**Behavior:**
- Builds a smart BPF filter that captures:
  1. Traffic on specified SIP port(s)
  2. UDP traffic on RTP port ranges (for heuristic RTP detection)
- SIP-correlated RTP (ports learned from SDP) works regardless of port range

**Use Case:** High-traffic networks where you want to limit capture to known SIP ports but still capture all associated RTP.

#### `--rtp-port-range <start>-<end>[,<start>-<end>...]`

**Purpose:** Configure custom RTP port range(s) for environments using non-standard ports.

**Behavior:**
- Overrides the default RTP port range (10000-32768)
- Multiple ranges can be specified (comma-separated)
- Only affects the BPF filter; SIP-correlated RTP detection still works for any port learned from SDP

**Default:** `10000-32768` (covers both IANA recommended 16384-32768 and legacy 10000-20000)

**Use Case:** PBX systems or VoIP providers that use non-standard RTP port ranges (e.g., 8000-9000, 40000-50000).

### Flag Combinations

| Flags | Resulting BPF Filter | Use Case |
|-------|---------------------|----------|
| (none) | (empty - capture all) | Low traffic, unknown SIP ports |
| `--udp-only` | `udp` | UDP SIP only, avoid TCP overhead |
| `--sip-port 5060` | `(port 5060) or (udp portrange 10000-32768)` | Known SIP port, capture RTP |
| `--sip-port 5060 --udp-only` | `udp and (port 5060 or portrange 10000-32768)` | UDP SIP only on port 5060 |
| `--sip-port 5060,5080` | `(port 5060 or port 5080) or (udp portrange 10000-32768)` | Multiple SIP ports |
| `--rtp-port-range 8000-9000` | `udp portrange 8000-9000` | Custom RTP range only |
| `--sip-port 5060 --rtp-port-range 8000-9000` | `(port 5060) or (udp portrange 8000-9000)` | SIP + custom RTP range |
| `--sip-port 5060 --rtp-port-range 8000-9000,40000-50000` | `(port 5060) or (udp portrange 8000-9000) or (udp portrange 40000-50000)` | Multiple custom RTP ranges |

---

## 4. Filter Construction Logic

### BPF Filter Building Algorithm

```
function BuildVoIPBPFFilter(sipPorts []int, rtpPortRanges []PortRange, udpOnly bool, baseFilter string) string:
    parts = []

    # 1. Build SIP port filter
    if len(sipPorts) > 0:
        sipPortFilter = join(" or ", ["port " + p for p in sipPorts])
        parts.append("(" + sipPortFilter + ")")

    # 2. Build RTP port range filter (always UDP)
    # Use custom ranges if provided, otherwise default to 10000-32768
    if len(rtpPortRanges) == 0:
        rtpPortRanges = [{start: 10000, end: 32768}]  # Default range

    for range in rtpPortRanges:
        rtpFilter = "udp portrange " + range.start + "-" + range.end
        parts.append("(" + rtpFilter + ")")

    # 3. Combine SIP and RTP with OR
    voipFilter = join(" or ", parts)

    # 4. Apply UDP-only constraint if requested
    if udpOnly:
        voipFilter = "udp and (" + voipFilter + ")"

    # 5. Combine with base filter if present
    if baseFilter != "":
        return "(" + baseFilter + ") and (" + voipFilter + ")"

    return voipFilter
```

### Example Outputs

**Input:** `sipPorts=[5060], rtpPortRanges=[], udpOnly=false, baseFilter=""`
**Output:** `(port 5060) or (udp portrange 10000-32768)`

**Input:** `sipPorts=[5060], rtpPortRanges=[], udpOnly=true, baseFilter=""`
**Output:** `udp and ((port 5060) or (portrange 10000-32768))`

**Input:** `sipPorts=[5060,5080], rtpPortRanges=[], udpOnly=false, baseFilter="not port 22"`
**Output:** `(not port 22) and ((port 5060 or port 5080) or (udp portrange 10000-32768))`

**Input:** `sipPorts=[5060], rtpPortRanges=[{8000,9000}], udpOnly=false, baseFilter=""`
**Output:** `(port 5060) or (udp portrange 8000-9000)`

**Input:** `sipPorts=[5060], rtpPortRanges=[{8000,9000}, {40000,50000}], udpOnly=true, baseFilter=""`
**Output:** `udp and ((port 5060) or (portrange 8000-9000) or (portrange 40000-50000))`

### Why This Works

1. **SIP on specified ports:** `(port 5060)` captures both TCP and UDP SIP (unless `--udp-only`)
2. **Heuristic RTP:** `(udp portrange 10000-32768)` captures RTP even before SDP is parsed
3. **SIP-correlated RTP:** Works regardless of port because the `portToCallID` map tracks ports learned from SDP - those packets will be captured by the broad port range

---

## 5. Shared Abstraction Design

### Location

New file: `internal/pkg/voip/filter.go`

### Interface

```go
package voip

// PortRange represents a port range with start and end values
type PortRange struct {
    Start int
    End   int
}

// VoIPFilterConfig holds configuration for VoIP-optimized BPF filter building
type VoIPFilterConfig struct {
    SIPPorts      []int       // Specific SIP ports (empty = any port)
    RTPPortRanges []PortRange // Custom RTP port ranges (empty = use default)
    UDPOnly       bool        // If true, capture UDP only (no TCP)
    BaseFilter    string      // User-provided base filter to combine with
}

// VoIPFilterBuilder builds optimized BPF filters for VoIP capture
type VoIPFilterBuilder struct{}

// NewVoIPFilterBuilder creates a new filter builder
func NewVoIPFilterBuilder() *VoIPFilterBuilder

// Build constructs a BPF filter string from the configuration
func (b *VoIPFilterBuilder) Build(config VoIPFilterConfig) string

// Default RTP port range constants (exported for documentation/testing)
const (
    DefaultRTPPortRangeStart = 10000
    DefaultRTPPortRangeEnd   = 32768
)

// DefaultRTPPortRange returns the default RTP port range
func DefaultRTPPortRange() PortRange {
    return PortRange{Start: DefaultRTPPortRangeStart, End: DefaultRTPPortRangeEnd}
}

// ParsePortRanges parses a comma-separated list of port ranges (e.g., "8000-9000,40000-50000")
func ParsePortRanges(s string) ([]PortRange, error)

// ParsePorts parses a comma-separated list of ports (e.g., "5060,5061,5080")
func ParsePorts(s string) ([]int, error)
```

### Usage in Commands

#### `cmd/sniff/voip.go`

```go
func voipHandler(cmd *cobra.Command, args []string) {
    // Build VoIP-optimized filter
    builder := voip.NewVoIPFilterBuilder()
    filterConfig := voip.VoIPFilterConfig{
        SIPPorts:      parseSIPPorts(sipPort),        // from --sip-port flag or viper
        RTPPortRanges: parseRTPPortRanges(rtpRange),  // from --rtp-port-range flag or viper
        UDPOnly:       udpOnly,                        // from --udp-only flag or viper
        BaseFilter:    filter,                         // from --filter flag (inherited)
    }
    effectiveFilter := builder.Build(filterConfig)

    // Use effective filter for capture
    if readFile == "" {
        voip.StartLiveVoipSniffer(interfaces, effectiveFilter)
    } else {
        voip.StartOfflineVoipSniffer(readFile, effectiveFilter)
    }
}
```

#### `cmd/hunt/voip.go`

```go
func runVoIPHunt(cmd *cobra.Command, args []string) error {
    // Build VoIP-optimized filter
    builder := voip.NewVoIPFilterBuilder()
    filterConfig := voip.VoIPFilterConfig{
        SIPPorts:      parseSIPPorts(sipPort),        // from --sip-port flag or viper
        RTPPortRanges: parseRTPPortRanges(rtpRange),  // from --rtp-port-range flag or viper
        UDPOnly:       udpOnly,                        // from --udp-only flag or viper
        BaseFilter:    bpfFilter,                      // from --filter flag (inherited)
    }
    effectiveFilter := builder.Build(filterConfig)

    config := hunter.Config{
        // ...
        BPFFilter: effectiveFilter,
        // ...
    }
    // ...
}
```

### Why This Location?

1. **`internal/pkg/voip/`** - Filter building is VoIP-specific logic
2. **Shared by both commands** - `cmd/sniff/voip.go` and `cmd/hunt/voip.go` both import `internal/pkg/voip`
3. **Near related constants** - Close to `constants.go` which has `SIPPort` definitions
4. **Testable** - Can write unit tests for filter construction logic

---

## 6. Impact Analysis

### `lc sniff voip`

| Aspect | Before | After |
|--------|--------|-------|
| Default behavior | Capture all, process all | Unchanged |
| With `--udp-only` | N/A | BPF filter: `udp` |
| With `--sip-port 5060` | N/A | Smart filter with RTP range |
| TCP overhead | Always present | Eliminated with `--udp-only` |

### `lc hunt voip`

| Aspect | Before | After |
|--------|--------|-------|
| Default behavior | Capture all, apply app filters | Unchanged |
| With `--udp-only` | N/A | BPF filter: `udp` |
| With `--sip-port 5060` | N/A | Smart filter with RTP range |
| Filter combination | Base + dynamic | Base + VoIP-optimized + dynamic |

### Performance Impact

**With `--udp-only` on a high-TCP-traffic network:**
- TCP packets filtered at kernel level (BPF)
- Zero packets reach TCP assembler
- Estimated CPU reduction: 50-90% depending on TCP traffic ratio

**With `--sip-port 5060`:**
- Non-SIP/RTP traffic filtered at kernel level
- Only relevant packets reach user space
- Estimated CPU reduction: Proportional to non-VoIP traffic ratio

---

## 7. Edge Cases and Considerations

### SIP on Non-Standard Ports

**Scenario:** SIP server uses port 5080 instead of 5060.

**Solution:** `--sip-port 5080` or `--sip-port 5060,5080`

**Consideration:** Without `--sip-port`, lippycat detects SIP on any port via content matching. With `--sip-port`, SIP on unlisted ports will not be captured.

### RTP on Non-Standard Ports

**Scenario:** PBX uses RTP ports outside 10000-32768 range (e.g., 8000-9000).

**Solution:** Use `--rtp-port-range` to specify custom port range(s):
```bash
sudo lc sniff voip -i eth0 --sip-port 5060 --rtp-port-range 8000-9000
```

**Multiple ranges supported:**
```bash
sudo lc sniff voip -i eth0 --sip-port 5060 --rtp-port-range 8000-9000,40000-50000
```

**Note:** SIP-correlated RTP (ports learned from SDP) works regardless of the configured port range - the port range only affects heuristic RTP detection for packets captured before SDP is parsed.

### TCP SIP Mixed with UDP SIP

**Scenario:** Some SIP endpoints use TCP, others use UDP.

**With `--udp-only`:** TCP SIP will NOT be captured.

**Recommendation:**
- Don't use `--udp-only` if TCP SIP is expected
- Use `--sip-port` alone (without `--udp-only`) to capture both TCP and UDP SIP

### Interaction with `--filter`

**Scenario:** User specifies both `--filter "host 192.168.1.100"` and `--sip-port 5060`.

**Behavior:** Filters are combined with AND:
```
(host 192.168.1.100) and ((port 5060) or (udp portrange 10000-32768))
```

**This is correct:** Capture VoIP traffic only from/to that specific host.

### Hunter Dynamic Filters

**Scenario:** Processor pushes dynamic BPF filters to hunter.

**Behavior:** Dynamic filters are combined in `buildCombinedBPFFilter()`. The VoIP-optimized base filter should work correctly with dynamic additions.

**Consideration:** Need to verify dynamic filter combination logic handles this correctly.

### PCAP File Reading

**Scenario:** `lc sniff voip --read-file capture.pcap --sip-port 5060`

**Behavior:** BPF filter is applied to PCAP file reading (gopacket supports this).

**Works correctly:** Only packets matching the filter are processed.

---

## 8. Configuration Examples

### CLI Examples

#### Example 1: UDP SIP Only (Original Problem)

```bash
# Problem: High TCP traffic overwhelming TCP SIP handler
# Solution: Capture UDP only

sudo lc sniff voip -i eth0 --udp-only

# Effective BPF: udp
```

#### Example 2: Known SIP Port with RTP

```bash
# Capture SIP on 5060 and all potential RTP traffic

sudo lc sniff voip -i eth0 --sip-port 5060

# Effective BPF: (port 5060) or (udp portrange 10000-32768)
```

#### Example 3: Multiple SIP Ports

```bash
# SIP on 5060 (standard) and 5080 (secondary)

sudo lc sniff voip -i eth0 --sip-port 5060,5080

# Effective BPF: (port 5060 or port 5080) or (udp portrange 10000-32768)
```

#### Example 4: UDP SIP on Specific Port

```bash
# UDP-only SIP on port 5060 (most restrictive, best performance)

sudo lc sniff voip -i eth0 --sip-port 5060 --udp-only

# Effective BPF: udp and ((port 5060) or (portrange 10000-32768))
```

#### Example 5: Custom RTP Port Range

```bash
# PBX uses non-standard RTP ports 8000-9000

sudo lc sniff voip -i eth0 --sip-port 5060 --rtp-port-range 8000-9000

# Effective BPF: (port 5060) or (udp portrange 8000-9000)
```

#### Example 6: Multiple RTP Port Ranges

```bash
# Two PBX systems with different RTP ranges

sudo lc sniff voip -i eth0 --sip-port 5060 --rtp-port-range 8000-9000,40000-50000

# Effective BPF: (port 5060) or (udp portrange 8000-9000) or (udp portrange 40000-50000)
```

#### Example 7: Combined with Host Filter

```bash
# VoIP traffic from specific PBX only

sudo lc sniff voip -i eth0 --filter "host 10.0.0.50" --sip-port 5060

# Effective BPF: (host 10.0.0.50) and ((port 5060) or (udp portrange 10000-32768))
```

#### Example 8: Hunter Mode

```bash
# Hunter with UDP-only VoIP capture and custom RTP range

sudo lc hunt voip --processor processor:50051 \
    --sip-port 5060 \
    --rtp-port-range 8000-9000 \
    --udp-only

# Same filter logic applies
```

### YAML Configuration File Examples

All VoIP filter options are configurable via YAML. Configuration file location: `~/.config/lippycat/config.yaml`

#### Basic VoIP Filter Configuration

```yaml
# ~/.config/lippycat/config.yaml

voip:
  # Restrict SIP detection to specific ports (empty = any port)
  sip_ports: [5060, 5061]

  # Custom RTP port ranges (empty = use default 10000-32768)
  # Each range is specified as "start-end"
  rtp_port_ranges:
    - start: 10000
      end: 32768

  # Capture UDP only (bypasses TCP reassembly)
  udp_only: false
```

#### High-Performance UDP-Only Configuration

```yaml
# For networks with UDP-only SIP and high TCP traffic

voip:
  sip_ports: [5060]
  udp_only: true
  rtp_port_ranges:
    - start: 10000
      end: 32768
```

#### Custom RTP Ranges for Non-Standard PBX

```yaml
# For PBX systems using non-standard RTP ports

voip:
  sip_ports: [5060, 5080]
  udp_only: false
  rtp_port_ranges:
    - start: 8000
      end: 9000
    - start: 40000
      end: 50000
```

#### Hunter-Specific Configuration

```yaml
# Hunter node configuration

hunter:
  processor_addr: "processor.example.com:50051"
  interfaces: ["eth0"]

  # VoIP filter settings (same options as sniff)
  voip:
    sip_ports: [5060]
    rtp_port_ranges:
      - start: 8000
        end: 9000
    udp_only: true
```

#### Complete Example with All Options

```yaml
# ~/.config/lippycat/config.yaml

# Global VoIP settings (used by lc sniff voip)
voip:
  # SIP port restriction
  sip_ports: [5060, 5061, 5080]

  # RTP port ranges for heuristic detection
  rtp_port_ranges:
    - start: 10000
      end: 20000
    - start: 16384
      end: 32768

  # UDP-only mode (disable TCP SIP processing)
  udp_only: false

  # Other VoIP settings (existing)
  gpu_enable: true
  gpu_backend: "auto"
  tcp_performance_mode: "balanced"

# Hunter-specific settings (used by lc hunt voip)
hunter:
  processor_addr: ""  # Required, set via CLI or here
  interfaces: ["any"]
  buffer_size: 10000

  # Hunter VoIP filter settings
  voip:
    sip_ports: [5060]
    rtp_port_ranges:
      - start: 8000
        end: 9000
    udp_only: true

  # TLS settings
  tls:
    enabled: true
    ca_file: "/etc/lippycat/certs/ca.crt"
```

### Flag to Config File Mapping

| CLI Flag | Config Key (sniff voip) | Config Key (hunt voip) |
|----------|------------------------|------------------------|
| `--sip-port` | `voip.sip_ports` | `hunter.voip.sip_ports` |
| `--rtp-port-range` | `voip.rtp_port_ranges` | `hunter.voip.rtp_port_ranges` |
| `--udp-only` | `voip.udp_only` | `hunter.voip.udp_only` |
| `--filter` | N/A (CLI only) | `hunter.bpf_filter` |

### Priority Order

Configuration values are resolved in this order (highest priority first):
1. CLI flags
2. Environment variables (if bound)
3. Config file
4. Built-in defaults

---

## Appendix: Current Code References

### BPF Filter Application

- `internal/pkg/capture/capture.go:280` - `handle.SetBPFFilter(filter)`

### TCP Packet Processing

- `internal/pkg/voip/core.go:203-206` - TCP packets go to `handleTcpPackets()`
- `internal/pkg/voip/tcp_main.go:13-34` - TCP assembler entry point

### UDP Packet Processing

- `internal/pkg/voip/core.go:207-209` - UDP packets go to `handleUdpPackets()`
- `internal/pkg/voip/udp.go:15-52` - UDP handler with SIP/RTP detection

### RTP Port Detection

- `internal/pkg/detector/signatures/voip/rtp.go:124-136` - Port range checks
- `internal/pkg/voip/rtp.go:62-75` - `IsTracked()` for SIP-correlated RTP

### Hunter Filter Building

- `internal/pkg/hunter/capture/manager.go:190-250` - `buildCombinedBPFFilter()`

### Flag Definitions

- `cmd/sniff/sniff.go:83` - `--filter` flag for sniff
- `cmd/hunt/hunt.go:72` - `--filter` flag for hunt

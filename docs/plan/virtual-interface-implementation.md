# Virtual Interface Implementation Plan

**Feature:** Virtual network interface for packet injection
**Purpose:** Enable third-party tools (Wireshark, Snort, Suricata, tcpdump) to monitor lippycat's packet stream
**Status:** Planning
**Target:** Core feature in `all`, `processor`, `cli` builds (opt-in via flag)

---

## Overview

This plan implements a virtual TAP interface that allows real-time packet injection for integration with standard network analysis tools. The feature transforms lippycat into a **universal packet broker** with filtering, protocol analysis, and tool integration capabilities.

**Scope:** Virtual interface support across multiple commands:
- **`lc sniff`** - Live capture + filtering → virtual interface
- **`lc sniff voip`** - VoIP-specific filtering + call tracking → virtual interface
- **`lc process`** - Distributed aggregation from hunters → virtual interface

**Key Use Cases:**
1. **PCAP Replay with Filtering** - `lc sniff voip -r huge.pcap --sipuser alice --virtual-interface` (like tcpreplay with filtering)
2. **Live Filtered Capture** - `lc sniff voip -i eth0 --virtual-interface` (expose VoIP-only stream to Wireshark/Snort)
3. **Distributed Aggregation** - `lc process --virtual-interface` (aggregate multiple hunters, expose unified stream)
4. **Protocol Enrichment** - lc's analyzers filter/enrich before exposing to standard tools

**Key Decisions:**
- **Reusable package** at `internal/pkg/vinterface/` (shared across commands)
- **Default interface name: `lc0`** (matches command name, short and clean, no conflicts)
- Linux-only initially (covers 90%+ server deployments)
- Use `github.com/vishvananda/netlink` (production-proven, used by Docker/Kubernetes)
- Opt-in activation via `--virtual-interface` flag (no mandatory root privileges)
- Equal status output channel alongside TUI, PCAP, and upstream forwarding

---

## Use Case Examples

### 1. PCAP Replay with Protocol Filtering (tcpreplay Alternative)
```bash
# Replay large PCAP, filtering for specific SIP user
sudo lc sniff voip -r 10GB-capture.pcap --sipuser alice --virtual-interface

# Monitor with Wireshark (only Alice's calls visible)
wireshark -i lc0

# Or run IDS on filtered stream
snort -i lc0 -c /etc/snort/snort.conf
```

**Benefit:** No need to pre-filter PCAP with tcpdump/editcap. lc filters in real-time during replay.

### 2. Live Capture with VoIP-Specific Filtering
```bash
# Capture only VoIP traffic, expose to virtual interface
sudo lc sniff voip -i eth0 --virtual-interface

# Multiple tools can monitor simultaneously
tcpdump -i lc0 -w voip-archive.pcap &
wireshark -i lc0 &
snort -i lc0 -c voip-rules.conf &
```

**Benefit:** VoIP-specific protocol detection and call tracking before injection. Tools receive clean, pre-filtered stream.

### 3. Distributed Capture Aggregation
```bash
# Processor aggregates from multiple hunters
lc process --listen 0.0.0.0:50051 --virtual-interface

# Single interface shows traffic from all edge sites
wireshark -i lc0  # See traffic from ALL hunters
```

**Benefit:** Centralized monitoring of geographically distributed capture points.

### 4. Format Conversion and Enrichment
```bash
# lc can reconstruct TCP streams, add metadata, filter protocols
sudo lc sniff -i eth0 --protocol voip,dns --virtual-interface

# Tools receive only specified protocols with lc's analysis
tshark -i lc0
```

**Benefit:** lc's protocol analyzers and reassembly engines work before tool integration.

---

## Phase 1: Core Virtual Interface Package (Reusable Foundation)

**Goal:** Build reusable virtual interface package that works across all commands

**Duration:** 3-5 days

### Tasks

#### Core Package Development
- [x] Add `github.com/vishvananda/netlink` dependency to go.mod
- [x] Create `internal/pkg/vinterface/` package structure (shared, not processor-specific)
- [x] Implement platform-agnostic Manager interface (manager.go)
  ```go
  type Manager interface {
      Name() string
      Start() error
      InjectPacket(packet []byte) error
      InjectPacketBatch(packets []types.PacketDisplay) error
      Shutdown() error
      Stats() Stats
  }
  ```
- [x] Implement Linux TAP manager (manager_linux.go)
  - [x] Interface creation via netlink.LinkAdd()
  - [x] Bring interface up via netlink.LinkSetUp()
  - [x] Open /dev/net/tun file descriptor for packet writing
  - [x] Async injection queue with buffered channel
  - [x] Non-blocking send (drop on overflow)
- [x] Implement unsupported platform stub (manager_unsupported.go)
  - [x] Return clear error message on non-Linux platforms
- [x] Implement packet conversion utilities (conversion.go)
  - [x] Convert types.PacketDisplay to raw Ethernet frames
  - [x] Construct Ethernet header (MAC addresses)
  - [x] Preserve IP layer (IPv4/IPv6) from PacketDisplay
  - [x] Preserve transport layer (TCP/UDP)
  - [x] Handle missing metadata gracefully

#### Initial Integration: `lc sniff voip` (Simplest Use Case)
- [x] Add CLI flags to sniff/voip command
  - [x] --virtual-interface (enable/disable)
  - [x] --vif-name (interface name, default: lc0)
  - [x] --vif-startup-delay (delay before injection starts, default: 3s)
  - [x] --vif-replay-timing (respect PCAP timestamps like tcpreplay)
- [x] Integrate vinterface manager into VoIP capture loop
  - [x] Initialize manager when flag is set
  - [x] Call InjectPacketBatch() for captured packets
  - [x] Shutdown manager on exit
- [x] Handle errors gracefully
  - [x] Permission denied → clear error message
  - [x] Continue sniffing even if virtual interface fails
- [x] Implement packet timing replay
  - [x] Track first packet timestamp and replay start time
  - [x] Calculate inter-packet delays from PCAP timestamps
  - [x] Sleep between injections to match original timing
  - [x] Only applies when --vif-replay-timing flag is set

#### Manual Testing
- [x] Test 1: Live VoIP capture with virtual interface
  - [x] `sudo lc sniff voip -i eth0 --virtual-interface`
  - [x] Verify interface appears in `ip link` as `lc0`
  - [x] Capture with `tcpdump -i lc0 -nn`
  - [x] Validate packets are VoIP traffic only
- [x] Test 2: PCAP replay with filtering
  - [x] `sudo lc sniff voip -r test.pcap --sipuser alice --virtual-interface`
  - [x] Capture with Wireshark on lc0
  - [x] Verify only Alice's calls are replayed
- [x] Test 3: Interface cleanup
  - [x] Start with --virtual-interface
  - [x] Send SIGTERM
  - [x] Verify interface is deleted (`ip link` should not show lc0)
- [x] Test 4: Custom interface name
  - [x] `sudo lc sniff voip -i eth0 --virtual-interface --vif-name lippycat-voip0`
  - [x] Verify custom name is used
- [x] Test 5: Packet timing replay (tcpreplay-like behavior)
  - [x] `sudo lc sniff voip -r test.pcap --virtual-interface --vif-replay-timing`
  - [x] Capture with `tcpdump -i lc0 -tttt -n`
  - [x] Verify packets arrive with realistic delays (not all at once)
  - [x] Compare timing with original PCAP
- [x] Test 6: Configurable startup delay
  - [x] `sudo lc sniff voip -r test.pcap --virtual-interface --vif-startup-delay 1s`
  - [x] Verify shorter startup delay allows faster testing
  - [x] `sudo lc sniff voip -r test.pcap --virtual-interface --vif-startup-delay 10s`
  - [x] Verify longer delay gives more time to start monitoring tools

**Acceptance Criteria:**
- ✅ TAP interface `lc0` created successfully when --virtual-interface flag is used
- ✅ Packets visible in tcpdump/Wireshark
- ✅ Packet filtering works (only VoIP packets with --sipuser filter)
- ✅ Custom interface names work via --vif-name flag
- ✅ Packet timing replay works like tcpreplay (--vif-replay-timing)
- ✅ Configurable startup delay allows tools to attach (--vif-startup-delay)
- ✅ Zero crashes during 5-minute test run
- ✅ Clean interface teardown on all exit paths (normal, SIGTERM, SIGINT)
- ✅ Clear error messages if CAP_NET_ADMIN is missing

**Phase 1 Status: ✅ COMPLETED**

**Commits:**
- `19bdc38` feat(vinterface): implement core virtual interface package
- `58e64be` feat(vinterface): add packet timing replay and configurable startup delay
- `12f4038` fix(vinterface): check permissions before processing packets, abort early

**Key Features Delivered:**
- Virtual TAP interface creation (`lc0` by default, configurable)
- VoIP-only packet injection (post-filtering)
- Realistic PCAP timing replay (tcpreplay-like behavior)
- Configurable startup delay for tool attachment
- Early permission checking with helpful error messages
- Clean resource cleanup on all exit paths

---

## Phase 2: Multi-Command Integration & Production Features

**Goal:** Extend virtual interface to all commands with robust configuration and testing

**Duration:** 1-2 weeks

### Tasks

#### Command Integration
- [x] Integrate with `lc sniff` (general capture)
  - [x] Add --virtual-interface flags to sniff command (inherited from parent)
  - [x] Initialize vinterface manager in capture loop
  - [x] Test with live capture and PCAP replay
  - [x] Create reusable TimingReplayer helper for packet timing
- [x] Integrate with `lc process` (distributed mode)
  - [x] Add --virtual-interface flags to process command
  - [x] Inject packets in processBatch() pipeline
  - [x] Test with hunter → processor → virtual interface flow
- [x] Verify build tags include virtual interface
  - [x] `all` build includes vinterface (verified: sniff and process commands have flag)
  - [x] `processor` build includes vinterface (verified: process command has flag)
  - [x] `cli` build includes vinterface (verified: sniff command has flag)
  - [x] `hunter` build does NOT include vinterface (verified: hunt command has no flag)

#### Configuration & CLI
- [x] Add comprehensive CLI flags (all commands)
  - [x] --vif-type (tap/tun, default: tap)
  - [x] --vif-buffer-size (injection queue size, default: 4096)
- [x] Add YAML configuration support
  - [x] virtual_interface.enabled
  - [x] virtual_interface.name
  - [x] virtual_interface.type
  - [x] virtual_interface.buffer_size
- [x] Implement Config struct and validation
- [x] Default interface name: `lc0` for all commands
- [x] Users can override with --vif-name for custom names
- [x] Implement proper TUN support (Layer 3, strips Ethernet headers)
  - [x] Add ConvertToIP() for TUN interfaces
  - [x] Add extractIPPacket() to strip Ethernet headers
  - [x] Add reconstructIPPacket() for TUN packet reconstruction
  - [x] Update InjectPacketBatch() to choose conversion based on interface type

#### Error Handling & Robustness
- [x] Handle interface creation failures
  - [x] Permission denied (CAP_NET_ADMIN required)
  - [x] Interface name conflicts
  - [x] /dev/net/tun access errors
- [x] Graceful degradation
  - [x] Command continues without virtual interface on failure
  - [x] Clear error messages and logging
- [x] Interface cleanup on crash/SIGTERM
  - [x] Register shutdown hook
  - [x] Delete interface in defer/cleanup
- [x] Handle packet conversion errors
  - [x] Log and skip malformed packets
  - [x] Don't block packet stream on conversion failures

#### Packet Processing
- [x] Implement robust PacketDisplay → Ethernet frame conversion
  - [x] Construct Ethernet header (MAC addresses)
  - [x] Preserve IP layer (IPv4/IPv6)
  - [x] Preserve transport layer (TCP/UDP)
  - [x] Handle missing metadata gracefully
- [x] Add packet buffering
  - [x] Async injection queue (buffered channel)
  - [x] Non-blocking send to queue
  - [x] Drop packets if queue full (don't block hunters)
- [x] Implement batch processing
  - [x] Process packets in batches to reduce syscall overhead

#### Metrics & Observability
- [x] Add metrics tracking
  - [x] Packets injected (counter)
  - [x] Packets dropped (queue full)
  - [x] Injection errors
  - [x] Queue utilization
- [x] Log metrics periodically
  - [x] On shutdown, log injection stats
- [ ] Expose metrics via debug command
  - [ ] Add virtual interface section to `lc debug metrics`

#### Testing
- [x] Unit tests for packet conversion
  - [x] IPv4 TCP packet
  - [x] IPv4 UDP packet
  - [x] IPv6 packets
  - [x] Edge cases (missing fields, malformed data)
- [x] Unit tests for error handling
  - [x] Permission denied
  - [x] Invalid configuration
  - [x] Queue overflow
- [x] Integration tests per command
  - [x] `lc sniff` → virtual interface → tcpdump
  - [x] `lc sniff voip -r` → virtual interface → Wireshark (PCAP replay filtering)
  - [x] `lc process` → virtual interface → tcpdump (distributed mode)
  - [x] Multi-consumer test (tcpdump + Wireshark simultaneously)
  - [x] Verify packet integrity (checksums, payloads)
- [x] Performance tests
  - [x] Injection throughput (target: 100k pps) - **ACHIEVED: 546k pps**
  - [x] Latency measurement (capture → TAP write) - **1.83µs avg**
  - [x] CPU and memory overhead - **1177 bytes per packet**

#### Tool Integration Validation
- [x] Test with tcpdump
  - [x] Verify packet capture
  - [x] Validate filters work correctly
- [x] Test with Wireshark
  - [x] Live capture on lc0
  - [ ] Verify protocol dissectors work
  - [ ] Check for packet drops in Wireshark stats
- [ ] Test with Snort/Suricata (if available)
  - [ ] Run basic IDS rules
  - [ ] Verify alerts triggered correctly

#### Documentation
- [x] User documentation (README.md files)
  - [x] cmd/sniff/README.md - Virtual interface section
    - [x] Live capture with filtering to virtual interface
    - [x] PCAP replay with filtering (tcpreplay alternative)
    - [x] Timing replay examples
  - [x] cmd/process/README.md - Virtual interface section
    - [x] Distributed aggregation to virtual interface
    - [x] Multi-hunter monitoring with single interface
  - [x] Common examples across all commands:
    - [x] tcpdump integration
    - [x] Wireshark integration
    - [x] Snort/Suricata integration
    - [x] Troubleshooting section
- [x] Architecture documentation (CLAUDE.md files)
  - [x] internal/pkg/vinterface/CLAUDE.md - Package documentation
    - [x] Design rationale
    - [x] Platform support matrix
    - [x] Packet conversion details
    - [x] Integration patterns
    - [x] Performance characteristics
  - [x] Update cmd/sniff/CLAUDE.md - Virtual interface integration
  - [x] Update cmd/process/CLAUDE.md - Virtual interface integration
- [x] Central documentation
  - [x] docs/VIRTUAL_INTERFACE.md - Complete guide
    - [x] Overview and use cases
    - [x] Setup and configuration
    - [x] Tool integration examples (tcpdump, Wireshark, Snort, Zeek)
    - [x] Performance characteristics
    - [x] Troubleshooting
    - [x] Advanced scenarios (multi-consumer, hierarchical aggregation)
  - [x] docs/SECURITY.md - Add virtual interface section
    - [x] Privilege requirements (CAP_NET_ADMIN)
    - [x] File capabilities setup (`setcap cap_net_admin+ep`)
    - [x] Security considerations
    - [x] Containerized deployment examples
    - [x] Security checklist
    - [x] Network namespace isolation (Phase 3 preview)
- [x] Update main README.md
  - [x] Add virtual interface to feature list
  - [x] Quick example showing PCAP replay filtering use case
  - [x] Add to Documentation section

**Acceptance Criteria:**
- Virtual interface works in all three commands (sniff, sniff voip, process)
- Configurable via both CLI flags and YAML
- Clean interface teardown on all exit paths (normal, SIGTERM, crash)
- Works with tcpdump, Wireshark, and Snort
- Performance metrics logged and exposed
- Comprehensive documentation across all commands
- All tests passing

---

## Phase 3: Advanced Features (Future)

**Goal:** Enterprise-grade features for production deployments

**Duration:** 2-3 weeks

### Tasks

#### Security Enhancements
- [x] Network namespace isolation
  - [x] Create interface in isolated namespace
  - [x] Document usage with `ip netns`
  - [x] Prevent unauthorized sniffing
- [x] Privilege dropping
  - [x] Create interface with CAP_NET_ADMIN
  - [x] Drop privileges after interface creation
  - [x] Run injection loop as unprivileged user
- [x] Access control
  - [x] File permissions on /dev/net/tun
  - [x] Per-tool access control (namespace isolation + group-based access)
  - [x] Document three access control options (file permissions, namespace isolation, per-tool)
  - [x] Provide production deployment examples
  - [x] Update security checklist and threat model

#### Advanced Packet Processing
- [ ] Preserve original timestamps
  - [ ] Embed hunter timestamps in PCAP-NG format
  - [ ] Support for enhanced block types
~- [ ] Filtering support~ (filtering is done on the hunter)
  ~- [ ] Only inject specific protocols (config: filters)~
  ~- [ ] IP/port-based filtering~
  ~- [ ] Protocol-specific filtering (e.g., VoIP only)~
- [ ] Rate limiting
  - [ ] Cap injection rate (e.g., 100k pps max)
  - [ ] Token bucket algorithm
  - [ ] Prevent flooding monitoring tools

#### Multi-Interface Support
- [ ] Multiple virtual interfaces
  - [ ] Per-hunter interfaces (lc-hunter1, lc-hunter2)
  - [ ] Per-protocol interfaces (lc-voip, lc-dns)
  - [ ] Configuration for interface mapping
- [ ] Dynamic interface management
  - [ ] Create interfaces on-demand
  - [ ] Cleanup unused interfaces

#### Cross-Platform Support
- [ ] macOS TUN support
  - [ ] Research netlink equivalent on macOS
  - [ ] Document limitations (Layer 3 only)
  - [ ] Fallback to Docker Desktop
- [ ] Windows TAP support
  - [ ] OpenVPN TAP driver integration
  - [ ] Document installation steps
  - [ ] Fallback to WSL2
- [ ] Cross-platform documentation
  - [ ] Platform-specific setup guides
  - [ ] Workarounds for unsupported platforms

#### Performance Optimizations
- [ ] Zero-copy optimizations
  - [ ] Reuse packet buffers (sync.Pool)
  - [ ] Minimize allocations
- [ ] Kernel buffer tuning
  - [ ] Increase txqueuelen (`ip link set txqueuelen`)
  - [ ] Document optimal settings
- [ ] Batch injection optimizations
  - [ ] Benchmark different batch sizes
  - [ ] Adaptive batching based on load

#### Advanced Testing
- [ ] Chaos testing
  - [ ] Interface deletion while running
  - [ ] Permission revocation during operation
  - [ ] High packet rate stress tests
- [ ] Platform-specific tests
  - [ ] Linux kernel version compatibility
  - [ ] macOS testing (if implemented)
  - [ ] Windows testing (if implemented)

#### Operational Features
- [ ] CI/CD integration examples
  - [ ] Automated testing with known traffic patterns
  - [ ] IDS configuration validation
  - [ ] Regression testing for security tools
  - [ ] Example: `lc sniff voip -r attack-traffic.pcap --virtual-interface` + Snort validation

**Acceptance Criteria:**
- Network namespace isolation working
- Per-hunter virtual interfaces functional
- Cross-platform support documented (workarounds)
- Rate limiting prevents tool flooding
- All advanced tests passing

---

## Implementation Notes

### Key Architectural Principles

1. **Reusable Package**: `internal/pkg/vinterface/` is shared across all commands (not command-specific)
2. **Opt-in Design**: Virtual interface is disabled by default, activated via `--virtual-interface` flag
3. **Default Name**: `lc0` for all commands (short, matches command name, no conflicts)
4. **Equal Output**: Virtual interface is one of multiple output channels (TUI, PCAP, upstream)
5. **Non-blocking**: Virtual interface never blocks packet stream (drops on overflow)
6. **Platform-specific**: Linux-first approach with documented workarounds for other platforms
7. **Graceful Degradation**: Command continues without virtual interface on failure

### Performance Targets

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Injection rate | 100k pps | Counter: packets_injected/second |
| Latency (p50) | < 1 ms | Hunter receive → TAP write timestamp |
| Latency (p99) | < 10 ms | Tail latency measurement |
| CPU overhead | < 10% | CPU profiling during injection |
| Memory overhead | < 50 MB | RSS increase with virtual interface enabled |
| Drop rate | < 0.1% | Under normal load (< 100k pps) |

### Dependencies

```bash
# Add to go.mod
go get github.com/vishvananda/netlink
```

### Security Considerations

- **Privilege Requirement**: Creating TAP/TUN devices requires `CAP_NET_ADMIN` capability
- **Mitigation**: Use file capabilities instead of running as root
  ```bash
  sudo setcap cap_net_admin+ep /usr/local/bin/lc
  ```
- **Phase 3**: Implement privilege dropping after interface creation
- **Phase 3**: Network namespace isolation for additional security

### Testing Strategy

1. **Unit Tests**: Packet conversion, error handling, configuration validation
2. **Integration Tests**: End-to-end hunter → processor → TAP → tcpdump
3. **Performance Tests**: Throughput, latency, CPU/memory overhead
4. **Tool Compatibility Tests**: tcpdump, Wireshark, Snort, Suricata
5. **Chaos Tests** (Phase 3): Interface deletion, permission revocation, high load

---

## Success Metrics

### Phase 1 (MVP)
- Reusable vinterface package created
- TAP interface works with `lc sniff voip`
- Packets visible in tcpdump/Wireshark
- PCAP replay filtering works (`-r` mode)
- Zero crashes during testing

### Phase 2 (Production)
- Virtual interface works in all three commands (sniff, sniff voip, process)
- Works with tcpdump, Wireshark, Snort
- All tests passing (unit + integration)
- Documentation complete for all commands
- Performance targets met

### Phase 3 (Advanced)
- Network namespace isolation working
- Cross-platform documented
- Advanced features functional (filtering, rate limiting, multi-interface)

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Permission errors (CAP_NET_ADMIN) | High | Clear error messages, documentation on setcap |
| Packet conversion bugs | High | Comprehensive unit tests, validation with Wireshark |
| Performance overhead | Medium | Benchmarking, optimization, async processing |
| Platform compatibility | Low | Linux-first approach, document workarounds |
| Interface cleanup on crash | Medium | Defer cleanup, shutdown hooks, integration tests |

---

## Next Steps

1. Review and approve this plan
2. Create GitHub issue/epic for virtual interface feature
3. Begin Phase 1 implementation:
   - Start with reusable `internal/pkg/vinterface/` package
   - Initial integration with `lc sniff voip` (simplest use case)
   - Validate PCAP replay filtering workflow
4. Iterate based on testing and feedback
5. Expand to other commands in Phase 2

## Value Proposition

This feature positions lippycat as a **universal packet broker** that:
- **Captures** packets (live or from PCAP files)
- **Filters** by protocol, user, call ID, etc.
- **Analyzes** with protocol-specific detectors
- **Exposes** clean streams to industry-standard tools

The virtual interface is the bridge that makes lippycat interoperable with the entire ecosystem of network security and analysis tools - without requiring custom plugins or adapters for each tool.

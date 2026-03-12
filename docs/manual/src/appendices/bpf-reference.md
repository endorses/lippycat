# BPF Filter Reference

BPF (Berkeley Packet Filter) expressions tell the kernel which packets to deliver to lippycat and which to discard. Filtering happens before packets reach userspace, so a well-chosen BPF filter is the single most effective way to reduce CPU load and prevent packet drops on busy links. lippycat uses standard libpcap BPF syntax — the same language accepted by tcpdump, tshark, and Wireshark — via the `--filter` / `-f` flag on all capture commands (`sniff`, `hunt`, `tap`).

## BPF Syntax Quick Reference

A BPF expression is built from **primitives** joined by **operators**.

### Primitives

A primitive consists of an optional qualifier followed by a value:

| Qualifier | Meaning | Example |
|-----------|---------|---------|
| `host` | Match an IP address | `host 10.0.1.5` |
| `net` | Match a subnet (CIDR) | `net 10.0.1.0/24` |
| `port` | Match a port number | `port 5060` |
| `portrange` | Match a port range | `portrange 10000-32768` |
| `proto` | Match a protocol number | `proto 17` (UDP) |

### Direction Qualifiers

Direction qualifiers restrict matching to the source or destination:

| Qualifier | Meaning | Example |
|-----------|---------|---------|
| `src` | Source only | `src host 10.0.1.5` |
| `dst` | Destination only | `dst port 443` |
| `src or dst` | Either (default) | `host 10.0.1.5` |
| `src and dst` | Both | `src and dst net 10.0.0.0/8` |

### Protocol Qualifiers

| Qualifier | Description |
|-----------|-------------|
| `tcp` | TCP segments |
| `udp` | UDP datagrams |
| `icmp` | ICMP messages |
| `icmp6` | ICMPv6 messages |
| `arp` | ARP packets |
| `ip` | IPv4 packets |
| `ip6` | IPv6 packets |
| `ether` | Ethernet frames |
| `vlan` | VLAN-tagged frames (802.1Q) |

### Operators

| Operator | Alias | Meaning |
|----------|-------|---------|
| `and` | `&&` | Both conditions must match |
| `or` | `\|\|` | Either condition must match |
| `not` | `!` | Negate a condition |
| `()` | — | Group sub-expressions |

### Basic Expressions

```
# Single primitive
udp port 5060

# Combined with 'and'
host 10.0.1.5 and udp port 5060

# Combined with 'or'
tcp port 80 or tcp port 443

# Negation
not host 10.0.1.254

# Grouped sub-expressions
host 10.0.1.5 and (tcp port 80 or tcp port 443)
```

> **Shell quoting**: Always wrap the filter in double quotes when passing it to `-f` so the shell does not interpret parentheses or special characters:
> ```bash
> sudo lc sniff -i eth0 -f "host 10.0.1.5 and (tcp port 80 or tcp port 443)"
> ```

## Common Filter Patterns

### VoIP Capture

VoIP traffic consists of SIP signaling (typically on UDP port 5060) and RTP media streams (on high-numbered UDP ports). Capturing both requires a filter that covers the signaling port and the expected media range.

```bash
# SIP signaling only
sudo lc sniff voip -i eth0 -f "udp port 5060"

# SIP + RTP (common media port range)
sudo lc sniff voip -i eth0 -f "udp port 5060 or udp portrange 10000-32768"

# SIP on non-standard port
sudo lc sniff voip -i eth0 -f "udp port 5080"

# SIP from a specific PBX
sudo lc sniff voip -i eth0 -f "host 10.0.1.100 and udp port 5060"

# Multiple SIP ports (disjunction)
sudo lc sniff voip -i eth0 -f "udp port 5060 or udp port 5061 or udp port 5080"
```

The `--sip-port` convenience flag generates optimized port filters without manual BPF:

```bash
# Equivalent to the multi-port filter above, but cleaner
sudo lc sniff voip -i eth0 --sip-port 5060,5061,5080
```

On networks where SIP runs exclusively over UDP, `--udp-only` drops all TCP traffic at the kernel level. This eliminates TCP processing overhead entirely:

```bash
# UDP-only VoIP capture — skips TCP reassembly
sudo lc sniff voip -i eth0 --udp-only --sip-port 5060
```

### DNS Analysis

```bash
# Standard DNS (port 53)
sudo lc sniff dns -i eth0 -f "udp port 53"

# Include mDNS
sudo lc sniff dns -i eth0 -f "udp port 53 or udp port 5353"

# Responses from a specific resolver
sudo lc sniff dns -i eth0 -f "src host 8.8.8.8 and udp port 53"

# DNS over TCP (zone transfers, large responses)
sudo lc sniff dns -i eth0 -f "port 53"
```

Or use the convenience flag:

```bash
sudo lc sniff dns -i eth0 --dns-port 53,5353
```

### TLS / HTTPS

```bash
# HTTPS only
sudo lc sniff tls -i eth0 -f "tcp port 443"

# Multiple TLS services
sudo lc sniff tls -i eth0 -f "tcp port 443 or tcp port 8443 or tcp port 993"

# TLS handshakes to a specific server
sudo lc sniff tls -i eth0 -f "dst host 10.0.1.50 and tcp port 443"
```

Or:

```bash
sudo lc sniff tls -i eth0 --tls-port 443,8443,993
```

### HTTP

```bash
# Standard HTTP ports
sudo lc sniff http -i eth0 -f "tcp port 80 or tcp port 8080"

# HTTP to a development server
sudo lc sniff http -i eth0 -f "dst host 10.0.1.10 and tcp port 3000"
```

Or:

```bash
sudo lc sniff http -i eth0 --http-port 80,8080,3000
```

### Network Analysis

```bash
# All traffic on a subnet
sudo lc sniff -i eth0 -f "net 10.0.1.0/24"

# Traffic between two hosts
sudo lc sniff -i eth0 -f "host 10.0.1.1 and host 10.0.1.2"

# Exclude management traffic
sudo lc sniff -i eth0 -f "not host 10.0.1.254"

# Exclude SSH (useful when capturing over SSH)
sudo lc sniff -i eth0 -f "not tcp port 22"

# Specific MAC address
sudo lc sniff -i eth0 -f "ether host aa:bb:cc:dd:ee:ff"

# VLAN-tagged SIP traffic
sudo lc sniff voip -i eth0 -f "vlan and udp port 5060"

# IPv6 traffic only
sudo lc sniff -i eth0 -f "ip6"

# ICMP (ping, traceroute)
sudo lc sniff -i eth0 -f "icmp"

# ARP requests
sudo lc sniff -i eth0 -f "arp"
```

### Distributed Capture

In distributed deployments, BPF filters are applied on hunter nodes at the edge. This reduces the volume of traffic forwarded to the processor over gRPC.

```bash
# Hunter with BPF filter
sudo lc hunt --processor processor:55555 -i eth0 \
  -f "net 10.0.1.0/24 and udp port 5060" \
  --tls-ca ca.crt

# VoIP hunter with convenience flags
sudo lc hunt voip --processor processor:55555 -i eth0 \
  --udp-only --sip-port 5060 \
  --tls-ca ca.crt

# Tap node with filter
sudo lc tap voip -i eth0 \
  -f "udp port 5060 or udp portrange 10000-32768" \
  --insecure
```

## lippycat Convenience Flags

lippycat provides protocol-aware flags that generate optimized BPF filters. These flags handle edge cases (port lists, UDP-only mode) and combine cleanly with any manual `-f` filter you provide.

| Flag | Equivalent BPF | Available On |
|------|---------------|--------------|
| `--udp-only` | Adds `udp` to the filter | `sniff voip`, `hunt voip`, `tap voip`, `hunt dns` |
| `--sip-port 5060,5080` | `udp port 5060 or udp port 5080` | `sniff voip`, `hunt voip`, `tap voip` |
| `--dns-port 53,5353` | `udp port 53 or udp port 5353` | `sniff dns`, `hunt dns`, `tap dns` |
| `--http-port 80,8080` | `tcp port 80 or tcp port 8080` | `sniff http`, `tap http` |
| `--tls-port 443,8443` | `tcp port 443 or tcp port 8443` | `sniff tls`, `tap tls` |

### Combining Convenience Flags with Manual Filters

Convenience flags and `-f` filters are combined with `and` logic. This lets you use a convenience flag for port selection and a manual filter for host or subnet scoping:

```bash
# SIP on ports 5060/5080, but only from a specific subnet
sudo lc sniff voip -i eth0 --sip-port 5060,5080 -f "net 10.0.1.0/24"

# DNS on standard port, excluding a chatty host
sudo lc sniff dns -i eth0 --dns-port 53 -f "not host 10.0.1.100"

# UDP-only VoIP from a specific PBX
sudo lc sniff voip -i eth0 --udp-only --sip-port 5060 -f "host 10.0.1.50"
```

## Performance Implications

BPF filters execute inside the kernel as compiled bytecode. The kernel discards non-matching packets before they are copied to userspace, saving both CPU cycles and memory bandwidth. On high-speed links, the difference between a broad capture and a focused BPF filter can determine whether lippycat keeps up with the wire rate or drops packets.

### Filter Complexity and Cost

Simple port filters compile to a handful of BPF instructions and add negligible overhead. Each additional `or` clause adds a few more instructions but remains fast — the kernel evaluates the bytecode in a tight loop with no system call overhead. In practice, the cost of the filter is always dwarfed by the cost of copying packets to userspace, so **more specific filters are almost always faster overall** even if they contain more clauses.

```bash
# Few BPF instructions — very fast
-f "udp port 5060"

# More instructions, still fast, but captures far less data
-f "udp port 5060 or udp portrange 10000-32768"

# Captures everything — slowest because every packet reaches userspace
# (no filter)
```

### Use `portrange` Instead of Port Lists

When filtering a contiguous range of ports, `portrange` is more efficient than listing individual ports:

```bash
# Efficient: single range check
-f "udp portrange 10000-32768"

# Less efficient: thousands of individual port comparisons
-f "udp port 10000 or udp port 10001 or udp port 10002 or ..."
```

### Interaction with Other Performance Settings

BPF filtering works alongside other lippycat performance features:

- **`--pcap-buffer-size`** — Sets the kernel capture buffer (in bytes). A larger buffer absorbs traffic bursts that exceed the processing rate. BPF filtering reduces the fill rate of this buffer, making smaller buffers viable. See [Performance Optimization](../part5-advanced/performance.md) for sizing guidance.

- **GPU acceleration** — GPU backends process packets that have already passed the BPF filter. A narrower BPF filter means fewer packets enter the GPU pipeline, leaving GPU resources for the protocol analysis that matters.

- **TCP performance profiles** — BPF filters that exclude TCP (`--udp-only`) eliminate TCP reassembly overhead entirely. On TCP-heavy networks where you only need UDP protocols (SIP, RTP, DNS), this is a significant optimization.

- **AF_XDP** — In AF_XDP mode, BPF programs are compiled for the XDP hook in the kernel's network stack, running even earlier than standard socket-level BPF. The filter syntax is identical. See [Performance Optimization](../part5-advanced/performance.md) for AF_XDP setup.

## Tips and Gotchas

### Shell Quoting

BPF expressions often contain parentheses and logical operators that the shell interprets. Always wrap the filter string in quotes:

```bash
# Correct — shell passes the full string to lippycat
sudo lc sniff -i eth0 -f "host 10.0.1.5 and (port 80 or port 443)"

# Wrong — shell tries to run "(port" as a subshell
sudo lc sniff -i eth0 -f host 10.0.1.5 and (port 80 or port 443)
```

### VLAN-Tagged Traffic

Standard BPF primitives do not match inside VLAN (802.1Q) headers. If your network uses VLANs, prepend the `vlan` qualifier:

```bash
# Matches SIP on VLAN-tagged frames
-f "vlan and udp port 5060"

# Without 'vlan', VLAN-tagged SIP packets are invisible to the filter
-f "udp port 5060"
```

### IPv6

IPv6 packets require the `ip6` qualifier. Bare `host` matches IPv4 only:

```bash
# IPv4 only
-f "host 10.0.1.5"

# IPv6 only
-f "ip6 host 2001:db8::1"

# Both
-f "host 10.0.1.5 or ip6 host 2001:db8::1"
```

### Fragmented Packets

IP-fragmented packets pose a challenge for port-based filters. Only the first fragment carries the TCP/UDP header with port numbers; subsequent fragments lack this information and will not match port-based filters. On modern networks with Path MTU Discovery, fragmentation is rare, but if you suspect fragments are being missed:

```bash
# Capture all fragments from a host (regardless of port)
-f "host 10.0.1.5"
```

### Testing Filters with tcpdump

Before deploying a filter in production, test it with `tcpdump -d` to inspect the compiled BPF bytecode, or with `tcpdump -c 10` to verify it matches expected traffic:

```bash
# Show compiled BPF instructions (no capture needed)
tcpdump -d "udp port 5060 or udp portrange 10000-32768"

# Capture 10 matching packets to verify
sudo tcpdump -i eth0 -c 10 "udp port 5060"
```

### Broadcast and Multicast

To exclude broadcast or multicast noise from a capture:

```bash
# Exclude broadcast
-f "not ether broadcast"

# Exclude multicast
-f "not ether multicast"

# Exclude both
-f "not ether broadcast and not ether multicast"
```

### Maximum Filter Length

libpcap imposes a limit on BPF program length (typically 4096 instructions on Linux). Extremely complex filters with hundreds of port clauses can exceed this limit. If you hit it, consolidate port lists into `portrange` expressions or use lippycat's convenience flags, which generate optimized filters.

## Further Reading

- [tcpdump filter syntax (pcap-filter manual page)](https://www.tcpdump.org/manpages/pcap-filter.7.html) — the authoritative reference for BPF expression syntax
- [Performance Optimization](../part5-advanced/performance.md) — tuning capture performance with TCP profiles, GPU acceleration, and AF_XDP
- [Distributed Architecture](../part3-distributed/architecture.md) — how BPF filters fit into hunter/processor deployments
